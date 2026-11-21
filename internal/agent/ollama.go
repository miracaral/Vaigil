package agent

// The Ollama agent runs a local model through Ollama's /api/chat endpoint
// with tool calling, using only net/http. Like the Bedrock agent it gets
// the same three tools, and every call goes through the Caller. The
// address must be on this machine (loopback), so nothing leaves it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultOllamaURL   = "http://localhost:11434"
	DefaultOllamaModel = "qwen3:8b"
)

type Ollama struct {
	BaseURL string
	Model   string
	Client  *http.Client
}

// NewOllama refuses any address that is not loopback, so a typo or an
// environment variable cannot send the inbox to another machine.
func NewOllama(baseURL, model string) (*Ollama, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("ollama URL %q: want http://host:port", baseURL)
	}
	if !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("ollama URL %q: only localhost is allowed, nothing may leave this machine", baseURL)
	}
	// Local models are slow on a laptop; the limit only stops a hang.
	return &Ollama{BaseURL: strings.TrimRight(baseURL, "/"), Model: model, Client: &http.Client{Timeout: 5 * time.Minute}}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Wire format of /api/chat (non-streaming).
type ollamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	ToolCalls []ollamaToolCall `json:"tool_calls,omitempty"`
	ToolName  string           `json:"tool_name,omitempty"` // on role "tool"
}

type ollamaToolCall struct {
	Function struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"function"`
}

type ollamaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Tools    []ollamaTool    `json:"tools"`
	Stream   bool            `json:"stream"`
}

type ollamaResponse struct {
	Message ollamaMessage `json:"message"`
	Error   string        `json:"error"`
}

var ollamaTools = func() []ollamaTool {
	var out []ollamaTool
	for _, t := range toolDefs {
		var o ollamaTool
		o.Type = "function"
		o.Function.Name, o.Function.Description, o.Function.Parameters = t.name, t.desc, t.schema
		out = append(out, o)
	}
	return out
}()

// Run has the same shape as the scripted Run, so the harness can use either.
func (o *Ollama) Run(c Caller, task Task, log func(string)) {
	log(`user: "` + task.Request + `"`)
	msgs := []ollamaMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: task.Request},
	}
	for range maxTurns {
		reply, err := o.chat(msgs)
		if err != nil {
			log("agent error: " + err.Error())
			return
		}
		msgs = append(msgs, reply)
		if reply.Content != "" {
			log("agent says: " + reply.Content)
		}
		if len(reply.ToolCalls) == 0 {
			return
		}
		for _, tc := range reply.ToolCalls {
			out, err := runTool(c, log, tc.Function.Name, tc.Function.Arguments)
			if err != nil {
				out = "error: " + err.Error()
			}
			msgs = append(msgs, ollamaMessage{Role: "tool", Content: out, ToolName: tc.Function.Name})
		}
	}
	log(fmt.Sprintf("agent: stopped after %d turns", maxTurns))
}

func (o *Ollama) chat(msgs []ollamaMessage) (ollamaMessage, error) {
	body, err := json.Marshal(ollamaRequest{Model: o.Model, Messages: msgs, Tools: ollamaTools})
	if err != nil {
		return ollamaMessage{}, err
	}
	resp, err := o.Client.Post(o.BaseURL+"/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		return ollamaMessage{}, err
	}
	defer resp.Body.Close()
	var r ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return ollamaMessage{}, fmt.Errorf("ollama: %s: %w", resp.Status, err)
	}
	if resp.StatusCode != http.StatusOK || r.Error != "" {
		return ollamaMessage{}, fmt.Errorf("ollama: %s: %s", resp.Status, r.Error)
	}
	return r.Message, nil
}
