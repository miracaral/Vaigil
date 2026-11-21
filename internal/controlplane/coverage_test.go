package controlplane

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/miracaral/vaigil/internal/policy"
)

const testSecret = "AWS_SECRET_ACCESS_KEY=demo-NOT-A-REAL-KEY"

// coverageTask names every word the coverage tests send, so
// tainted-egress-novel-data lets them through and the coverage limit is
// what decides. (A user who types the words themselves.)
const coverageTask = "x body demo-NOT -A-REAL- 2d412d5245414c2d guide q demo page 2"

// secretSession returns a mediator that approves every ask, with a
// counter of asks and the audit log. The inbox is read only when read is
// true, so the context starts clean otherwise.
func secretSession(t *testing.T, read bool) (*Mediator, *int, *bytes.Buffer) {
	t.Helper()
	asked := 0
	audit := &bytes.Buffer{}
	m := New(map[string]Tool{
		"read_inbox": func(map[string]string) (string, error) { return "note: " + testSecret, nil },
		"web_fetch":  func(map[string]string) (string, error) { return "ok", nil },
	}, Config{UserTask: coverageTask, AllowedDomains: []string{"github.com", "docs.aws.amazon.com"}, Enforce: true,
		Approve: func(string, map[string]string, policy.Decision) bool { asked++; return true },
	}, audit)
	if read {
		if _, err := m.Call("read_inbox", nil); err != nil {
			t.Fatal(err)
		}
	}
	return m, &asked, audit
}

func get(m *Mediator, u string) error {
	_, err := m.Call("web_fetch", map[string]string{"url": u})
	return err
}

// 8 bytes of the secret may leave; the next 8 would make 16 and are
// denied without asking, so the ask budget is not spent on them.
func TestCoverageDeniesCumulativeLeak(t *testing.T) {
	m, asked, audit := secretSession(t, true)
	if err := get(m, "https://github.com/x?body=demo-NOT"); err != nil {
		t.Fatalf("first 8 bytes: want allowed, got %v", err)
	}
	if err := get(m, "https://github.com/x?body=-A-REAL-"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("next 8 bytes: want blocked, got %v", err)
	}
	if *asked != 1 {
		t.Fatalf("want 1 ask (the denied call must not ask), got %d", *asked)
	}
	if !strings.Contains(audit.String(), `"rule":"tainted-coverage-exceeded"`) {
		t.Fatalf("audit log has no tainted-coverage-exceeded entry:\n%s", audit)
	}
}

// Encoding a piece does not hide it from the count.
func TestCoverageSeesEncodedPieces(t *testing.T) {
	m, _, _ := secretSession(t, true)
	_ = get(m, "https://github.com/x?body=demo-NOT")
	// "-A-REAL-" in hex
	audit := m.audit.(*bytes.Buffer)
	if err := get(m, "https://github.com/x?body=2d412d5245414c2d"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("hex piece: want blocked, got %v", err)
	}
	if !strings.Contains(audit.String(), `"rule":"tainted-coverage-exceeded"`) {
		t.Fatalf("want the coverage rule to block it:\n%s", audit)
	}
}

// False-alarm check: a short common word that also sits in the secret
// ("demo", 4 bytes) must not block innocent fetches, even repeated.
func TestCoverageAllowsShortCommonWord(t *testing.T) {
	m, _, _ := secretSession(t, true)
	for _, u := range []string{
		"https://docs.aws.amazon.com/guide?q=demo",
		"https://docs.aws.amazon.com/guide?q=demo&page=2#demo",
	} {
		if err := get(m, u); err != nil {
			t.Fatalf("%s: want allowed, got %v", u, err)
		}
	}
}

// What was sent before the context was tainted is the user's own data,
// not a leak, so it does not count later.
func TestCoverageCountsOnlyTaintedEgress(t *testing.T) {
	m, _, _ := secretSession(t, false)
	if err := get(m, "https://github.com/x?body=demo-NOT"); err != nil {
		t.Fatalf("clean context: want allowed, got %v", err)
	}
	if _, err := m.Call("read_inbox", nil); err != nil {
		t.Fatal(err)
	}
	if err := get(m, "https://github.com/x?body=-A-REAL-"); err != nil {
		t.Fatalf("only 8 tainted bytes sent: want allowed, got %v", err)
	}
}

// WHERE is not measured: the path of an allowlisted URL is left to the
// domain rules. This pins the known gap behind the path-split scenario.
func TestCoverageDoesNotMeasurePath(t *testing.T) {
	m, _, _ := secretSession(t, true)
	for _, u := range []string{"https://github.com/demo-NOT", "https://github.com/-A-REAL-"} {
		if err := get(m, u); err != nil {
			t.Fatalf("%s: want allowed (path not measured), got %v", u, err)
		}
	}
}
