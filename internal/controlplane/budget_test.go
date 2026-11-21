package controlplane

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/miracaral/vaigil/internal/policy"
)

// taintedSession returns a mediator whose context is already tainted, a
// counter of how often the user was asked, and the audit log.
func taintedSession(t *testing.T) (*Mediator, *int, *bytes.Buffer) {
	t.Helper()
	asked := 0
	audit := &bytes.Buffer{}
	m := New(map[string]Tool{
		"read_inbox": func(map[string]string) (string, error) { return "untrusted", nil },
		"web_fetch":  func(map[string]string) (string, error) { return "ok", nil },
	}, Config{AllowedDomains: []string{"github.com"}, Enforce: true,
		Approve: func(string, map[string]string, policy.Decision) bool { asked++; return true },
	}, audit)
	if _, err := m.Call("read_inbox", nil); err != nil {
		t.Fatal(err)
	}
	return m, &asked, audit
}

// fetch carries no content (WHAT), so tainted-egress-novel-data lets it
// through and the ask rule is what decides.
func fetch(m *Mediator, i int) error {
	_, err := m.Call("web_fetch", map[string]string{"url": "https://github.com/"})
	return err
}

func TestAsksWithinBudgetReachTheUser(t *testing.T) {
	m, asked, _ := taintedSession(t)
	for i := 0; i < askBudget; i++ {
		if err := fetch(m, i); err != nil {
			t.Fatalf("ask %d: want approved, got %v", i+1, err)
		}
	}
	if *asked != askBudget {
		t.Fatalf("want %d asks, got %d", askBudget, *asked)
	}
}

func TestAskOverBudgetIsDenied(t *testing.T) {
	m, asked, audit := taintedSession(t)
	for i := 0; i < askBudget; i++ {
		_ = fetch(m, i)
	}
	if err := fetch(m, askBudget); !errors.Is(err, ErrBlocked) {
		t.Fatalf("want blocked, got %v", err)
	}
	if *asked != askBudget {
		t.Fatalf("the user was asked again: %d asks, want %d", *asked, askBudget)
	}
	if !strings.Contains(audit.String(), `"rule":"ask-budget-exceeded"`) {
		t.Fatalf("audit log has no ask-budget-exceeded entry:\n%s", audit)
	}
}
