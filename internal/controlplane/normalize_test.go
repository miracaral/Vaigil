package controlplane

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/miracaral/vaigil/internal/policy"
)

const secret = "AWS_SECRET_ACCESS_KEY=demo-NOT-A-REAL-KEY"

func b64(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }

// fetchAfterReading reads untrusted data holding the secret, then tries to
// fetch url from an allowlisted domain with task as the user's request. It
// returns the rule that decided and the fetch error. The user approves
// every ask, so only a deny blocks the call. These tests measure the
// decoder, so they check which rule fired, not only that the call failed.
func fetchAfterReading(t *testing.T, task, url string) (string, error) {
	t.Helper()
	yes := func(string, map[string]string, policy.Decision) bool { return true }
	audit := &bytes.Buffer{}
	m := New(map[string]Tool{
		"read_inbox": func(map[string]string) (string, error) { return "note: " + secret, nil },
		"web_fetch":  func(map[string]string) (string, error) { return "ok", nil },
	}, Config{UserTask: task, AllowedDomains: []string{"github.com"}, Enforce: true, Approve: yes}, audit)
	if _, err := m.Call("read_inbox", nil); err != nil {
		t.Fatal(err)
	}
	_, err := m.Call("web_fetch", map[string]string{"url": url})
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	var last auditEntry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	return last.Decision.Rule, err
}

func TestEncodedSecretIsBlocked(t *testing.T) {
	for name, payload := range map[string]string{
		"base64":        b64(secret),
		"base64-std":    base64.StdEncoding.EncodeToString([]byte(secret)),
		"double-base64": b64(b64(secret)),
		"hex":           hex.EncodeToString([]byte(secret)),
	} {
		rule, err := fetchAfterReading(t, "", "https://github.com/a/b/issues/new?body="+payload)
		if !errors.Is(err, ErrBlocked) || rule != "tainted-data-in-args" {
			t.Errorf("%s: want blocked by tainted-data-in-args, got %v (%s)", name, err, rule)
		}
	}
}

// Four layers is one more than maxDecodeDepth, so the decoder does not
// see the secret. The test pins the limit down: if it changes, this test
// tells us. The call is still denied, by tainted-egress-novel-data.
func TestFourLayersExceedTheLimit(t *testing.T) {
	payload := b64(b64(b64(b64(secret))))
	rule, err := fetchAfterReading(t, "", "https://github.com/a/b/issues/new?body="+payload)
	if rule == "tainted-data-in-args" {
		t.Fatalf("the decoder saw through 4 layers; update maxDecodeDepth tests")
	}
	if !errors.Is(err, ErrBlocked) || rule != "tainted-egress-novel-data" {
		t.Fatalf("want blocked by tainted-egress-novel-data, got %v (%s)", err, rule)
	}
}

// An allowlisted URL made of the user's own words must still work: the
// decoder must not find the secret in it.
func TestCleanURLIsAllowed(t *testing.T) {
	_, err := fetchAfterReading(t, "Find open cedar-policy cedar-go issues (q is:open)",
		"https://github.com/cedar-policy/cedar-go/issues?q=is%3Aopen")
	if err != nil {
		t.Fatalf("want allowed, got %v", err)
	}
}
