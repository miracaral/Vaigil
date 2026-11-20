package controlplane

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/miracaral/vaigil/internal/policy"
)

const secret = "AWS_SECRET_ACCESS_KEY=demo-NOT-A-REAL-KEY"

func b64(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }

// fetchAfterReading reads untrusted data holding the secret, then tries to
// fetch url from an allowlisted domain. It returns the fetch error.
// The user approves every ask, so only a deny (copied data) blocks the call:
// these tests measure the decoder, not the ask rule.
func fetchAfterReading(t *testing.T, url string) error {
	t.Helper()
	yes := func(string, map[string]string, policy.Decision) bool { return true }
	m := New(map[string]Tool{
		"read_inbox": func(map[string]string) (string, error) { return "note: " + secret, nil },
		"web_fetch":  func(map[string]string) (string, error) { return "ok", nil },
	}, Config{AllowedDomains: []string{"github.com"}, Enforce: true, Approve: yes}, nil)
	if _, err := m.Call("read_inbox", nil); err != nil {
		t.Fatal(err)
	}
	_, err := m.Call("web_fetch", map[string]string{"url": url})
	return err
}

func TestEncodedSecretIsBlocked(t *testing.T) {
	for name, payload := range map[string]string{
		"base64":        b64(secret),
		"base64-std":    base64.StdEncoding.EncodeToString([]byte(secret)),
		"double-base64": b64(b64(secret)),
		"hex":           hex.EncodeToString([]byte(secret)),
	} {
		err := fetchAfterReading(t, "https://github.com/a/b/issues/new?body="+payload)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want blocked, got %v", name, err)
		}
	}
}

// Four layers is one more than maxDecodeDepth, so this still gets through.
// The test pins the limit down: if it changes, this test tells us.
func TestFourLayersExceedTheLimit(t *testing.T) {
	payload := b64(b64(b64(b64(secret))))
	if err := fetchAfterReading(t, "https://github.com/a/b/issues/new?body="+payload); err != nil {
		t.Fatalf("want allowed (beyond the decode limit), got %v", err)
	}
}

// An allowlisted URL with no copied data must still work.
func TestCleanURLIsAllowed(t *testing.T) {
	if err := fetchAfterReading(t, "https://github.com/cedar-policy/cedar-go/issues?q=is%3Aopen"); err != nil {
		t.Fatalf("want allowed, got %v", err)
	}
}
