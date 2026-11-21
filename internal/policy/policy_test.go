package policy

import "testing"

func TestUnnamedRecipientAsksUser(t *testing.T) {
	d := Evaluate(Request{Tool: "send_email", Recipient: "someone@else.example", SessionTainted: true})
	if d.Effect != Ask {
		t.Fatalf("want ask, got %+v", d)
	}
}

func TestTaintedBodyIsDeniedNotAsked(t *testing.T) {
	d := Evaluate(Request{Tool: "send_email", Recipient: "backup@attacker.example",
		SessionTainted: true, ArgsCarryTaintedData: true})
	if d.Effect != Deny {
		t.Fatalf("want deny, got %+v", d)
	}
}

func TestUserNamedRecipientIsAllowed(t *testing.T) {
	d := Evaluate(Request{Tool: "send_email", Recipient: "boss@company.example",
		UserNamedRecipients: []string{"boss@company.example"}, SessionTainted: true})
	if d.Effect != Allow {
		t.Fatalf("want allow, got %+v", d)
	}
}

// Regression test for the allowlist-abuse bypass found on 2026-11-19.
func TestTaintedDataBeatsAllowlist(t *testing.T) {
	d := Evaluate(Request{Tool: "web_fetch", URL: "https://github.com/x?d=secret",
		AllowedDomains: []string{"github.com"}, SessionTainted: true, ArgsCarryTaintedData: true})
	if d.Effect != Deny || d.Rule != "tainted-data-in-args" {
		t.Fatalf("want tainted-data-in-args deny, got %+v", d)
	}
}

// Closes split-secret: an allowlisted domain is no longer a plain allow
// once the context is tainted.
func TestAllowlistedFetchInTaintedContextAsks(t *testing.T) {
	d := Evaluate(Request{Tool: "web_fetch", URL: "https://github.com/",
		AllowedDomains: []string{"github.com"}, SessionTainted: true})
	if d.Effect != Ask || d.Rule != "tainted-egress" {
		t.Fatalf("want tainted-egress ask, got %+v", d)
	}
}

func TestUnlistedFetchInTaintedContextIsDenied(t *testing.T) {
	d := Evaluate(Request{Tool: "web_fetch", URL: "https://collect.attacker.example/x",
		AllowedDomains: []string{"github.com"}, SessionTainted: true})
	if d.Effect != Deny || d.Rule != "tainted-fetch" {
		t.Fatalf("want tainted-fetch deny, got %+v", d)
	}
}

// Closes subdomain-exfil: a subdomain is another host, and its labels can
// carry data, so only the exact allowlisted host is accepted.
func TestSubdomainIsNotAllowlisted(t *testing.T) {
	for _, u := range []string{"https://4157.github.com/", "https://github.com.attacker.example/"} {
		d := Evaluate(Request{Tool: "web_fetch", URL: u, AllowedDomains: []string{"github.com"}, SessionTainted: true})
		if d.Rule != "tainted-fetch" {
			t.Errorf("%s: want tainted-fetch deny, got %+v", u, d)
		}
	}
}

func TestFetchInCleanContextIsAllowed(t *testing.T) {
	if d := Evaluate(Request{Tool: "web_fetch", URL: "https://github.com/x"}); d.Effect != Allow {
		t.Fatalf("want allow, got %+v", d)
	}
}

func TestReadOnlyIsAllowed(t *testing.T) {
	if d := Evaluate(Request{Tool: "read_inbox", SessionTainted: true}); d.Effect != Allow {
		t.Fatalf("want allow, got %+v", d)
	}
}
