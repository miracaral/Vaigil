// Package policy decides whether a tool call may run.
//
// v0.1 keeps the rules in plain Go so the demo has no dependencies.
// The same rules are written in Cedar in policies/vaigil.cedar; v0.2
// swaps this file for the cedar-go engine.
package policy

import (
	"fmt"
	"net/url"
	"strings"
)

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
	// Ask means: risky but possibly legitimate, so a human decides.
	Ask Effect = "ask"
)

// Request is everything the policy needs to judge one tool call.
type Request struct {
	Tool string
	// Recipient is the email address a send_email call targets.
	Recipient string
	// URL is the address a web_fetch call targets.
	URL string
	// Subject and Body are the content of a send_email call.
	Subject, Body string
	// UserTask is what the user typed. With the allowlist it is the only
	// trusted source of content an egress call may carry from a tainted
	// context (tainted-egress-novel-data).
	UserTask string
	// UserNamedRecipients are addresses the user typed in their own request.
	UserNamedRecipients []string
	// AllowedDomains may be fetched from a tainted context if the user
	// approves; any other host is denied. Matching is exact: a subdomain
	// of an allowed domain is another host (subdomain-exfil).
	AllowedDomains []string
	// SessionTainted is true once untrusted content has entered the agent's context.
	SessionTainted bool
	// ArgsCarryTaintedData is true when the call's arguments contain text
	// copied from an untrusted tool result (data flow, not just context).
	ArgsCarryTaintedData bool
}

type Decision struct {
	Effect Effect `json:"effect"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// egressTools can carry data out of the system.
var egressTools = map[string]bool{"send_email": true, "web_fetch": true}

func Evaluate(r Request) Decision {
	// Checked first: what leaves matters more than where it goes.
	// The user may still send their own words to anyone they named.
	if egressTools[r.Tool] && r.ArgsCarryTaintedData && !userNamed(r) {
		return Decision{Deny, "tainted-data-in-args",
			"arguments contain data copied from an untrusted tool result"}
	}
	switch r.Tool {
	case "send_email":
		return evalSendEmail(r)
	case "web_fetch":
		return evalWebFetch(r)
	default:
		return Decision{Allow, "read-only", "tool has no side effects"}
	}
}

func userNamed(r Request) bool {
	if r.Tool != "send_email" {
		return false
	}
	for _, addr := range r.UserNamedRecipients {
		if strings.EqualFold(addr, r.Recipient) {
			return true
		}
	}
	return false
}

func evalSendEmail(r Request) Decision {
	if userNamed(r) {
		return Decision{Allow, "user-named-recipient", "the user asked for this recipient"}
	}
	if !r.SessionTainted {
		return Decision{Allow, "clean-context", "no untrusted data in context"}
	}
	if _, novel := novelData(r); novel {
		// Text the agent wrote itself (a reply) to someone the user did not
		// name. Copied untrusted data was denied above (tainted-data-in-args)
		// and the mediator's coverage limit still applies, so what is left
		// is new text: show all of it and let the user decide, once.
		return Decision{Ask, "tainted-egress-agent-text",
			fmt.Sprintf("the agent wrote text the user never gave, to %q; it will send subject %q, body %q",
				r.Recipient, r.Subject, r.Body)}
	}
	// The recipient may come from the data (e.g. "reply to the sender").
	// The content is made of trusted words only (novel-data ran first), so
	// this is a "where", not a "what" question: let the user decide.
	return Decision{Ask, "tainted-egress",
		fmt.Sprintf("context holds untrusted data and %q was never named by the user", r.Recipient)}
}

// A URL is an outbound channel too: data can leave in its path or query.
func evalWebFetch(r Request) Decision {
	if !r.SessionTainted {
		return Decision{Allow, "clean-context", "no untrusted data in context"}
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Hostname() == "" {
		return Decision{Deny, "bad-url", "could not parse the URL"}
	}
	host := strings.ToLower(u.Hostname())
	for _, d := range r.AllowedDomains {
		d = strings.ToLower(d)
		if host == d {
			if nd, novel := novelData(r); novel {
				return nd
			}
			// Not a plain allow: data can still leave in pieces too small for
			// fragment matching (split-secret), so a human decides.
			return Decision{Ask, "tainted-egress",
				fmt.Sprintf("context holds untrusted data and the user never asked to fetch from %q", host)}
		}
	}
	return Decision{Deny, "tainted-fetch",
		fmt.Sprintf("context holds untrusted data and %q is not on the allowlist", host)}
}
