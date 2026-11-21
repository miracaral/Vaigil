package controlplane

import (
	"fmt"
	"net/url"

	"github.com/miracaral/vaigil/internal/policy"
	"github.com/miracaral/vaigil/internal/taint"
)

// Cumulative taint coverage: tainted-data-in-args catches a whole fragment
// in one call, but calls are judged one at a time, so a value sent in
// pieces got through. Here the mediator remembers what already left in
// this session and asks: together with this call, how many bytes of any
// one untrusted value would be out?
const (
	// coverageLimit is how many bytes of one untrusted value may leave in
	// a session. Above it the call is denied, not asked.
	coverageLimit = 8
	// minMatch is the shortest run that counts as a copy. 4 bytes: at 3,
	// common trigrams ("com", "the", "=de") add up past the limit on
	// innocent text; at 8, any piece of up to 7 bytes would never be
	// seen. Pieces shorter than minMatch still get through (short-pieces).
	minMatch = 4
)

// egressWhat returns the parts of an egress call that carry content
// (WHAT), as separate strings so no match spans two of them. For a URL
// that is each query key and value and the #fragment; scheme, host and
// path are WHERE and are judged by the domain rules. Data hidden in the
// path is not measured (path-split).
func egressWhat(tool string, args map[string]string) []string {
	switch tool {
	case "send_email":
		return []string{args["subject"], args["body"]}
	case "web_fetch":
		u, err := url.Parse(args["url"])
		if err != nil {
			return []string{args["url"]} // unparsable: measure all of it
		}
		return policy.QueryParts(u)
	}
	return nil
}

// whatDecoded is egressWhat plus every decoded form, so encoding the
// pieces does not hide them either.
func whatDecoded(tool string, args map[string]string) []string {
	var out []string
	for _, w := range egressWhat(tool, args) {
		if w != "" {
			out = append(out, decodings(w)...)
		}
	}
	return out
}

// checkCoverage turns a non-deny decision into a deny when this call,
// together with what already left in the session, would reveal more than
// coverageLimit bytes of one untrusted value. It runs only in a tainted
// context and before the ask, so a denied call never reaches the user and
// never spends the ask budget.
func (m *Mediator) checkCoverage(tool string, args map[string]string, d policy.Decision) policy.Decision {
	if d.Effect == policy.Deny || !m.tainted || payloadArgs[tool] == nil {
		return d
	}
	texts := append(whatDecoded(tool, args), m.sent...)
	for _, f := range m.fragments {
		cov := taint.NewCoverage(len(f))
		for _, t := range texts {
			cov.MarkMatches(f, t, minMatch)
		}
		if n := cov.Count(); n > coverageLimit {
			return policy.Decision{Effect: policy.Deny, Rule: "tainted-coverage-exceeded",
				Reason: fmt.Sprintf("egress in this session would reveal %d bytes of one untrusted value (limit %d)", n, coverageLimit)}
		}
	}
	return d
}

// recordEgress remembers what an egress call sent from a tainted context.
func (m *Mediator) recordEgress(tool string, args map[string]string) {
	if m.tainted && payloadArgs[tool] != nil {
		m.sent = append(m.sent, whatDecoded(tool, args)...)
	}
}
