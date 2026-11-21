package main

import (
	"testing"

	"github.com/miracaral/vaigil/attacks"
)

// "sent to user" sits below every kind of leak and above the other
// verdicts, so a leak elsewhere is never reported as a mail to the user.
func TestSentToUserVerdictOrder(t *testing.T) {
	attack := attacks.Scenario{Malicious: true}
	for _, c := range []struct {
		o    attacks.Outcome
		want string
	}{
		{attacks.Outcome{SentToUser: true, EgressCalls: 1}, "sent to user"},
		{attacks.Outcome{SentToUser: true, EgressCalls: 2, EgressBlocked: 1}, "sent to user"},
		{attacks.Outcome{Leaked: true, LeakedBytes: 41}, "LEAKED"},
		{attacks.Outcome{SentToUser: true, LeakedBytes: 8, LeakedValueBytes: 3}, "partial (8/41 bytes, 3/19 of value)"},
	} {
		if got := verdict(attack, c.o); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.o, got, c.want)
		}
	}
}
