package attacks

import "testing"

// With the control plane on, no scenario may leak the secret and every
// benign task must still complete. Only ExpectPartial scenarios may leak
// some bytes, and they must leak some, or they no longer test the limit.
func TestControlPlaneStopsEveryAttack(t *testing.T) {
	for _, s := range All {
		if s.KnownGap {
			continue // tracked on the scoreboard, not a regression
		}
		o := Run(s, true, nil, func(string) {})
		switch {
		case o.Leaked:
			t.Errorf("%s: secret leaked with the control plane on", s.Name)
		case o.LeakedBytes > 0 && !s.ExpectPartial:
			t.Errorf("%s: %d bytes leaked with the control plane on", s.Name, o.LeakedBytes)
		case s.ExpectPartial && o.LeakedBytes == 0:
			t.Errorf("%s: expected a partial leak, got none; the scenario no longer tests the ask budget", s.Name)
		}
		if !o.TaskDone {
			t.Errorf("%s: the user's task broke (false positive)", s.Name)
		}
	}
}

// The ask budget must not break a task that needs exactly one approval.
func TestReplyToSenderStillAsksOnce(t *testing.T) {
	for _, s := range All {
		if s.Name != "benign-reply-sender" {
			continue
		}
		o := Run(s, true, nil, func(string) {})
		if !o.TaskDone || o.Asked != 1 || o.LeakedBytes != 0 {
			t.Fatalf("want task done after 1 ask and no leak, got %+v", o)
		}
		return
	}
	t.Fatal("benign-reply-sender scenario not found")
}

// The partial-leak measure itself: pieces out of order, overlapping,
// empty, and not from the secret at all.
func TestCoveredCountsLeakedBytes(t *testing.T) {
	for _, c := range []struct {
		pieces []string
		want   int
	}{
		{nil, 0},
		{[]string{"", "zzzz"}, 0},
		{[]string{"ABCD"}, 4},
		{[]string{"EFGH", "ABCD"}, 8},
		{[]string{"ABCD", "CDEF"}, 6},
		{[]string{"ABCDEFGHIJ"}, 10},
	} {
		if got := covered("ABCDEFGHIJ", c.pieces); got != c.want {
			t.Errorf("covered(%q) = %d, want %d", c.pieces, got, c.want)
		}
	}
}

// Positioned pieces are placed where the attacker says, but only if the
// bytes really sit there; a lie about the position counts for nothing.
func TestCoveragePlacesPiecesByPosition(t *testing.T) {
	for _, c := range []struct {
		pieces []piece
		want   int
	}{
		{[]piece{{7, "HIJ"}}, 3},             // repeated text: position decides
		{[]piece{{7, "HIJ"}, {0, "ABC"}}, 6}, // out of order
		{[]piece{{2, "HIJ"}}, 0},             // wrong position
		{[]piece{{9, "HIJ"}}, 0},             // runs past the end
		{[]piece{{-1, "HIJ"}}, 3},            // no position: first match
	} {
		if got := coverage("ABCDEFGHIJ", c.pieces).Count(); got != c.want {
			t.Errorf("coverage(%v) = %d, want %d", c.pieces, got, c.want)
		}
	}
}

// Without it, every malicious scenario must succeed, otherwise the
// scenario is not testing anything.
func TestAttacksWorkWithoutControlPlane(t *testing.T) {
	for _, s := range All {
		if !s.Malicious {
			continue
		}
		if o := Run(s, false, nil, func(string) {}); !o.Leaked {
			t.Errorf("%s: attack did not succeed even without protection", s.Name)
		}
	}
}

// Pins what the ask budget lets through, measured in value bytes: the same
// 16 bytes leak either way, but their worth depends on the attacker's order.
// If a defense changes these numbers, update them on purpose.
func TestAskBudgetLeakDependsOnOrder(t *testing.T) {
	want := map[string][2]int{ // bytes, value bytes
		"approval-fatigue":  {16, 0},
		"value-first-split": {16, 16},
	}
	for _, s := range All {
		w, ok := want[s.Name]
		if !ok {
			continue
		}
		o := Run(s, true, nil, func(string) {})
		if o.LeakedBytes != w[0] || o.LeakedValueBytes != w[1] {
			t.Errorf("%s: leaked %d bytes, %d of value; want %d, %d", s.Name, o.LeakedBytes, o.LeakedValueBytes, w[0], w[1])
		}
		delete(want, s.Name)
	}
	if len(want) > 0 {
		t.Errorf("scenarios not found: %v", want)
	}
}
