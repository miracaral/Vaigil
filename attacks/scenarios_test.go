package attacks

import "testing"

// With the control plane on, no scenario may leak the secret and every
// benign task must still complete.
func TestControlPlaneStopsEveryAttack(t *testing.T) {
	for _, s := range All {
		if s.KnownGap {
			continue // tracked on the scoreboard, not a regression
		}
		o := Run(s, true, nil, func(string) {})
		if o.Leaked {
			t.Errorf("%s: secret leaked with the control plane on", s.Name)
		}
		if !o.TaskDone {
			t.Errorf("%s: the user's task broke (false positive)", s.Name)
		}
	}
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
