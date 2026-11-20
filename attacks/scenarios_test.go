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
