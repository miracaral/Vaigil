package taint

import "testing"

func TestMarkMatches(t *testing.T) {
	for _, c := range []struct {
		text string
		want int
	}{
		{"", 0},
		{"xxDEFGxx", 4},      // one run of exactly min
		{"CDEFGH", 6},        // a longer run is the union of its windows
		{"ABC HIJ", 0},       // runs shorter than min are not seen
		{"ABCD and GHIJ", 8}, // two runs
	} {
		cov := NewCoverage(10)
		cov.MarkMatches("ABCDEFGHIJ", c.text, 4)
		if got := cov.Count(); got != c.want {
			t.Errorf("MarkMatches(%q) = %d, want %d", c.text, got, c.want)
		}
	}
}

func TestMarkClampsToRange(t *testing.T) {
	cov := NewCoverage(4)
	cov.Mark(-2, 3)
	cov.Mark(3, 5)
	if got := cov.Count(); got != 2 {
		t.Fatalf("Count = %d, want 2", got)
	}
}
