package taint

import "strings"

// Coverage marks which bytes of one untrusted value have left the system.
// The control plane uses it to stop a value leaking piece by piece; the
// attack harness uses it to score how much of the secret got out.
type Coverage []bool

func NewCoverage(n int) Coverage { return make(Coverage, n) }

// Mark marks n bytes starting at at; out-of-range bytes are ignored.
func (c Coverage) Mark(at, n int) {
	for i := max(at, 0); i < at+n && i < len(c); i++ {
		c[i] = true
	}
}

// MarkMatches marks every byte of value that lies in a run of at least
// min bytes also found in text. Runs shorter than min are not seen: that
// is the price of not matching every common short word.
func (c Coverage) MarkMatches(value, text string, min int) {
	for i := 0; i+min <= len(value); i++ {
		if strings.Contains(text, value[i:i+min]) {
			c.Mark(i, min)
		}
	}
}

func (c Coverage) Count() int {
	n := 0
	for _, b := range c {
		if b {
			n++
		}
	}
	return n
}
