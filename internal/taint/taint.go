// Package taint labels every piece of data with where it came from.
// Data the user typed is Trusted; anything a tool returns (an email, a web
// page, a file) is Untrusted, because an attacker may have written it.
package taint

type Label string

const (
	Trusted   Label = "trusted"
	Untrusted Label = "untrusted"
)

// Value is a piece of data plus its origin.
type Value struct {
	Data   string `json:"data"`
	Label  Label  `json:"label"`
	Source string `json:"source"` // e.g. "user", "tool:read_inbox"
}

func FromUser(s string) Value { return Value{Data: s, Label: Trusted, Source: "user"} }

func FromTool(tool, s string) Value {
	return Value{Data: s, Label: Untrusted, Source: "tool:" + tool}
}
