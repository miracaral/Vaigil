// Package controlplane is the enforcement point between the agent and its
// tools: every call is checked by the policy, every result is labelled
// untrusted, and every decision is written to the audit log.
package controlplane

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/miracaral/vaigil/internal/policy"
	"github.com/miracaral/vaigil/internal/taint"
)

// Tool is anything the agent can call.
type Tool func(args map[string]string) (string, error)

// Approver asks a human about a risky call. It returns true to let it run.
type Approver func(tool string, args map[string]string, d policy.Decision) bool

type Config struct {
	UserRecipients []string // addresses the user named in their own request
	AllowedDomains []string // domains web_fetch may reach from a tainted context
	Enforce        bool     // false = log decisions only (audit mode)
	Approve        Approver // nil = every "ask" is treated as "no"
}

// payloadArgs are the arguments that carry content ("what"), as opposed to
// addressing ("where"). Only these are checked for copied tainted data;
// the address is judged by the policy rules themselves.
var payloadArgs = map[string][]string{
	"send_email": {"body"},
	"web_fetch":  {"url"}, // a URL is both: data hides in its path and query
}

type Mediator struct {
	tools   map[string]Tool
	cfg     Config
	tainted bool
	// fragments are distinctive pieces of untrusted tool output, kept so
	// we can spot them again if the agent copies them into a later call.
	fragments []string
	audit     io.Writer
}

// minFragment is the shortest token we track; shorter words are too
// common ("the", "inbox") and would block everything.
const minFragment = 12

func New(tools map[string]Tool, cfg Config, audit io.Writer) *Mediator {
	return &Mediator{tools: tools, cfg: cfg, audit: audit}
}

func (m *Mediator) remember(out string) {
	for _, tok := range strings.FieldsFunc(out, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(`()<>"'`, r)
	}) {
		if len(tok) >= minFragment {
			m.fragments = append(m.fragments, tok)
		}
	}
}

func (m *Mediator) argsCarryTainted(tool string, args map[string]string) bool {
	for _, name := range payloadArgs[tool] {
		// Check the raw value and every decoded form, so encoding the
		// data (base64, hex, %xx) does not hide it.
		for _, v := range decodings(args[name]) {
			for _, f := range m.fragments {
				if strings.Contains(v, f) {
					return true
				}
			}
		}
	}
	return false
}

type auditEntry struct {
	Time     string            `json:"time"`
	Tool     string            `json:"tool"`
	Args     map[string]string `json:"args,omitempty"`
	Decision policy.Decision   `json:"decision"`
	Approved *bool             `json:"approved,omitempty"` // set only for "ask"
	Enforced bool              `json:"enforced"`
}

// ErrBlocked is returned when the policy denies a call or the user says no.
var ErrBlocked = fmt.Errorf("blocked by control plane")

func (m *Mediator) Call(tool string, args map[string]string) (taint.Value, error) {
	fn, ok := m.tools[tool]
	if !ok {
		return taint.Value{}, fmt.Errorf("unknown tool %q", tool)
	}
	d := policy.Evaluate(policy.Request{
		Tool:                 tool,
		Recipient:            args["to"],
		URL:                  args["url"],
		UserNamedRecipients:  m.cfg.UserRecipients,
		AllowedDomains:       m.cfg.AllowedDomains,
		SessionTainted:       m.tainted,
		ArgsCarryTaintedData: m.argsCarryTainted(tool, args),
	})

	allowed := true
	var approved *bool
	if m.cfg.Enforce {
		switch d.Effect {
		case policy.Deny:
			allowed = false
		case policy.Ask:
			ok := m.cfg.Approve != nil && m.cfg.Approve(tool, args, d)
			approved, allowed = &ok, ok
		}
	}
	m.log(tool, args, d, approved)
	if !allowed {
		return taint.Value{}, fmt.Errorf("%w: %s", ErrBlocked, d.Reason)
	}

	out, err := fn(args)
	if err != nil {
		return taint.Value{}, err
	}
	// Whatever a tool returns may have been written by an attacker.
	m.tainted = true
	m.remember(out)
	return taint.FromTool(tool, out), nil
}

func (m *Mediator) log(tool string, args map[string]string, d policy.Decision, approved *bool) {
	if m.audit == nil {
		return
	}
	short := map[string]string{}
	for k, v := range args {
		if len(v) > 60 {
			v = v[:60] + "..."
		}
		short[k] = v
	}
	b, _ := json.Marshal(auditEntry{time.Now().UTC().Format(time.RFC3339), tool, short, d, approved, m.cfg.Enforce})
	fmt.Fprintln(m.audit, string(b))
}
