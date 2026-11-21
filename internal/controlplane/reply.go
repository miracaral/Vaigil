package controlplane

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/miracaral/vaigil/internal/policy"
)

// The reply channel. Tool calls are not the only way out: the agent's
// final answer is shown to the user, and a link in it leaves the moment
// the user clicks it, or with no click at all when a client renders a
// markdown image (it fetches the image to show it). So every link in the
// answer is judged as if the agent had fetched it, by the same rules and
// the same session state, and a link they deny is cut out of the answer.
// Text that is not a link is not judged: a secret written out in plain
// words reaches the user untouched (reply-plain-secret).

// RemovedLink replaces a link the control plane cut out of the answer.
const RemovedLink = "[link removed by Vaigil]"

// replyLink finds, in one pass so no link is judged twice:
//  1. a markdown link or image, [text](target) or ![alt](target); the whole
//     construct goes, so link text cannot carry data out either
//  2. a URL with a scheme, up to whitespace or a quote or angle bracket
//     (plain text, <autolinks>, HTML attributes, reference definitions)
//  3. a "www." address, which markdown renderers turn into a link too
//
// Plain URLs are taken greedily: trailing punctuation is judged along with
// the URL and removed with it, never left behind as part of a link.
var replyLink = regexp.MustCompile("(?i)!?\\[[^\\]]*\\]\\(([^)]*)\\)|[a-z][a-z0-9+.-]*://[^\\s<>\"'`]+|www\\.[^\\s<>\"'`]+")

// Reply judges every link in the agent's final answer, logs each decision
// and returns the answer the user should see. With a clean context it is
// returned untouched and nothing is logged. A link the rules deny is
// replaced by RemovedLink (rule response-link-removed, the reason names
// the rule that denied it); any other link stays (response-link-kept).
// A link that stays counts as sent for the coverage limit, so a secret
// split over several links is still added up. An "ask" keeps the link
// without asking: a link is only a suggestion until the user clicks it,
// and the click is the user's decision. It spends no ask budget. In audit
// mode (Enforce false) the decisions are logged and nothing is removed.
func (m *Mediator) Reply(text string) string {
	if !m.tainted || text == "" {
		return text
	}
	var out strings.Builder
	last := 0
	for _, ix := range replyLink.FindAllStringSubmatchIndex(text, -1) {
		match := text[ix[0]:ix[1]]
		target := match
		switch {
		case ix[2] >= 0: // markdown: the target, without <> or a "title"
			target = strings.TrimSpace(text[ix[2]:ix[3]])
			if f := strings.Fields(target); len(f) > 0 {
				target = f[0]
			}
			target = strings.Trim(target, "<>")
		case strings.HasPrefix(strings.ToLower(match), "www."):
			target = "https://" + match
		}
		out.WriteString(text[last:ix[0]])
		out.WriteString(m.judgeLink(match, target))
		last = ix[1]
	}
	out.WriteString(text[last:])
	return out.String()
}

// judgeLink decides one link as a web_fetch of target from this session
// and returns what the answer should show in place of match.
func (m *Mediator) judgeLink(match, target string) string {
	args := map[string]string{"url": target}
	d := policy.Evaluate(policy.Request{
		Tool:                 "web_fetch",
		URL:                  target,
		UserTask:             m.cfg.UserTask,
		AllowedDomains:       m.cfg.AllowedDomains,
		SessionTainted:       true,
		ArgsCarryTaintedData: m.argsCarryTainted("web_fetch", args),
	})
	d = m.checkCoverage("web_fetch", args, d)
	if d.Effect == policy.Deny {
		m.log("reply", args, policy.Decision{Effect: policy.Deny, Rule: "response-link-removed",
			Reason: fmt.Sprintf("%s: %s", d.Rule, d.Reason)}, nil)
		if m.cfg.Enforce {
			return RemovedLink
		}
	} else {
		m.log("reply", args, policy.Decision{Effect: policy.Allow, Rule: "response-link-kept",
			Reason: fmt.Sprintf("%s: %s", d.Rule, d.Reason)}, nil)
	}
	// Left in the answer: it leaves when the user follows it.
	m.recordEgress("web_fetch", args)
	return match
}
