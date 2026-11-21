package policy

import "testing"

func fetchReq(task, u string) Request {
	return Request{Tool: "web_fetch", URL: u, UserTask: task,
		AllowedDomains: []string{"github.com", "docs.aws.amazon.com"}, SessionTainted: true}
}

func TestNovelData(t *testing.T) {
	const task = "Find the Lambda pricing page"
	for _, c := range []struct {
		name string
		r    Request
		want string // rule
	}{
		// Allowed through to the ask: only trusted content.
		{"no content", fetchReq(task, "https://github.com/"), "tainted-egress"},
		{"task words, any case", fetchReq(task, "https://docs.aws.amazon.com/lambda/pricing?page=FIND"), "tainted-egress"},
		{"allowlist words", fetchReq(task, "https://docs.aws.amazon.com/aws/amazon"), "tainted-egress"},
		// Denied: new data, however short.
		{"one new letter", fetchReq(task, "https://github.com/?x"), "tainted-egress-novel-data"},
		{"new path segment", fetchReq(task, "https://github.com/demo"), "tainted-egress-novel-data"},
		{"new fragment", fetchReq(task, "https://github.com/#KEY"), "tainted-egress-novel-data"},
		{"punctuation only", fetchReq(task, "https://github.com/?find=-_-_"), "tainted-egress-novel-data"},
		// The cost: an innocent page whose words the user never typed.
		{"innocent but unnamed", fetchReq(task, "https://docs.aws.amazon.com/lambda/latest/dg/welcome.html"), "tainted-egress-novel-data"},
		// Email to an unnamed recipient: text the agent wrote is asked
		// about with its full text, not denied.
		{"email body", Request{Tool: "send_email", Recipient: "a@b.example", Body: "Thanks, got it.",
			UserTask: "Reply to the email", SessionTainted: true}, "tainted-egress-agent-text"},
		{"email subject", Request{Tool: "send_email", Recipient: "a@b.example", Subject: "KEY",
			UserTask: "Reply to the email", SessionTainted: true}, "tainted-egress-agent-text"},
		// ...but copied untrusted data is still denied.
		{"copied email body", Request{Tool: "send_email", Recipient: "a@b.example", Body: "AWS_SECRET...",
			UserTask: "Reply to the email", SessionTainted: true, ArgsCarryTaintedData: true}, "tainted-data-in-args"},
		{"email of task words", Request{Tool: "send_email", Recipient: "a@b.example", Body: "reply to the email",
			UserTask: "Reply to the email", SessionTainted: true}, "tainted-egress"},
		// Out of scope: named recipient, clean context, unlisted domain.
		{"named recipient", Request{Tool: "send_email", Recipient: "boss@company.example", Body: "anything new",
			UserNamedRecipients: []string{"boss@company.example"}, SessionTainted: true}, "user-named-recipient"},
		{"clean context", Request{Tool: "web_fetch", URL: "https://github.com/x?y=z"}, "clean-context"},
		{"unlisted domain", fetchReq(task, "https://attacker.example/x"), "tainted-fetch"},
	} {
		if d := Evaluate(c.r); d.Rule != c.want {
			t.Errorf("%s: want %s, got %+v", c.name, c.want, d)
		}
	}
}
