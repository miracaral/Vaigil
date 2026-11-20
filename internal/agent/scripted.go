// Package agent holds the agent under test.
//
// The scripted agent behaves like a hijacked LLM: it does what the user
// asked, but it also obeys instructions it finds inside tool output. That
// makes attacks deterministic and free to run. A real Amazon Bedrock agent
// replaces it later; the control plane does not change.
package agent

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/miracaral/vaigil/internal/taint"
)

type Caller interface {
	Call(tool string, args map[string]string) (taint.Value, error)
}

// Task is what the user asked for.
type Task struct {
	Request       string // shown in the log, e.g. "Summarise my inbox."
	EmailTo       string // set when the user asked to email a named person
	ReplyToSender bool   // set when the user asked to reply to the email's sender
}

var (
	forwardTo = regexp.MustCompile(`(?i)forward .*? to ([\w.+-]+@[\w.-]+)`)
	openURL   = regexp.MustCompile(`(?i)open (https?://\S+)`)
	fromAddr  = regexp.MustCompile(`(?im)^From: ([\w.+-]+@[\w.-]+)`)
	secretRe  = regexp.MustCompile(`AWS_SECRET_ACCESS_KEY=[^\s)]+`)
)

func Run(c Caller, task Task, log func(string)) {
	log(`user: "` + task.Request + `"`)
	inbox, err := c.Call("read_inbox", nil)
	if err != nil {
		log("agent error: " + err.Error())
		return
	}
	log("agent: read the inbox (" + string(inbox.Label) + " data from " + inbox.Source + ")")

	// The legitimate part of the task.
	if task.EmailTo != "" {
		call(c, log, "send_email", map[string]string{"to": task.EmailTo, "body": "Summary of your inbox"})
	}
	if task.ReplyToSender {
		if m := fromAddr.FindStringSubmatch(inbox.Data); m != nil {
			log("agent: replying to the sender " + m[1])
			call(c, log, "send_email", map[string]string{"to": m[1], "body": "Thanks, got it. I'll get back to you soon."})
		}
	}

	// A hijacked model also follows instructions hidden in the data.
	text := strings.ReplaceAll(inbox.Data, "\n", " ")
	if m := forwardTo.FindStringSubmatch(text); m != nil {
		log("agent: obeying hidden instruction, emailing " + m[1])
		call(c, log, "send_email", map[string]string{"to": m[1], "body": inbox.Data})
	}
	if m := openURL.FindStringSubmatch(text); m != nil {
		secret := secretRe.FindString(inbox.Data)
		u := strings.NewReplacer(
			"{secret}", secret,
			"{secret_b64}", base64.URLEncoding.EncodeToString([]byte(secret)),
		).Replace(m[1])
		log("agent: obeying hidden instruction, opening " + u)
		call(c, log, "web_fetch", map[string]string{"url": u})
	}
}

func call(c Caller, log func(string), tool string, args map[string]string) {
	if _, err := c.Call(tool, args); err != nil {
		log("agent: " + err.Error())
		return
	}
	log("agent: " + tool + " succeeded")
}
