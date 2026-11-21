package agent

// The Bedrock agent is a real LLM (Amazon Bedrock Converse API with tool
// use). It gets the same three tools as the scripted agent, and every tool
// call it makes still goes through the Caller, so the control plane judges
// it exactly like a scripted call. Whether it obeys hidden instructions is
// up to the model, not to us.

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

const (
	DefaultBedrockModel  = "global.anthropic.claude-sonnet-4-6"
	DefaultBedrockRegion = "us-east-1"
)

// Converser is the one Bedrock call the agent needs. The real client
// satisfies it; tests pass a fake so no network call is made.
type Converser interface {
	Converse(ctx context.Context, in *bedrockruntime.ConverseInput, opts ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
}

type Bedrock struct {
	Client  Converser
	ModelID string
}

// NewBedrock builds a client from the standard AWS credential chain
// (environment variables, ~/.aws, SSO, instance role). No keys are read
// or stored anywhere else.
func NewBedrock(ctx context.Context, modelID, region string) (*Bedrock, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return &Bedrock{Client: bedrockruntime.NewFromConfig(cfg), ModelID: modelID}, nil
}

var bedrockTools = func() *types.ToolConfiguration {
	var tools []types.Tool
	for _, t := range toolDefs {
		tools = append(tools, &types.ToolMemberToolSpec{Value: types.ToolSpecification{
			Name:        aws.String(t.name),
			Description: aws.String(t.desc),
			InputSchema: &types.ToolInputSchemaMemberJson{Value: document.NewLazyDocument(t.schema)},
		}})
	}
	return &types.ToolConfiguration{Tools: tools}
}()

// Run has the same shape as the scripted Run, so the harness can use either.
func (b *Bedrock) Run(c Caller, task Task, log func(string)) {
	log(`user: "` + task.Request + `"`)
	ctx := context.Background()
	msgs := []types.Message{{
		Role:    types.ConversationRoleUser,
		Content: []types.ContentBlock{&types.ContentBlockMemberText{Value: task.Request}},
	}}
	for range maxTurns {
		out, err := b.Client.Converse(ctx, &bedrockruntime.ConverseInput{
			ModelId:    aws.String(b.ModelID),
			System:     []types.SystemContentBlock{&types.SystemContentBlockMemberText{Value: systemPrompt}},
			Messages:   msgs,
			ToolConfig: bedrockTools,
		})
		if err != nil {
			log("agent error: " + err.Error())
			return
		}
		reply, ok := out.Output.(*types.ConverseOutputMemberMessage)
		if !ok {
			log("agent error: no message in Bedrock response")
			return
		}
		msgs = append(msgs, reply.Value)

		var results []types.ContentBlock
		for _, block := range reply.Value.Content {
			switch blk := block.(type) {
			case *types.ContentBlockMemberText:
				log("agent says: " + blk.Value)
			case *types.ContentBlockMemberToolUse:
				results = append(results, b.useTool(c, log, blk.Value))
			}
		}
		if out.StopReason != types.StopReasonToolUse || len(results) == 0 {
			return
		}
		msgs = append(msgs, types.Message{Role: types.ConversationRoleUser, Content: results})
	}
	log(fmt.Sprintf("agent: stopped after %d turns", maxTurns))
}

// useTool runs one tool call through the control plane and wraps the
// answer (or the block reason) as a tool result for the model.
func (b *Bedrock) useTool(c Caller, log func(string), use types.ToolUseBlock) types.ContentBlock {
	var raw map[string]any
	if use.Input != nil {
		if err := use.Input.UnmarshalSmithyDocument(&raw); err != nil {
			log("agent error: bad tool input: " + err.Error())
		}
	}
	res := types.ToolResultBlock{ToolUseId: use.ToolUseId}
	out, err := runTool(c, log, aws.ToString(use.Name), raw)
	if err != nil {
		res.Status = types.ToolResultStatusError
		out = err.Error()
	}
	res.Content = []types.ToolResultContentBlock{&types.ToolResultContentBlockMemberText{Value: out}}
	return &types.ContentBlockMemberToolResult{Value: res}
}
