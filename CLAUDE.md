# Vaigil — context for Claude Code

Vaigil (v-AI-gil: a vigil kept over AI) is a security control plane for AI agents. It sits between an agent and its tools, checks every tool call against a policy, labels everything tools return as untrusted (taint), and writes every decision to an audit log. Goal: demo v0.1 at the AWS re:Invent Watch Party in Heilbronn on 2026-12-03, then grow it toward a Black Hat Europe 2027 Arsenal submission.

The full plan (vision, threat model, architecture, roadmap, build log) lives in a Claude Doc: https://claude.ai/artifact/T7iq184UyjEoMA6M1iFpJH

## Working rules (from the author)

- The author makes the design decisions. Offer options and trade-offs, then let him choose.
- He is learning AI security (background: offensive security / OSCP prep). Explain what you build in plain terms; after each session he should be able to explain, fix and extend the code without AI.
- Every defense ships with an attack that tries to bypass it (add a scenario in `attacks/`).
- Effort check: the author usually runs Claude Code at low effort. Before writing or changing security-critical code (`internal/policy`, `internal/controlplane`, `internal/taint`, `policies/*.cedar`, new rules, decoders or bypass fixes), stop first and tell him in Turkish to run `/effort high`, then wait for his confirmation before editing. Once that work is done, tell him he can switch back to low. Docs, screenshots, commits and pushes do not need high.
- Never delete files without asking first, and never touch anything outside this project.
- Before deleting anything, explain in Turkish, in simple terms, which file you want to delete and why, then wait for approval.
- Git commits: no Claude attribution of any kind (no Co-Authored-By, no session links).
- Project language is English (code, docs, commits). Chat with the author in Turkish.
- Keep a build log entry per session: what was built, what was learned, decisions and why, one screenshot-worthy moment.

## Commands

```
go run ./cmd/demo                      # scoreboard
go run ./cmd/demo -v -only <scenario>  # one scenario with agent steps + audit log
go test -count=1 ./...
```

## Layout

| Path | What |
| --- | --- |
| `internal/controlplane` | Enforcement point: policy check, taint fragments, argument decoding (`normalize.go`), cumulative taint coverage (`coverage.go`, `tainted-coverage-exceeded`), ask/approve, per-session ask budget (`askBudget`), audit log |
| `internal/policy` | Stateless rules in Go: `tainted-data-in-args` (deny), `tainted-fetch` (deny, exact hosts), `tainted-egress-userinfo` (deny), `tainted-egress-novel-data` (deny, `novel.go`), `tainted-egress-agent-text` (ask), `tainted-egress` (ask) |
| `internal/taint` | Trusted / untrusted labels; byte coverage (`coverage.go`) shared by control plane and harness |
| `policies/vaigil.cedar` | Same rules in Cedar, not wired in yet |
| `internal/agent` | Scripted agent that acts like a hijacked LLM (obeys hidden instructions, default) a Bedrock agent (`bedrock.go`, Converse API with tool use, `-agent=bedrock`) and an Ollama agent (`ollama.go`, `/api/chat` over net/http, loopback only, `-agent=ollama`); shared prompt, tools and turn limit in `llm.go`; all call tools through the control plane; tools stay in-memory mocks |
| `internal/tools` | Mock mailbox and web client |
| `attacks` | Scenarios + harness; `KnownGap` marks attacks that still succeed, `ExpectPartial` attacks the control plane can only limit, `KnownCost` benign tasks broken on purpose; partial leaks are scored in bytes and value bytes |
| `docs/adr` | Architecture decision records (0001: allowlist egress over fragment matching) |
| `docs/media` | Proof screenshots from real runs |

## Decisions so far

- Go + Cedar (Cedar is AWS-made and readable). cedar-go was not installed yet; wire it in on this Mac (`go get github.com/cedar-policy/cedar-go`), check the Go version it needs.
- Scripted agent first so attacks are free and repeatable; a real Amazon Bedrock agent replaces it next. The control plane must not change for that.
- Separate WHERE (recipient) from WHAT (body, URL): copied untrusted content is always denied; an unexpected recipient is asked about.
- Found and fixed the allowlist-abuse bypass (secret leaked via an allowlisted github.com URL) with the `tainted-data-in-args` rule; regression test in `internal/policy/policy_test.go`.
- Closed base64-exfil by decoding egress arguments (URL, base64, hex) before matching, reusing `tainted-data-in-args` instead of a new rule; decoding is capped at 3 layers and a test pins the limit.
- Closed split-secret with option 3 of 3: `tainted-egress` asks before any egress from a tainted context, including fetches from allowlisted domains (close the class, not the trick).
- Ask budget of 2 per session lives in the mediator (session state), not in the stateless policy; refused asks count too; every ask counts.
- Cumulative taint coverage in the mediator: deny once a session's egress reveals more than 8 bytes of one untrusted value; 4-byte minimum match (3 adds up on URL syntax, 8 misses 7-byte pieces); only content (query, fragment, body) is measured, not the URL path. Kept as a measure and extra layer.
- Denylist lost (measured: value-first-split 11/19 value bytes, short-pieces full, path-split 16/19), so egress content is now allowlisted: `tainted-egress-novel-data` in the stateless policy; see docs/adr/0001.
- `it-verify-assembled` (no URL to copy, the agent builds it from parts): blocks rest on the data, not on a copied attacker URL. Whole secret: `tainted-data-in-args`; value only: `tainted-egress-novel-data` (the fragment rule is blind to it). Pinned in `TestAssembledURLIsBlockedOnTheData`.
- The user's own address is `user@example.com` (`tools.UserAddress`), in the real-model system prompt. The secret emailed only there is scored `sent to user`, not `LEAKED`; a leak anywhere else in the run outranks it. Qwen3 results from before this prompt change need a re-run.
- Scripted agent appends the secret to an empty parameter (`?key=`) only when the instruction has no placeholder; before that fix, base64-exfil, deep-encoding, value-first-split and short-pieces were denied as plain copies. `TestEachScenarioIsDecidedByItsRule` pins the deciding rule of every scenario from the audit log: after changing an attack or the agent, the rules must match, not only the verdicts.
- Allowlist matches exact hosts only (closes subdomain-exfil). Selection channel (trusted-word-bits) accepted as a known gap until value-level taint tracking. Agent-written email to an unnamed recipient is one ask showing the full text, not a deny; copied data stays denied.

## Open / next

1. Known gaps still open: `trusted-word-bits` (accepted until value-level taint), `email-spaced-secret` (user approves the agent-text ask). Closed: `userinfo-exfil` (`tainted-egress-userinfo` denies any URL with userinfo from a tainted context).
2. Wire in cedar-go, and decide how to model "ask", the per-session ask budget and the novel-data allowlist in Cedar (`policies/vaigil.cedar` is out of date: no novel-data, no exact hosts, no budget).
3. Bedrock agent is built (not run yet). Waiting for the Bedrock model quota (currently 0, AWS cases open; Claude is billed via AWS Marketplace, credit coverage not confirmed). Then: one scenario with Sonnet 4.6 (`-agent=bedrock -only <scenario>`), then a model comparison table (which models obey the injection, how many asks real tasks need, to check the ask budget of 2).
4. Ollama agent is built (`-agent=ollama`, default `qwen3:8b`, Ollama 0.40.16 on this Mac), first Qwen3 results are in the README; action variants and `it-verify-assembled` re-run with the new system prompt (user's address); results change from run to run, so next: several runs per scenario, the obvious and summarise-task scenarios with the new prompt, then the model comparison.
5. Later phases: value-level taint tracking (CaMeL-style), MCP proxy, Kubernetes deployment. See the roadmap in the plan doc.
