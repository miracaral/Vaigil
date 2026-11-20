# Vaigil — context for Claude Code

Vaigil (v-AI-gil: a vigil kept over AI) is a security control plane for AI agents. It sits between an agent and its tools, checks every tool call against a policy, labels everything tools return as untrusted (taint), and writes every decision to an audit log. Goal: demo v0.1 at the AWS re:Invent Watch Party in Heilbronn on 2026-12-03, then grow it toward a Black Hat Europe 2027 Arsenal submission.

The full plan (vision, threat model, architecture, roadmap, build log) lives in a Claude Doc: https://claude.ai/artifact/T7iq184UyjEoMA6M1iFpJH

## Working rules (from the author)

- The author makes the design decisions. Offer options and trade-offs, then let him choose.
- He is learning AI security (background: offensive security / OSCP prep). Explain what you build in plain terms; after each session he should be able to explain, fix and extend the code without AI.
- Every defense ships with an attack that tries to bypass it (add a scenario in `attacks/`).
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
| `internal/controlplane` | Enforcement point: policy check, taint fragments, ask/approve, audit log |
| `internal/policy` | Rules in Go: `tainted-data-in-args` (deny), `tainted-fetch` (deny), `tainted-egress` (ask) |
| `policies/vaigil.cedar` | Same rules in Cedar, not wired in yet |
| `internal/agent` | Scripted agent that acts like a hijacked LLM (obeys hidden instructions) |
| `internal/tools` | Mock mailbox and web client |
| `attacks` | Scenarios + harness; `KnownGap` marks attacks that still succeed |
| `docs/media` | Proof screenshots from real runs |

## Decisions so far

- Go + Cedar (Cedar is AWS-made and readable). cedar-go was not installed yet; wire it in on this Mac (`go get github.com/cedar-policy/cedar-go`), check the Go version it needs.
- Scripted agent first so attacks are free and repeatable; a real Amazon Bedrock agent replaces it next. The control plane must not change for that.
- Separate WHERE (recipient) from WHAT (body, URL): copied untrusted content is always denied; an unexpected recipient is asked about.
- Found and fixed the allowlist-abuse bypass (secret leaked via an allowlisted github.com URL) with the `tainted-data-in-args` rule; regression test in `internal/policy/policy_test.go`.

## Open / next

1. Add a `KnownGap` scenario for the decode limit: data encoded 4+ times (or with gzip/ROT13, or split into pieces) still slips past `normalize.go`.
2. Wire in cedar-go.
3. Replace the scripted agent with an Amazon Bedrock agent (needs AWS budget alarm + Bedrock model access first).
4. Later phases: value-level taint tracking (CaMeL-style), MCP proxy, Kubernetes deployment. See the roadmap in the plan doc.
