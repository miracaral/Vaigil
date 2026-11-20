# Vaigil — Project Plan

Mirror of the working plan, kept in the repo so every tool and contributor can read it. Last updated 2026-11-20.

## Vision

An open-source, model-agnostic control plane that sits between AI agents and their tools, enforces security policy deterministically, and proves it against a reproducible attack benchmark.

**Problem.** Agents read untrusted content (email, web pages, documents) and hold real permissions (send mail, read files, run code). One hidden instruction in that content can turn the agent against its user. Model-side guardrails are probabilistic: they lower the odds of an attack but cannot guarantee a block.

**Thesis.** Treat the agent like an untrusted process. Every tool call passes an enforcement point that tracks where data came from, grants the minimum capability for the task, and logs every decision, the way a firewall and IAM protect a network. Inspired by DeepMind's CaMeL ("Defeating Prompt Injections by Design").

**Pitch.** A firewall and IAM layer for AI agents: build an agent, break it, then watch the control plane stop the attack.

**Goals**
- Demo v0.1 at the AWS re:Invent Watch Party in Heilbronn, 2026-12-03.
- Submit to Black Hat Europe 2027 Arsenal.
- Understand AI security well enough to explain every design decision without notes.

## Threat model

Phase 1 covers indirect prompt injection and data exfiltration; each later phase adds one attack family.

| # | Area | Example attack | Offsec analogy | Control plane defense | Phase |
| --- | --- | --- | --- | --- | --- |
| 1 | Indirect prompt injection | Hidden instruction in an email the agent reads | Stored XSS | Taint untrusted data; tainted data cannot choose tool calls or arguments | v0.1 |
| 2 | Data exfiltration | Secret put into a URL or markdown image link | Exfiltration over HTTP/DNS | Egress policy; copied untrusted content cannot leave; domain allowlist | v0.1 |
| 3 | Excessive agency, confused deputy | Mail-reading agent tricked into sending mail | Privilege escalation | Capabilities scoped per task; high-risk actions need approval | v0.2 |
| 4 | Insecure output handling | Model output reaches a shell or SQL query | Command / SQL injection | Typed tool schemas, argument validation | v0.2 |
| 5 | MCP tool poisoning, rug pull | Instructions hidden in a tool description; tool changes after install | Supply-chain backdoor | Pin and hash tool manifests, alert on change | v0.3 |
| 6 | Memory and RAG poisoning | Planted memory steers later sessions | Persistence | Provenance on memory writes | v0.3 |
| 7 | Sandbox escape | Code-execution tool breaks out to the host | Container escape | Run code tools in a sandbox under a strict profile | v0.3 |
| 8 | Multi-agent trust | Compromised agent instructs another | Lateral movement | Identity per agent; inter-agent messages are untrusted | v0.4 |

Out of scope: model-level attacks (jailbreaks, model or training-data extraction) and poisoned model files or datasets. Vaigil defends the agent's actions, not the model's weights.

Frameworks: OWASP Top 10 for LLM Applications, OWASP agentic AI threats, MITRE ATLAS.

## Architecture

Agent → **control plane** (policy engine, taint tracker, capability broker, audit log) → tools (email, files, web fetch, code exec in sandbox). The attack harness plants payloads in tool content and scores what gets blocked. Runs on Docker Compose first, then Kubernetes (homelab, EKS). The agent never talks to a tool directly.

## Tech stack

| Layer | Choice | Why |
| --- | --- | --- |
| Protocol | MCP | Common way agents call tools; control plane as MCP proxy = model-agnostic |
| Core | Go | Fast single binary |
| Policy | Cedar | AWS's policy language, readable; rules already drafted in `policies/vaigil.cedar` |
| Target agents | Amazon Bedrock Agents, then Claude via API | AWS context first; second model proves model-agnostic |
| Baseline | Bedrock Guardrails | Comparison point |
| Attack harness | Own scenarios, later AgentDojo, garak, PyRIT | AgentDojo is the standard agent prompt-injection benchmark |
| Observability | JSON audit log, OpenTelemetry later | Every decision replayable |
| Deployment | Docker Compose, then Helm on Kubernetes | Reuses homelab experience |

## Roadmap

| Release | Target | Goal | Exit criteria |
| --- | --- | --- | --- |
| v0.1 Proof of concept | by 2026-12-03 | One agent, indirect prompt injection, a rule that blocks it | Demo runs live on a laptop in Heilbronn |
| v0.2 Core defenses | Dec 2026 – Jan 2027 | Value-level taint, scoped capabilities, audit log; exfiltration and output attacks; cedar-go | AgentDojo numbers (no defense vs. Vaigil) published |
| v0.3 Wider attack surface | Feb – Apr 2027 | MCP tool poisoning, memory/RAG poisoning, sandboxed code exec | Every new attack has a test, a defense and a write-up |
| v0.4 Production shape | May – Jun 2027 | Kubernetes (homelab, EKS), multi-agent, Guardrails comparison | One-command install on a fresh cluster |
| v1.0 Integration and polish | Summer 2027 | End-to-end demo, benchmark report, docs, whitepaper | Black Hat Europe 2027 Arsenal submission sent |

A phase is done only when its exit criteria are true. Each release must be demo-able on its own.

### v1.0 checklist
- One-command install (Compose + Helm)
- End-to-end demo short enough for an Arsenal booth
- Benchmark report: attack success rate for no defense, Guardrails only, Vaigil only, both
- Docs: architecture, threat model, install, policy guide, contributing
- Short technical paper
- Tagged v1.0 release with license and changelog

## Content plan

Build in public, in English. Every release ships a GitHub release, a Medium article (series: *Agentic AI Security from Scratch*) and a LinkedIn post, all drawn from the build log.

| Release | Medium | Other |
| --- | --- | --- |
| v0.1 | Part 1: Why AI agents need a firewall ("I broke my own agent firewall in 10 minutes") | Heilbronn demo photos, Builder Center post |
| v0.2 | Part 2: Measuring prompt injection with AgentDojo | Benchmark chart |
| v0.3 | Part 3: MCP tool poisoning and memory attacks | One attack per short post |
| v0.4 | Part 4: Running a secured agent platform on Kubernetes | EKS write-up |
| v1.0 | Part 5: Lessons from building an agent firewall | Launch post, paper |

Screenshots go in `docs/media/YYYY-MM-DD-<name>.png`, always from real runs.

## Working rules

1. The author makes the decisions; ask for options and trade-offs, then choose and record why.
2. The author writes the core (taint tracking, policy decisions); AI can scaffold, test and document.
3. Understanding test after every session: explain a random file, fix a bug in it, add a small feature, without AI.
4. Every defense ships with an attack that tries to bypass it.
5. README states: built with AI assistance; design and security decisions by the author.
6. Ship small: nothing merges without a test.

## Build log

| Date | Phase | Built | Learned | Decisions |
| --- | --- | --- | --- | --- |
| 2026-11-20 | v0.1 | `deep-encoding` scenario: secret base64-encoded 4 times to an allowlisted URL slips past the 3-layer decoder, kept as a known gap; scripted agent `{secret_b64x4}` placeholder; harness counts plain and 1-4x base64 forms as leaks; effort-check rule in CLAUDE.md | Test the measuring tool too: the harness only looked for plain and 1x base64 secrets, so a 4x leak would have scored as "blocked" | Track the decode-limit bypass on the scoreboard instead of raising the limit; next bypasses: gzip/ROT13 and split secrets |
| 2026-11-20 | v0.1 | Closed base64-exfil: egress args are URL/base64/hex-decoded up to 3 layers before taint matching (`normalize.go`), with tests for base64, double base64, hex and the 4-layer limit; README scoreboard now shows every attack blocked. Proof: [scoreboard, all blocked](media/2026-11-20-scoreboard-all-blocked.png) | Normalise before you match: an encoding is just another way to hide the same bytes; any decode limit is itself a bypass | Reuse the existing tainted-data-in-args rule instead of a new one; cap decoding at 3 layers and pin the limit with a test |
| 2026-11-20 | v0.1 | First push to GitHub (miracaral/Vaigil); separate SSH key for GitHub; verified GitHub host key fingerprint before trusting it; deletion-safety settings in `.claude/settings.json` (ask before rm/git rm/git clean, deny reset --hard and force push) | Verify a host key fingerprint against the official value instead of blindly typing yes; one key per purpose limits blast radius | Dedicated GitHub key instead of reusing the k3s key; destructive git commands blocked by config, not just by convention |
| 2026-11-20 | v0.1 | Ask mode, reply-to-sender check, base64 attack as known gap; ran on own Mac; named the project Vaigil; first commit. Proof: [base64 leak](media/2026-11-20-base64-before.png), [decoded secret](media/2026-11-20-base64-decoded.png) | Separate WHERE (recipient) from WHAT (content); encoding beats string matching | Ask instead of deny for unexpected recipients; keep known gaps visible on the scoreboard |
| 2026-11-19 | v0.1 | Mediator, taint labels, 3 rules, audit log, attack harness, Cedar draft | Checking only where data goes is not enough; an allowlisted domain anyone can post to still leaks | Go + Cedar; scripted agent first, Bedrock next; added tainted-data-in-args after finding the allowlist-abuse bypass |
| 2026-11-19 | Planning | Plan, threat model, roadmap | Prompt injection is one of eight AI security areas | Merged the control plane with the Bedrock "build, break, secure" idea |

## Risks

| Risk | Mitigation |
| --- | --- |
| Scope creep | Exit criteria per phase; nothing new enters a running phase |
| Busy semester | Phases sized for a few sessions a week; v0.1 tiny |
| Code the author doesn't understand | Understanding test after every session |
| Fast-moving field | Re-check the threat model at each phase start |
| Cloud cost | AWS budget alarm before the first Bedrock call; mocks for tests |
| Approval fatigue in ask mode | Keep asks rare; deny when content is copied |

## Learning resources

- OWASP GenAI Security Project (genai.owasp.org), MITRE ATLAS (atlas.mitre.org)
- Lakera Gandalf, PortSwigger Web Security Academy: LLM attacks
- CaMeL paper (Google DeepMind), Model Context Protocol docs, Cedar (cedarpolicy.com), Open Policy Agent
- AgentDojo (github.com/ethz-spylab/agentdojo), garak (github.com/NVIDIA/garak), PyRIT (github.com/Azure/PyRIT)
