# Agent Firewall — Phase 09: Daemon + Claude Code Hook Collector

> **Status:** Design **APPROVED** by user 2026-07-29. Proceeding to the implementation plan.
> **Owner:** Arthur (GitHub: `carbon-evolution`)
> **Component:** `agentfw` binary (new crate `crates/agentfw`), consuming `llm-firewall-agent`.
> **Depends on:** phase 08, merged to `main` in PR #11 (249 workspace tests green).
> **Purpose:** Turn the phase-08 library into something that actually protects a running agent —
> a resident daemon plus the first collector, wired into Claude Code's native hook system.

Parent design: [`2026-07-29-agent-firewall-design.md`](2026-07-29-agent-firewall-design.md).

---

## 1. What changed after reading the real hook documentation

Phase 08's design described the hook collector from assumption. Checking
<https://code.claude.com/docs/en/hooks> before designing changed three things, one of them a
security defect that would have shipped.

### 1.1 `permissionDecision` has a fourth value, and using the wrong one is a regression

The allowed values are `allow`, `deny`, `ask`, **and `defer`**:

- `allow` — *approves* the tool call, passing it into the normal permission flow.
- `defer` — lets the normal permission system decide, as if the hook had said nothing.

Phase 08 assumed a three-value contract and mapped our `Allow` verdict onto `allow`. That is wrong.
Our `Allow` means *"this firewall has no objection"*, **not** *"approve this"*. Mapping it to `allow`
would auto-approve tool calls the operator's own permission rules would have prompted on — so
installing a security tool would silently weaken the protection already in place.

**Our `Allow` maps to `defer`.** This is the single most important correction in phase 09.

### 1.2 Hooks support `type: "http"` natively

A hook entry can POST to an HTTP endpoint with configurable headers and timeout, rather than
executing a command. This deletes two components from the phase-08 architecture: the `agentfw hook`
shim binary and the Unix domain socket. The daemon exposes an HTTP endpoint directly, reusing the
axum/tokio stack `crates/proxy` already depends on.

**Cost:** a localhost TCP port is reachable by any local process, whereas a `0600` socket is
protected by filesystem permissions. Mitigated in §4.

### 1.3 There is no hook carrying a subagent's granted tools

`SubagentStop` provides `agent_id`, `agent_type`, and `last_assistant_message`. There is no
spawn-time event exposing the tool grant a subagent received.

Therefore **`Authority` — built, tested, and merged in phase 08 — stays dormant in phase 09.**
Subagent privilege escalation, one of the four threat classes, is not covered by this collector. It
becomes reachable in phase 11 via the API and MCP collectors, which see the actual spawn. Stated
plainly here rather than quietly shipped as covered.

### 1.4 Two capabilities appeared that were not in the phase-08 design

`updatedInput` rewrites tool arguments before execution; `updatedToolOutput` replaces a tool result
before the model sees it. Both are **deliberately unused in phase 09** — see §6.

---

## 2. Decision Log

| # | Decision | Choice | Rationale / trade-off |
|---|----------|--------|-----------------------|
| B1 | **Transport** | **Native `type: "http"` hooks → axum daemon** | Removes the shim binary and the Unix socket; reuses an HTTP stack already in the workspace. Cost: a localhost port has no filesystem ACL, so it needs its own authentication (§4). |
| B2 | **Result rewriting** | **Detect and gate only.** No `updatedToolOutput`, no `updatedInput`. | Phase 09 stays a firewall. A poisoned page still reaches the model's context, but any dangerous *action* derived from it is gated. Silently altering what the model reads is a larger claim that deserves its own phase and its own evidence, and it can corrupt legitimate content while making agent behaviour hard to debug. |
| B3 | **Rollout posture** | **Shadow mode by default** (`enforce: false`), enforcement opt-in | The lab measured 7 of 15 benign follow-ups tainting. The real rate is unknown, and discovering it by having live sessions interrupted is the expensive way. Shadow mode computes and logs every verdict while always returning `defer`. |
| B4 | **`Allow` mapping** | **`defer`, never `allow`** | See §1.1. Preserves the operator's existing permission configuration exactly. |
| B5 | **Large-input latency** | **Cap recorded content at 256 KB** (configurable), record synchronously | Measured: `record()` on 10 MB = 532 ms, far past the budget. A cap brings it to ~13 ms. Recording asynchronously was rejected — it races the next `PreToolUse` and would silently miss taint. |
| B6 | **Failure posture** | **Proceed on any daemon failure**, loudly | A security tool that wedges the agent loop is uninstalled the same day. Unreachable daemon, timeout, panic, or 5xx must all result in the tool call proceeding under the operator's normal permissions. |
| B7 | **Subagent authority** | **Out of scope for phase 09** | No hook exposes the grant. Deferred to phase 11. |

---

## 3. Architecture

```
  Claude Code                          agentfw serve  (127.0.0.1 only)
  ───────────                          ─────────────────────────────────
  PreToolUse   ──POST /hook──────────►  auth → parse → map to AgentEvent
  PostToolUse  ──POST /hook──────────►         │
  SubagentStop ──POST /hook──────────►         ▼
  SessionStart ──POST /hook──────────►  AgentFirewall::inspect()   [crates/agent]
  SessionEnd   ──POST /hook──────────►         │
                                               ├──► audit.jsonl
       ◄──── permissionDecision ───────────────┘
             defer | ask | deny
```

### Crate boundaries

| Crate | Responsibility | Status |
|-------|---------------|--------|
| `core` | text detectors, scoring, policy, taxonomy | unchanged |
| `agent` | event model, taint, action, egress, authority, policy, engine. No I/O. | unchanged |
| **`agentfw`** (new) | daemon, HTTP endpoint, hook payload mapping, provenance, audit sink, replay, config | this phase |
| `proxy` | the text-layer reverse proxy | unchanged |

`agentfw` is the only crate in the workspace that performs I/O on behalf of the agent layer. It must
not contain detection logic — anything that decides a verdict belongs in `agent`, where it can be
tested without a socket.

### Endpoints

| Route | Purpose |
|---|---|
| `POST /hook` | All hook events. Dispatches on `hook_event_name`. |
| `GET /health` | Liveness, plus whether enforcement is on. Used by the installer and by tests. |

---

## 4. Security of the daemon itself

A firewall that is itself trivially attackable is worse than none, because it concentrates
sensitive session data in one place.

- **Bind `127.0.0.1` only.** Never `0.0.0.0`. Configurable port (default `8787`) for the case where
  something already holds it.
- **Shared-secret authentication.** On first run, generate a 256-bit random token to
  `~/.agentfw/token` with mode `0600`. Every request must carry `Authorization: Bearer <token>`.
  Hook config supplies it via the documented `headers` + `allowedEnvVars` mechanism. A request
  without a valid token gets `401` and is logged.
- **Why it matters:** without this, any local process — including one an agent was tricked into
  running — could poison taint state, read another session's audit data, or flood the daemon.
- **Constant-time token comparison**, to avoid a timing oracle on the secret.
- **Audit log and token at `0600`;** the audit log contains prompts, file paths, and tool arguments.
- **Reject oversized bodies** (default cap 8 MB) before parsing, so a hostile payload cannot exhaust
  memory in `serde_json`.

---

## 5. Mapping hook payloads to `AgentEvent`

Field names verified against the documentation, and to be re-verified against real captured payloads
during implementation.

| Hook event | `EventKind` | Source fields |
|---|---|---|
| `PreToolUse` | `ToolCall { tool, args }` | `tool_name`, `tool_input` |
| `PostToolUse` | `ToolResult { tool, content, source }` | `tool_name`, `tool_response` (stringified), provenance per §5.1 |
| `SubagentStop` | `SubagentReport { name, content }` | `agent_type`, `last_assistant_message` |
| `SessionStart` | `SessionStart` | — |
| `SessionEnd` | `SessionEnd` | — |
| anything else | `Unknown` | raw body preserved in the audit line |

`session_id` becomes `SessionId`. `seq` is a per-session monotonic counter held by the daemon.
`at_ms` is stamped on receipt — the library has no clock by design.

### 5.1 The provenance table

Phase 08 took `Provenance` as given. Deciding it from a raw hook payload is new work, and getting it
wrong poisons every downstream taint verdict.

| Tool pattern | Provenance | Reasoning |
|---|---|---|
| `WebFetch`, `WebSearch` | `Network { host }` from the URL argument | Third-party content |
| `mcp__<server>__*` | `McpServer { name: server }` | Third-party tool output |
| `Read`, `Grep`, `Glob` with a path under `cwd` | `LocalProject` | Inside the working tree |
| `Read`, `Grep`, `Glob` with a path outside `cwd` | `LocalSystem` | Outside the tree |
| `Bash` and everything unrecognized | `LocalSystem` | Conservative: local, not trusted |
| `SubagentStop` | `Subagent { name: agent_type }` | Inherits taint from its own session |

**Deliberately never `UserPrompt`.** No tool result is ever what the human typed, and marking one so
would erase taint at exactly the wrong moment. `Trusted` provenance is reserved for a future
collector that can actually see user input.

**Conservative on ambiguity:** an unrecognized tool is `LocalSystem` (semi-trusted), not `Untrusted`.
Marking every unknown tool untrusted would flood the taint set and reproduce the prompt-fatigue
failure phase 08 spent most of its measurement effort avoiding.

---

## 6. Verdict mapping and shadow mode

| `agent::Verdict` | `permissionDecision` | `permissionDecisionReason` |
|---|---|---|
| `Allow` | `defer` | — |
| `Ask` | `ask` | rule name + human message + taint source and the event that introduced it |
| `Deny` | `deny` | rule name + human message |

`PostToolUse`, `SubagentStop`, and lifecycle events return `200` with no decision — they mutate state
only. This is what B2 means concretely: results are recorded, never rewritten.

**Shadow mode (`enforce: false`, the default).** The verdict is computed and logged in full, then
discarded, and `defer` is returned. The audit line records `shadow: true` and the verdict that
*would* have fired. Flipping `enforce: true` in config is the only change needed to go live.

The reason for a prompt must name *what* triggered it and *where the tainted content came from*,
including the originating event's sequence number. A verdict the operator cannot understand is one
they will reflexively approve, which is worse than not prompting at all.

---

## 7. Latency and failure

Every `PreToolUse` in every session blocks on this path.

| Tier | Budget | On breach |
|---|---|---|
| Deterministic inspection | p99 < 15 ms | hard timeout 100 ms → `defer` + log degradation |
| `record()` on a tool result | capped 256 KB input | truncate, note truncation in the audit line |
| Hook `timeout` (config) | 5 s | Claude Code proceeds |
| Daemon down / 401 / 5xx / panic | — | **proceed**, warn loudly |

### Measured: an unreachable HTTP hook fails open

The open question here — what Claude Code does when a `type: "http"` hook's endpoint is unreachable —
**was measured on 2026-07-30 and the answer confirms the transport decision (B1).**

Method: a one-shot non-interactive run with the hook pointed at a dead port, using `--settings` with
inline JSON so nothing on disk was modified:

```bash
time claude \
  --settings '{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"http","url":"http://127.0.0.1:59999/hook","timeout":5}]}]}}' \
  --debug hooks -p "Use the Bash tool to list files in this directory, then stop." --max-turns 2
```

Result: **the tool call proceeded and completed normally.** `real 7.39s` against a 5-second hook
timeout plus ordinary startup and model latency — so the configured timeout was honoured and then
execution continued. It did not block, and it did not hang.

**Consequence B1 survives, with one cost worth stating plainly:** when the daemon is *down*, every
tool call pays the full hook timeout before proceeding. Nothing breaks, but a 5-second penalty per
tool call is genuinely irritating and would look like Claude Code being slow rather than like
`agentfw` not running. Three mitigations, all cheap:

1. The `install` output must say explicitly that a stopped daemon costs the timeout per tool call, so
   the symptom is recognizable.
2. `SessionStart` is a natural place to probe `/health` and warn loudly when the daemon is
   unreachable — the operator learns immediately rather than inferring it from sluggishness.
3. The timeout stays at 5 s rather than being shortened, because phase 10's local-model judge tier
   has a 3 s budget of its own. Shortening it now would time out legitimate slow judgments later. The
   daemon-down penalty is the price of that headroom, and it is paid only when something is already
   wrong.

---

## 8. Audit log

`~/.agentfw/audit.jsonl`, append-only, mode `0600`, one JSON object per event:

```json
{
  "at_ms": 1753000000000, "session": "abc123", "seq": 42,
  "tool": "Bash", "event": "tool_call",
  "verdict": "deny", "shadow": true, "rule": "deny-tainted-privilege",
  "risk_score": 90,
  "findings": [{"detector":"secret.aws_key","severity":"critical","owasp":"LLM02:2025 …"}],
  "taint": {"source":"network:blog.example.com","seq":7},
  "egress_hosts": ["archive.evil.com"],
  "latency_us": 1840,
  "truncated": false
}
```

This log is not a by-product. It is:

- the **phase 10 tuning corpus**, via `agentfw replay`;
- the **benign-session benchmark corpus** for phase 12, which no public dataset supplies;
- the only way to learn the real false-positive rate before enforcement is switched on.

Raw received bytes are preserved for `Unknown` events, per the obligation recorded in phase 08 —
`Unknown` re-serializes lossily, so the events most worth investigating would otherwise be
forensically empty. Unknown events are also counted and warn-logged, so a typo'd collector tag is
visible rather than silently inert.

---

## 9. Configuration and installation

`~/.agentfw/config.yaml`:

```yaml
bind: 127.0.0.1
port: 8787
enforce: false            # shadow mode by default
policy: ~/.agentfw/agent-policy.yaml   # falls back to the crate's shipped default
audit: ~/.agentfw/audit.jsonl
max_record_bytes: 262144
deterministic_timeout_ms: 100
```

`agentfw install` prints — and with `--write` applies — the `settings.json` hook block for all five
events, with the token wired through `allowedEnvVars`. It never edits settings without `--write`,
and it never overwrites existing hook entries; it merges or reports a conflict.

---

## 10. Testing strategy

- **Payload fixtures:** real hook payloads captured from a live session, replayed at `POST /hook`.
  This is what makes the daemon testable without driving Claude Code.
- **Mapping unit tests:** hook JSON → `AgentEvent`, especially the provenance table, including
  path-inside-vs-outside-`cwd` and `mcp__server__tool` name parsing.
- **Verdict mapping tests:** `Allow → defer` pinned explicitly, since mapping it to `allow` is the
  regression this phase exists to avoid.
- **Shadow-mode test:** a payload that would `deny` returns `defer` with `shadow: true` logged.
- **Auth tests:** missing, malformed, and wrong tokens all `401`; correct token passes.
- **Failure tests:** oversized body, malformed JSON, unknown `hook_event_name` — none may panic, all
  must degrade to proceed.
- **`agentfw replay`:** re-run an audit log through a modified policy and diff the verdicts.
- **CI:** the workspace must stay green at 249+ tests; no changes to `core` or `agent` public APIs.

---

## 11. What phase 09 does not deliver

- **Subagent authority containment** — no hook exposes the grant (§1.3). Phase 11.
- **Result rewriting / sanitization** — deliberately out of scope (B2).
- **The local LLM judge** — phase 10, and it needs this phase's audit data to be tuned honestly.
- **API and MCP collectors** — phase 11.
- **Enforcement by default** — shipped in shadow mode (B3). Real protection requires one config
  change, made deliberately, after seeing real numbers.
