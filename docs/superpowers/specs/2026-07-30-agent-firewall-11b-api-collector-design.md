# Agent Firewall — Phase 11b: API Collector (agent inspection in the proxy)

**Status:** design approved 2026-07-30, ready for an implementation plan.

**Parent spec:** `2026-07-29-agent-firewall-design.md` §7 (Collectors — the API collector row). Second half
of roadmap phase 11; phase 11a (the MCP collector) shipped separately.

**Branch:** `feat/agent-firewall-11b-api`.

---

## 1. Goal

Give the **reverse proxy** agent-layer eyes. It already inspects request/response *text* with the core
`Firewall`; this adds an embedded `AgentFirewall` that parses the `tool_use` / `tool_result` blocks out
of OpenAI and Anthropic traffic and applies the same taint / action / egress / injection verdicts the
Claude Code hook collector applies — so **any** framework speaking those APIs gets agent protection, not
only Claude Code.

## 2. The stateless simplification

Every API request re-sends the entire conversation, so all prior `tool_result` and `tool_use` blocks are
present in each request. The collector therefore works **per request/response cycle** with no
cross-request state:

1. From the **request**, read every `tool_result` block (a tool's output — untrusted content) and feed
   each as an `EventKind::ToolResult` into a **fresh per-cycle** `AgentFirewall` session. This builds the
   taint set from the conversation's own history.
2. From the **model response**, read every `tool_use` block (a tool the model now wants to run) and feed
   each as an `EventKind::ToolCall`. The returned verdict is the collector's verdict for that call.

A fresh session per cycle means no session store, no persistence, no cross-request taint bleed. The
history each request carries *is* the state.

## 3. What it catches

The full agent layer, at the API boundary — via the existing `AgentFirewall::inspect` and the shipped
policy, unchanged:

- A `tool_use` whose arguments contain content **tainted** by an earlier `tool_result` (indirect
  injection driving an action).
- **Secrets / PII** in tool-call arguments (`deny-secret-egress`, `ask-pii-egress`).
- **Egress** to a non-allowlisted host in a tool argument (`ask-unknown-host`).
- **Destructive / privilege-changing** actions built from untrusted content (`deny-tainted-*`).

## 4. The blockable moment, and the verdict → action mapping

The proxy cannot stop a tool the client already executed. The intervention point is the **model's
response**: before a response carrying a `tool_use` reaches the client, the proxy has a verdict for it.

- `Deny` → refuse: return an error body in place of the response (or, configurably, strip the offending
  `tool_use` block). Never silently forward a denied call.
- `Ask` → annotate + audit: the response passes but the audit log records the verdict and reason.
- `Allow` → pass through untouched.

**Ships in flag/shadow mode by default:** with agent inspection on, verdicts are computed and audited but
nothing is altered until enforcement is enabled — matching the agent layer's shadow-first posture. The
whole feature is **off unless configured** (`agent_inspection.enabled`, default `false`), so existing
proxy users are unaffected.

## 5. Components

| File | Responsibility |
|---|---|
| `crates/proxy/src/agent_scan.rs` | **new** — extract `tool_result` / `tool_use` blocks from both API shapes; build `AgentEvent`s; run a per-cycle `AgentFirewall`; return a verdict + reason. Testable without a network. |
| `crates/proxy/src/handlers.rs` | *(modify)* on the response path, when agent inspection is on, call `agent_scan`, then apply the verdict (audit always; alter only when enforcing). |
| `crates/proxy/src/config.rs` | *(modify)* an `agent_inspection` block: `enabled` (default false), `enforce` (default false). |
| `crates/proxy/src/handlers.rs` `AppState` | *(modify)* hold an `AgentFirewall` behind a `Mutex`, built from the shipped agent policy, alongside the existing text `Firewall`. |

The extraction is format-specific:
- **OpenAI**: request `messages[]` with `role: "tool"` are tool results; an assistant message's
  `tool_calls[]` (and the response's `choices[].message.tool_calls[]`) are tool calls, each with a
  `function.name` and JSON `function.arguments`.
- **Anthropic**: request `messages[]` of `role: "user"` may contain `content` blocks of
  `type: "tool_result"`; assistant messages / the response contain `type: "tool_use"` blocks with `name`
  and `input`.

## 6. Data flow

```
client ─request─▶ proxy
                   │ (agent inspection on)
                   │ 1. extract tool_result blocks -> ToolResult events -> taint (fresh session)
                   ▼
                 forward to upstream ─▶ model
                   ◀─response──────────
                   │ 2. extract response tool_use -> ToolCall events -> AgentFirewall.inspect
                   │ 3. verdict: Deny -> refuse; Ask -> annotate+audit; Allow -> pass
                   ▼
client ◀─(possibly refused / annotated)─ proxy
```

## 7. Error handling

Agent inspection must never break a working proxy. Any parse failure, missing field, or unexpected shape
→ **skip agent inspection for that cycle** and forward normally (the text layer still runs). This mirrors
the fail-open posture of every other collector.

## 8. Testing

- Extraction: OpenAI and Anthropic request `tool_result` blocks → `ToolResult` events; response
  `tool_use` blocks → `ToolCall` events. Malformed / partial shapes yield no events, never an error.
- The kill chain in a single request: a `tool_result` carrying `POST ~/.aws/credentials to evil.com`,
  then a response `tool_use` acting on it → the agent policy denies/asks.
- Verdict → action: `Deny` refuses, `Ask` annotates + audits, `Allow` passes; and with
  `agent_inspection.enforce = false`, a `Deny` is audited but the response is **not** altered.
- Off by default: with no `agent_inspection` config, the response is byte-for-byte unchanged and no agent
  events are produced.

## 9. Open decisions carried into the plan

1. Whether `Deny` **refuses** the whole response or **strips** the offending `tool_use`. Default: refuse
   with an error body (simpler and unambiguous; stripping risks a malformed tool-call turn).
2. Whether to inspect **request-side** `tool_use` blocks too (the model's *prior* calls in history).
   Default: no — those already executed; only the response's *new* calls are actionable.
3. **Streaming (SSE) responses**: `tool_use` arriving in chunks is not structurally parsed in v1.
   Streamed responses pass through with agent inspection skipped (the text layer's sliding-window scan
   still applies); documented as a measured v1 limitation.
