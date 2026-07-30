# Agent Firewall — Phase 11a: MCP Collector (handshake supply-chain defenses)

**Status:** design approved 2026-07-30, ready for an implementation plan.

**Parent spec:** `2026-07-29-agent-firewall-design.md` (§6.4 Subagent & MCP supply chain, §7 Collectors,
open questions #1 and #2). This is the first half of roadmap phase 11; the API collector in
`crates/proxy` is a separate later cycle (phase 11b).

**Branch:** to be created, e.g. `feat/agent-firewall-11-mcp`.

---

## 1. Goal

Give the agent firewall eyes on the **MCP server boundary** so it can catch three supply-chain attacks
that neither the hook collector nor the judge can see:

1. **Rug-pull** — an MCP server that ships a benign tool manifest, gets trusted, then silently changes a
   tool's description or schema in a later session to smuggle in instructions or widen its reach.
2. **Tool-name shadowing** — two servers (or a server and a builtin like `Read`/`Bash`) declaring the
   same tool name, so the agent may invoke the wrong one.
3. **Description poisoning** — injection text planted in a tool *description*, which the model reads at
   handshake as if it were guidance.

All three are decided **at handshake**, deterministically, with no LLM required.

**Explicitly out of scope for v1** (deferred, not forgotten): per-call argument/result inspection at the
MCP boundary (overlaps the hook collector's taint work), HTTP/SSE MCP transport (stdio only — the common
local case), and any auto-approval of drift.

## 2. How it inserts itself

The MCP collector is a **transparent stdio proxy**, configured by wrapping the real server command in
the MCP client's config (Claude Code `.mcp.json`, Claude Desktop config, etc.):

```json
{
  "mcpServers": {
    "github": {
      "command": "agentfw",
      "args": ["mcp", "--id", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

`agentfw mcp` spawns `<server-cmd>` as a child process and relays JSON-RPC 2.0 messages
(newline-delimited JSON over stdio) **byte-for-byte in both directions**. It tees only the handshake
messages (`initialize`, `tools/list`) to an inspector; everything else — and anything it cannot parse —
passes straight through untouched. The proxy must never break, reorder, or hang an MCP session.

**Server identity** is keyed by an explicit `--id <name>` flag (approved). If absent, it falls back to a
stable hash of the full server command + args. The `--id` is what the pin store and the audit log key on,
so a user renaming or relocating a server keeps its pin.

## 3. The three checks (daemon-side)

The proxy forwards a new `McpHandshake` `AgentEvent` (carrying the server id and its tool manifest) to
the running daemon over the existing loopback `/hook` endpoint, reusing bearer-token auth, the policy
engine, and the audit sink. The daemon runs:

### 3.1 Manifest drift (the rug-pull defense)
Canonicalize the manifest — sort tools by name; for each tool include name, description, and a
canonical form of its `inputSchema` — and hash it (SHA-256). Compare to the per-server pin:
- **No pin yet** → pin it silently (`allow`). First sighting is trust-on-first-use.
- **Hash unchanged** → `allow`.
- **Hash changed** → `ask`, with a human-readable diff (added/removed tools, changed descriptions or
  schemas) as the reason. Policy condition: `mcp_manifest: changed`.

### 3.2 Tool-name shadowing
Against a `ToolRegistry` of every tool name currently known (from other servers' pinned manifests plus
the builtins `Read`, `Write`, `Edit`, `Bash`, …), a name that collides → `ask`. Policy condition:
`mcp_tool_shadow: true`. This needs the daemon's central, cross-server view — the reason the
daemon-connected architecture was chosen over a self-contained proxy.

### 3.3 Description poisoning
Each tool description is projected onto the existing `tool_description` facet and run through the
**injection detector already in core**. This reuses the shipped `ask-injection-in-tool-description`
policy rule verbatim — the collector only has to feed the facet, no new detection logic.

## 4. Components (each testable in isolation)

| Unit | Responsibility | Depends on |
|---|---|---|
| `agentfw/src/mcp/jsonrpc.rs` | Minimal, tolerant JSON-RPC 2.0 framing over newline-delimited stdio; recognizes `initialize` and `tools/list`, extracts the manifest, passes everything else through as opaque bytes. | serde_json |
| `agentfw/src/mcp/manifest.rs` | Canonicalize + SHA-256 a tool manifest; diff two manifests into a reason string. Pure. | serde_json, sha2 |
| `agentfw/src/mcp/proxy.rs` | The concurrent bidirectional relay: spawn child, two async pump tasks (client→server, server→client), tee handshake to the inspector, POST `McpHandshake` to the daemon, enforce the verdict. Fail-open on any inspector/daemon error. | tokio, reqwest |
| `agentfw/src/mcp/store.rs` (`ManifestStore`) | Persistent per-server pins at `~/.agentfw/manifests/<id>.json`, `0600`. Round-trippable. | serde_json |
| daemon `AppState` additions | `ManifestStore` + `ToolRegistry` (in-memory cross-server tool-name set, seeded from pins at startup). | — |
| daemon handshake handling | New `EventKind::McpHandshake` + `map`/handler path that runs the three checks and returns a verdict, audited with the new fields. | existing policy/audit |
| policy conditions | `mcp_manifest: changed`, `mcp_tool_shadow: true` (parse + evaluate). `mcp_description` reuses the existing injection-over-`tool_description` rule. | — |

New workspace dependency: `sha2` (already transitively present via other crates; make it direct in
`agentfw`).

## 5. Data flow

```
MCP client ──stdio──▶ agentfw mcp (proxy) ──stdio──▶ real MCP server
                          │  tee initialize + tools/list
                          ▼
                    build manifest, POST McpHandshake ──HTTP──▶ daemon /hook
                          ▲                                        │ hash vs pin,
                          │            verdict + reason            │ shadow check,
                          └────────────────────────────────────────┘ injection scan, audit
                          │
              shadow: pass through unchanged
              enforce + ask/deny: return a JSON-RPC error to the client,
                                  so the server's tools are withheld this session
```

## 6. Enforcement posture

- **Ships in shadow mode, like phase 09.** By default every handshake is inspected, pinned, and
  audited, but nothing is ever withheld — the operator runs normally, then reads the audit log.
- **Enforcement is opt-in** (`enforce: true`). MCP handshake has no interactive "ask" moment, so in
  enforce mode a non-interactive `ask` (and `deny`) **fails closed**: the proxy returns a JSON-RPC error
  in place of the manifest and the server starts with no tools available. This matches the parent spec's
  open-question #1 default (non-interactive `ask` → deny) and is stated loudly in `agentfw install`.

## 7. Failure handling — never break a session

- **Daemon unreachable, HTTP error, or any inspector panic** → the proxy passes the handshake through
  **unchanged** (fail open) and logs a warning. Same posture as the hook collector: a security tool that
  wedges MCP gets uninstalled the same day.
- **The relay is two independent async pumps** so neither direction can deadlock waiting on the other.
- **Unparseable JSON-RPC** is forwarded verbatim; the inspector only acts on messages it fully
  understands.

## 8. Testing

- `jsonrpc`: framing/round-trip, recognizes `initialize`/`tools/list`, passes unknown methods through,
  tolerates partial/garbage lines without erroring.
- `manifest`: hash **stability** (reordering tools or schema keys does not change the hash) and
  **sensitivity** (a changed description or schema does), and diff correctness.
- `store`: pin round-trip, `0600`, silent first-pin (no drift on first sight).
- daemon handshake handler: drift → `ask` with a diff; shadowing → `ask`; a poisoned description → the
  existing injection rule fires; a clean re-handshake → `allow`; **shadow mode never withholds**.
- integration: a **mock MCP child server** driven end-to-end through the proxy — proves transparent
  relay of a normal session, and drift detection when the mock's manifest changes between two runs.

## 9. Open decisions carried into the plan

1. Whether `McpHandshake` reuses `/hook` with a new `EventKind` (preferred — maximum reuse) or gets a
   dedicated `/mcp` endpoint. Default: reuse `/hook`.
2. Canonical form of `inputSchema` for hashing — full recursive key-sort vs. a shallow normalization.
   Default: recursive key-sort of the JSON value, which is stable and simple.
3. `ToolRegistry` seeding at daemon startup from the pin directory, and how a removed server's names age
   out. Default: seed from pins on boot; a server whose pin is deleted drops its names.
