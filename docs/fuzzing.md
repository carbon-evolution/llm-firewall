# Fuzzing

The code that parses untrusted input is fuzzed with
[cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) (libFuzzer with
AddressSanitizer). The harnesses are in `fuzz/`, which is its own Cargo workspace with
its own `fuzz/Cargo.lock`. The root workspace excludes it, so the stable build,
`cargo test --all` and `cargo deny check` never see it.

## Targets

| Target | What it feeds | What it checks beyond "no panic" |
|---|---|---|
| `detectors` | Arbitrary text through all five detectors, the full normalizer (zero-width, homoglyph, base64), scoring, the shipped policy and a mask-everything policy. The input's tail also becomes synthetic findings with arbitrary spans, which go straight to `mask`. | Detector spans are in bounds and on UTF-8 char boundaries. `mask` agrees with a reference model that masks every byte covered by any valid span. |
| `openai_request` | A `/v1/chat/completions` body through `ChatRequest` → `decide_input` → re-serialization, then agent-layer tool-call/tool-result extraction and `inspect_cycle`. The same bytes are also read as an upstream response. | The forwarded request still serializes, re-parses and keeps its message count. |
| `anthropic_request` | The same for `/v1/messages`: `AnthropicRequest` with string-or-blocks `system`/`content`, `tool_result`/`tool_use` blocks. | As above. |
| `sse_stream` | An upstream SSE byte stream, cut into fuzzer-chosen chunks, through `SseParser` and `StreamInspector` (OpenAI and Anthropic framing, with fuzzer-chosen hold-back and hold flags). | The parser gives the same events whole or split, and they reassemble to the exact input. A clean stream reaches the client byte-for-byte. A blocked stream has released only a prefix. |
| `policy_yaml` | One YAML document through `PolicySet`, `AgentPolicySet`, the proxy `Config` and the agentfw `Config`. A policy that parses is then evaluated. | Bad YAML fails cleanly. It never crashes or exhausts memory. |
| `mcp_manifest` | MCP `tools/list` JSON-RPC lines (`manifest_from_line`) and `/mcp` handshake tool lists through `manifest_hash`, `diff` and `inspect_mcp_handshake`. | The pin hash does not change when the tools are reordered. `diff(m, m)` is "no change". |
| `agent_hook` | Newline-separated Claude Code hook payloads, mapped by `map::to_event` (byte 0 sets the truncation limit) and fed in order into one `AgentFirewall`, so tool results taint later tool calls. | UTF-8-safe truncation. Stateful taint, egress and authority paths. |

Seed inputs are in `fuzz/corpus/<target>/`. They include realistic requests, tool-call
conversations, texts with secrets/PII/homoglyphs/zero-width characters, and the
shipped policies. `fuzz/llm-firewall.dict` is a libFuzzer dictionary of JSON/YAML
tokens, field names and detector triggers. Secret-shaped seeds must not trip
gitleaks: CI scans the full history.

## Running locally

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked

cd fuzz
cargo +nightly fuzz list
# New inputs go to the FIRST corpus dir: keep it a scratch dir (git-ignored) so
# the committed seeds stay small.
mkdir -p corpus-work/detectors
cargo +nightly fuzz run detectors corpus-work/detectors corpus/detectors -- \
  -dict=llm-firewall.dict -max_total_time=300 -timeout=10 -rss_limit_mb=2048

# Reproduce / minimise a crash
cargo +nightly fuzz run detectors artifacts/detectors/crash-<hash>
cargo +nightly fuzz tmin detectors artifacts/detectors/crash-<hash>
```

For long inputs (to find slow paths) add `-max_len=262144 -len_control=0`. A crash
fix belongs in the crate that panicked, together with a regression unit test built
from the minimised input.

## CI

`.github/workflows/fuzz.yml` builds every target on a dated nightly. It runs each
target for 2 minutes on PRs that touch `crates/`, `fuzz/`, `policies/` or
`Cargo.lock`, and for 15 minutes weekly. Crash inputs are uploaded as the
`fuzz-artifacts-<target>` artifact. The job is not a required check.
