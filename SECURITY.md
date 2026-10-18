# Security Policy

## Reporting a vulnerability

Please **do not** report security vulnerabilities in public issues, discussions or pull requests.

**Report privately** through GitHub: **[Report a vulnerability](https://github.com/carbon-evolution/llm-firewall/security/advisories/new)**
(Security → Advisories → *Report a vulnerability*). Include:

- a description of the issue and its impact,
- steps to reproduce (endpoint, request shape, `firewall.yaml` / policy used) and, where possible, a
  proof of concept,
- the commit or release you tested, and whether it was built with `--features ml`.

What to expect:

- acknowledgement within **3 business days**,
- an initial assessment and severity rating within **7 days**,
- a fix or mitigation plan, coordinated disclosure, and credit in the advisory if you want it.

Supported versions: the latest release and `main`.

## Scope

This project is a **defensive** tool — a firewall for LLM traffic. Relevant reports include:

- Detection **bypasses** (a prompt-injection / secret / PII / harmful-content payload that evades a
  detector it should catch), with a concrete example.
- **Inspection gaps** — a request or response shape the proxy forwards without inspecting.
- **Over-defense** regressions (benign inputs wrongly blocked) that materially raise the false-positive
  rate.
- Memory-safety, denial-of-service, or request-smuggling issues in the proxy (`llm-firewall`) or the
  agent daemon (`agentfw`).
- Weaknesses in `agentfw`'s local authentication (token, loopback binding) or audit-log handling.

## Out of scope / by design

- The rule layer (regex + heuristics) is the only prompt-injection stage the **proxy** runs today. The
  DeBERTa classifier behind `--features ml` is used by the benchmark harness; the proxy does not yet
  attach it (see LLM01 below). A miss by the rule layer is a known, documented recall limit, not a
  vulnerability on its own. (`--features ml` in the proxy enables only the opt-in output-moderation
  model.)
- Detection is probabilistic. No classifier is perfect; see `docs/methodology.md` and the README
  benchmark for measured recall and false-positive rates and their honest limits.
- The content-moderation layer is **not** a full safety system and makes no claim to detect illegal
  material (e.g. CSAM).
- `agentfw` fails open on internal errors by design (a hook that wedges the agent loop gets
  uninstalled); this is documented in the README and is not itself a vulnerability.

## Security assessment

*Assessed 2026-10-18 against commit `9d4039f` (`main`, after #22 and #23). Re-assess after major
changes; the automated controls at the end run continuously.*

**Method:** manual code review of the proxy request path (`crates/proxy`: router, handlers, pipeline,
config, streaming, moderation, agent scan), the detectors and ML loaders (`crates/core`), and the agent
daemon's auth/config (`crates/agentfw`); `cargo deny --all-features check`; review of the CI workflows,
`deny.toml`, `.gitleaks.toml`, `deploy/`; GitHub code-scanning, Dependabot and secret-scanning alert
lists and the published OpenSSF Scorecard; **OWASP ZAP** (`zap-baseline.py` and `zap-api-scan.py` with an
OpenAPI description of `/v1/chat/completions` and `/v1/messages`) against a release build bound to
`127.0.0.1:18080` with the repo `firewall.yaml` and a local mock upstream; targeted manual probes
(oversized/malformed/nested bodies, long and numerous headers, request smuggling, slow and idle
connections, slow upstream, unicode/obfuscated and indirect injection variants, output-side secret
placement, upstream failure); and the repo's own benchmark results and documented limitations
(README benchmark, `docs/methodology.md`, `docs/garak-validation.md`, phase 13/14 plans).

**Rating scale (residual risk, after current mitigations):** **High** — exploitable weakness with
material impact, fix now · **Medium** — real weakness with limited impact or partial mitigation, fix
planned · **Low** — controls in place; minor or theoretical gaps · **N/A** — not applicable to this
project, with the reason stated.

For a firewall, each LLM risk has two angles, rated together: **(a) protection** it provides to the
application behind it, and **(b) exposure** of the firewall itself.

### Summary — OWASP Top 10 for LLM Applications 2025

| # | Category | Residual risk |
|---|---|---|
| LLM01 | Prompt Injection | 🔴 **High** |
| LLM02 | Sensitive Information Disclosure | 🟠 **Medium** |
| LLM03 | Supply Chain | 🟢 **Low** |
| LLM04 | Data and Model Poisoning | 🟠 **Medium** |
| LLM05 | Improper Output Handling | 🟠 **Medium** |
| LLM06 | Excessive Agency | 🟠 **Medium** |
| LLM07 | System Prompt Leakage | 🟠 **Medium** |
| LLM08 | Vector and Embedding Weaknesses | ⚪ **N/A** |
| LLM09 | Misinformation | ⚪ **N/A** |
| LLM10 | Unbounded Consumption | 🟠 **Medium** |

### Summary — OWASP Top 10:2025 (the proxy as a network service)

| # | Category | Residual risk |
|---|---|---|
| A01 | Broken Access Control | 🟠 **Medium** |
| A02 | Security Misconfiguration | 🟠 **Medium** |
| A03 | Software Supply Chain Failures | 🟢 **Low** |
| A04 | Cryptographic Failures | 🟠 **Medium** |
| A05 | Injection | 🟢 **Low** |
| A06 | Insecure Design | 🔴 **High** |
| A07 | Authentication Failures | 🟢 **Low** |
| A08 | Software or Data Integrity Failures | 🟠 **Medium** |
| A09 | Security Logging and Alerting Failures | 🟠 **Medium** |
| A10 | Mishandling of Exceptional Conditions | 🟠 **Medium** |

**Overall (both lists): 2 High, 12 Medium, 4 Low, 2 N/A.** The project's engineering hygiene is strong — memory-safe
Rust with two `unsafe` blocks, no open RustSec findings that reach the build, SHA-pinned CI, signed
release images, and an audit log that verifiably records no prompt text or credentials. The High
ratings are about the **security function itself**: the proxy inspects fewer request/response shapes
than the README implies, and the injection recall that ships in the proxy is the rule layer's, not the
DeBERTa figure. ZAP found no High or Medium issues (details under A02).

### LLM01 — Prompt Injection · 🔴 High

*(a) Protection*
- ✅ Three-stage detector exists (`crates/core/src/detectors/injection/`): regex signatures, heuristics,
  optional DeBERTa classifier. Policy `block-high-injection` / `block-ml-injection` blocks with HTTP 400
  before anything reaches the upstream (`policies/default.yaml`); verified on a classic override phrase.
- ✅ Normalization pre-pass (zero-width strip, NFKC + confusable folding; base64 opt-in) is on by default.
  Verified: Cyrillic-homoglyph, zero-width-split and full-width variants of a known phrase are blocked.
  Benchmark (rule layer, safe-guard): obfuscated recall 0.0% → 14.5%, base64 0.0% → 30.6%, at 0.00% FPR
  on a multilingual benign control (README "Obfuscation resilience").
- ✅ OpenAI `role: "tool"` messages and the Anthropic `system` prompt are scanned as input (indirect
  injection via tool output is covered on the OpenAI path; verified).
- ⚠️ **The proxy never attaches the ML classifier.** `build_firewall` constructs
  `InjectionDetector::new()` without `with_ml` (`crates/proxy/src/lib.rs:25-45`); only the bench harness
  loads `models/injection` (`crates/bench/src/main.rs:105`). The README prerequisites table says building
  with `--features ml` "turns on the AI detection stage", but in the proxy that flag only enables output
  moderation. **Deployed injection recall is therefore the "Default" row of the README benchmark: 1.9%
  (deepset), 23.7% (jailbreak-classification), 14.6% (safe-guard) at ≤ 0.1% FPR** — not the "+ ML"
  84.3% / 85.6% / 41.4%. Manual probes confirm: paraphrased, leetspeak, non-English and base64-wrapped
  instructions are forwarded.
- ⚠️ **Inspection gaps (verified with a mock upstream):** Anthropic content blocks other than top-level
  `type: "text"` — notably `tool_result` (string or nested text) and `document` blocks — are forwarded
  unscanned (`crates/proxy/src/pipeline.rs:113-131`), so indirect injection via tool results is *not*
  covered on `/v1/messages`, contrary to the comment in `policies/default.yaml`. Tool/function
  *definitions* (`tools[].description`) are not scanned on either path. Each message is scored
  independently, so a phrase split across consecutive messages is not matched.
- ⚠️ OpenAI content-part arrays (`content: [{"type":"text",...}]`, used for multimodal input) are rejected
  with 422 (`crates/proxy/src/openai.rs:11`) — fail-closed, but it breaks such clients.
- ⚠️ Known, documented ML limits that will apply once the classifier is wired in: deepset recall 41.4%
  (broad labels), JailbreakBench 0% (harmful goals, out of scope), base64 over-blocking on output
  (`docs/garak-validation.md`).

*(b) Exposure*
- ✅ The firewall has no model of its own on the request path, so it cannot be prompt-injected; the
  `agentfw` judge accepts only the two tokens `INJECTION`/`DOCUMENTATION` and may only tighten a verdict.

**Recommended:** wire `MlClassifier` into `build_firewall` behind config (`injection.ml_model_path`,
threshold) and fail closed if it is configured but cannot load; until then, correct the README
prerequisites line. Scan Anthropic `tool_result`/`document` text and `tools[].description`; accept
OpenAI content-part arrays and scan their `text` parts; consider a joined-conversation scan.

### LLM02 — Sensitive Information Disclosure · 🟠 Medium

*(a) Protection*
- ✅ Input: AWS key ids, GitHub PATs, Slack tokens, JWTs, private-key headers and high-entropy tokens are
  detected (`crates/core/src/detectors/secret.rs`); an AWS key in a prompt scored 93 and was blocked by
  `block-high-risk`. Emails and card numbers are masked before forwarding — verified on the wire
  (`‹EMAIL›`, `‹CREDIT_CARD›`); a US-format phone number was not masked.
- ✅ Output: `block-secret-output` blocks a secret in a non-streamed reply (verified on both endpoints,
  HTTP 502).
- ⚠️ **Output inspection gaps (verified):** only `choices[0].message.content` (OpenAI) and text blocks
  (Anthropic) are scanned (`crates/proxy/src/handlers.rs:167-170`, `266-280`). Secrets in additional
  choices (when the client requests `n > 1`), in `tool_calls` arguments / `tool_use` input, or in
  **non-200 upstream bodies** (forwarded unscanned, `handlers.rs:163-165`) reach the client. Streaming
  output is covered only partially (see A06).
- ⚠️ PII masking applies to input only: `decide_output` acts on `block` alone
  (`crates/proxy/src/pipeline.rs:177-188`), so `mask-pii` never redacts PII in a reply.
- ⚠️ No provider-specific patterns for OpenAI (`sk-…`) or Anthropic (`sk-ant-…`) keys; they rely on the
  generic entropy gate.

*(b) Exposure*
- ✅ The audit log records decision, score, reason labels, OWASP/ATLAS tags and latency only — verified
  over ~1,100 requests (ZAP + probes): no prompt text, no secret values, no `Authorization` header.
- ✅ Client credentials (`authorization`, `x-api-key`, vendor headers) are forwarded only to the
  configured upstream (`handlers.rs:88-112`); the proxy never stores or injects keys of its own.
- ⚠️ The listener is plain HTTP and binds `0.0.0.0` by default, so API keys cross the network in clear
  unless the proxy is a loopback sidecar or behind TLS (see A04).
- ⚠️ With `fail_mode: fail_closed` (the default) the 502 body includes the transport error, which names
  the internal upstream URL (`handlers.rs:331-334`).

**Recommended:** scan every choice, tool-call arguments and error bodies; add output-side masking;
add `sk-`/`sk-ant-` patterns; return a generic upstream-error message and log the detail instead.

### LLM03 — Supply Chain · 🟢 Low

- ✅ `cargo deny --all-features check`: advisories, bans, licenses and sources all **ok**. Four documented
  ignores in `deny.toml`, all in the optional `ml` tree: `paste` (RUSTSEC-2024-0436, compile-time
  proc-macro, unmaintained) and `zip` RUSTSEC-2026-0367/0368/0369 (archive *extraction*; candle only
  reads entries and the project loads `.safetensors`, so `extract()` is unreachable).
- ✅ `Cargo.lock` committed with h2 0.4.20 and rustls 0.23.46; `serde_yaml` replaced by `serde-saphyr`,
  removing `unsafe-libyaml` (#22). Registry and git sources are allow-listed; license allow-list is
  explicit.
- ✅ CI (#23): every action pinned to a commit SHA, least-privilege tokens, CodeQL (Rust + Actions,
  `security-extended`), full-history gitleaks with a narrow path-and-value allowlist for synthetic
  fixtures, ClamAV over the source and fetched crates, Dependabot for cargo/actions/docker,
  digest-pinned Docker bases. Dependabot, secret-scanning and code-scanning: **0 open security alerts**
  (the 6 open code-scanning alerts are Scorecard posture checks, below).
- ⚠️ **Scorecard "Vulnerabilities" scores 1/10** because its OSV scan reads `Cargo.lock` as a flat list: it
  counts the four ignored advisories above plus five `quinn-proto` 0.11.16 advisories
  (RUSTSEC-2026-0338…0342). `quinn-proto` appears in the lockfile via reqwest's optional HTTP/3 support
  but is **not in the resolved build graph** (`cargo tree -i quinn-proto --all-features --target all`
  is empty; it is not compiled). Not exploitable, but it is noise in every scanner.
- ⚠️ ML weights are a separate supply chain — see LLM04.

**Recommended:** `cargo update -p quinn-proto` (≥ 0.11.17) to clear the scanner noise; drop the `zip`
ignores when candle moves to zip ≥ 9.

### LLM04 — Data and Model Poisoning · 🟠 Medium

- ✅ Nothing is trained or fine-tuned on traffic; no feedback loop can poison the detectors at runtime.
  The default build loads no model at all.
- ✅ Models are loaded from `.safetensors` (no pickle code execution).
- ⚠️ **No integrity check on model files.** `scripts/fetch-model.sh:21` downloads from
  `…/resolve/main/…` — an unpinned branch, no revision hash, no checksum — and `HF_HOST` can redirect to
  a third-party mirror. A changed upstream repository or a tampered mirror would silently replace the
  classifier that makes security decisions (e.g. one that always scores "safe").
- ⚠️ The two `unsafe` blocks (`crates/core/src/detectors/injection/ml.rs:33`,
  `crates/core/src/detectors/moderation.rs:66`) memory-map weights with
  `VarBuilder::from_mmaped_safetensors`; if the file is modified or truncated while mapped, behaviour is
  undefined (crash or silently wrong weights). Exposure requires write access to the model directory.
- ⚠️ The moderation gate silently degrades to a no-op if `output_moderation.enabled` is set but the model
  fails to load (`crates/proxy/src/moderation.rs:79`, warning only).

**Recommended:** pin model revisions (commit SHA) and verify SHA-256 in `fetch-model.sh` and again at
load; keep the model directory read-only to the service user (read-only volume in containers); fail
startup when a configured model cannot load.

### LLM05 — Improper Output Handling · 🟠 Medium

*(a) Protection*
- ✅ `OutputDetector` (`crates/core/src/detectors/output.rs`) blocks destructive shell (`rm -rf`,
  pipe-to-shell), HTML/JS (`<script>`, event handlers) and markdown-image exfiltration in replies via
  `block-dangerous-output`; the phase 14 control check shows each artifact blocks at High/Critical.
- ✅ Injection rules are scoped to `direction: input` after phase 13 found they over-blocked 16% of
  legitimate security answers on replies (README "What this phase fixed").
- ⚠️ Same coverage gaps as LLM02: additional choices, tool-call arguments, non-200 bodies and streamed
  replies (A06) are not fully inspected.
- ⚠️ Documented limit (phase 14 plan): harmful operational *prose* with no executable artifact is covered
  only by the opt-in moderation model, which caught 84.0% at threshold 0.8 with 0.0% over-block; the
  worst case scored 0.467 and evades at both 0.8 and 0.5.
- ⚠️ Moderation `block` returns **HTTP 200** with an error envelope (`handlers.rs:196`, `303`); clients
  that only check the status code treat it as success.

*(b) Exposure*
- ✅ The proxy never renders or executes model output; it forwards JSON/SSE verbatim.

**Recommended:** inspect all output surfaces (see LLM02); return a non-2xx status (or a well-formed
completion carrying the refusal text) for moderation blocks.

### LLM06 — Excessive Agency · 🟠 Medium

*(a) Protection*
- ✅ Agent firewall (`crates/agent`, `agentfw`): taint tracking, action classification, egress allowlists,
  subagent authority containment, MCP manifest pinning (drift, shadowing, description poisoning).
  Benchmark: **73.7% detection (14/19) at 0.0% FPR (0/21)** on the hand-authored 40-session corpus; known
  misses are tainted exfil to a novel host without the judge, `destructive-from-taint` 0/2 and
  `mcp-poisoning` 1/2 (README "agent layer").
- ✅ Optional local judge tier: 100% / 4% FP on a 50-sample corpus, tighten-only, loopback-only.
- ⚠️ Everything is opt-in and shadow-first: `agentfw` defaults to `enforce: false`; the proxy's
  `agent_inspection` is off and, when on, shadow-only unless `enforce: true`
  (`crates/proxy/src/config.rs`), and it runs on non-streaming responses only. Out of the box the proxy
  enforces nothing at the tool boundary.
- ⚠️ Documented judge limit: an injection after the first 4 KB of a page is not seen
  (`max_span_bytes: 4096`).

*(b) Exposure*
- ✅ `agentfw` refuses non-loopback binds at parse time, requires a 256-bit bearer token compared in
  constant time, creates the token and audit log `0600`, caps body size and restricts the judge URL to
  loopback with exact host matching (`crates/agentfw/src/config.rs`, `token.rs`).
- ⚠️ `agentfw` fails open on internal errors and on bodies over the cap (by design, documented).

**Recommended:** document an "enforce" deployment profile; extend proxy agent inspection to streams;
pursue the span-cache fix the judge design already identifies.

### LLM07 — System Prompt Leakage · 🟠 Medium

- ✅ A "reveal/print your system prompt" signature exists and feeds the risk score; combined with an
  override phrase it blocks (score 90).
- ⚠️ On its own the exfiltration request is Medium severity and scored 58 — **allowed** (below the 85
  `block-high-risk` threshold). There is no output-side check for system-prompt echo, so leakage
  protection depends on the model.
- ✅ Exposure: the proxy holds no system prompt; the `agentfw` judge prompt never includes the action
  and only a two-token answer is accepted.

**Recommended:** an opt-in output rule that blocks replies reproducing a configured system prompt
(canary token or n-gram overlap).

### LLM08 — Vector and Embedding Weaknesses · ⚪ N/A

The firewall has no vector store, embeddings or retrieval pipeline. Retrieved content an application
passes in messages is inspected as input under LLM01.

### LLM09 — Misinformation · ⚪ N/A

Fact-checking model output is outside the firewall's purpose; no detector claims it. (The accuracy of
the project's *own* claims is addressed under LLM01: the README "+ ML" detection numbers do not
describe the proxy as shipped.)

### LLM10 — Unbounded Consumption · 🟠 Medium

*(b) Exposure*
- ✅ Request bodies are capped by axum's default 2 MiB limit (3 MiB → 413; a 1.9 MiB prompt was scanned in
  ~40 ms); JSON nesting is bounded by serde's recursion limit (10,000-deep → 400); headers are bounded
  (200 headers → 431, 1 MiB header → connection closed); the `regex` crate is linear-time, so no ReDoS.
- ⚠️ **No timeouts anywhere:** the upstream client is `reqwest::Client::new()` with no timeout
  (`crates/proxy/src/main.rs:18`) — a 20 s upstream stall was waited out in full; an idle connection that
  sent no bytes was still open after 70 s, and a body trickled at 1 byte/s was held for 25 s.
- ⚠️ No connection or concurrency limit (300 concurrent idle connections were accepted) and no rate
  limiting; detectors run synchronously on the async worker threads.

*(a) Protection*
- ⚠️ No per-client quotas, token budgets or `max_tokens` ceiling, so the firewall does not limit spend
  or denial-of-wallet against the upstream.

**Recommended:** set connect/read/total timeouts on the upstream client; add a header-read timeout and
request timeout (`tower-http` `TimeoutLayer`), a concurrency limit and an optional per-key rate limit;
optional policy for a maximum `max_tokens`.

### A01 — Broken Access Control · 🟠 Medium

- ✅ The proxy exposes exactly two `POST` routes (`crates/proxy/src/lib.rs:48-53`); there are no admin,
  config or debug endpoints; other methods → 405, other paths → 404, `..` paths are not normalized into
  routes. Upstream URLs are fixed by config, so there is no SSRF via request input.
- ⚠️ **No access control on the proxy:** anyone who can reach the port can relay requests. With hosted
  providers the caller still needs a valid key, but in front of a key-less internal model server the
  proxy grants open access to it.
- ⚠️ Binds `0.0.0.0:8080` by default (`config.rs:139-141`, `firewall.yaml`, `deploy/Dockerfile`); the
  Kubernetes sidecar example sets `LLM_FW_BIND=0.0.0.0:8080` even though the app talks to `localhost`,
  exposing the proxy on the pod IP to the whole cluster (`deploy/k8s-sidecar.yaml`).
- ✅ `agentfw` is loopback-only with token auth (see LLM06).

**Recommended:** default bind to `127.0.0.1` and use it in the sidecar example; optional inbound
client authentication (static key or mTLS) for shared deployments; a NetworkPolicy example.

### A02 — Security Misconfiguration · 🟠 Medium

ZAP on the running proxy: **baseline — 0 High, 0 Medium, 0 Low, 1 Informational** alert type (66 rules
passed; the root URL is a 404, so the spider has little to crawl). **API scan** (OpenAPI, active rules
over ~1,100 requests) — **0 High, 0 Medium, 2 Low** (`X-Content-Type-Options` missing,
`Cross-Origin-Resource-Policy` missing), 3 Informational; 117 rules passed; no crash, no 5xx from the
proxy itself.
- ✅ Safe defaults where it matters: `fail_mode: fail_closed`, normalization on, moderation and agent
  inspection opt-in with `flag`/shadow first.
- ⚠️ `0.0.0.0` default bind and plain-HTTP listener (A01, A04); the container runs as **root** (no `USER`
  in `deploy/Dockerfile`).
- ⚠️ No health/readiness route (`/health` → 404), so orchestrators can only probe TCP.
- ⚠️ Missing `X-Content-Type-Options: nosniff` / `Cross-Origin-Resource-Policy` on responses (low impact
  for a JSON API).

**Recommended:** non-root user in the image; `/healthz`; add the two headers; document a hardened
deployment profile (loopback/sidecar, TLS in front, enforce modes).

### A03 — Software Supply Chain Failures · 🟢 Low

See LLM03 for detail. RustSec clean for the built graph; lockfile committed; SHA-pinned actions;
CodeQL + gitleaks + ClamAV + Dependabot; digest-pinned bases; cosign-signed release images with SLSA
provenance and SBOM. **OpenSSF Scorecard 6.4/10**; remaining gaps: Code-Review 0 and Maintained 0
(single maintainer, new repository), Fuzzing 0, CII Best Practices 0, Vulnerabilities 1 (the lockfile
noise explained under LLM03), SAST 7 (CodeQL only recently added).

**Recommended:** clear the `quinn-proto` lockfile entry; add `cargo-fuzz` targets for the JSON request
models, normalizer and detectors; apply for the OpenSSF Best Practices badge.

### A04 — Cryptographic Failures · 🟠 Medium

- ✅ Upstream TLS via rustls 0.23.46 with webpki roots (no OpenSSL); default upstreams are `https://`.
- ✅ `agentfw` token: 256 bits from the OS-seeded RNG, constant-time comparison, `0600` file.
- ⚠️ The proxy has **no TLS listener option**; client API keys reach it in clear unless it runs on
  loopback / in the same pod or behind a TLS terminator, and the default bind is `0.0.0.0`.
- ⚠️ No check that upstream bases are `https://`; an `LLM_FW_OPENAI_BASE=http://…` override silently
  forwards keys in clear.

**Recommended:** refuse non-`https` upstreams unless the host is loopback (or an explicit
`allow_insecure_upstream`); optional rustls listener, or document TLS termination as required for
non-loopback deployments.

### A05 — Injection · 🟢 Low

- ✅ Requests are parsed into typed structs and **re-serialized** before forwarding, so the upstream never
  sees bytes the firewall did not parse (no JSON parser differential; duplicate `Content-Length` and
  `CL`+`TE` smuggling attempts → 400 from hyper).
- ✅ No SQL, shell, template or filesystem sinks on the request path; audit records are serialized JSON
  (no log injection); CodeQL `security-extended`: **0 open alerts**.
- ⚠️ Deserialization errors echo the JSON path and serde message back to the client as `text/plain`
  (e.g. `messages[0].content: invalid type …`) — minor reflection, no HTML context.

### A06 — Insecure Design · 🔴 High

The proxy's security function has design-level gaps where traffic passes without the inspection the
documentation describes. Each was reproduced against the release build with a mock upstream.
- ⚠️ **Streamed output is not reliably inspected.** The SSE scanner matches against the raw upstream
  bytes (JSON frames included) in a tail window of `stream_window × 4` = 256 bytes
  (`crates/proxy/src/handlers.rs:382-398`), rather than against the reassembled assistant text. A
  secret delivered across several delta frames was forwarded to the client and the stream logged
  `stream_done`. Each chunk is also forwarded right after the scan, so earlier chunks have already been
  delivered when a block fires. Output moderation and agent inspection do not run on streams at all.
- ⚠️ **Partial response inspection** — only the first choice's text (LLM02).
- ⚠️ **Partial request inspection** — Anthropic `tool_result`/`document` blocks and tool definitions are
  not scanned (LLM01).
- ⚠️ **ML stage not wired into the proxy** (LLM01).
- ✅ Good design elsewhere: fail-closed default, dual-scan normalization (obfuscation alone is never a
  block reason), direction-scoped policies, tighten-only judge, shadow-first rollout of new enforcement.

**Recommended:** reassemble streamed deltas per choice (parse SSE events, accumulate `delta.content` /
`content_block_delta` text) and scan the accumulated text with overlap, holding back a small tail
before release; treat "every text-bearing field is inspected" as an invariant with tests per API
shape; add a regression test for each gap above.

### A07 — Authentication Failures · 🟢 Low

- ✅ The proxy has no authentication mechanism of its own to break; it passes client credentials through
  and the upstream provider authenticates them. (The lack of inbound access control is rated under A01.)
- ✅ `agentfw` uses a 256-bit bearer token, strict `Bearer ` parsing, constant-time compare and `0600`
  storage; `agentfw install` prints the token by environment variable, never literally.

### A08 — Software or Data Integrity Failures · 🟠 Medium

- ✅ Release images are signed keylessly with Sigstore cosign; the workflow verifies its own signature and
  attaches SLSA provenance (`mode=max`) and an SBOM (`.github/workflows/release.yml`). `Cargo.lock` is
  committed.
- ⚠️ ML model files have no pinning or hash verification, and are memory-mapped with `unsafe` (LLM04).
- ✅ Branch protection on `main` requires 6 passing checks (test, deny, gitleaks, CodeQL rust/actions/
  results) and verified signed commits, and blocks force-push and deletion. ⚠️ No required reviews
  (single maintainer).
- ⚠️ `deploy/Dockerfile` builds without `--locked`.

**Recommended:** require the CI, deny, gitleaks and CodeQL checks and signed commits on `main`;
`cargo build --locked` in the Dockerfile; model pinning (LLM04).

### A09 — Security Logging and Alerting Failures · 🟠 Medium

- ✅ One structured JSON audit record per decision with score, reason labels, OWASP LLM and MITRE ATLAS
  tags and latency (`crates/proxy/src/audit.rs`); verified to exclude prompt text, secrets and
  credentials. `agentfw` keeps an append-only `0600` JSONL audit log with `replay` tooling.
- ⚠️ **Streaming requests get no input audit record** (the stream path returns before `audit_allow`,
  `handlers.rs:138-152`); only an output `stream_done`/`block` line is written.
- ⚠️ Non-200 upstream responses and requests rejected before the handler (413, 415, 422, 400 parse
  errors) are not audited.
- ⚠️ Records carry no client identity (address or key fingerprint), the `req-N` counter restarts with the
  process and is not returned to the client, and there is no metrics/alerting hook.

**Recommended:** audit every request outcome, including streams and rejections; add a client
identifier (hashed key or address), a UUID request id echoed in a response header, and counters for
blocks by rule.

### A10 — Mishandling of Exceptional Conditions · 🟠 Medium

- ✅ Upstream failure → **502 fail-closed** (non-streaming and streaming); malformed JSON → 400; schema
  errors → 422; no panics observed under ZAP or probes; `unwrap`/`expect` on the request path are
  limited to a static response builder and the agent mutex.
- ⚠️ The fail-closed error body exposes the upstream URL (LLM02).
- ⚠️ `fail_mode: fail_open` does not change behaviour beyond the error text (both modes return 502), so
  the option is misleading.
- ⚠️ Output moderation configured but unable to load its model silently disables itself (LLM04).
- ⚠️ The proxy's agent mutex uses `lock().expect(…)` (`handlers.rs:46`): after any panic while held, every
  later inspected request panics (only when `agent_inspection.enabled`).
- ⚠️ No timeouts (LLM10).

**Recommended:** generic client-facing errors; implement or remove `fail_open`; fail startup when an
enabled feature cannot initialize; recover from a poisoned mutex or use `parking_lot`.

### Automated security controls

| Control | Where | Runs |
|---|---|---|
| `cargo fmt`, `clippy -D warnings`, `cargo test --all --all-features` | `ci.yml` (`test`) | every PR, push to `main` |
| `cargo deny check` (RustSec advisories, unmaintained, licenses, bans, sources; all features) | `ci.yml` (`deny`) | every PR, push to `main` |
| gitleaks over full git history (narrow fixture allowlist in `.gitleaks.toml`) | `ci.yml` (`gitleaks`) | every PR, push to `main` |
| CodeQL `security-extended` (Rust + GitHub Actions) | `codeql.yml` | every PR, push to `main`, weekly |
| ClamAV malware scan (source + fetched crate sources, incl. `ml` tree) | `malware.yml` | every PR, push to `main`, weekly |
| OpenSSF Scorecard (SARIF to code scanning) | `scorecard.yml` | push to `main`, weekly |
| Dependabot version updates (cargo, actions, docker) + security updates | `dependabot.yml` / repo settings | weekly / continuous |
| Secret scanning + push protection | GitHub settings | every push |
| Private vulnerability reporting | GitHub settings | continuous |
| Signed release image (cosign keyless), SLSA provenance, SBOM | `release.yml` | every `v*` tag |
| OWASP ZAP baseline + API scan | manual, this assessment | 2026-10-18 (not yet in CI) |

**OpenSSF Scorecard:** 6.4/10 (2026-10-18). Branch protection requires the CI, cargo-deny, gitleaks
and CodeQL checks above (merge-blocking) and signed commits, but not reviews.
