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

- A default build of the proxy runs the rule layer (regex + heuristics) only; a build with
  `--features ml` also runs the DeBERTa classifier (`injection.ml`, see LLM01). A miss by the stage(s)
  you run is a known, documented recall limit (README benchmark), not a vulnerability on its own.
- Detection is probabilistic. No classifier is perfect; see `docs/methodology.md` and the README
  benchmark for measured recall and false-positive rates and their honest limits.
- The content-moderation layer is **not** a full safety system and makes no claim to detect illegal
  material (e.g. CSAM).
- `agentfw` fails open on internal errors by design (a hook that wedges the agent loop gets
  uninstalled); this is documented in the README and is not itself a vulnerability.

## Security assessment

*Assessed 2026-10-18 against commit `9d4039f` (`main`, after #22 and #23); findings since fixed are
marked ✅ with the PR that fixed them (#34, #35, and the scanning-coverage fix referred to as "this
PR"). Re-assess after major changes; the automated controls at the end run continuously.*

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
| LLM01 | Prompt Injection | 🟠 **Medium** |
| LLM02 | Sensitive Information Disclosure | 🟠 **Medium** |
| LLM03 | Supply Chain | 🟢 **Low** |
| LLM04 | Data and Model Poisoning | 🟠 **Medium** |
| LLM05 | Improper Output Handling | 🟢 **Low** |
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
| A06 | Insecure Design | 🟢 **Low** |
| A07 | Authentication Failures | 🟢 **Low** |
| A08 | Software or Data Integrity Failures | 🟠 **Medium** |
| A09 | Security Logging and Alerting Failures | 🟠 **Medium** |
| A10 | Mishandling of Exceptional Conditions | 🟠 **Medium** |

**Overall (both lists): 0 High, 12 Medium, 6 Low, 2 N/A** (originally 2 High / 12 Medium / 4 Low;
LLM01 and A06 re-rated to Medium after the streaming fix in #34 and the ML-wiring fix in #35; LLM05 and
A06 re-rated to Low after the scanning-coverage fix in this PR). The project's engineering hygiene is
strong — memory-safe Rust with two `unsafe` blocks, no open RustSec findings that reach the build,
SHA-pinned CI, signed release images, and an audit log that verifiably records no prompt text or
credentials. The two original High ratings were about the **security function itself** — streamed
replies were barely inspected (fixed in #34) and the proxy never loaded the DeBERTa classifier (fixed
in #35); the request/response shapes that were still forwarded uninspected are covered by this PR.
What remains Medium is mostly deployment posture (bind/auth defaults, TLS, timeouts and limits), model
supply chain, and reply-side masking. ZAP found no High or Medium issues (details under A02).

### LLM01 — Prompt Injection · 🟠 Medium

*(a) Protection*
- ✅ Three-stage detector exists (`crates/core/src/detectors/injection/`): regex signatures, heuristics,
  optional DeBERTa classifier. Policy `block-high-injection` / `block-ml-injection` blocks with HTTP 400
  before anything reaches the upstream (`policies/default.yaml`); verified on a classic override phrase.
- ✅ Normalization pre-pass (zero-width strip, NFKD + combining-mark strip + confusable folding; base64
  opt-in) is on by default. Verified: Cyrillic-homoglyph, zero-width-split, full-width and accented /
  combining-mark variants of a known phrase are blocked (combining marks found by fuzzing, fixed in this PR;
  no change in benign multilingual FPR).
  Benchmark (rule layer, safe-guard): obfuscated recall 0.0% → 14.5%, base64 0.0% → 30.6%, at 0.00% FPR
  on a multilingual benign control (README "Obfuscation resilience").
- ✅ OpenAI `role: "tool"` messages and the Anthropic `system` prompt are scanned as input.
- ✅ **The proxy attaches the ML classifier — fixed in #35.** *Was:*
  `build_firewall` never called `with_ml`, so even an `ml` build ran the rule layer only (README
  "Default" row: 1.9% / 23.7% / 14.6% recall) while the README implied the "+ ML" figures. *Now:* an `ml`
  build loads the classifier from `injection.ml.model_dir` (default `models/injection`, threshold
  `injection.ml.threshold`, default 0.5) and **refuses to start** if it is enabled but cannot load,
  unless `injection.ml.optional: true`; the startup log names the active stages. Verified with the real
  model: of the four probe classes that the rule layer forwarded, paraphrased and Spanish overrides are
  now blocked (400), benign controls pass. ⚠️ Residual: leetspeak and base64-wrapped instructions are
  still forwarded (classifier limit; base64 decoding is an opt-in normalizer tier), and **default
  builds — including release binaries and the Docker image — still run the rule layer only** (README
  now says so).
- ✅ **Indirect content and tool definitions are scanned — fixed in this PR.** *Was:* Anthropic
  `tool_result` (string or nested blocks) and `document` blocks were forwarded unscanned, so indirect
  injection via tool results was not covered on `/v1/messages` (contrary to the comment in
  `policies/default.yaml`); tool/function definitions were not scanned on either path; OpenAI
  content-part arrays were rejected with 422. *Now* (`crates/proxy/src/pipeline.rs`): Anthropic
  `tool_result` and `search_result` content (recursively), `document` blocks with `text`, `content` or
  base64 `text/*` sources (decoded, scanned, re-encoded if masked) plus their `title`/`context`, and on
  both endpoints every `description` in `tools[]` / `functions[]` (the tool's and those nested in its
  parameter schema) are scanned as `input` with the same detectors and policy as the prompt — the
  direction the pipeline already uses for retrieved and tool content. OpenAI content-part arrays are
  accepted: `text` parts are scanned and masked in place, image/audio parts forwarded unchanged; `tool`
  messages may use either form. Regression tests (`crates/proxy/tests/scan_coverage.rs`) cover each
  shape, with benign controls (realistic tool descriptions with imperative phrasing, tool results,
  documents) that must pass. ⚠️ Residual: documents and files the proxy cannot read as text (PDF, URL
  or file-id sources, OpenAI `file` parts) and images are forwarded uninspected by default —
  `input.reject_unscannable_documents: true` refuses them instead. In `ml` builds the classifier now
  also sees tool descriptions; its false-positive rate on that text has not been measured.
- ⚠️ Each message is scored independently, so a phrase split across consecutive messages is not
  matched.
- ⚠️ Known, documented ML limits that will apply once the classifier is wired in: deepset recall 41.4%
  (broad labels), JailbreakBench 0% (harmful goals, out of scope), base64 over-blocking on output
  (`docs/garak-validation.md`).

*(b) Exposure*
- ✅ The firewall has no model of its own on the request path, so it cannot be prompt-injected; the
  `agentfw` judge accepts only the two tokens `INJECTION`/`DOCUMENTATION` and may only tighten a verdict.

**Recommended:** consider an `ml` variant of the release image so the "+ ML" recall is available
without building from source; pin and checksum the model (LLM04); consider a joined-conversation
scan; measure the classifier's false-positive rate on tool descriptions.

LLM01 stays **Medium**: the request shapes are now covered, but default builds (release binaries,
Docker image) run the rule layer only, whose recall on paraphrased and multilingual injection is low.

### LLM02 — Sensitive Information Disclosure · 🟠 Medium

*(a) Protection*
- ✅ Input: AWS key ids, GitHub PATs, Slack tokens, JWTs, private-key headers and high-entropy tokens are
  detected (`crates/core/src/detectors/secret.rs`); an AWS key in a prompt scored 93 and was blocked by
  `block-high-risk`. Emails and card numbers are masked before forwarding — verified on the wire
  (`‹EMAIL›`, `‹CREDIT_CARD›`); a US-format phone number was not masked.
- ✅ Output: `block-secret-output` blocks a secret in a non-streamed reply (verified on both endpoints,
  HTTP 502).
- ✅ **Every output surface of a non-streamed reply is scanned — fixed in this PR.** *Was:* only
  `choices[0].message.content` (OpenAI) and text blocks (Anthropic) were scanned; secrets in further
  choices (`n > 1`), `tool_calls` arguments / `tool_use` input, or non-200 upstream bodies reached the
  client. *Now* non-streamed replies go through the same extraction as streams
  (`crates/proxy/src/stream.rs`, `scan_reply`): every choice's text and `refusal`, each
  `tool_calls[].function.arguments` and the legacy `function_call`, and every Anthropic content block
  (`text`, `tool_use` input serialised, `thinking`), each scanned as its own channel. Non-200 upstream
  bodies (streamed and non-streamed requests) are scanned on the output policy and replaced by the
  firewall's 502 error when they match; clean error bodies keep their status and content.
- ⚠️ PII masking applies to input only: `decide_output` acts on `block` alone, so `mask-pii` never
  redacts PII in a reply (reply-side masking depends on `crates/core/src/masking.rs`, being changed in
  a separate PR).
- ⚠️ No provider-specific patterns for OpenAI (`sk-…`) or Anthropic (`sk-ant-…`) keys; they rely on the
  generic entropy gate.

*(b) Exposure*
- ✅ The audit log records decision, score, reason labels, OWASP/ATLAS tags and latency only — verified
  over ~1,100 requests (ZAP + probes): no prompt text, no secret values, no `Authorization` header.
- ✅ Client credentials (`authorization`, `x-api-key`, vendor headers) are forwarded only to the
  configured upstream (`handlers.rs:88-112`); the proxy never stores or injects keys of its own.
- ⚠️ The listener is plain HTTP and binds `0.0.0.0` by default, so API keys cross the network in clear
  unless the proxy is a loopback sidecar or behind TLS (see A04).
- ✅ **Upstream failures return a generic error — fixed in this PR.** *Was:* with `fail_mode:
  fail_closed` the 502 body included the transport error, naming the internal upstream URL. *Now* the
  client gets `upstream error (fail_closed)` / `bad upstream body`; the detail is logged only.

**Recommended:** add output-side masking; add `sk-`/`sk-ant-` patterns.

LLM02 stays **Medium**: output coverage is closed, but replies are never masked (only blocked) and the
default plain-HTTP `0.0.0.0` listener exposes client keys in transit.

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
- ✅ Fuzzing: cargo-fuzz targets for request parsing, SSE streams, detectors/masking, policy YAML, agentfw hooks and MCP manifests run on PRs and weekly (`.github/workflows/fuzz.yml`, `docs/fuzzing.md`).
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
- ✅ A configured model that fails to load now refuses startup (injection classifier and output
  moderation), unless the block sets `optional: true` (fixed in #35).

**Recommended:** pin model revisions (commit SHA) and verify SHA-256 in `fetch-model.sh` and again at
load; keep the model directory read-only to the service user (read-only volume in containers).

### LLM05 — Improper Output Handling · 🟢 Low

*(a) Protection*
- ✅ `OutputDetector` (`crates/core/src/detectors/output.rs`) blocks destructive shell (`rm -rf`,
  pipe-to-shell), HTML/JS (`<script>`, event handlers) and markdown-image exfiltration in replies via
  `block-dangerous-output`; the phase 14 control check shows each artifact blocks at High/Critical.
- ✅ Injection rules are scoped to `direction: input` after phase 13 found they over-blocked 16% of
  legitimate security answers on replies (README "What this phase fixed").
- ✅ All output surfaces are inspected, streamed (#34) and non-streamed (this PR): every choice,
  tool-call arguments, Anthropic `tool_use` input and `thinking`, and non-200 error bodies (see LLM02).
  Behaviour note: a tool call whose arguments contain a dangerous artifact (e.g. a destructive shell
  command) is now refused in non-streamed replies too, as it already was in streams.
- ⚠️ Documented limit (phase 14 plan): harmful operational *prose* with no executable artifact is covered
  only by the opt-in moderation model, which caught 84.0% at threshold 0.8 with 0.0% over-block; the
  worst case scored 0.467 and evades at both 0.8 and 0.5.
- ✅ **Moderation `block` returns HTTP 502 — fixed in this PR.** *Was:* HTTP 200 with an error
  envelope, so clients that only check the status code treated it as success. *Now* it uses the same
  status and protocol-native error envelope as every other output block. (Streams end with the
  protocol's error event, unchanged.)

*(b) Exposure*
- ✅ The proxy never renders or executes model output; it forwards JSON/SSE verbatim.

**Recommended:** apply output `mask` actions to replies (LLM02).

Re-rated **Low** (was Medium): every output surface is now inspected on both paths and blocks are
unambiguous; what remains is the documented recall limit on artifact-free harmful prose.

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
  (`crates/proxy/src/config.rs`). (It now also covers streamed responses — see A06.) Out of the box the proxy
  enforces nothing at the tool boundary.
- ⚠️ Documented judge limit: an injection after the first 4 KB of a page is not seen
  (`max_span_bytes: 4096`).

*(b) Exposure*
- ✅ `agentfw` refuses non-loopback binds at parse time, requires a 256-bit bearer token compared in
  constant time, creates the token and audit log `0600`, caps body size and restricts the judge URL to
  loopback with exact host matching (`crates/agentfw/src/config.rs`, `token.rs`).
- ⚠️ `agentfw` fails open on internal errors and on bodies over the cap (by design, documented).

**Recommended:** document an "enforce" deployment profile;
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
provenance and SBOM; signed GitHub Releases with Sigstore bundles and build provenance (v0.3.0+);
cargo-fuzz targets on PRs and weekly. **OpenSSF Scorecard** remaining gaps: Code-Review 0 and Maintained 0
(single maintainer, new repository), CII Best Practices 0, Vulnerabilities 6 (the 4 documented `ml`-feature
ignores explained under LLM03), SAST 7 (CodeQL only recently added).

**Recommended:** apply for the OpenSSF Best Practices badge.

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

### A06 — Insecure Design · 🟢 Low

The assessment found design-level gaps where traffic passed without the inspection the documentation
described, each reproduced against the release build with a mock upstream. All are now closed.
- ✅ **Streamed output is inspected on the reassembled text — fixed in #34.**
  *Was:* the SSE scanner matched raw upstream bytes (JSON frames included) in a 256-byte tail window and
  forwarded each chunk right after its scan, so a secret split across delta frames reached the client;
  moderation and agent inspection did not run on streams. *Now* (`crates/proxy/src/stream.rs`): SSE
  events are parsed incrementally; reply text, tool-call arguments (OpenAI `delta.tool_calls`,
  Anthropic `input_json_delta`) and thinking are reassembled per choice / content block and scanned
  with the same output policy as non-streamed replies; an event is released only once its text is
  `stream_holdback_bytes` (default 256) older than the newest text and has been scanned in context, so
  no part of a match up to that length is ever sent; each channel gets a full scan when it finishes.
  A block ends the stream with a protocol-native error event and drops the upstream. Agent inspection
  runs on the reassembled tool calls (held until the verdict when enforcing) and output moderation on
  the reassembled reply (streams held in full when `action: block`). Regression tests: split AWS key
  over 3+ OpenAI / Anthropic delta frames, split tool-call arguments, clean byte-for-byte passthrough.
  Residual: a match longer than the hold-back (e.g. a risk score that only crosses the threshold over
  the whole reply) is caught at the channel's final scan, after its start may have been released;
  output `mask` actions are not applied to replies (same as non-streamed, LLM02).
- ✅ **ML stage wired into the proxy, fail-closed** (LLM01; fixed in #35). With the streaming fix
  (#34) both High items were closed and A06 was re-rated Medium.
- ✅ **Full response inspection — fixed in this PR.** Non-streamed replies share the stream path's
  extraction, so both paths inspect the same surfaces: every choice, tool-call arguments, Anthropic
  `tool_use` / `thinking` blocks; non-200 bodies are scanned too (LLM02).
- ✅ **Full request inspection — fixed in this PR.** Anthropic `tool_result` / `search_result` /
  text `document` content, tool definitions on both endpoints, and OpenAI content-part arrays (now
  accepted instead of 422) are scanned as input (LLM01). "Every text-bearing field is inspected" is
  pinned by per-shape regression tests with benign controls (`crates/proxy/tests/scan_coverage.rs`).
  Residual (documented, opt-in refusal): content that is not text — PDF/URL/file document sources,
  OpenAI `file` parts, images — is forwarded uninspected unless `input.reject_unscannable_documents`.
  A06 is re-rated **Low**.
- ✅ Good design elsewhere: fail-closed default, dual-scan normalization (obfuscation alone is never a
  block reason), direction-scoped policies, tighten-only judge, shadow-first rollout of new enforcement.

**Recommended:** extend the per-shape tests whenever the providers add a text-bearing field; consider
turning `reject_unscannable_documents` on in hardened profiles.

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
- ✅ Streaming requests now get the same input audit record as non-streaming ones, written before the
  stream starts, plus an output `stream_done` / `stream_error` / `block` record (fixed in #34).
- ✅ **Rejections and upstream errors are audited — fixed in this PR.** Request bodies the proxy
  cannot accept (400 malformed JSON, 413, 415, 422) get an input `reject` record (status only — never
  the serde message, which can quote request content); every forwarded request gets its input `allow`
  record before forwarding; non-200 upstream replies and transport failures get an output
  `upstream_error` record with the status, or `block` when the error body was refused. (Unknown routes
  and wrong methods — 404/405 — are still not audited.)
- ⚠️ Records carry no client identity (address or key fingerprint), the `req-N` counter restarts with the
  process and is not returned to the client, and there is no metrics/alerting hook.

**Recommended:** add a client
identifier (hashed key or address), a UUID request id echoed in a response header, and counters for
blocks by rule.

### A10 — Mishandling of Exceptional Conditions · 🟠 Medium

- ✅ Upstream failure → **502 fail-closed** (non-streaming and streaming); malformed JSON → 400; schema
  errors → 422; no panics observed under ZAP or probes; `unwrap`/`expect` on the request path are
  limited to a static response builder and the agent mutex.
- ✅ Upstream-failure bodies are generic and use the endpoint's own error envelope; the detail, which
  names the upstream URL, is logged only (LLM02; fixed in this PR).
- ⚠️ `fail_mode: fail_open` does not change behaviour beyond the error text (both modes return 502), so
  the option is misleading.
- ✅ An enabled model (injection ML or output moderation) that cannot load refuses startup instead of
  silently disabling itself, unless `optional: true` (fixed in #35).
- ⚠️ The proxy's agent mutex uses `lock().expect(…)` (`handlers.rs:46`): after any panic while held, every
  later inspected request panics (only when `agent_inspection.enabled`).
- ⚠️ No timeouts (LLM10).

**Recommended:** implement or remove `fail_open`; recover from a poisoned mutex or use `parking_lot`.

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
