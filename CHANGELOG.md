# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- **MCP manifest pins use an unambiguous v2 hash** (`v2:` + SHA-256 over length-prefixed fields). The
  old NUL-separated hash let two different manifests be crafted to collide (found by fuzzing). Existing
  pins keep working: a legacy pin is compared with the legacy hash and silently re-pinned as v2 on the
  next handshake, so upgrading raises no false drift alerts.
- **Normalization strips combining marks** before confusable folding, so accented look-alikes
  ("ígnore") no longer evade the keyword detectors (found by fuzzing).

## [0.3.0] - 2026-10-18

The agent firewall: inspection of agent tool calls (Claude Code hooks, MCP, and tool blocks in
API traffic), plus output moderation, and the first signed release.

### Added
- **Agent firewall library** (`llm-firewall-agent`): one `AgentEvent` schema, facet projection
  into the existing detectors, winnowed fingerprinting, taint tracking, action classification,
  egress extraction, subagent authority containment, and an agent policy engine returning
  `Allow` / `Ask` / `Deny`.
- **`agentfw` daemon**: `agentfw serve` wired into Claude Code's native hooks, `agentfw install`,
  `agentfw replay`; ships in shadow mode.
- **Local-model judge tier**: an `escalate` policy action with a required `fallback` that asks a
  loopback-only local model one narrow question, and may only tighten a verdict. Off by default.
- **MCP supply-chain collector**: `agentfw mcp` stdio proxy pinning each server's tool manifest
  and catching manifest drift, tool-name shadowing, and description poisoning. Off by default.
- **API collector**: the proxy inspects `tool_use` / `tool_result` blocks in OpenAI/Anthropic
  traffic (`agent_inspection` config block, off by default, shadow-first).
- **Output moderation** in the proxy (`output_moderation` config block): harmful replies flagged
  or refused regardless of backend. Off by default, `flag` before `block`.
- **Benchmarks**: agent-attack corpus and `--agent` scorecard mode; `--direction` and
  `--moderation-threshold` for output-path measurement.
- **Release artifacts**: prebuilt `llm-firewall` + `agentfw` archives for Linux (x86_64,
  aarch64) and macOS (x86_64, arm64), with `SHA256SUMS`, keyless Sigstore signature bundles,
  SLSA build provenance (GitHub artifact attestation) and CycloneDX SBOMs. See "Verifying a release" in the README.

### Fixed
- Injection policy rules are now scoped to the input path, so they no longer run on (and
  over-block) model replies.

### Security
- Dependency advisories resolved (h2, rustls, unsafe-libyaml).
- CI hardening: SHA-pinned actions, cargo-deny, gitleaks, CodeQL, ClamAV, OpenSSF Scorecard, and
  keyless-signed container images with SLSA provenance and SBOM attestations.

## [0.2.0] - 2026-07-28

Obfuscation / evasion resilience — a normalization pre-pass so attacks hidden by
zero-width characters, Unicode homoglyphs, or base64 are still caught.

### Added
- **Dual-scan normalization** (`llm-firewall-core::normalize`): the firewall now scans a
  de-obfuscated *copy* of the text with the same injection / secret / PII detectors, then
  merges findings. The original text is still what gets forwarded and masked, and
  **obfuscation alone is never a block reason — only a decoded attack is.**
  - Tier 1: strip zero-width & bidi control characters (Trojan-Source class, CVE-2021-42574).
  - Tier 2: NFKC fold + curated Unicode-confusable (UTS #39) Cyrillic/Greek → ASCII mapping.
  - Tier 3 (opt-in): decode base64-looking segments and append the payload for scanning.
- Proxy config `normalize` block (`enabled`, `strip_zero_width`, `fold_homoglyphs`,
  `decode_encoded`; zero-width + homoglyph on by default, base64 opt-in).
- Benchmark flags `--no-normalize` and `--normalize-base64`, plus
  `scripts/obfuscate-dataset.py` to transform malicious rows for obfuscation-resilience runs.

### Validation
- Offline rule-layer benchmark: obfuscated-attack recall 0.0% → 14.5% (base64 0.0% → 30.6%)
  with 0.00% FPR on a multilingual benign control.
- External check with NVIDIA garak `encoding.InjectBase64` (see `docs/garak-validation.md`).

## [0.1.0] - 2026-07-27

First public release — a pure-Rust firewall for LLMs (OpenAI-compatible + native Anthropic
reverse proxy) with a standardized head-to-head benchmark.

### Detection
- Prompt-injection / jailbreak detection: regex signatures + heuristics + optional DeBERTa ML stage.
- Secret detection (provider patterns + high-entropy gate) and PII detection + masking.
- Improper output handling (OWASP LLM05): dangerous shell / HTML-JS / markdown data-exfiltration.
- Content moderation (Trust & Safety): optional harmful-content classifier (opt-in).
- Weighted, diminishing-returns (noisy-OR) 0–100 risk score.
- Flat first-match YAML policy engine: allow / mask / block / flag, scoped by direction.

### Proxy
- OpenAI `/v1/chat/completions` and native Anthropic `/v1/messages`, with header propagation.
- SSE streaming via verbatim byte passthrough with a sliding-window output scan.
- Structured JSON audit log with OWASP LLM Top 10 (2025) + MITRE ATLAS tags per request.

### Benchmark & standards
- Head-to-head harness reporting **malicious accuracy AND over-defense FPR** on four public corpora.
  Full system (+ML): safe-guard 84.3% @ 0.2% FPR, jailbreak 85.6% @ 1.6%, deepset 41.4% @ 1.0%;
  content moderation lifts JailbreakBench 0% → 58%.
- OWASP LLM Top 10 (2025) coverage/risk report (`--report`).

### Deploy
- Multi-stage Dockerfile and Kubernetes sidecar manifest.

[0.3.0]: https://github.com/carbon-evolution/llm-firewall/releases/tag/v0.3.0
[0.2.0]: https://github.com/carbon-evolution/llm-firewall/releases/tag/v0.2.0
[0.1.0]: https://github.com/carbon-evolution/llm-firewall/releases/tag/v0.1.0
