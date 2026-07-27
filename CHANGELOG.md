# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/carbon-evolution/llm-firewall/releases/tag/v0.1.0
