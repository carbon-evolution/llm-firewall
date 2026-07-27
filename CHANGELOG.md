# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

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
