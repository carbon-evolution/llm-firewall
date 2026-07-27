# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub's **[Report a vulnerability](https://github.com/carbon-evolution/llm-firewall/security/advisories/new)**
(Security → Advisories) rather than opening a public issue. Include steps to reproduce and, where
possible, a proof of concept. We aim to acknowledge reports within a few days.

## Scope

This project is a **defensive** tool — a firewall for LLM traffic. Relevant reports include:

- Detection **bypasses** (a prompt-injection / secret / PII / harmful-content payload that evades a
  detector it should catch), with a concrete example.
- **Over-defense** regressions (benign inputs wrongly blocked) that materially raise the false-positive
  rate.
- Memory-safety, denial-of-service, or request-smuggling issues in the proxy.

## Out of scope / by design

- The default build is regex + heuristics only; higher recall requires the optional `--features ml`
  stage. A "miss" that the ML stage catches is a documented tradeoff, not a vulnerability.
- Detection is probabilistic. No classifier is perfect; see `docs/methodology.md` for measured recall
  and false-positive rates and their honest limits.
- The content-moderation layer is **not** a full safety system and makes no claim to detect illegal
  material (e.g. CSAM).
