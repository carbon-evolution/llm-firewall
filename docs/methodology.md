# Benchmark methodology (fairness rules)

- **Same corpora, same labels** for every guard (ours + rivals), loaded from `datasets/*.jsonl`.
- **Two headline metrics**, always reported together: malicious accuracy (recall on attacks) and
  over-defense FPR (false positives on benign sets like NotInject). One without the other is not a
  valid comparison.
- **Rivals run isolated**: each Python rival in its own venv, warmed once before timing.
- **Same hardware / same process invocation overhead**; subprocess startup is included for all
  subprocess-based guards so latency is apples-to-apples (or noted when it isn't).
- **Missing rival = visible under-count**, never a silent skip: if a rival isn't installed the
  adapter emits benign, which *lowers* its measured recall rather than inflating ours.
- **Published numbers** for guards we don't re-run (e.g. Lakera) are cited with source + date, and
  clearly separated from numbers we measured locally.

## Corpus notes

- **`deepset/prompt-injections`** (662 prompts, 263 injection / 399 benign; train+test merged) is
  our primary corpus because a single labeled set carries both classes, yielding both headline
  metrics at once. Its "injection" label is *broad* — it tags many roleplay, capability
  ("write SQL that…"), and non-English benign prompts as injection. A signature/heuristic filter or
  a strict injection classifier will therefore show conservative recall against it; that is a
  property of the ground truth, not muted detection. We verify classifier fidelity separately
  (`cargo run -p llm-firewall-core --features ml --release --example ml_probe`): unambiguous attacks
  score P(injection) ≈ 1.00 and clean prompts ≈ 0.00.
- **Reproduce:** `./scripts/fetch-datasets.sh` regenerates the corpus from the Hugging Face
  datasets-server REST API (standard library only — no `pip install datasets`).
