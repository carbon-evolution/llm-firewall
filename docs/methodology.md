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

We report against four recognized public corpora (all pulled by `./scripts/fetch-datasets.sh` from
the Hugging Face datasets-server REST API — standard library only, no `pip install datasets`):

- **`xTRam1/safe-guard-prompt-injection`** (test split, 2060 prompts, 650 inj / 1410 benign) — our
  largest and most representative prompt-injection set. Full system: **79.7% recall @ 0.2% FPR**.
- **`jackhhao/jailbreak-classification`** (test split, 262 prompts, 139 / 123) — jailbreak vs. benign.
  Full system: **74.1% recall @ 1.6% FPR**.
- **`deepset/prompt-injections`** (train+test, 662 prompts, 263 / 399) — its "injection" label is
  *broad*: it tags many roleplay, capability ("write SQL that…"), and non-English benign prompts as
  injection, so a strict injection detector shows conservative recall (38.8%). That is a property of
  the ground truth, not muted detection — verify classifier fidelity directly with
  `cargo run -p llm-firewall-core --features ml --release --example ml_probe` (unambiguous attacks
  score P(injection) ≈ 1.00, clean prompts ≈ 0.00).
- **`JailbreakBench/JBB-Behaviors`** (harmful split, 100 goals) — **out of scope**: it measures
  harmful-*content* requests, not prompt injection. Reported (0% recall) only for scope transparency;
  this firewall is not a content-moderation classifier.
- **Latency** is measured per-prompt on Apple Silicon CPU, single-threaded. The ML stage runs only
  when the cheap stages are inconclusive, so the default (rules-only) build stays in the microseconds.
