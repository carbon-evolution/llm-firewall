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
