# Contributing

Thanks for your interest in the LLM Firewall!

## Development

```bash
# build + test the whole workspace
cargo test --all

# lint + format (both are enforced in CI)
cargo clippy --all-targets -- -D warnings
cargo fmt --all

# optional ML stage (pulls candle; needs a fetched model)
./scripts/fetch-model.sh injection
cargo test -p llm-firewall-core --features ml -- --ignored
```

## Ground rules

- **Both build modes must stay green:** default (regex + heuristics) *and* `--features ml`.
- `cargo clippy -D warnings` and `cargo fmt --check` must pass.
- New detectors live in `crates/core/src/detectors/`, are unit-tested in isolation, and return
  `Finding`s (never bare bools) so scoring, masking, policy, and the audit log all work.
- Tag findings with their OWASP/MITRE mapping via `crates/core/src/taxonomy.rs` when applicable.
- Keep the benchmark honest: report **malicious accuracy AND over-defense FPR** together
  (see `docs/methodology.md`).

## Pull requests

- Keep PRs focused. Describe the change and how you verified it.
- Include tests for new behavior.
- Commits are squashed or merged as-is; keep messages clear.
