#!/usr/bin/env bash
# Print GitHub Release notes for a tag: the matching CHANGELOG.md section (without
# its heading) followed by a pointer to the verification instructions.
# Used by .github/workflows/release.yml; runnable locally:
#   scripts/release-notes.sh v0.3.0 carbon-evolution/llm-firewall
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <tag e.g. v0.3.0> <owner/repo>" >&2
  exit 2
fi

tag="$1"
repo="$2"
version="${tag#v}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

section="$(awk -v v="${version}" '
  index($0, "## [" v "]") == 1 { on = 1; next }
  on && /^## \[/ { exit }
  on && /^\[[^]]+\]: / { exit }
  on && !body && /^[[:space:]]*$/ { next }
  on { body = 1; print }
' "${root}/CHANGELOG.md")"

if [ -z "$(printf '%s' "${section}" | tr -d '[:space:]')" ]; then
  echo "warning: no CHANGELOG.md section for ${version}" >&2
else
  printf '%s\n\n' "${section}"
fi

cat <<EOF
### Verifying this release

Every archive, SBOM and \`SHA256SUMS\` has a keyless Sigstore signature bundle
(\`<file>.sigstore.json\`), and \`llm-firewall-${tag}.intoto.jsonl\` is SLSA build provenance for
the archives and SBOMs. The container image \`ghcr.io/${repo}:${version}\` is signed the same way.
See [Verifying a release](https://github.com/${repo}#verifying-a-release) for the commands.
EOF
