#!/usr/bin/env bash
# Package already-built release binaries for one target into
#   <out-dir>/llm-firewall-<tag>-<target>.tar.gz
# containing a single top-level directory with the binaries, the default
# config + policies, and the licence/readme/changelog.
#
# Used by .github/workflows/release.yml; runnable locally:
#   cargo build --release --locked --target <target> -p llm-firewall -p agentfw
#   scripts/package-release.sh v0.3.0 <target> dist
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <tag e.g. v0.3.0> <rust target triple> [out-dir, default dist]" >&2
  exit 2
fi

tag="$1"
target="$2"
out_dir="${3:-dist}"
bins=(llm-firewall agentfw)

case "${tag}" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "error: tag '${tag}' is not of the form vX.Y.Z" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir="${root}/target/${target}/release"
name="llm-firewall-${tag}-${target}"

mkdir -p "${out_dir}"
out_dir="$(cd "${out_dir}" && pwd)"
staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT

mkdir -p "${staging}/${name}"
for bin in "${bins[@]}"; do
  if [ ! -x "${release_dir}/${bin}" ]; then
    echo "error: ${release_dir}/${bin} not found; build it first" >&2
    exit 1
  fi
  cp "${release_dir}/${bin}" "${staging}/${name}/"
done
cp "${root}/LICENSE" "${root}/README.md" "${root}/CHANGELOG.md" "${root}/firewall.yaml" \
  "${staging}/${name}/"
cp -R "${root}/policies" "${staging}/${name}/policies"

# gzip -n: no name/timestamp in the gzip header.
(cd "${staging}" && tar -cf - "${name}" | gzip -9n > "${out_dir}/${name}.tar.gz")
echo "${out_dir}/${name}.tar.gz"
