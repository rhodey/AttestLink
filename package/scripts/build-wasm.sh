#!/usr/bin/env bash
# Build the pinned verifier on Linux ARM64 and copy its browser module locally.
set -euo pipefail

if [[ $# -gt 1 ]]; then
    printf 'Usage: %s [OUTPUT_DIRECTORY]\n' "$0" >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
output=${1:-$repo/package/wasm}
store_path=$(nix build "$repo#attest-link-wasm" --no-link --print-out-paths --no-write-lock-file -L)
mkdir -p "$output"
install -m 0644 "$store_path/attest-link.js" "$output/attest-link.js"
printf 'Browser verifier: %s/attest-link.js\n' "$output"
