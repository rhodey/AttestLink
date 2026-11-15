#!/usr/bin/env bash
# Build and compare exactly two portable Linux helpers, then collect the result.
#   bash package/scripts/build-linux.sh [OUTPUT_DIRECTORY]
set -euo pipefail

[[ $(uname -s) == Linux ]] || { echo 'Run on the Linux release builder.' >&2; exit 1; }
case "$(uname -m)" in
    aarch64) platform=linux-arm64 ;;
    x86_64) platform=linux-x64 ;;
    *) echo 'Expected ARM64 or x86-64 Linux.' >&2; exit 1 ;;
esac
[[ $# -le 1 ]] || { echo 'Expected at most one output directory.' >&2; exit 1; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output=${1:-"$root/package/bin/$platform"}
mkdir -p "$output"
output=$(realpath "$output")

build_tmp=$(mktemp -d /tmp/attest-link-linux-build.XXXXXXXX)
trap 'rm -rf -- "$build_tmp"' EXIT
target="$root#attest-link-rust-static"
# The flake selects only Rust, musl and OpenSSL here, even on the Nitro builder.
# A single core/job keeps the release build suitable for a medium EC2 instance.
nix build "$target" --no-write-lock-file --no-link --json -L \
    --cores 1 --max-jobs 1 >"$build_tmp/first.json"
result=$(jq -er '.[0].outputs.out' "$build_tmp/first.json")
first_hash=$(sha256sum "$result/bin/attest-link-rust" | cut -d ' ' -f 1)
first_nar=$(nix hash path "$result")

# Nix also compares the entire derivation output and fails on a mismatch.
nix build "$target" --no-write-lock-file --no-link --rebuild -L \
    --cores 1 --max-jobs 1
second_hash=$(sha256sum "$result/bin/attest-link-rust" | cut -d ' ' -f 1)
[[ $first_hash == "$second_hash" && $first_nar == "$(nix hash path "$result")" ]]

install -m 0755 "$result/bin/attest-link-rust" "$output/attest-link-rust"
install -m 0644 "$result/share/licenses/OpenSSL.txt" "$output/OpenSSL.txt"
derivation=$(jq -er '.[0].drvPath' "$build_tmp/first.json")
nix derivation show "$derivation" >"$output/derivation.json"
jq -n --arg platform "$platform" --arg nix "$(nix --version)" \
    --arg derivation "$derivation" --arg output "$result" \
    --arg sha256 "$first_hash" --arg narHash "$first_nar" \
    '{platform: $platform, nix: $nix, derivation: $derivation, output: $output,
      sha256: $sha256, narHash: $narHash, builds: 2, matched: true,
      linkage: "static musl (ELF interpreter and shared dependencies rejected during build)"}' \
    >"$output/build.json"
cat "$output/build.json"
