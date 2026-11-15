#!/usr/bin/env bash
# Qualify the Nitro Sandbox build on Linux ARM64:
#   bash nitro/scripts/reproduce.sh PUBLIC_KEY_FILE NEW_OUTPUT_DIRECTORY
#
# The output directory must be outside this checkout. It contains an image
# symlink, artifact hashes, manifests, exact input records and rebuild logs.
#
# After obtaining a baseline, ONE forced rebuild pass compiles the custom
# kernel/helpers and rebuilds the npm package and image in fresh Nix sandboxes.
# Nix --rebuild compares complete outputs against their original store objects;
# merely downloading or repacking the same cached kernel does not pass this test.
#
# Scope: this is repeatability on one Linux ARM64 host with pinned foundational
# dependencies. Node, OpenSSH, OpenSSL, the compiler/stdenv, and npm-supplied
# libsodium JS/WASM artifacts can be reused from the cache. They are NOT source-rebuilt
# here. The report records their versions/paths and the locked npm dependencies.
# This script does not launch a Sandbox or establish hardware attestation validity.
set -euo pipefail
umask 077

die() { printf 'reproduce.sh: %s\n' "$*" >&2; exit 1; }
if [[ $# != 2 || ${1:-} == --help ]]; then
    printf 'Usage: %s PUBLIC_KEY_FILE NEW_OUTPUT_DIRECTORY\n' "$0" >&2
    exit 2
fi
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] || die 'Run on Linux ARM64.'
for utility in nix jq ssh-keygen realpath sha256sum cmp install mktemp; do
    command -v "$utility" >/dev/null || die "Missing command: $utility"
done

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
public_key=$(realpath -e -- "$1")
output=$(realpath -m -- "$2")
[[ $output != "$repo" && $output != "$repo/"* ]] || die 'Put the report directory outside the checkout.'
[[ ! -e $output && ! -L $output ]] || die 'Use a new output directory; existing evidence is never overwritten.'
[[ -f $public_key ]] || die 'Public key file not found.'
awk 'NF && $1 !~ /^#/ { if ($1 !~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$/ || NF < 2) exit 1; n++ } END { if (n != 1) exit 1 }' \
    "$public_key" || die 'Expected exactly one ordinary SSH public key; never supply a private key.'
ssh-keygen -l -f "$public_key" >/dev/null
mkdir -p -- "$(dirname -- "$output")"
mkdir -- "$output"
mkdir -- "$output/logs"

repro_tmp=$(mktemp -d)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
stage=initialization
cleanup() {
    local code=$?
    trap - EXIT
    rm -rf -- "$repro_tmp"
    if [[ $code != 0 ]]; then
        jq -n --arg stage "$stage" --argjson exitCode "$code" \
            '{passed: false, failedStage: $stage, exitCode: $exitCode}' >"$output/status.json"
        printf 'Qualification failed at %s; evidence retained in %s\n' "$stage" "$output" >&2
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_logged() {
    stage=$1
    shift
    local logfile="$output/logs/$stage.log"
    local beginning
    beginning=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\n' "Running $stage (log: $logfile)"
    { printf 'Command:'; printf ' %q' "$@"; printf '\n'; } >"$logfile"
    if "$@" >>"$logfile" 2>&1; then
        jq -cn --arg stage "$stage" --arg start "$beginning" --arg end "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            '{stage: $stage, passed: true, startedAt: $start, finishedAt: $end}' >>"$output/steps.jsonl"
    else
        local code=$?
        tail -n 60 "$logfile" >&2
        return "$code"
    fi
}

nix --version >"$output/nix-version.txt"
# Configuration may contain private cache credentials; retain only build settings.
nix config show --json | jq '{
    sandbox: .sandbox,
    system: .system,
    cores: .cores,
    "max-jobs": ."max-jobs",
    "experimental-features": ."experimental-features",
    "require-sigs": ."require-sigs"
}' >"$output/nix-config.json"
jq -e '.sandbox.value == true' "$output/nix-config.json" >/dev/null ||
    die 'This qualification requires sandboxed Nix builds.'
ssh-keygen -l -f "$public_key" >"$output/public-key-fingerprint.txt"

mkdir "$repro_tmp/ssh-keys"
install -m 0644 "$public_key" "$repro_tmp/ssh-keys/authorized_keys"
flake_options=(--override-input ssh-keys "path:$repro_tmp/ssh-keys" --no-write-lock-file)

# Archive once so edits to the checkout cannot change the source between passes.
# Use Nix's normal Git-aware lookup, which excludes ignored/untracked identities.
stage=archive-inputs
nix flake archive --json "$repo" "${flake_options[@]}" >"$output/flake-archive.json"
source_snapshot=$(jq -er .path "$output/flake-archive.json")
key_snapshot=$(jq -er '.inputs["ssh-keys"].path' "$output/flake-archive.json")
nixpkgs_snapshot=$(jq -er '.inputs.nixpkgs.path' "$output/flake-archive.json")
flake_options=(--override-input ssh-keys "path:$key_snapshot" --no-write-lock-file)
nix flake metadata --json "$source_snapshot" "${flake_options[@]}" >"$output/flake-metadata.json"
nix hash path "$source_snapshot" >"$output/source-nar-hash.txt"
cp "$source_snapshot/flake.lock" "$output/flake.lock"
cp "$source_snapshot/package/package-lock.json" "$output/package-lock.json"

build_options=("${flake_options[@]}" --keep-failed --log-format raw -L)
run_logged baseline-image nix build "$source_snapshot#nitro-sandbox" \
    --out-link "$output/image" "${build_options[@]}"
image_path=$(realpath -e "$output/image")

snapshot_artifacts() {
    local name=$1
    mkdir "$output/$name"
    (cd "$image_path"; sha256sum Image initramfs.cpio.gz image.eif) >"$output/$name/SHA256SUMS"
    cp "$image_path/measurements.json" "$output/$name/measurements.json"
    # Retain the independently generated manifest's expected hashes and verify
    # that it refers to the actual bytes being qualified.
    jq -e '.sha256.kernel and .sha256.initramfs and .sha256.eif' "$image_path/measurements.json" >/dev/null
    local kernel_hash initramfs_hash image_hash
    read -r kernel_hash _ < <(sha256sum "$image_path/Image")
    read -r initramfs_hash _ < <(sha256sum "$image_path/initramfs.cpio.gz")
    read -r image_hash _ < <(sha256sum "$image_path/image.eif")
    jq -e --arg kernel "$kernel_hash" --arg initramfs "$initramfs_hash" --arg eif "$image_hash" \
        '.sha256.kernel == $kernel and .sha256.initramfs == $initramfs and .sha256.eif == $eif' \
        "$image_path/measurements.json" >/dev/null || die 'Image manifest does not match the artifact bytes.'
}
snapshot_artifacts baseline

components=(nitro-sandbox-kernel attest-link-rust attest-link-wasm attest-link nitro-eif nitro-sandbox)
: >"$output/components.jsonl"
for component in "${components[@]}"; do
    component_path=$(nix eval --raw "$source_snapshot#packages.aarch64-linux.$component.outPath" "${flake_options[@]}")
    jq -cn --arg name "$component" --arg path "$component_path" '{name: $name, path: $path}' >>"$output/components.jsonl"
done

for component in "${components[@]}"; do
    run_logged "pass-1-$component" nix build "$source_snapshot#$component" \
        --rebuild --no-link "${build_options[@]}"
done
stage=compare-pass-1
snapshot_artifacts pass-1
cmp "$output/baseline/SHA256SUMS" "$output/pass-1/SHA256SUMS"
cmp "$output/baseline/measurements.json" "$output/pass-1/measurements.json"

# This expression evaluates metadata only, from the already archived Nixpkgs
# source. --impure permits importing that explicit store path; builds above use
# the locked flake and never enable impure evaluation.
stage=record-foundations
cat >"$repro_tmp/foundations.nix" <<'EOF'
{ source, project }:
let
  pkgs = import (builtins.toPath source) { system = "aarch64-linux"; };
  describe = package: { version = package.version or "unspecified"; path = toString package; };
in builtins.mapAttrs (_: describe) {
  node = pkgs.callPackage (builtins.toPath (project + "/nix/nodejs.nix")) {};
  openssh = pkgs.openssh;
  openssl = pkgs.openssl;
  busybox = pkgs.busybox;
  chrony = pkgs.chrony;
  dnsproxy = pkgs.dnsproxy;
  cacert = pkgs.cacert;
  stdenv = pkgs.stdenv;
  compiler = pkgs.stdenv.cc;
  rustc = pkgs.rustc;
  cargo = pkgs.cargo;
  cpio = pkgs.cpio;
  gzip = pkgs.gzip;
}
EOF
NITRO_SANDBOX_REPRO_NIXPKGS="$nixpkgs_snapshot" NITRO_SANDBOX_REPRO_PROJECT="$source_snapshot" nix eval --impure --json \
    --file "$repro_tmp/foundations.nix" \
    --apply 'f: f { source = builtins.getEnv "NITRO_SANDBOX_REPRO_NIXPKGS"; project = builtins.getEnv "NITRO_SANDBOX_REPRO_PROJECT"; }' \
    >"$output/foundations.json"
mapfile -t foundation_paths < <(jq -r '.[].path' "$output/foundations.json")
mapfile -t component_paths < <(jq -r .path "$output/components.jsonl")
nix path-info --recursive --json "${foundation_paths[@]}" "${component_paths[@]}" >"$output/store-closure.json"

stage=report
jq -n --arg start "$started_at" --arg end "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg kernel "$(uname -r)" --arg source "$source_snapshot" --arg image "$image_path" \
    --slurpfile manifests "$output/baseline/measurements.json" \
    --slurpfile components "$output/components.jsonl" \
    --slurpfile steps "$output/steps.jsonl" \
    --slurpfile foundations "$output/foundations.json" '{
      passed: true,
      startedAt: $start,
      finishedAt: $end,
      system: "aarch64-linux",
      hostKernel: $kernel,
      sourceSnapshot: $source,
      imagePath: $image,
      totalBuilds: 2,
      forcedRebuildPasses: 1,
      comparison: "Nix full-output equality plus byte-identical kernel/initramfs/EIF hashes and manifest",
      components: $components,
      steps: $steps,
      artifacts: $manifests[0],
      foundations: $foundations[0],
      limits: [
        "A baseline and one forced rebuild in fresh Nix build sandboxes on the same Linux ARM64 host; not a second-host reproduction.",
        "Pinned foundational packages and npm JS/WASM artifacts may be cached; Node, OpenSSH, OpenSSL, compiler/stdenv and libsodium dependencies were not independently source-rebuilt.",
        "The npm package is rebuilt from the locked dependency output; package-lock.json records those exact dependencies.",
        "No Sandbox launch or hardware attestation check is performed by this script."
      ]
    }' >"$output/report.json"
printf '{"passed":true}\n' >"$output/status.json"
printf '\nRebuild qualification passed. Report: %s/report.json\n' "$output"
cat "$output/baseline/SHA256SUMS"
