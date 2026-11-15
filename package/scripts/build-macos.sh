#!/usr/bin/env bash
# Build the macOS helper twice with pinned tools and compare the executables.
set -euo pipefail

if [[ $# -gt 2 ]]; then
    printf 'Usage: %s [OUTPUT_DIRECTORY] [WORK_DIRECTORY]\n' "$0" >&2
    exit 2
fi
[[ $(uname -sm) == 'Darwin arm64' ]] || { echo 'Build on an Apple Silicon Mac.' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
output=${1:-$repo/package/bin/darwin-arm64}
work=${2:-$(mktemp -d "${TMPDIR:-/tmp}/attest-link-macos.XXXXXX")}
mkdir -p "$work" "$output"
work=$(cd "$work" && pwd)
[[ ! -e $work/source ]] || { echo 'Use a fresh work directory.' >&2; exit 1; }

# Install with: rustup toolchain install 1.94.0 --profile minimal
# Xcode provides both the compiler and SDK. Update these pins deliberately.
export RUSTUP_TOOLCHAIN=1.94.0
export MACOSX_DEPLOYMENT_TARGET=13.5
export SOURCE_DATE_EPOCH=1
export ZERO_AR_DATE=1
export CARGO_PROFILE_RELEASE_STRIP=none
export LC_ALL=C
export TZ=UTC
[[ $(rustc --version) == 'rustc 1.94.0 (4a4ef493e 2026-03-02)' ]]
[[ $(xcrun --show-sdk-version) == 27.2 ]]
[[ $(xcodebuild -version) == $'Xcode 27.2\nBuild version 27B52' ]]
[[ $(xcrun clang --version | head -n 1) == 'Apple clang version 21.0.0 (clang-2100.4.1.1)' ]]
export SDKROOT
SDKROOT=$(xcrun --show-sdk-path)
export CC
CC=$(xcrun --find clang)
export AR
AR=$(xcrun --find ar)
export RANLIB
RANLIB=$(xcrun --find ranlib)
export CFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
export OPENSSL_STATIC=1
export OPENSSL_NO_VENDOR=0

# Copy only crate inputs, never target/, credentials or unrelated local files.
mkdir "$work/source"
cp "$repo/rust/"{Cargo.toml,Cargo.lock,root.pem,LICENSE} "$work/source/"
cp -R "$repo/rust/src" "$repo/rust/tests" "$work/source/"
cargo fetch --locked --manifest-path "$work/source/Cargo.toml"
export CARGO_BUILD_JOBS=${ATTEST_LINK_BUILD_JOBS:-$(sysctl -n hw.ncpu)}

# openssl-src embeds its installation path. Use one fixed, freshly created Cargo
# target directory and clean it between builds. Only one release build may own it.
build_root=/private/tmp/attest-link-macos-build
mkdir "$build_root" || { echo "Build directory already exists: $build_root" >&2; exit 1; }
trap 'rm -rf -- "$build_root"' EXIT
export CARGO_TARGET_DIR="$build_root/target"
mkdir "$CARGO_TARGET_DIR"

for build in first second; do
    mkdir "$work/$build"
    # Rust's LLVM strip can misalign proc-macro dylibs on macOS 27. Keep it off
    # and let Xcode's linker strip debug/local symbols before deriving the UUID.
    export RUSTFLAGS="--remap-path-prefix=$work=/build -C link-arg=-Wl,-S,-x,-reproducible"
    cargo build --manifest-path "$work/source/Cargo.toml" --locked --offline \
        --release --target aarch64-apple-darwin --bin attest-link-rust \
        >"$work/$build/rust.log" 2>&1
    cp "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/attest-link-rust" "$work/$build/attest-link-rust"
    if [[ $build == first ]]; then
        cargo test --manifest-path "$work/source/Cargo.toml" --locked --offline --release \
            --target aarch64-apple-darwin >"$work/rust-tests.log" 2>&1
        rm -rf -- "$CARGO_TARGET_DIR"
        mkdir "$CARGO_TARGET_DIR"
    fi
done

cmp "$work/first/attest-link-rust" "$work/second/attest-link-rust"
otool -L "$work/first/attest-link-rust" >"$work/dynamic-libraries.txt"
# A release helper may use macOS libraries, but no Homebrew/Nix/build libraries.
awk 'NR > 1 && $1 !~ /^\/usr\/lib\// && $1 !~ /^\/System\/Library\// { bad = 1 } END { exit bad }' \
    "$work/dynamic-libraries.txt"
xcrun vtool -show-build "$work/first/attest-link-rust" >"$work/deployment-target.txt"
codesign --verify --strict "$work/first/attest-link-rust"
install -m 0755 "$work/first/attest-link-rust" "$output/attest-link-rust"
node --input-type=module - "$work" "$output/attest-link-rust" <<'JS'
import fs from 'node:fs'
import crypto from 'node:crypto'
import { execFileSync } from 'node:child_process'
const [work, binary] = process.argv.slice(2)
const sha256 = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')
const command = (file, args) => execFileSync(file, args, { encoding: 'utf8' }).trim()
const metadata = JSON.parse(command('cargo', ['metadata', '--manifest-path', `${work}/source/Cargo.toml`, '--locked', '--offline', '--format-version', '1']))
const openssl = metadata.packages.find(crate => crate.name === 'openssl-src')
const report = {
  platform: 'darwin-arm64', target: 'aarch64-apple-darwin',
  minimumMacOS: process.env.MACOSX_DEPLOYMENT_TARGET,
  testedMacOS: command('sw_vers', ['-productVersion']),
  rust: command('rustc', ['-Vv']), cargo: command('cargo', ['-V']),
  xcode: command('xcodebuild', ['-version']), sdk: command('xcrun', ['--show-sdk-version']),
  clang: command('xcrun', ['clang', '--version']),
  make: command('make', ['--version']), perl: command('perl', ['-e', 'print "$^V"']),
  openssl: { crateVersion: openssl.version, source: openssl.source },
  cargoLockSha256: sha256(`${work}/source/Cargo.lock`),
  binarySha256: sha256(binary), builds: 2, reproducible: true,
  dynamicLibraries: fs.readFileSync(`${work}/dynamic-libraries.txt`, 'utf8'),
  deploymentTarget: fs.readFileSync(`${work}/deployment-target.txt`, 'utf8'),
}
fs.writeFileSync(`${work}/report.json`, `${JSON.stringify(report, null, 2)}\n`)
JS
printf 'macOS helper: %s/attest-link-rust\nReport and logs: %s\n' "$output" "$work"
