# npm release guide

This document is for package maintainers and agents preparing releases of
`attest-link`. Package users should start with [README.md](README.md). Building
or deploying the demo is covered by the [Nitro README](../nitro/README.md).

Run commands from the repository root unless a different directory is specified.
Preparing a release does not authorize an agent to commit, tag or publish it;
those actions require the maintainer's instruction.

## Package contents

Publish one npm package containing the JavaScript, TypeScript declarations,
browser verifier, native helpers and dependency notices. Installation must not
download additional executables, run Cargo or require an install script.

| Platform | Native helper inside `package/` |
| --- | --- |
| macOS ARM64 | `bin/darwin-arm64/attest-link-rust` |
| Linux ARM64 | `bin/linux-arm64/attest-link-rust` |
| Linux x86-64 | `bin/linux-x64/attest-link-rust` |

The browser verifier is `wasm/attest-link.js`, a self-contained ES module with
embedded WASM. It uses the same Rust verification code and `rust/root.pem` as
the native helpers. Dependency notices belong in `licenses/*.txt`. Generated
artifacts and build reports stay out of Git.

Keep the `files` allowlist in [package.json](package.json) and
[.npmignore](.npmignore) consistent with this layout. `npm pack` can succeed
when a generated file is missing, so inspect the archive before releasing it.

## Compatibility contracts

[util.js](src/util.js) selects the helper in this order:

1. An explicit `ATTEST_LINK_RUST` path.
2. The bundled executable for `process.platform` and `process.arch`, if present.
3. `attest-link-rust` on `PATH`.

An explicit override or an existing bundled executable that fails to launch
must report that failure. Preserve the CLI arguments, evidence format and exit
codes: `0` for success, `2` for invalid evidence, and `1` for an operational or
invocation error. Keep manual installation from the matching source release
working for platforms without a bundle; see the [Rust README](../rust/README.md).
Document generation requires Linux and `/dev/nsm`; verification does not.

The Node engine range describes API compatibility. Qualify releases using a
patched Node runtime and record the version used. The Sandbox runtime is pinned
separately through Nix.

## Source and build inputs

Choose the final reviewed source revision before building release artifacts.
Keep the npm and Rust package versions and their lockfiles aligned, and use a
matching `vVERSION` source tag. Every builder must receive that same source.
See the root guide's [source snapshot notes](../AGENTS.md#build-inputs-and-source-snapshots)
when testing uncommitted changes. Keep host addresses and credentials in local
configuration, outside source snapshots and release artifacts.

The release scripts and Nix lockfile pin the build environment. Update those
pins deliberately: `Cargo.lock` alone does not pin the compiler, linker or SDK.
Linux helpers use OpenSSL from pinned Nixpkgs; macOS and WASM use Cargo's locked
vendored OpenSSL. Maintain these dependency paths without separate OpenSSL
source patches.

Start each builder and the packaging Mac with a clean checkout of the reviewed
commit. Clone the repo and run `git checkout --detach <full-commit>`, or unpack
`git archive <full-commit>` from the maintainer's checkout. Record that same
commit in a fresh directory outside the checkout on each machine. The examples
use the following variables (set `revision` explicitly for an unpacked archive).

```sh
revision=$(git rev-parse HEAD)
release_dir="$HOME/attest-link-releases/$revision"
mkdir -p "$release_dir"
printf '%s\n' "$revision" > "$release_dir/commit.txt"
```

Require exactly two independent, byte-identical builds of each native helper
and the WASM module. Compare builds of the same target; different architectures
produce different bytes. Retain source revision, tool versions, build reports,
test results and SHA-256 hashes with the release artifacts.

## Build the artifacts

### Linux helpers

Set up the ARM64 Nitro builder using the [EC2 setup instructions](../nitro/README.md#ec2-setup).
On the x86-64 Ubuntu builder, run `bash package/scripts/setup-linux.sh` and
reconnect. Run `bash package/scripts/setup-linux.sh --check` on each Linux
builder. Source `/nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh` if
the new login shell cannot find Nix.

Install the official Linux Node distribution for the exact `node-version` in
the [CI workflow](../.github/workflows/run.yml). Run this in Bash on each Linux
builder, using that version in the first line.

```sh
node_version=24.22.3
case "$(uname -m)" in
  aarch64) node_arch=arm64 ;;
  x86_64)  node_arch=x64 ;;
esac
dist="node-v$node_version-linux-$node_arch"
base="https://nodejs.org/dist/v$node_version"
(
  cd "$release_dir" &&
  curl -fsSLO "$base/SHASUMS256.txt" &&
  curl -fsSLO "$base/$dist.tar.xz" &&
  awk -v file="$dist.tar.xz" '$2 == file' SHASUMS256.txt | sha256sum -c - &&
  tar -xJf "$dist.tar.xz"
) && export PATH="$release_dir/$dist/bin:$PATH" && node --version && npm --version
```

On both Linux builders, run the native build from the repo root.

```sh
nix develop .#release --no-write-lock-file --command bash package/scripts/build-linux.sh "$release_dir/native"
nix-store --add-root "$release_dir/native-result" --realise "$(jq -r .output "$release_dir/native/build.json")"
```

The script builds twice, compares the complete Nix outputs and collects the
executable, OpenSSL notice and build reports in `$release_dir/native/`.
Compilation uses one job/core to accommodate smaller builders. The x86 builder
needs only the native helper and its test tools, not the Sandbox or WASM build.

Use the `attest-link-rust-static` output for npm. It produces fully static musl
executables and rejects shared-library dependencies. The separate
`attest-link-rust` output is Nix-linked and belongs to development and the
Sandbox. Release helpers must run without Nix installed.

### macOS helper

Use an Apple Silicon Mac with Node and npm installed. Install the Rust toolchain
and select the Xcode version pinned in [build-macos.sh](scripts/build-macos.sh),
then run:

```sh
bash package/scripts/build-macos.sh package/bin/darwin-arm64 "$release_dir/macos-build"
```

The script builds twice with Cargo's vendored OpenSSL, compares the executables,
runs Rust tests, and checks linkage and the ad-hoc signature. Only one release
build may run on a Mac at a time because the script reserves a fixed temporary
build path. Keep the separate report/log directory printed by the script.

The deployment target is macOS 13.5. This setting alone does not establish
compatibility: test on the oldest macOS version claimed and record the actual
OS versions tested. The helper must not depend on Homebrew or Nix libraries.

### Browser verifier

On the ARM64 Linux builder, build the module and perform its comparison rebuild:

```sh
nix build .#attest-link-wasm --out-link "$release_dir/wasm-result" --no-write-lock-file -L
nix build .#attest-link-wasm --rebuild --no-link --no-write-lock-file -L
sha256sum "$release_dir/wasm-result/attest-link.js"
```

Nix checks the rebuilt output against the first result. The collected module
must pass the WASM verification and browser bundling tests; a missing generated
module is not a reason to skip them.

On the packaging Mac, copy each Linux builder's `native/attest-link-rust` to
its platform path in the table above and copy the ARM builder's
`wasm-result/attest-link.js` to `package/wasm/attest-link.js`. Create these
destination directories in the clean checkout. Copy the build reports to platform-specific
directories under `$release_dir`. Compare the hashes printed by
`shasum -a 256 package/bin/*/attest-link-rust package/wasm/attest-link.js`
to the four builder results. The three executables must have mode 0755.

## Dependency notices

On ARM, collect the Linux and WASM notice sources from the locked flake. Transfer
the resulting archive to `$release_dir` on the packaging Mac.

```sh
nix build .#release-notice-inputs --no-write-lock-file --out-link "$release_dir/linux-notices"
tar -czf "$release_dir/linux-notices.tgz" -C "$release_dir/linux-notices" .
```

On the Mac, combine those files with the locked Cargo sources and the Rust
toolchain recorded by the macOS build. Generate notices in a clean packaging
checkout with no existing `package/licenses/`. Keep the inputs and
`package/licenses/sources.txt` with the build reports.

```sh
mkdir "$release_dir/linux-notices"
tar -xzf "$release_dir/linux-notices.tgz" -C "$release_dir/linux-notices"
node package/scripts/license-inputs.mjs "$release_dir/linux-notices" "$release_dir/macos-build/report.json" "$release_dir/notice-inputs"
node package/scripts/licenses.mjs "$release_dir/notice-inputs/inputs.json" package/licenses
```

## Qualify the package

Check CI for the recorded commit. The native builds run the Rust verifier and
CLI tests. Run the JS suite on all three platforms with the collected WASM and
native helpers. On macOS, several tests bind to `127.0.0.2`. Check
`ifconfig lo0` before the run. If the alias is missing, add it with
`sudo ifconfig lo0 alias 127.0.0.2` and remove it after testing with
`sudo ifconfig lo0 -alias 127.0.0.2`.

Pack once on the Mac. Save the dry-run and actual manifests and inspect the
archive for the JS, declarations, three executable helpers, WASM, metadata,
README, license and generated notices. Fixtures, credentials, build reports
and maintainer scripts belong outside the archive.

```sh
version=$(node -p "require('./package/package.json').version")
tarball="$release_dir/attest-link-$version.tgz"
(cd package && npm ci && npm test)
(cd package && npm pack --dry-run --ignore-scripts --json) > "$release_dir/pack-dry.json"
(cd package && npm pack --ignore-scripts --json --pack-destination "$release_dir") > "$release_dir/pack.json"
tar -tvzf "$tarball"
(cd "$release_dir" && shasum -a 256 "attest-link-$version.tgz" > SHA256SUMS)
```

Generate a signed synthetic fixture once for this run. The exporter uses the
current clock so the real native and WASM verifiers can check the certificate
chain. On the Mac with the release Rust toolchain, run:

```sh
ATTEST_LINK_FIXTURE="$release_dir/fixture.json" cargo test --locked --manifest-path rust/Cargo.toml --lib export_release_fixture -- --ignored
```

Capture `aws-fixture.json` from the running measured demo on ARM using the
[hardware instructions below](#nitro-hardware-checks).
Copy both fixture files, the tarball and `SHA256SUMS` to each builder. From
the matching source checkout on each platform, run the installed-package
checks outside any Nix shell. Use a new output directory for each run.

```sh
version=$(node -p "require('./package/package.json').version")
tarball="$release_dir/attest-link-$version.tgz"
sha256=$(awk '{print $1}' "$release_dir/SHA256SUMS")
node package/scripts/qualify-tarball.mjs "$tarball" "$sha256" "$release_dir/fixture.json" "$release_dir/aws-fixture.json" "$release_dir/qualification"
```

The harness checks the tarball digest before installing with scripts disabled.
It exercises npm/npx, the bundled helper, overrides, `PATH` fallback, and
native and WASM verification of valid and invalid evidence. Keep each
`qualification/result.json` under its platform name. On each Linux builder,
verify the installed static helper using the AWS fixture in an empty chroot.
Then copy the candidate artifacts into the source checkout for the JS suite
(its HTTPS tests use the system `openssl` command).

```sh
installed="$release_dir/qualification/consumer/node_modules/attest-link"
empty_root="$release_dir/empty-root"
mkdir "$empty_root"
install -m 0755 "$installed/bin/linux-$(node -p process.arch)/attest-link-rust" "$empty_root/helper"
aws="$release_dir/aws-fixture.json"
jq -r .document "$aws" | sudo chroot "$empty_root" /helper -v \
  --nonce "$(jq -r .nonce "$aws")" --public-key "$(jq -r .publicKey "$aws")" --pcr0 "$(jq -r .pcr0 "$aws")" \
  > "$release_dir/chroot-evidence.json"

cp -R "$installed/wasm" "$installed/bin" package/
(cd package && npm ci && npm test)
```

Keep the tarball, checksum and qualification reports together. Qualify a new
candidate if the source or packaged artifacts change.

## Nitro hardware checks

On the ARM builder, follow the [Nitro build and start instructions](../nitro/README.md#build)
through the first successful attestation. Restore the official Node runtime to
the front of `PATH` after those instructions add the Sandbox host tools.
Capture the raw signed document while the private SSH demo is running.

```sh
export PATH="$release_dir/$dist/bin:$PATH"
npm ci --prefix package --ignore-scripts
ATTEST_LINK_RUST="$HOME/sandbox-demo-tools/bin/attest-link-rust" \
  node nitro/scripts/capture-evidence.mjs "$HOME/sandbox-demo-image" > "$release_dir/aws-fixture.json"
```

The capture verifies the fresh challenge and server key against the AWS root
and checks PCR0, PCR1, PCR2 and PCR6 against the built image. Use the same
`aws-fixture.json` on all three platforms during npm qualification. Once the exact
tarball is installed on ARM, put that consumer's CLI first on `PATH` and run the
SSH suite against the running demo.

```sh
consumer="$release_dir/qualification/consumer"
unset ATTEST_LINK_RUST
export PATH="$consumer/node_modules/.bin:$PATH"
(
  set -e
  trap 'bash nitro/scripts/sandbox.sh stop' EXIT
  test "$(command -v attest-link)" = "$consumer/node_modules/.bin/attest-link"
  node nitro/scripts/integration.mjs --image "$HOME/sandbox-demo-image" \
    --identity "$HOME/.ssh/sandbox-demo-key" > "$release_dir/ssh.json"
)
```

For releases that change browser fetch, an additional measured image can
exercise the installed browser package on real hardware. The test workload
returns its request path and an incrementing counter from an unprivileged
HTTP listener on loopback. Build it in a fresh copy of the release commit.
If the builder received a source tarball, unpack that tarball a second time
in `http-source/` in place of the `git archive` step.

```sh
mkdir "$release_dir/http-source"
git archive HEAD | tar -x -C "$release_dir/http-source"
git -C "$release_dir/http-source" apply "$PWD/nitro/scripts/http-backend.patch"
bash "$release_dir/http-source/nitro/scripts/build.sh" \
  "$HOME/.ssh/sandbox-demo-key.pub" "$release_dir/http-image"
```

With the SSH demo stopped, run the HTTP test from the original checkout.

```sh
(
  set -e
  state="$release_dir/http-state"
  bash nitro/scripts/sandbox.sh start "$release_dir/http-image" "$HOME/sandbox-demo-tools" --state "$state"
  trap 'bash nitro/scripts/sandbox.sh stop --state "$state"' EXIT
  curl --http2-prior-knowledge -fsS --retry-all-errors --retry 30 --retry-delay 1 \
    --max-time 2 http://172.30.0.2:2222/health
  node nitro/scripts/test-fetch.mjs "$consumer" "$release_dir/http-image" > "$release_dir/browser.json"
)
```

Three calls must return in sequence with one hello and matching verified
evidence. Keep the results and both images' `measurements.json` with the release.

## Publish

With the maintainer's authorization, confirm npm ownership/access and publish
the tested tarball:

```sh
npm whoami
npm publish "$tarball" --access public
```

Tag the commit recorded before building. Compare npm's published integrity
with the saved pack manifest and install the public version before announcing it.

```sh
revision=$(cat "$release_dir/commit.txt")
git tag -a "v$version" "$revision" -m "attest-link $version" &&
git push origin "refs/tags/v$version"

expected=$(node -p 'require(process.argv[1])[0].integrity' "$release_dir/pack.json")
test "$(npm view "attest-link@$version" dist.integrity)" = "$expected"
npm install --prefix "$release_dir/published" --ignore-scripts "attest-link@$version"
```
