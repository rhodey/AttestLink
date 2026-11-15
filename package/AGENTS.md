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

Require exactly two independent, byte-identical builds of each native helper
and the WASM module. Compare builds of the same target; different architectures
produce different bytes. Retain source revision, tool versions, build reports,
test results and SHA-256 hashes with the release artifacts.

## Build the artifacts

### Linux helpers

Use an ARM64 Linux builder and an x86-64 Linux builder. If a builder needs Nix
and prerequisites, run [setup-linux.sh](scripts/setup-linux.sh). On each host:

```sh
nix develop .#release --command bash package/scripts/build-linux.sh
```

The script builds twice, compares the complete Nix outputs and collects the
executable and reports under `package/bin/linux-arm64/` or `package/bin/linux-x64/`.
Compilation uses one job/core to accommodate smaller builders. The x86 builder
needs only the native helper and its test tools, not the Sandbox or WASM build.

Use the `attest-link-rust-static` output for npm. It produces fully static musl
executables and rejects shared-library dependencies. The separate
`attest-link-rust` output is Nix-linked and belongs to development and the
Sandbox. Release helpers must run without Nix installed.

### macOS helper

Use an Apple Silicon Mac with the Rust and Xcode versions pinned in
[build-macos.sh](scripts/build-macos.sh), then run:

```sh
bash package/scripts/build-macos.sh
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
bash package/scripts/build-wasm.sh
nix build .#attest-link-wasm --rebuild --no-link --no-write-lock-file
```

Nix checks the rebuilt output against the first result. The collected module
must pass the WASM verification and browser bundling tests; a missing generated
module is not a reason to skip them.

Copy the three native executables and browser module into the packaging checkout
at the paths above. Preserve executable permissions and keep build reports
separately. Retain Nix build outputs against garbage collection while preparing
the release; see the root [validation notes](../AGENTS.md#validation).

## Dependency notices

Generate notices from the dependency sources and toolchains actually used for
the release. [licenses.mjs](scripts/licenses.mjs) accepts an input JSON file
with `cargoMetadata` and a `components` array. Each component has `id`, `name`,
`version`, `source` and a `files` mapping from notice names to source paths.
Paths are relative to the input JSON file; absolute paths also work.

```sh
cargo metadata --manifest-path rust/Cargo.toml --locked --format-version 1 > /path/to/cargo-metadata.json
node package/scripts/licenses.mjs /path/to/license-inputs.json
```

Keep these input files outside the checkout. Include the OpenSSL versions,
Rust standard-library notices, Emscripten, musl and GCC runtime notices used
across the native and WASM builds. Cargo metadata must point to available source
files. The generator writes `package/licenses/*.txt`, including a source-hash
inventory. Start with an empty generated `licenses/` directory to avoid carrying
obsolete notices into the release. Refresh notices whenever dependencies change.

## Qualify the package

Check that CI passes for the final source revision. Run native Rust verifier
and CLI tests on each platform, then prepare the package from `package/`:

```sh
npm ci
npm test
npm pack --dry-run
npm pack
```

Inspect the resulting archive for the current JavaScript, types, WASM, all three
executable helpers, package metadata, README and licenses. Exclude credentials,
test fixtures, build reports and maintainer instructions. Packing must use the
qualified artifacts without rebuilding them.

Install that exact tarball into fresh directories on all three platforms with
install scripts disabled. Check npm/npx invocation, bundled helper selection,
explicit overrides, `PATH` fallback, native and WASM verification, and rejection
of invalid evidence. Run the package tests with the collected artifacts and
record the runtime versions. Confirm Linux helpers run outside Nix.

Use the ARM64 Sandbox for real AWS attestation and SSH checks, following the
[hardware validation instructions](../nitro/README.md#tests-and-reproducibility).
Record image qualification separately from npm package qualification. Keep the
tested tarball, its SHA-256 checksum and the qualification reports together.
If source or artifacts change, prepare and qualify a new release candidate.

## Publish

With the maintainer's authorization, confirm npm ownership/access and publish
the tested tarball:

```sh
npm whoami
npm publish /path/to/attest-link-VERSION.tgz --access public
```

Publish the matching source tag and retain the qualified artifacts, hashes and
reports with the release. Keep repository metadata pointed at the release's
source repository. Verify installation of the published version before
announcing it.
