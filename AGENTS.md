# Working on AttestLink

These notes are for agents helping someone try the demo or fork it to run
another app. Keep user-facing instructions in the READMEs and link to them
instead of maintaining another copy here.

## Read first

- [Project README](README.md): what AttestLink does and example workloads.
- [Nitro README](nitro/README.md): EC2 setup, building, deployment, SSH from a
  laptop, cleanup and reproducibility checks.
- [Package README](package/README.md): client/server usage and attestation hooks.
- [Rust README](rust/README.md): the native attestation helper.
- [EIF README](nitro/eif/README.md): image construction and measurements.

[package/AGENTS.md](package/AGENTS.md) is the upstream maintainer's npm release
plan. Publishing a package is not a prerequisite for adapting the Sandbox.

## Adapting the demo

Add your app and its dependencies to the measured runtime in
[nitro/nix/sandbox.nix](nitro/nix/sandbox.nix). Package them through Nix and
include their configuration in the image. Code downloaded after boot is outside
the image measurement, so installing the app at startup changes what attestation
can establish about it.

Start the app from [nitro/boot.sh](nitro/boot.sh) and point attest-link at its
loopback backend. Keep service supervision and shutdown working when replacing
SSH. Use an unprivileged app account; accounts and filesystem permissions are
created in `sandbox.nix`. If removing SSH altogether, also adjust the public-key
input in [flake.nix](flake.nix) and [build.sh](nitro/scripts/build.sh).

Update [integration.mjs](nitro/scripts/integration.mjs) for the new app. Its
current checks expect SSH, fortune data, specific accounts and ports. Replace
those app-specific expectations with requests and responses your app supports,
while keeping signed-measurement comparisons, wrong-PCR rejection and checks
that application traffic passes through the attested tunnel.

Network changes span `boot.sh` and [sandbox.sh](nitro/scripts/sandbox.sh): keep
addresses, routes, allowed ports and the publish mapping consistent. The launcher
uses a fixed TAP device, subnet and firewall table. A different `--state` path
alone does not make it support multiple simultaneous Sandboxes.

Changing CPU, memory or launch flags requires coordinated updates to
`sandbox.nix`, the [EIF writer adapter](nitro/eif/src/main.rs),
[measurement code](nitro/eif/measure.mjs), launcher and their tests. Follow the
EIF README before changing that profile. Preserve the vendored writer's upstream
license and provenance.

## Build inputs and source snapshots

Keep dependency changes explicit. Use the existing lockfiles and pinned sources;
update them deliberately when adding or upgrading dependencies. Preserve the
timestamp, ownership and archive normalization in the kernel and image builds.
Keep private keys, credentials and runtime-generated state out of Nix inputs.

Git-backed Nix flakes omit untracked files. When testing uncommitted work, make
sure the builder sees all intended changes, including new files. A separate
source snapshot without `.git` can do this; include only intended source files
and exclude ignored secrets, local dependencies and build outputs. Do not stage
or commit someone else's work merely to make Nix see it. Record the source
revision or snapshot that was actually tested.

[nix/attest-link.nix](nix/attest-link.nix) also has an explicit source fileset
and `npmDepsHash`. Adding package assets or changing npm dependencies may require
updating these alongside `package.json` and its lockfile. Runtime dependencies
must enter the image closure, not just the development shell.

Use the user's own host and SSH configuration for remote work. Keep connection
details and generated reports outside the repository. Record additional host
preparation in [setup.sh](nitro/scripts/setup.sh) so another developer can repeat it.

## Runtime boundaries

Keep `/dev/nsm` access limited to the attestation service and the measured Nix
store read-only to app users. Preserve certificate, nonce and key-binding checks
when changing the transport. A passing test must not depend on weakening image
approval or accepting debug documents.

Clock initialization and ongoing synchronization have separate jobs. Keep the
document-time verification path confined to bootstrapping; ordinary verification
uses system time. Chrony owns synchronization afterward. Preserve authenticated
time and DNS when adapting the app; changing the workload should not introduce
unauthenticated fallbacks or another time-sync loop.

## Validation

Use the [CI workflow](.github/workflows/run.yml) for the package, Rust verifier
and EIF checks and their pinned development environment. Run the checks relevant
to the change. Sandbox and WASM outputs target ARM64 Linux; portable native helper
outputs also support x86-64 Linux. macOS release builds use the pinned Xcode/Rust
script described in the npm release guide.

CI installs an official Node binary and uses `nix develop .#ci` for Rust and
other test tools. Keep that shell free of Node so it preserves the CI runtime.
WASM builds use ordinary pinned Nixpkgs tools, including Node for their install
check; the package tests also exercise WASM under the official Node release.
The Sandbox runtime and default development shell use the separate Node source
build. Keep that override out of the CI and WASM build dependencies.

For boot, image, kernel or networking changes, use the
[hardware and reproducibility instructions](nitro/README.md#tests-and-reproducibility).
Transport fixtures do not establish that NSM, the real Sandbox clock or the
measured image works. Keep hardware validation and build reproducibility results
distinct when reporting them.

Documentation-only edits need link and example checks, not an image rebuild.
Report which checks ran, which did not, and any remaining failures. Keep the
matching image measurements and logs with the tested source snapshot.

Keep Nix's dependency cache between normal development cycles. Protect expensive
outputs with result links or GC roots; `--no-link` alone does not preserve them
against garbage collection. Rebuilding project outputs with cached dependencies
is different from rebuilding Node/V8 or the toolchain from source. Reserve
`--rebuild` for requested reproducibility checks. Monitor active builds through
their logs, without running build tools inside their temporary directories.

## Code style

Keep the flow easy to follow in the existing small modules. JavaScript uses
two-space indentation and no line-ending semicolons; follow the namespace-import
style used for `util` and `attest`. JavaScript handles the transport and process
orchestration; Rust handles NSM access, attestation parsing/verification and
MessagePack encoding/decoding.
