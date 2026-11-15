#!/usr/bin/env bash
# End-to-end test on the configured Linux ARM64 Nitro host. Identity, generated
# images, process state and logs stay outside the Git checkout/Nix flake source.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
test_dir=${NITRO_SANDBOX_TEST_DIR:-$HOME/nitro-sandbox-test}
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] || {
    echo 'Run this on the Linux ARM64 Nitro host.' >&2; exit 1;
}
test_dir=$(realpath -m -- "$test_dir")
if [[ $test_dir == "$repo" || $test_dir == "$repo/"* ]]; then
    echo 'Keep test identities and runtime state outside the source checkout.' >&2
    exit 1
fi
mkdir -p "$test_dir"
chmod 0700 "$test_dir"
if [[ ! -f $test_dir/id_ed25519 ]]; then
    ssh-keygen -q -t ed25519 -N '' -C nitro-sandbox-integration -f "$test_dir/id_ed25519"
fi
[[ -f $test_dir/id_ed25519.pub ]] || { echo 'Missing test public key.' >&2; exit 1; }
bash "$repo/nitro/scripts/build.sh" "$test_dir/id_ed25519.pub" "$test_dir/image"
nix build "$repo#nitro-host-tools" --out-link "$test_dir/tools" -L
export PATH="$test_dir/tools/bin:$PATH"
started=false
cleanup() {
    if [[ $started == true ]]; then bash "$repo/nitro/scripts/sandbox.sh" stop --state "$test_dir/sandbox"; fi
}
trap cleanup EXIT
bash "$repo/nitro/scripts/sandbox.sh" start "$test_dir/image" "$test_dir/tools" --state "$test_dir/sandbox"
started=true
node "$repo/nitro/scripts/integration.mjs" --image "$test_dir/image" \
    --identity "$test_dir/id_ed25519" --endpoint http://172.30.0.2:2222
