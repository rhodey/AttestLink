#!/usr/bin/env bash
# Run on the AL2023 ARM64 development host as ec2-user, not on macOS:
#   bash nitro/scripts/setup.sh
# If requested at the end, reboot separately, reconnect, and check:
#   sudo reboot
#   bash nitro/scripts/setup.sh --check
#
# This prepares the host. Sandbox builds and Firecracker will come from the
# repository's locked Nix flake. Host RPMs are not Sandbox build inputs.
set -euo pipefail

readonly NIX_VERSION=2.35.3
readonly NIX_SHA256=4a770896faa4d308806d0b4516575e0581443dc817d634b951a219a280554c09
# Checksum source: https://releases.nixos.org/nix/nix-2.35.3/install
readonly NIX_BIN=/nix/var/nix/profiles/default/bin/nix
readonly MEMORY_ARG=nitro_enclaves.mempool=3G@0
readonly POOL=/sys/class/misc/nitro_enclaves

usage() {
    cat <<'EOF'
Usage: bash nitro/scripts/setup.sh [--check | --help]

Default: install host utilities and pinned multi-user Nix, enable flakes and
sandboxed builds, and configure a 3 GiB Nitro memory reservation on NUMA node 0.
Does not reboot automatically. Rerunning does not upgrade Nix or the host kernel.

--check: inspect host readiness without installing or configuring anything.
EOF
}

die() { printf 'setup.sh: %s\n' "$*" >&2; exit 1; }
log() { printf '\n%s\n' "$*"; }

mode=setup
case "${1:-}" in
    '') ;;
    --check) mode=check ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
esac
[[ $# -le 1 ]] || die 'Expected at most one argument.'
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] ||
    die 'Run this script on the Linux ARM64 EC2 host.'
[[ $EUID -ne 0 ]] || die 'Run as the development user with sudo, not as root.'
# shellcheck source=/dev/null
source /etc/os-release
[[ $ID == amzn && $VERSION_ID == 2023 ]] || die 'Expected Amazon Linux 2023.'
sudo -n true || die 'Passwordless sudo is required for this development host.'
[[ -d /run/systemd/system ]] || die 'Expected a systemd host.'
[[ -c /dev/nitro_enclaves ]] || die 'Missing /dev/nitro_enclaves; check the EC2 Enclaves option and kernel.'
[[ $(cat /sys/devices/system/node/online) == 0 ]] ||
    die 'This initial memory reservation is intended for a single NUMA node.'

kernel_release=$(uname -r)
[[ $kernel_release == 6.18.*.amzn2023.aarch64 ]] ||
    die "Expected the AL2023 6.18 ARM64 kernel; found $kernel_release."
printf '%s\n' 6.18.51-120.162 "${kernel_release%.amzn2023.aarch64}" | sort -VC ||
    die 'Kernel is below the documented Sandbox compatibility floor.'
log "Host: $PRETTY_NAME; kernel $kernel_release"

check_nix() {
    [[ -x $NIX_BIN ]] || die 'Nix is not installed; run bash nitro/scripts/setup.sh.'
    [[ $("$NIX_BIN" --version) == "nix (Nix) $NIX_VERSION" ]] ||
        die "Expected Nix $NIX_VERSION; refusing to silently change an existing installation."
    "$NIX_BIN" store info --store daemon
    "$NIX_BIN" config show --json | jq -e '
        .sandbox.value == true and
        (."experimental-features".value | index("nix-command") != null and index("flakes") != null)
    ' >/dev/null || die 'Expected sandboxed Nix builds with nix-command and flakes enabled.'
}

check_pool() {
    log 'Nitro memory pool (bytes) and free CPUs:'
    for name in mem_pool/total mem_pool/free cpu_pool/free; do
        [[ -r $POOL/$name ]] || die "Missing Nitro status file: $POOL/$name"
        printf '%s: %s\n' "$name" "$(cat "$POOL/$name")"
    done
    # Existing hosts may reserve more than setup's default 3 GiB.
    [[ $(cat "$POOL/mem_pool/total") -ge $((3 * 1024 * 1024 * 1024)) ]]
}

if [[ $mode == check ]]; then
    for utility in git curl xz tar gzip bzip2 rsync jq grubby; do
        command -v "$utility" >/dev/null || die "Missing host utility: $utility"
    done
    check_nix
    check_pool || die 'Need at least 3 GiB of reserved Nitro memory; run setup and reboot as directed.'
    log 'Host bootstrap checks passed. Sandbox image, Firecracker and TAP setup are separate steps.'
    exit 0
fi

if command -v getenforce >/dev/null && [[ $(getenforce) == Enforcing ]]; then
    die 'The pinned upstream Nix installer does not support SELinux Enforcing; no SELinux changes were made.'
fi

log 'Installing host utilities (the Sandbox toolchain will be pinned in Nix).'
sudo dnf install -y git curl-minimal xz tar gzip bzip2 rsync jq grubby

setup_tmp=$(mktemp -d /tmp/nitro-sandbox-setup.XXXXXXXX)
trap 'rm -rf -- "$setup_tmp"' EXIT

if [[ ! -x $NIX_BIN ]]; then
    [[ ! -e /nix ]] || die '/nix already exists without the expected installation; inspect it before retrying.'
    log "Installing checksum-verified Nix $NIX_VERSION."
    nix_archive="$setup_tmp/nix.tar.xz"
    curl --fail --show-error --location --proto '=https' --tlsv1.2 --retry 3 \
        "https://releases.nixos.org/nix/nix-$NIX_VERSION/nix-$NIX_VERSION-aarch64-linux.tar.xz" \
        --output "$nix_archive"
    printf '%s  %s\n' "$NIX_SHA256" "$nix_archive" | sha256sum --check --status ||
        die 'Nix archive checksum mismatch.'
    tar -xJf "$nix_archive" -C "$setup_tmp"
    "$setup_tmp/nix-$NIX_VERSION-aarch64-linux/install" --daemon --yes --no-channel-add
fi
[[ $("$NIX_BIN" --version) == "nix (Nix) $NIX_VERSION" ]] ||
    die "An existing Nix installation differs from the $NIX_VERSION pin; it was not replaced."

log 'Configuring the Nix daemon and flakes.'
# AL2023 defaults to a 10 MiB hard stack limit. Nix requests 60 MiB for large
# evaluations, so allow 64 MiB in new login sessions and in the build daemon.
printf '%s soft stack 65536\n%s hard stack 65536\n' "$(id -un)" "$(id -un)" >"$setup_tmp/limits.conf"
sudo install -m 0644 "$setup_tmp/limits.conf" /etc/security/limits.d/90-attest-link-nix.conf
sudo install -d -m 0755 /etc/systemd/system/nix-daemon.service.d
printf '[Service]\nLimitSTACK=64M\n' >"$setup_tmp/stack.conf"
nix_service_changed=false
if ! sudo cmp -s "$setup_tmp/stack.conf" /etc/systemd/system/nix-daemon.service.d/stack.conf; then
    sudo install -m 0644 "$setup_tmp/stack.conf" /etc/systemd/system/nix-daemon.service.d/stack.conf
    sudo systemctl daemon-reload
    nix_service_changed=true
fi
cat >"$setup_tmp/attest-link.conf" <<'EOF'
# Managed by attest-link/nitro/scripts/setup.sh.
extra-experimental-features = nix-command flakes
sandbox = true
# Use the host's available CPUs for one build at a time.
cores = 0
max-jobs = 1
EOF
nix_config_changed=false
if ! sudo cmp -s "$setup_tmp/attest-link.conf" /etc/nix/attest-link.conf; then
    sudo install -m 0644 "$setup_tmp/attest-link.conf" /etc/nix/attest-link.conf
    nix_config_changed=true
fi
if ! sudo grep -Fxq '!include /etc/nix/attest-link.conf' /etc/nix/nix.conf; then
    printf '\n!include /etc/nix/attest-link.conf\n' | sudo tee -a /etc/nix/nix.conf >/dev/null
    nix_config_changed=true
fi
sudo systemctl enable --now nix-daemon.socket
if [[ $nix_config_changed == true || $nix_service_changed == true ]]; then
    sudo systemctl restart nix-daemon.service
fi
check_nix

# AWS: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitro-sandboxes-run-firecracker.html
# The new driver supplies CPUs dynamically; no legacy allocator service is needed.
log 'Configuring the Nitro memory pool; preserving unrelated boot arguments.'
boot_entry=$(sudo grubby --info=DEFAULT)
if [[ $boot_entry == *nitro_enclaves.mempool=* && $boot_entry != *"$MEMORY_ARG"* ]]; then
    die 'A different Nitro memory reservation is already configured; it was not replaced.'
fi
sudo grubby --update-kernel=ALL --args="$MEMORY_ARG"

if check_pool; then
    log 'Host bootstrap checks passed. Open a new SSH shell to pick up Nix in PATH.'
else
    log 'Setup is saved. Reboot to activate the memory reservation:'
    printf '  sudo reboot\n  # After reconnecting:\n  bash nitro/scripts/setup.sh --check\n'
fi
