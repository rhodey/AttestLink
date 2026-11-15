#!/usr/bin/env bash
# Install the pinned Nix builder for npm's Linux helpers; no Nitro setup.
# Run as the development user on Ubuntu/Debian or Amazon Linux 2023.
set -euo pipefail

readonly NIX_VERSION=2.35.3
readonly NIX_BIN=/nix/var/nix/profiles/default/bin/nix

die() { printf 'setup-linux.sh: %s\n' "$*" >&2; exit 1; }
[[ $(uname -s) == Linux ]] || die 'Run on a Linux release builder.'
[[ $EUID != 0 ]] || die 'Run as the development user with sudo, not root.'
case "$(uname -m)" in
    aarch64)
        system=aarch64-linux
        nix_sha256=4a770896faa4d308806d0b4516575e0581443dc817d634b951a219a280554c09 ;;
    x86_64)
        system=x86_64-linux
        nix_sha256=6ce3ce3703fdc241b560cba401c5d338042122fe5b1a81e07bf1a623f259eba0 ;;
    *) die 'Expected ARM64 or x86-64 Linux.' ;;
esac
# Checksums: https://releases.nixos.org/nix/nix-2.35.3/install

check() {
    [[ -x $NIX_BIN ]] || die 'Nix is missing; run this script without --check.'
    [[ $("$NIX_BIN" --version) == "nix (Nix) $NIX_VERSION" ]] ||
        die "Expected Nix $NIX_VERSION; an existing installation will not be replaced."
    "$NIX_BIN" store info --store daemon
    "$NIX_BIN" config show --json | jq -e '
        .sandbox.value == true and
        (."experimental-features".value | index("nix-command") != null and index("flakes") != null)
    ' >/dev/null
}

case "${1:-}" in
    --check) [[ $# == 1 ]] || die 'Expected only --check.'; check; exit 0 ;;
    --help|-h)
        printf 'Usage: bash package/scripts/setup-linux.sh [--check]\n'
        exit 0 ;;
    '') [[ $# == 0 ]] || die 'Unexpected arguments.' ;;
    *) die 'Expected --check or no arguments.' ;;
esac
sudo -n true || die 'Passwordless sudo is required for this builder.'
[[ -d /run/systemd/system ]] || die 'Expected a systemd host.'
if command -v getenforce >/dev/null && [[ $(getenforce) == Enforcing ]]; then
    die 'The upstream Nix installer does not support SELinux Enforcing.'
fi

# Host utilities only. Compilers, musl and OpenSSL come from the locked flake.
# shellcheck source=/dev/null
source /etc/os-release
case "$ID" in
    ubuntu|debian)
        sudo apt-get update
        sudo apt-get install -y ca-certificates curl xz-utils bzip2 git jq ;;
    amzn)
        [[ $VERSION_ID == 2023 ]] || die 'Expected Amazon Linux 2023.'
        sudo dnf install -y ca-certificates curl-minimal xz bzip2 git jq ;;
    *) die 'Supported bootstrap hosts are Ubuntu, Debian and Amazon Linux 2023.' ;;
esac

setup_tmp=$(mktemp -d /tmp/attest-link-npm-setup.XXXXXXXX)
trap 'rm -rf -- "$setup_tmp"' EXIT
if [[ ! -x $NIX_BIN ]]; then
    [[ ! -e /nix ]] || die '/nix already exists without the expected installation.'
    curl --fail --show-error --location --proto '=https' --tlsv1.2 --retry 3 \
        "https://releases.nixos.org/nix/nix-$NIX_VERSION/nix-$NIX_VERSION-$system.tar.xz" \
        --output "$setup_tmp/nix.tar.xz"
    printf '%s  %s\n' "$nix_sha256" "$setup_tmp/nix.tar.xz" | sha256sum --check --status
    tar -xJf "$setup_tmp/nix.tar.xz" -C "$setup_tmp"
    "$setup_tmp/nix-$NIX_VERSION-$system/install" --daemon --yes --no-channel-add
fi
[[ $("$NIX_BIN" --version) == "nix (Nix) $NIX_VERSION" ]] ||
    die "An existing Nix installation differs from $NIX_VERSION; it was not replaced."

# A small builder should run only one compilation at a time. This script does
# not reserve Nitro memory, install a VM toolchain or change boot arguments.
cat >"$setup_tmp/npm.conf" <<'EOF'
# Managed by attest-link/package/scripts/setup-linux.sh.
extra-experimental-features = nix-command flakes
sandbox = true
cores = 1
max-jobs = 1
EOF
sudo install -m 0644 "$setup_tmp/npm.conf" /etc/nix/attest-link-npm.conf
if ! sudo grep -Fxq '!include /etc/nix/attest-link-npm.conf' /etc/nix/nix.conf; then
    printf '\n!include /etc/nix/attest-link-npm.conf\n' | sudo tee -a /etc/nix/nix.conf >/dev/null
fi
printf '%s soft stack 65536\n%s hard stack 65536\n' "$(id -un)" "$(id -un)" >"$setup_tmp/limits.conf"
sudo install -m 0644 "$setup_tmp/limits.conf" /etc/security/limits.d/90-attest-link-nix.conf
sudo install -d -m 0755 /etc/systemd/system/nix-daemon.service.d
printf '[Service]\nLimitSTACK=64M\n' >"$setup_tmp/stack.conf"
sudo install -m 0644 "$setup_tmp/stack.conf" /etc/systemd/system/nix-daemon.service.d/stack.conf
sudo systemctl daemon-reload
sudo systemctl enable --now nix-daemon.socket
sudo systemctl restart nix-daemon.service
check
printf '\nNpm helper builder ready. Open a new SSH shell to pick up Nix and stack limits.\n'
