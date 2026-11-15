#!/usr/bin/env bash
# Build a Nitro Sandbox image with an explicit public-key input. Private keys
# must never be passed here: Nix build inputs become readable store objects.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    printf 'Usage: %s PUBLIC_KEY_FILE [OUTPUT_LINK]\n' "$0" >&2
    exit 2
fi
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
public_key=$(realpath -- "$1")
output_link=${2:-$repo/result}
[[ -f $public_key ]] || { echo 'Public key file not found.' >&2; exit 1; }
# Accept one ordinary public key, with an optional comment. A private-key file
# or an authorized_keys options list is not this command's input format.
awk 'NF && $1 !~ /^#/ { if ($1 !~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$/ || NF < 2) exit 1; n++ } END { if (n != 1) exit 1 }' "$public_key" || {
    echo 'Expected exactly one SSH public key.' >&2
    exit 1
}
ssh-keygen -l -f "$public_key" >/dev/null
key_input=$(mktemp -d)
trap 'rm -rf -- "$key_input"' EXIT
install -m 0644 "$public_key" "$key_input/authorized_keys"

nix build "$repo#nitro-sandbox" --out-link "$output_link" \
    --override-input ssh-keys "path:$key_input" --no-write-lock-file -L
printf '\nImage: %s/image.eif\nMeasurements: %s/measurements.json\n' "$output_link" "$output_link"
