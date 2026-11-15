#!/usr/bin/env bash
# Start a real confidential Nitro Sandbox on the Linux development host.
#
#   sandbox.sh start IMAGE_DIRECTORY FIRECRACKER [--publish]
#   sandbox.sh status
#   sandbox.sh stop
#
# All commands accept --state DIRECTORY (default: ~/nitro-sandbox-state).
# FIRECRACKER can be a binary or a Nix package directory containing bin/firecracker.
# IMAGE_DIRECTORY must contain image.eif and measurements.json from nitro-eif.
# --publish forwards the parent's inbound TCP port 2222 to the attestation service.
#
# State is outside the source tree, root-owned and readable by the invoking user's
# group. Stop removes only this launcher's tagged TAP and nftables table. IPv4
# forwarding stays enabled, because disabling it could disrupt other workloads.
set -euo pipefail
umask 027

die() { printf 'sandbox.sh: %s\n' "$*" >&2; exit 1; }
log() { printf '%s\n' "$*"; }
usage() { sed -n '2,15s/^# \{0,1\}//p' "${BASH_SOURCE[0]}"; }

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
[[ $(uname -s) == Linux ]] || die 'Run this on the Linux EC2 host.'

# Keep the Nix-provided PATH when crossing sudo. The caller already has explicit
# administrative access to this development host; state is written only as root.
if [[ $EUID -ne 0 ]]; then
    exec sudo -n env "PATH=$PATH" "NITRO_SANDBOX_CALLER_HOME=$HOME" \
        "NITRO_SANDBOX_CALLER_GID=$(id -g)" bash "$(realpath "${BASH_SOURCE[0]}")" "$@"
fi

readonly TAP=nitro-sandbox0
readonly TABLE=nitro_sandbox
readonly SANDBOX_IP=172.30.0.2
readonly GATEWAY=172.30.0.1
readonly SUBNET=172.30.0.0/30
readonly MAC=06:00:AC:1E:00:02
action=${1:-}
[[ $action == start || $action == status || $action == stop ]] || { usage >&2; exit 1; }
shift

image_directory=''
firecracker=''
publish=false
state="${NITRO_SANDBOX_CALLER_HOME:-$HOME}/nitro-sandbox-state"
state_group=${NITRO_SANDBOX_CALLER_GID:-0}
if [[ $action == start ]]; then
    [[ $# -ge 2 ]] || die 'Start requires IMAGE_DIRECTORY and FIRECRACKER.'
    image_directory=$1
    firecracker=$2
    shift 2
fi
while [[ $# -gt 0 ]]; do
    case $1 in
        --state)
            [[ $# -ge 2 ]] || die '--state requires a directory.'
            state=$2; shift 2 ;;
        --publish)
            [[ $action == start ]] || die '--publish is a start option.'
            publish=true; shift ;;
        *) die "Unknown argument: $1" ;;
    esac
done

for utility in ip nft jq sysctl realpath flock setsid sha256sum; do
    command -v "$utility" >/dev/null || die "Missing host tool: $utility; build .#nitro-host-tools and add its bin directory to PATH (see AGENTS.md)."
done
[[ ! -L $state ]] || die 'State must be a dedicated directory, not a symbolic link.'
state=$(realpath -m "$state")
[[ $state != / ]] || die 'State must be a dedicated directory.'
[[ $state_group =~ ^[0-9]+$ ]] || die 'Invalid state group.'

# One network namespace/profile is supported. A lock prevents racing start/stop.
exec 9>/run/lock/nitro-sandbox.lock
flock -n 9 || die 'Another sandbox command is running.'

token=''
if [[ -e $state ]]; then
    [[ -d $state && -f $state/owner && $(stat -c %u "$state/owner") == 0 ]] ||
        die "Refusing to use an unrecognized state directory: $state"
    token=$(cat "$state/owner")
    [[ $token =~ ^nitro-sandbox-[0-9a-f-]{36}$ ]] || die 'Invalid state ownership marker.'
elif [[ $action != start ]]; then
    log 'No Sandbox state exists.'
    exit 0
fi

process_start_time() {
    local stat_line remainder
    local -a fields
    [[ -r /proc/$1/stat ]] || return 1
    stat_line=$(cat "/proc/$1/stat") || return 1
    remainder=${stat_line##*) }
    read -r -a fields <<<"$remainder"
    printf '%s\n' "${fields[19]}"
}

process_matches() {
    local pid started expected_executable actual_executable
    local -a command
    [[ -f $state/process.json ]] || return 1
    pid=$(jq -er '.pid | select(type == "number" and . > 1)' "$state/process.json") || return 1
    started=$(jq -er '.startTime' "$state/process.json") || return 1
    expected_executable=$(jq -er '.executable' "$state/process.json") || return 1
    [[ $(process_start_time "$pid") == "$started" ]] || return 1
    actual_executable=$(readlink "/proc/$pid/exe") || return 1
    [[ $actual_executable == "$expected_executable" ]] || return 1
    mapfile -d '' -t command <"/proc/$pid/cmdline" || return 1
    [[ ${command[1]:-} == --api-sock && ${command[2]:-} == "$state/api.sock" &&
       ${command[3]:-} == --config-file && ${command[4]:-} == "$state/firecracker.json" ]]
}

check_network_ownership() {
    if ip link show "$TAP" >/dev/null 2>&1; then
        [[ $(ip -j link show "$TAP" | jq -r '.[0].ifalias // ""') == "$token" ]] ||
            die "TAP $TAP belongs to another owner; it was not changed."
    fi
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        [[ $(nft -j list table inet "$TABLE" | jq -r '.nftables[] | select(.table.name == "nitro_sandbox") | .table.comment // ""') == "$token" ]] ||
            die "nftables table $TABLE belongs to another owner; it was not changed."
    fi
}

remove_network() {
    check_network_ownership
    if nft list table inet "$TABLE" >/dev/null 2>&1; then nft delete table inet "$TABLE"; fi
    if ip link show "$TAP" >/dev/null 2>&1; then ip link delete "$TAP"; fi
}

stop_process() {
    if process_matches; then
        local pid
        pid=$(jq -r .pid "$state/process.json")
        kill -TERM "$pid"
        for ((attempt=0; attempt<50; attempt++)); do
            process_matches || break
            sleep 0.1
        done
        # Recheck identity before escalation, so a recycled PID cannot be killed.
        if process_matches; then kill -KILL "$pid"; fi
    elif [[ -f $state/process.json ]]; then
        log 'Recorded Firecracker process is gone or its identity changed; no signal was sent.'
    fi
    rm -f -- "$state/process.json" "$state/api.sock"
}

if [[ $action == status ]]; then
    if process_matches; then
        log "Firecracker is running (PID $(jq -r .pid "$state/process.json"))."
        log "Attestation endpoint: http://$SANDBOX_IP:2222 (h2c); logs: $state/firecracker.log"
    else
        log "Firecracker is not running; logs, if any: $state/firecracker.log"
    fi
    check_network_ownership
    ip -brief address show "$TAP" 2>/dev/null || true
    exit 0
fi

if [[ $action == stop ]]; then
    check_network_ownership
    stop_process
    remove_network
    log 'Sandbox stopped; owned TAP and firewall table removed. Logs were retained.'
    exit 0
fi

image_directory=$(realpath -e "$image_directory")
[[ -d $firecracker ]] && firecracker=$firecracker/bin/firecracker
firecracker=$(realpath -e "$firecracker")
[[ -x $firecracker ]] || die 'Firecracker is not executable.'
image=$image_directory/image.eif
manifest=$image_directory/measurements.json
[[ -f $image && -f $manifest ]] || die 'Image directory must contain image.eif and measurements.json.'
jq -e '.launch.memoryMiB == 2048 and .launch.vcpus == 1 and .launch.flags == "0x0241" and
       .launch.confidential == true and .launch.cpuOvercommit == false and .launch.hotplug == false' \
    "$manifest" >/dev/null || die 'Image manifest does not match this launcher profile.'
actual_hash=$(sha256sum "$image")
[[ ${actual_hash%% *} == "$(jq -er .sha256.eif "$manifest")" ]] || die 'EIF does not match the manifest SHA-256.'
[[ -c /dev/nitro_enclaves ]] || die 'Missing Nitro Enclaves device.'
[[ $(cat /sys/class/misc/nitro_enclaves/mem_pool/free) -gt $((2048 * 1024 * 1024)) ]] ||
    die 'Need more than 2 GiB free Nitro pool memory for this Sandbox and device overhead.'

if process_matches; then die 'A Sandbox is already running; stop it before changing images.'; fi
if ip link show "$TAP" >/dev/null 2>&1 || nft list table inet "$TABLE" >/dev/null 2>&1; then
    check_network_ownership
    die 'Owned network state remains; run stop before starting again.'
fi
if ip -j -4 route show match "$SANDBOX_IP" | jq -e 'any(.[]; .dst != "default")' >/dev/null; then
    die "The chosen Sandbox subnet $SUBNET overlaps an existing route."
fi
uplink=$(ip -j -4 route show default | jq -er '.[0].dev')
[[ $uplink =~ ^[a-zA-Z0-9_.:-]+$ && $uplink != "$TAP" ]] || die 'Invalid default-route interface.'

if [[ -z $token ]]; then
    install -d -m 0750 -o root -g "$state_group" "$state"
    token="nitro-sandbox-$(cat /proc/sys/kernel/random/uuid)"
    printf '%s\n' "$token" >"$state/owner"
fi
chgrp "$state_group" "$state"
chmod 2750 "$state"

cleanup_failed_start() {
    local result=$?
    trap - EXIT
    if [[ $result != 0 ]]; then
        stop_process || true
        remove_network || true
        log "Launch failed; inspect $state/firecracker.log."
    fi
    exit "$result"
}
trap cleanup_failed_start EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

jq -n --arg image "$image" --arg tap "$TAP" --arg mac "$MAC" '{
  "boot-source": {"kernel_image_path": $image},
  "machine-config": {"vcpu_count": 1, "mem_size_mib": 2048},
  "drives": [],
  "network-interfaces": [{"iface_id": "eth0", "guest_mac": $mac, "host_dev_name": $tap}],
  "enclave": {}
}' >"$state/firecracker.json"

# Dedicated chains leave unrelated host rules untouched. Established replies
# are allowed; unsolicited traffic to the Sandbox can reach only TCP2222. IPv6
# and private/link-local destinations are deliberately outside this first profile.
cat >"$state/network.nft" <<EOF
create table inet $TABLE {
  comment "$token"
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "$TAP" meta nfproto != ipv4 drop
    iifname "$TAP" ip saddr != $SANDBOX_IP drop
    iifname "$TAP" ct state established,related accept
    iifname "$TAP" drop
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "$TAP" meta nfproto != ipv4 drop
    iifname "$TAP" ip saddr != $SANDBOX_IP drop
    iifname "$TAP" ct state established,related accept
    iifname "$TAP" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } drop
    iifname "$TAP" oifname "$uplink" accept
    iifname "$TAP" drop
    oifname "$TAP" ct state established,related accept
    oifname "$TAP" ip daddr $SANDBOX_IP tcp dport 2222 accept
    oifname "$TAP" drop
  }
  chain output {
    type filter hook output priority -10; policy accept;
    oifname "$TAP" ct state established,related accept
    oifname "$TAP" ip daddr $SANDBOX_IP tcp dport 2222 accept
    oifname "$TAP" drop
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
EOF
if [[ $publish == true ]]; then
    printf '    iifname "%s" fib daddr type local tcp dport 2222 dnat ip to %s:2222\n' \
        "$uplink" "$SANDBOX_IP" >>"$state/network.nft"
fi
cat >>"$state/network.nft" <<EOF
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SANDBOX_IP oifname "$uplink" masquerade
  }
}
EOF
nft --check --file "$state/network.nft"
ip tuntap add dev "$TAP" mode tap
ip link set dev "$TAP" alias "$token"
ip address add "$GATEWAY/30" dev "$TAP"
ip link set dev "$TAP" up
nft --file "$state/network.nft"
sysctl -q -w net.ipv4.ip_forward=1

rm -f -- "$state/api.sock"
# Close the lock FD in the child, detach it from this SSH session, and keep the
# upstream seccomp policy enabled. No debug/direct mode or entropy device.
setsid "$firecracker" --api-sock "$state/api.sock" --config-file "$state/firecracker.json" \
    9>&- </dev/null >"$state/firecracker.log" 2>&1 &
pid=$!
started=$(process_start_time "$pid") || {
    tail -n 40 "$state/firecracker.log" >&2
    die 'Firecracker exited before its process identity could be recorded.'
}
jq -n --argjson pid "$pid" --arg started "$started" --arg executable "$firecracker" \
    '{pid: $pid, startTime: $started, executable: $executable}' >"$state/process.json"

# Give argument parsing/device setup time to fail; this is process readiness,
# not an assertion that the measured Sandbox has booted or passed attestation.
sleep 1
if ! process_matches; then
    tail -n 40 "$state/firecracker.log" >&2
    die 'Firecracker exited during startup.'
fi
trap - EXIT INT TERM
log "Firecracker started (PID $pid). Sandbox attestation endpoint: http://$SANDBOX_IP:2222 (h2c)"
if [[ $publish == true ]]; then log 'Parent TCP2222 is forwarded; the EC2 security group must permit the client.'; fi
log "State and logs: $state; Sandbox boot and attestation still need verification."
