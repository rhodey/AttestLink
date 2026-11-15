#!@bash@/bin/bash
# Prepare the Nitro Sandbox, then supervise its services. BusyBox remains PID 1.
set -euo pipefail
export PATH='@runtimePath@'
export TZ=UTC
export LANG=C
umask 077

pids=()

shutdown() {
    local status=$?
    trap - EXIT CHLD
    trap '' TERM INT
    echo "nitro-sandbox boot: stopping (status $status); powering off" >&2
    if ((${#pids[@]})); then
        kill -TERM "${pids[@]}" 2>/dev/null || true
        sleep 1
        kill -KILL "${pids[@]}" 2>/dev/null || true
    fi
    @busybox@/bin/busybox poweroff -f
}

trap shutdown EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

hostname nitro-sandbox
mkdir -p /run/ssh /run/sandbox /run/chrony /home/sandbox
chown 1000:1000 /home/sandbox
chmod 0700 /home/sandbox
chown 1001:1001 /run/sandbox
chmod 0700 /run/sandbox
chown 1002:1002 /run/chrony
chmod 0750 /run/chrony

# PCI devices can finish probing asynchronously during early boot.
for _ in $(seq 1 100); do
    [[ -c /dev/nsm && -d /sys/class/net/eth0 ]] && break
    sleep 0.1
done
[[ -c /dev/nsm && -d /sys/class/net/eth0 ]]

# The kernel's NSM driver registers a hardware RNG with entropy quality 1000.
# Select it explicitly; never seed from a constant or a parent-provided file.
printf 'nsm-hwrng\n' > /sys/class/misc/hw_random/rng_current

# Initialize the real Linux clock before any certificate checks or services.
# Chrony alone maintains time after this one fresh, authenticated NSM request.
[[ $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource) == arch_sys_counter ]]
nonce=$(openssl rand -hex 32)
public_key=$(openssl rand -base64 32)
timestamp=$(timeout 1 @package@/bin/attest-link -g -x \
    --nonce "$nonce" --public-key "$public_key" | jq -er '.timestamp / 1000')
@coreutils@/bin/date --utc --set="@$timestamp"
unset nonce public_key timestamp

# The upstream driver creates this node world-writable. Only the service account
# may make attestation requests; an SSH user must not attest arbitrary keys.
chown 1001:1001 /dev/nsm
chmod 0600 /dev/nsm

@iproute@/bin/ip link set lo up
@iproute@/bin/ip address add 172.30.0.2/30 dev eth0
@iproute@/bin/ip link set eth0 up
@iproute@/bin/ip route add default via 172.30.0.1

# Preserve measured code and dependencies while /run, /tmp and /home stay writable.
mount --bind /nix/store /nix/store
mount -o remount,bind,ro /nix/store

# getrandom() waits for initialized kernel entropy. Each boot has a new SSH key.
@openssh@/bin/ssh-keygen -q -t ed25519 -N '' -f /run/ssh/ssh_host_ed25519_key
@openssh@/bin/sshd -t -f /etc/ssh/sshd_config -p 2223

# Exit on any service ending, including before all services have started.
umask 022
trap 'exit 1' CHLD

# Services must not inherit supplementary root groups.
# Give DNS only the capability needed to bind port 53. Upstream IP literals avoid
# bootstrap DNS; TLS uses the measured CA bundle, with no plaintext fallback.
# NSM has already initialized time for certificate checks.
SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    @utilLinux@/bin/setpriv --reuid=1003 --regid=1003 --clear-groups \
    --inh-caps=-all,+net_bind_service --ambient-caps=-all,+net_bind_service \
    --bounding-set=-all,+net_bind_service --no-new-privs \
    @dnsproxy@/bin/dnsproxy --listen 127.0.0.1 --port 53 \
    --upstream tls://1.1.1.1 --upstream tls://1.0.0.1 --cache &
pids+=("$!")

@utilLinux@/bin/setpriv --clear-groups \
    @chrony@/bin/chronyd -d -4 -F 1 -u chrony -f /etc/chrony.conf &
pids+=("$!")

@utilLinux@/bin/setpriv --clear-groups \
    @openssh@/bin/sshd -D -e -f /etc/ssh/sshd_config -p 2223 &
pids+=("$!")

(
    cd /run/sandbox
    export HOME=/run/sandbox
    export ATTEST_LINK_RUST=@rust@/bin/attest-link-rust
    exec @utilLinux@/bin/setpriv --reuid=1001 --regid=1001 --clear-groups \
        @package@/bin/attest-link -s 2222 2223 \
        -c 'fortune -s | jq -Rs "{fortune: .}"'
) &
pids+=("$!")

wait
