# Nitro Sandbox demo

This builds the SSH demo from the root README. Nix builds the Linux kernel and
userspace into an EIF image, then Firecracker starts it as a confidential Nitro
Sandbox with 1 dedicated vCPU and 2 GiB RAM.

[boot.sh](boot.sh) sets the clock from a fresh attestation doc, starts DNS over
DoT, then chrony with NTS, then SSH and `attest-link`. The tunnel listens on
2222 and forwards to `sshd` on loopback 2223. The attestation hook runs
[fortune](https://wiki.archlinux.org/title/Fortune), so you'll get a random quote
in `userData.fortune` for fun.

## ETA

This could be a 10 minute task for you and an agent but nodejs needs to be built
from sources because the patches from the [nov 11 release](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases)
have not made it into Nix land yet. The result: expect a 40 minute cold-build
time. `m8g.2xlarge` instances are recommended for dev/builds but `m6g.large`
(cheaper) can be used for prod.

## EC2 setup

Use `m8g.2xlarge` with Amazon Linux 2023 ARM64. Enable **Nitro Enclaves** when
launching the instance. Choose the AL2023 **6.18 kernel** image; the running
kernel must be at least `6.18.51-120.162.amzn2023.aarch64`. See the
[AWS setup guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitro-sandboxes-run-firecracker.html)
for platform requirements. Our setup script checks the host but does not install
or upgrade its kernel.

Give Nix room for its builds: 50 GiB of EBS storage is a reasonable starting
point. Allow SSH to EC2 from your machine. The host needs internet access for
build downloads, and the Sandbox needs outbound TCP 853 for DNS, TCP 4460 and
UDP 123 for time sync.

SSH in as `ec2-user`. All commands below run on EC2 from the AttestLink root
dir unless otherwise noted:

```sh
sudo dnf install -y git
git clone https://github.com/rhodey/AttestLink.git
cd AttestLink
bash nitro/scripts/setup.sh
```

Setup installs pinned Nix and reserves 3 GiB for Nitro. If it asks for a reboot,
run `sudo reboot`, reconnect, and return to `~/AttestLink`. Then:

```sh
bash nitro/scripts/setup.sh --check
source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
```

## Build

Create a Sandbox demo key, or use an existing one. At this stage we'll keep the
key on EC2, outside the repo run:

```sh
mkdir -p "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/sandbox-demo-key"
bash nitro/scripts/build.sh "$HOME/.ssh/sandbox-demo-key.pub" "$HOME/sandbox-demo-image"
nix build --no-write-lock-file .#nitro-host-tools --out-link "$HOME/sandbox-demo-tools"
export PATH="$HOME/sandbox-demo-tools/bin:$PATH"
```

The `.pub` file is required. It authorizes the demo key to log in as `sandbox`;
the private key stays outside the image. Changing this public key or the code
changes PCR0.

`~/sandbox-demo-image` contains `Image`, `initramfs.cpio.gz`, `image.eif`,
`measurements.json` and `SHA256SUMS`. The host tools include Firecracker,
`attest-link`, and its Rust helper. Build inputs are pinned in [flake.lock](../flake.lock).

## Start

The launcher sets up networking and starts Firecracker in the background:

```sh
bash nitro/scripts/sandbox.sh start "$HOME/sandbox-demo-image" "$HOME/sandbox-demo-tools"
bash nitro/scripts/sandbox.sh status
```

Give the Sandbox a few seconds to boot. `status` reports the Firecracker
process; getting back an attest document is how we check the demo is ready:

```sh
PCR0=$(jq -r '.measurements.PCR0' "$HOME/sandbox-demo-image/measurements.json")
attest-link 0 http://172.30.0.2:2222 "$PCR0"
```

You should see JSON with the image's PCRs and `userData.fortune`.

## SSH into

On EC2, start the client tunnel and leave it running:

```sh
attest-link 2222 http://172.30.0.2:2222 "$PCR0"
```

We're going to SSH into the demo from EC2, soon after we'll SSH in from laptop:

```sh
ssh -i "$HOME/.ssh/sandbox-demo-key" -p 2222 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null sandbox@127.0.0.1
```

The Sandbox makes a new SSH host key each boot, those SSH options are about
skipping host key auth. attest-link binds to PCR0 so in context we have no problems.

You're now the `sandbox` user inside the VM. Try `date -u` or `chronyc tracking`.
The image has no persistent disk, files you create inside are lost when it stops,
future work can add entryped block-storage.

## SSH from laptop

Exit the Sandbox SSH session, then stop the attest-link tunnel with Ctrl-C.
Back on EC2, from the repo root, restart the demo with `--publish`:

```sh
bash nitro/scripts/sandbox.sh stop
bash nitro/scripts/sandbox.sh start "$HOME/sandbox-demo-image" "$HOME/sandbox-demo-tools" --publish
jq -r '.measurements.PCR0' "$HOME/sandbox-demo-image/measurements.json"
```

Allow inbound TCP 2222 in the EC2 security group. Give the Sandbox a few
seconds to boot. We're starting the same image, so the demo key and PCR0
stay the same. No rebuild needed. Now on your laptop you'll need Node.js.
We'll use `npx` to run `attest-link`; the npm package includes the rust
attestation helper.

Copy the demo key we created on EC2 to your laptop. Replace the EC2 address,
login key path and PCR0 below with yours. Use the PCR0 printed from your build's
`measurements.json` above. The EC2 login key gets us into EC2; the copied
Sandbox demo key gets us into the Sandbox.

```sh
EC2_HOST=ec2.ip.addr.ess
PCR0=PASTE_THE_PCR0_FROM_YOUR_BUILD
mkdir -p "$HOME/.ssh"
scp -i /path/to/ec2-login-key "ec2-user@$EC2_HOST:.ssh/sandbox-demo-key" "$HOME/.ssh/"
chmod 600 "$HOME/.ssh/sandbox-demo-key"
npx attest-link 2222 "http://$EC2_HOST:2222" "$PCR0"
```

Leave that tunnel running. In another terminal on your laptop:

```sh
ssh -i "$HOME/.ssh/sandbox-demo-key" -p 2222 \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null sandbox@127.0.0.1
```

You're back inside the Sandbox, this time through the laptop's tunnel. When
you're done exit the Sandbox SSH session and Ctrl-C the laptop tunnel.
Finally to stop the Sandbox, in your EC2 terminal, from the repo root:

```sh
bash nitro/scripts/sandbox.sh stop
tail -n 50 "$HOME/nitro-sandbox-state/firecracker.log"
```

Stop removes the Sandbox's TAP device and firewall rules and keeps the log.
The log contains Firecracker output; Nitro confidential mode doesn't expose
logs internal to the Sandbox.

## Tests and reproducibility

If the demo has already worked for you you're probably content but you or your
agent may want to run the test suite including checking that builds are
reproducible. After stopping the Sandbox, run:

```sh
bash nitro/scripts/test.sh
```

It builds a separate image and key under `~/nitro-sandbox-test`, checks real
attestation, the fortune hook, SSH, data transfer, DNS and time, then stops its
Sandbox. A wrong PCR0 must fail before SSH gets through.

To compare builds, use the same public key and a new output dir:

```sh
bash nitro/scripts/reproduce.sh "$HOME/.ssh/sandbox-demo-key.pub" "$HOME/nitro-sandbox-repro-001"
```

This compares two builds on the same ARM host: a baseline and one forced
rebuild. It checks complete Nix outputs plus kernel, initramfs and EIF hashes
and measurements. Foundational dependencies can come from the Nix cache.

## Collaborations

This work is licensed `MIT`. Also I happen to be looking for new work opportunities:

Copyright 2026: Email:  mike@rhodey.org
