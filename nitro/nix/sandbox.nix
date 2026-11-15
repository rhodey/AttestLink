{ pkgs, kernel, rust, package, eif, authorizedKeys }:

let
  inherit (pkgs) lib;
  runtime = [
    pkgs.busybox pkgs.bash pkgs.openssh pkgs.iproute2 pkgs.nodejs_24
    pkgs.openssl pkgs.chrony pkgs.dnsproxy pkgs.cacert pkgs.jq pkgs.fortune pkgs.util-linux rust package
  ];
  runtimePath = lib.makeBinPath runtime;
  closure = pkgs.closureInfo { rootPaths = runtime ++ [ pkgs.coreutils ]; };
  commandLine = "panic=1 initcall_blacklist=i8042_init";
in
pkgs.runCommand "nitro-sandbox" {
  nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.findutils pkgs.coreutils eif ];
  meta = {
    description = "ARM64 Nitro Sandbox image with OpenSSH and attest-link";
    platforms = [ "aarch64-linux" ];
  };
  passthru = {
    inherit commandLine;
    memoryMiB = 2048;
    vcpus = 1;
    sandboxAddress = "172.30.0.2";
    gatewayAddress = "172.30.0.1";
  };
} ''
  set -euo pipefail
  ${pkgs.chrony}/bin/chronyd -p -f ${../chrony.conf} >/dev/null
  mkdir -p root/{bin,sbin,dev,proc,sys,run,tmp,home,nix/store,etc/ssh,etc/ssl/certs,var/empty}
  while IFS= read -r storePath; do
    # Nix store optimization may hardlink equal files. Do not let that local
    # storage detail change cpio hardlink records or the resulting measurements.
    cp -a --no-preserve=ownership,links --reflink=auto "$storePath" root/nix/store/
  done < ${closure}/store-paths

  # All runtime programs and their shared-library dependencies are measured.
  ln -s ${pkgs.bash}/bin/bash root/bin/bash
  ln -s ${pkgs.busybox}/bin/busybox root/bin/sh
  ln -s ${pkgs.busybox}/bin/busybox root/sbin/init
  ln -s ${pkgs.busybox}/bin/busybox root/sbin/poweroff
  ln -s ${pkgs.busybox}/bin/busybox root/bin/umount

  substitute ${../init} root/init \
    --subst-var-by busybox ${pkgs.busybox} \
    --subst-var-by runtimePath ${lib.escapeShellArg runtimePath}
  substitute ${../boot.sh} root/sbin/nitro-sandbox-boot \
    --subst-var-by bash ${pkgs.bash} \
    --subst-var-by busybox ${pkgs.busybox} \
    --subst-var-by iproute ${pkgs.iproute2} \
    --subst-var-by openssh ${pkgs.openssh} \
    --subst-var-by chrony ${pkgs.chrony} \
    --subst-var-by dnsproxy ${pkgs.dnsproxy} \
    --subst-var-by rust ${rust} \
    --subst-var-by package ${package} \
    --subst-var-by coreutils ${pkgs.coreutils} \
    --subst-var-by utilLinux ${pkgs.util-linux} \
    --subst-var-by runtimePath ${lib.escapeShellArg runtimePath}
  substitute ${../sshd_config} root/etc/ssh/sshd_config \
    --subst-var-by runtimePath ${lib.escapeShellArg runtimePath}
  chmod 0555 root/init root/sbin/nitro-sandbox-boot
  cp ${../inittab} root/etc/inittab
  cp ${../chrony.conf} root/etc/chrony.conf
  ln -s ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt root/etc/ssl/certs/ca-certificates.crt

  cat > root/etc/passwd <<'EOF'
  root:x:0:0:root:/root:/bin/bash
  sshd:x:74:74:OpenSSH privilege separation:/var/empty:/bin/sh
  sandbox:x:1000:1000:Nitro Sandbox user:/home/sandbox:/bin/bash
  attest-link:x:1001:1001:attest-link service:/run/sandbox:/bin/sh
  chrony:x:1002:1002:Clock synchronization:/run/chrony:/bin/sh
  dnsproxy:x:1003:1003:Encrypted DNS resolver:/var/empty:/bin/sh
  EOF
  cat > root/etc/group <<'EOF'
  root:x:0:
  tty:x:5:
  sshd:x:74:
  sandbox:x:1000:
  attest-link:x:1001:
  chrony:x:1002:
  dnsproxy:x:1003:
  EOF
  cat > root/etc/shadow <<'EOF'
  root:!:1:0:99999:7:::
  sshd:!:1:0:99999:7:::
  sandbox:*:1:0:99999:7:::
  attest-link:!:1:0:99999:7:::
  chrony:!:1:0:99999:7:::
  dnsproxy:!:1:0:99999:7:::
  EOF
  chmod 0600 root/etc/shadow
  cat > root/etc/nsswitch.conf <<'EOF'
  passwd: files
  group: files
  shadow: files
  hosts: files dns
  EOF
  printf '127.0.0.1 localhost\n::1 localhost\n172.30.0.2 nitro-sandbox\n' > root/etc/hosts
  printf 'nameserver 127.0.0.1\noptions timeout:2 attempts:2\n' > root/etc/resolv.conf
  printf '/bin/bash\n/bin/sh\n' > root/etc/shells
  printf 'nitro-sandbox\n' > root/etc/hostname
  printf 'export PATH=%s\n' ${lib.escapeShellArg runtimePath} > root/etc/profile
  cat > root/etc/os-release <<'EOF'
  NAME="Nitro Sandbox"
  ID=nitro-sandbox
  PRETTY_NAME="Nitro Sandbox"
  EOF

  # This must be a PUBLIC key file. Private identities are runtime test inputs.
  if grep -q 'PRIVATE KEY' ${authorizedKeys}; then
    echo 'Refusing to put a private key into the measured image.' >&2
    exit 1
  fi
  ${pkgs.openssh}/bin/ssh-keygen -l -f ${authorizedKeys} >/dev/null
  cp ${authorizedKeys} root/etc/ssh/authorized_keys
  chmod 0444 root/etc/ssh/authorized_keys
  chmod 0555 root/var/empty

  # Normalize ownership in cpio and all timestamps, including symlinks. A sorted
  # traversal plus --reproducible removes filesystem inode/device variation.
  find root -print0 | xargs -0 touch -h -d @1
  mkdir -p "$out"
  (cd root; find . -print0 | LC_ALL=C sort -z | \
    cpio --null --create --format=newc --owner=0:0 --reproducible --quiet) | \
    gzip --no-name -9 > "$out/initramfs.cpio.gz"

  ln -s ${kernel}/Image "$out/Image"
  ln -s ${kernel}/config "$out/kernel.config"
  printf '%s\n' ${lib.escapeShellArg commandLine} > "$out/cmdline"
  nitro-eif --kernel "$out/Image" --initramfs "$out/initramfs.cpio.gz" \
    --cmdline ${lib.escapeShellArg commandLine} --output "$out/image.eif" \
    --manifest "$out/measurements.json"
  (cd "$out"; sha256sum Image initramfs.cpio.gz image.eif > SHA256SUMS)
''

