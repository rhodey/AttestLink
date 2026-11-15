{ stdenv, lib, source, bison, flex, bc, perl, python3, pkg-config, openssl, elfutils }:

stdenv.mkDerivation {
  pname = "nitro-sandbox-kernel";
  version = "6.18.56";
  src = source;
  nativeBuildInputs = [ bison flex bc perl python3 pkg-config ];
  buildInputs = [ openssl elfutils ];
  enableParallelBuilding = true;
  dontStrip = true;
  hardeningDisable = [ "all" ];

  # Never use the build machine's date, hostname, username, Git state, or path.
  SOURCE_DATE_EPOCH = "1";
  KBUILD_BUILD_TIMESTAMP = "1970-01-01 00:00:01 UTC";
  KBUILD_BUILD_USER = "nix";
  KBUILD_BUILD_HOST = "nix";
  KBUILD_BUILD_VERSION = "1";
  LOCALVERSION = "-nitro-sandbox";
  ARCH = "arm64";

  configurePhase = ''
    runHook preConfigure
    cp ${./kernel.config} .config
    make olddefconfig
    for option in EFI EFI_STUB ACPI PCI VIRTIO_PCI VIRTIO_NET NSM BLK_DEV_INITRD DEVTMPFS; do
      grep -qx "CONFIG_$option=y" .config || { echo "Missing required kernel option $option"; exit 1; }
    done
    runHook postConfigure
  '';

  buildPhase = ''
    runHook preBuild
    make -j "$NIX_BUILD_CORES" Image \
      KCFLAGS="-ffile-prefix-map=$PWD=/build/linux -fdebug-prefix-map=$PWD=/build/linux"
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp arch/arm64/boot/Image $out/Image
    cp .config $out/config
    make -s kernelrelease > $out/version
    runHook postInstall
  '';

  meta = {
    description = "ARM64 Linux kernel with Nitro Sandbox networking and attestation support";
    platforms = [ "aarch64-linux" ];
    license = lib.licenses.gpl2Only;
  };
}
