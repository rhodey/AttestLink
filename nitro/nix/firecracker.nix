{ pkgs, source }:

# The musl target selects Firecracker's audited release seccomp policy.
# An ordinary GNU-target build silently falls back to an empty policy upstream.
pkgs.pkgsStatic.firecracker.overrideAttrs (old: {
  version = "1.18.0";
  src = source;
  cargoHash = null;
  cargoDeps = pkgs.rustPlatform.importCargoLock {
    lockFile = source + "/Cargo.lock";
    outputHashes = {
      "micro_http-0.1.0" = "sha256-UTj6L1WjgWgopiAic/30KfTS/U84tuXZpJjiChCR+/k=";
    };
  };
  cargoBuildFlags = [ "--package" "firecracker" "--package" "jailer" ];
  # Nixpkgs' cargo hook forces system libraries during preConfigure. This VMM
  # builds the locked AWS-LC source for musl, so override that hook afterward.
  postConfigure = (old.postConfigure or "") + ''
    unset AWS_LC_SYS_USE_SYSTEM
  '';
  # Upstream VM tests require devices unavailable inside a Nix build sandbox.
  # Our integration tests exercise the finished binary against the Nitro device.
  doCheck = false;
  # The 1.17 recipe patches an older aws-lc vendor layout; 1.18 no longer
  # needs that workaround. Retain only the explicit libseccomp search path.
  postPatch = ''
    substituteInPlace src/seccompiler/build.rs \
      --replace-fail "/usr/local/lib" "${pkgs.lib.getLib pkgs.pkgsStatic.libseccomp}/lib"
    test -s resources/seccomp/aarch64-unknown-linux-musl.json
  '';
  meta = old.meta // {
    description = "Firecracker VMM with Nitro Sandbox support";
  };
})
