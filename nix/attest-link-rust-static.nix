{ lib, rustPlatform, pkg-config, openssl, buildPackages }:

let
  metadata = (builtins.fromTOML (builtins.readFile ../rust/Cargo.toml)).package;
in
rustPlatform.buildRustPackage {
  pname = metadata.name;
  inherit (metadata) version;
  src = lib.cleanSource ../rust;
  cargoLock.lockFile = ../rust/Cargo.lock;
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];
  OPENSSL_STATIC = "1";

  # Call this derivation through pkgsStatic: Rust's target and OpenSSL use musl.
  # Keep generic target defaults so the executable is portable between CPUs.
  doCheck = true;
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    ${buildPackages.binutils-unwrapped}/bin/${buildPackages.binutils-unwrapped.targetPrefix}readelf -lW "$out/bin/attest-link-rust" > program-headers
    ${buildPackages.binutils-unwrapped}/bin/${buildPackages.binutils-unwrapped.targetPrefix}readelf -dW "$out/bin/attest-link-rust" > dynamic-section
    if grep -q INTERP program-headers || grep -q NEEDED dynamic-section; then
      echo "The npm helper must be fully static" >&2
      exit 1
    fi
    runHook postInstallCheck
  '';
  postInstall = ''
    mkdir -p "$out/share/licenses"
    tar -xf ${openssl.src} --wildcards --strip-components=1 \
      -C "$out/share/licenses" '*/LICENSE.txt'
    mv "$out/share/licenses/LICENSE.txt" "$out/share/licenses/OpenSSL.txt"
  '';
  meta = {
    inherit (metadata) description;
    platforms = [ "aarch64-linux" "x86_64-linux" ];
    license = lib.licenses.mit;
    mainProgram = metadata.name;
  };
}
