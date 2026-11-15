{ lib, rustPlatform, pkg-config, openssl }:

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
  meta = {
    inherit (metadata) description;
    platforms = [ "aarch64-linux" ];
    license = lib.licenses.mit;
    mainProgram = metadata.name;
  };
}
