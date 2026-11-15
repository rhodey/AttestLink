{ lib, rustPlatform, nodejs, makeWrapper }:

let
  metadata = (builtins.fromTOML (builtins.readFile ../eif/Cargo.toml)).package;
in
rustPlatform.buildRustPackage {
  pname = "nitro-eif";
  inherit (metadata) version;
  src = lib.cleanSource ../eif;
  cargoLock.lockFile = ../eif/Cargo.lock;
  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    mkdir -p "$out/share/nitro-eif"
    cp cli.mjs measure.mjs "$out/share/nitro-eif/"
    makeWrapper ${nodejs}/bin/node "$out/bin/nitro-eif" \
      --add-flags "$out/share/nitro-eif/cli.mjs" \
      --set NITRO_EIF_WRITER "$out/bin/nitro-eif-write"
    NITRO_EIF_WRITER="$out/bin/nitro-eif-write" ${nodejs}/bin/node --test test.mjs
  '';

  meta = {
    description = "Deterministic Nitro Sandbox EIF writer and measurement tool";
    license = lib.licenses.asl20;
    platforms = [ "aarch64-linux" ];
    mainProgram = "nitro-eif";
  };
}
