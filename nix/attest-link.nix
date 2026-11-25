{ lib, buildNpmPackage, nodejs_24, makeWrapper, bash, rust, wasm }:

let
  metadata = builtins.fromJSON (builtins.readFile ../package/package.json);
in
buildNpmPackage {
  pname = metadata.name;
  inherit (metadata) version;
  nodejs = nodejs_24;
  src = lib.fileset.toSource {
    root = ../package;
    fileset = lib.fileset.unions [ ../package/package.json ../package/package-lock.json ../package/src ];
  };
  npmDepsHash = "sha256-K4TOBOovPkzWKd+awCBg7m6mCvdX8GWRVgvlFbRkP+A=";
  dontNpmBuild = true;
  nativeBuildInputs = [ makeWrapper ];
  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/attest-link $out/bin
    cp -r src node_modules package.json $out/share/attest-link/
    cp -r ${wasm} $out/share/attest-link/wasm
    makeWrapper ${nodejs_24}/bin/node $out/bin/attest-link \
      --add-flags "$out/share/attest-link/src/bin.js" \
      --prefix PATH : ${lib.makeBinPath [ bash ]} \
      --set ATTEST_LINK_RUST ${rust}/bin/attest-link-rust
    runHook postInstall
  '';
  meta = {
    inherit (metadata) description;
    platforms = [ "aarch64-linux" ];
    license = lib.licenses.mit;
    mainProgram = "attest-link";
  };
}
