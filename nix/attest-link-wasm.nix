{ lib, pkgs, fetchurl, runCommand, makeRustPlatform, emscripten, perl, nodejs_24 }:

let
  metadata = (builtins.fromTOML (builtins.readFile ../rust/Cargo.toml)).package;
  # The upstream compiler and target std must match. Nixpkgs' source-built
  # compiler uses different crate metadata, even at the same Rust version.
  toolchain = pkgs.rust.packages.prebuilt;
  rustPlatform = makeRustPlatform {
    inherit (toolchain) cargo rustc;
  };
  target = "wasm32-unknown-emscripten";
  targetStd = fetchurl {
    url = "https://static.rust-lang.org/dist/rust-std-${toolchain.rustc.version}-${target}.tar.xz";
    hash = "sha256-F5f8nkXRqP6BlXPp0AL9nz1OaA08/Eu0mvQ869MJbpA=";
  };
  sysroot = runCommand "rust-emscripten-sysroot-${toolchain.rustc.version}" {} ''
    mkdir -p "$out/lib/rustlib"
    ln -s ${toolchain.rustc}/lib/rustlib/* "$out/lib/rustlib/"
    tar -xJf ${targetStd}
    cp -r rust-std-*/rust-std-${target}/lib/rustlib/${target} "$out/lib/rustlib/"
  '';
in
rustPlatform.buildRustPackage {
  pname = "attest-link-wasm";
  inherit (metadata) version;
  src = lib.cleanSource ../rust;
  cargoLock.lockFile = ../rust/Cargo.lock;
  nativeBuildInputs = [ emscripten perl ];

  # openssl-src is pinned in Cargo.lock and compiled for WebAssembly, with no
  # dependence on the builder's system OpenSSL or a browser-side verifier fork.
  WASM32_UNKNOWN_EMSCRIPTEN_OPENSSL_NO_VENDOR = "0";
  CC_wasm32_unknown_emscripten = "${emscripten}/bin/emcc";
  CXX_wasm32_unknown_emscripten = "${emscripten}/bin/em++";
  AR_wasm32_unknown_emscripten = "${emscripten}/bin/emar";
  RANLIB_wasm32_unknown_emscripten = "${emscripten}/bin/emranlib";
  CARGO_TARGET_WASM32_UNKNOWN_EMSCRIPTEN_LINKER = "${emscripten}/bin/emcc";

  buildPhase = ''
    runHook preBuild
    export EM_CACHE="$TMPDIR/emscripten-cache"
    mkdir -p "$EM_CACHE"
    export CARGO_TARGET_WASM32_UNKNOWN_EMSCRIPTEN_RUSTFLAGS="\
      --sysroot ${sysroot} -C panic=abort \
      -C link-arg=-O3 -C link-arg=-sASSERTIONS=0 \
      -C link-arg=-sMODULARIZE=1 -C link-arg=-sEXPORT_ES6=1 \
      -C link-arg=-sSINGLE_FILE=1 -C link-arg=-sENVIRONMENT=web,worker \
      -C link-arg=-sALLOW_MEMORY_GROWTH=1 -C link-arg=-sSTACK_SIZE=1048576 \
      -C link-arg=-sEXPORTED_FUNCTIONS=['_attest_link_verify','_attest_link_free','_malloc','_free'] \
      -C link-arg=-sEXPORTED_RUNTIME_METHODS=['ccall','UTF8ToString']"
    cargo build --offline --frozen --release --target ${target} \
      --features wasm --bin attest-link-wasm
    runHook postBuild
  '';

  doCheck = false;
  dontStrip = true;
  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    install -m 0644 target/${target}/release/attest-link-wasm.js "$out/attest-link.js"
    runHook postInstall
  '';
  doInstallCheck = true;
  nativeInstallCheckInputs = [ nodejs_24 ];
  installCheckPhase = ''
    runHook preInstallCheck
    node --input-type=module - "$out/attest-link.js" <<'JS'
    import assert from 'node:assert/strict'
    import { pathToFileURL } from 'node:url'
    const { default: createVerifier } = await import(pathToFileURL(process.argv[2]))
    const verifier = await createVerifier({ noInitialRun: true })
    const input = JSON.stringify({ document: 'AA==', nonce: '00'.repeat(32), publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' })
    const pointer = verifier.ccall('attest_link_verify', 'number', ['string'], [input])
    assert.equal(verifier.UTF8ToString(pointer), 'false')
    verifier._attest_link_free(pointer)
    JS
    runHook postInstallCheck
  '';
  meta = {
    description = "Browser WebAssembly build of the attest-link Rust verifier";
    platforms = [ "aarch64-linux" ];
    license = lib.licenses.mit;
  };
}
