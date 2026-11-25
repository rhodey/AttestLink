# Collect the runtime notices for both static helpers and the WASM verifier.
{ runCommand, emscripten, rust, arm, x86 }:

let
  cc = arm.stdenv.cc;
  wasmRust = rust.packages.prebuilt.rustc;
  nativeInputs = static: map (pkg: { inherit (pkg) version; inherit (pkg.src) outputHash; }) [
    static.openssl static.stdenv.cc.libc static.stdenv.cc.cc static.rustPlatform.rust.rustc
  ];
  component = id: name: version: source: { inherit id name version source; };
  manifest = builtins.toJSON [
    (component "emscripten" "Emscripten runtime" emscripten.version
      "https://github.com/emscripten-core/emscripten/tree/${emscripten.version}")
    (component "gcc-runtime" "GCC runtime libraries" cc.cc.version
      "https://gcc.gnu.org/releases.html")
    (component "musl" "musl libc" cc.libc.version
      "https://musl.libc.org/releases/musl-${cc.libc.version}.tar.gz")
    (component "openssl-linux" "OpenSSL (Linux static helpers)" arm.openssl.version
      "https://github.com/openssl/openssl/releases/tag/openssl-${arm.openssl.version}")
    (component "rust-linux-wasm" "Rust standard library (Linux and WebAssembly)" wasmRust.version
      "https://github.com/rust-lang/rust/tree/${wasmRust.version}")
  ];
in
# These targets currently share notices. Split the affected component if their sources diverge.
assert nativeInputs arm == nativeInputs x86;
assert arm.rustPlatform.rust.rustc.version == wasmRust.version;
runCommand "attest-link-release-notice-inputs" {} ''
  mkdir -p "$out"/{emscripten,gcc-runtime,musl,openssl-linux,rust-linux-wasm}
  echo '${manifest}' > "$out/components.json"
  tar -xf ${cc.cc.src} -C "$out/gcc-runtime" --strip-components=1 \
    gcc-${cc.cc.version}/{COPYING3,COPYING.RUNTIME}
  tar -xf ${cc.libc.src} -C "$out/musl" --strip-components=1 musl-${cc.libc.version}/COPYRIGHT
  tar -xf ${arm.openssl.src} -C "$out/openssl-linux" --strip-components=1 \
    openssl-${arm.openssl.version}/{LICENSE.txt,AUTHORS.md}
  cp -RL ${wasmRust.unwrapped}/share/doc/rust/{COPYRIGHT-library.html,licenses} "$out/rust-linux-wasm/"
  cd ${emscripten}/share/emscripten
  for file in AUTHORS LICENSE system/lib/compiler-rt/CREDITS.TXT system/lib/libc/musl/COPYRIGHT \
    system/lib/{compiler-rt,libcxx,libcxxabi,libunwind,llvm-libc}/LICENSE.TXT; do
    install -Dm644 "$file" "$out/emscripten/$file"
  done
''
