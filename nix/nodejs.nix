{ lib, nodejs_24, nodejs-slim_24, fetchurl, llhttp, sqlite, testers }:

let
  nodejs = nodejs-slim_24.overrideAttrs (previous: rec {
    version = "24.22.3";
    src = fetchurl {
      url = "https://nodejs.org/dist/v${version}/node-v${version}.tar.xz";
      sha256 = "48ca3aa8a9b02133356922ef4fc80200e00598c80a4ef446f7c39a459222593d";
    };
    # This security release also updates llhttp and SQLite. Use its bundled
    # sources until the Nixpkgs pin includes those fixes too.
    configureFlags = lib.filter (flag:
      !(builtins.elem flag [ "--shared-http-parser" "--shared-sqlite" ])
    ) previous.configureFlags;
    buildInputs = lib.filter (input: input != llhttp && input != sqlite) previous.buildInputs;
    passthru = previous.passthru // {
      tests = previous.passthru.tests // {
        version = testers.testVersion { package = nodejs; version = "v${version}"; };
      };
    };
    meta = previous.meta // { changelog = "https://github.com/nodejs/node/releases/tag/v${version}"; };
  });
in
nodejs_24.override { nodejs-slim = nodejs; }
