{
  description = "attest-link TCP/HTTP tunnels and an ARM64 Nitro Sandbox SSH demo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/f4a03c008967841f2a0b3cb7c436fc6fc31671f6";
    linux = {
      url = "github:amazonlinux/linux/7483450dec64b4f923037de31d8c28298a7c3359";
      flake = false;
    };
    firecracker = {
      url = "github:firecracker-microvm/firecracker/eaf83bb718a559d324613d566eaf776b31a62340";
      flake = false;
    };
    ssh-keys = {
      url = "path:./nitro";
      flake = false;
    };
  };

  outputs = { nixpkgs, linux, firecracker, ssh-keys, ... }:
    let
      system = "aarch64-linux";
      buildPkgs = import nixpkgs { inherit system; };
      packagesFor = target: import nixpkgs {
        system = target;
        overlays = [ (_: previous: {
          nodejs_24 = previous.callPackage ./nix/nodejs.nix {
            inherit (previous) nodejs_24 nodejs-slim_24;
          };
        }) ];
      };
      pkgs = packagesFor system;
      releasePackages = target:
        let releasePkgs = packagesFor target;
        in {
          attest-link-rust-static = releasePkgs.pkgsStatic.callPackage ./nix/attest-link-rust-static.nix {};
        };
      releaseShell = target:
        # Helper builds use the cached Nixpkgs tools, independently of Sandbox Node.
        let releasePkgs = import nixpkgs { system = target; };
        in releasePkgs.mkShell {
          packages = with releasePkgs; [ nodejs_24 jq file binutils ];
        };
      kernel = pkgs.callPackage ./nitro/nix/kernel.nix { source = linux; };
      vmm = import ./nitro/nix/firecracker.nix { inherit pkgs; source = firecracker; };
      rust = pkgs.callPackage ./nix/attest-link-rust.nix {};
      # Keep the Sandbox's Node build out of the WASM toolchain.
      wasm = buildPkgs.callPackage ./nix/attest-link-wasm.nix {};
      package = pkgs.callPackage ./nix/attest-link.nix { inherit rust wasm; };
      eif = pkgs.callPackage ./nitro/nix/eif.nix { nodejs = pkgs.nodejs_24; };
      hostTools = pkgs.symlinkJoin {
        name = "nitro-host-tools";
        paths = [ vmm package rust eif pkgs.iproute2 pkgs.nftables pkgs.jq
          pkgs.procps pkgs.coreutils pkgs.openssh pkgs.nodejs_24 pkgs.util-linux pkgs.bash ];
        meta.description = "Tools to build, run, and test the Nitro Sandbox demo";
      };
      sandbox = import ./nitro/nix/sandbox.nix {
        inherit pkgs kernel rust package eif;
        authorizedKeys =
          let path = ssh-keys + "/authorized_keys";
          in if builtins.pathExists path then path
          else throw "Sandbox builds require an SSH public key. Use: bash nitro/scripts/build.sh PUBLIC_KEY_FILE [OUTPUT_LINK]";
      };
    in {
      packages.x86_64-linux = releasePackages "x86_64-linux";
      packages.${system} = releasePackages system // {
        attest-link = package;
        attest-link-rust = rust;
        attest-link-wasm = wasm;
        nitro-sandbox = sandbox;
        nitro-sandbox-kernel = kernel;
        nitro-eif = eif;
        nitro-host-tools = hostTools;
        firecracker = vmm;
        default = sandbox;
      };
      devShells.${system} = {
        default = pkgs.mkShell {
          packages = with pkgs; [ nodejs_24 cargo rustc rustfmt clippy openssl pkg-config jq shellcheck ];
        };
        ci = buildPkgs.mkShell {
          # CI supplies Node separately, using the official prebuilt release.
          packages = with buildPkgs; [ cargo rustc rustfmt openssl pkg-config ];
        };
        release = releaseShell system;
      };
      devShells.x86_64-linux.release = releaseShell "x86_64-linux";
      formatter.${system} = pkgs.nixfmt;
      checks.${system}.package = pkgs.runCommand "attest-link-package-tests" {
        nativeBuildInputs = [ pkgs.nodejs_24 pkgs.openssl ];
      } ''
        cp -r ${./package/test} test
        ln -s ${package}/share/attest-link/src src
        ln -s ${package}/share/attest-link/wasm wasm
        ln -s ${package}/share/attest-link/node_modules node_modules
        cp ${./package/package.json} package.json
        cp ${./package/.npmignore} .npmignore
        node --test test/*.test.js test/browser/*.test.js
        touch $out
      '';
    };
}
