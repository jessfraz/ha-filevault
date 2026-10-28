{
  description = "FileVault development environment and read-only CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    ...
  }: let
    systems = ["aarch64-darwin" "aarch64-linux" "x86_64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        overlays = [(import rust-overlay)];
      };
    rustFor = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
  in {
    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      rust = rustFor pkgs;
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rust;
        rustc = rust;
      };
    in rec {
      ha-filevault = rustPlatform.buildRustPackage {
        pname = "ha-filevault";
        version = (builtins.fromTOML (builtins.readFile ./cli/Cargo.toml)).package.version;
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./LICENSE
            ./cli
            ./src
          ];
        };
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = ["--package" "ha-filevault"];
        cargoTestFlags = ["--package" "ha-filevault"];
        # Real-process HTTP fixtures need loopback access inside Darwin's sandbox.
        __darwinAllowLocalNetworking = true;
        meta = {
          description = "Read-only external API CLI for Home Assistant FileVault";
          license = pkgs.lib.licenses.mit;
          mainProgram = "ha-filevault";
          platforms = systems;
        };
      };
      default = ha-filevault;
    });
    apps = forAllSystems (system: rec {
      ha-filevault = {
        type = "app";
        meta = self.packages.${system}.ha-filevault.meta;
        program = "${self.packages.${system}.ha-filevault}/bin/ha-filevault";
      };
      default = ha-filevault;
    });
    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [
          (rustFor pkgs)
          python314
          uv
          cmake
          pkg-config
          jq
          just
          actionlint
          shellcheck
          cargo-deny
        ];
      };
    });
  };
}
