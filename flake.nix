{
  description = "FileVault development environment and CLI";

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
    # Shared UI and companion crates must resolve to one tagged Git source.
    kitSources = nixpkgs.lib.unique (
      map (package: package.source or "") (
        builtins.filter
          (package: builtins.elem package.name ["ha-app-ui" "ha-app-kit-ha"])
          (builtins.fromTOML (builtins.readFile ./Cargo.lock)).package
      )
    );
    cargoLockFile =
      assert nixpkgs.lib.assertMsg (
        builtins.length kitSources <= 1
        && builtins.all
          (source: builtins.match "git[+]https://github[.]com/jessfraz/ha-app-kit[?]tag=v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?#[0-9a-f]{40}" source != null)
          kitSources
      ) "App Kit crates must use one tagged release from github.com/jessfraz/ha-app-kit.";
      ./Cargo.lock;
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
        cargoLock = {
          lockFile = cargoLockFile;
          allowBuiltinFetchGit = true;
          outputHashes = {
            "sqlx-0.9.0" = "sha256-kLvUfUy6vmL9LYU7nzHv+iB6cIJm2CjDf9Yo6wpWrWg=";
          };
        };
        cargoBuildFlags = ["--package" "ha-filevault"];
        cargoTestFlags = ["--package" "ha-filevault"];
        # Real-process HTTP fixtures need loopback access inside Darwin's sandbox.
        __darwinAllowLocalNetworking = true;
        meta = {
          description = "Home Assistant FileVault CLI";
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
          nodejs_22
          just
          actionlint
          shellcheck
          cargo-deny
        ];
      };
    });
  };
}
