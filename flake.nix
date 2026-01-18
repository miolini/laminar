{
  description = "Laminar: Userspace L2 Mesh over Multi-path QUIC Datagrams";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        toolchain = pkgs.rust-bin.stable.latest.default;
        
        rustPlatform = pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };

        laminar = rustPlatform.buildRustPackage {
          pname = "laminar";
          version = "0.1.0";
          
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = [
            pkgs.pkg-config
          ];

          buildInputs = [
            # Add any system dependencies here
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          meta = with pkgs.lib; {
            description = "Userspace L2 Mesh over Multi-path QUIC Datagrams";
            homepage = "https://github.com/yourusername/laminar";
            license = licenses.mit;
            maintainers = [];
          };
        };
      in
      {
        packages.default = laminar;
        packages.laminar = laminar;

        devShells.default = pkgs.mkShell {
          buildInputs = [
            toolchain
            pkgs.rust-analyzer
            pkgs.pkg-config
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          shellHook = ''
            echo "🌊 Laminar Dev Environment"
            echo "   Components: Rust $(rustc --version), Cargo $(cargo --version)"
          '';
        };
      }
    );
}
