{
  description = "Laminar: Userspace L2 Mesh over Multi-path QUIC Datagrams";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    in
    flake-utils.lib.eachSystem supportedSystems (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        toolchain = pkgs.rust-bin.stable."1.81.0".default;
        
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
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          meta = with pkgs.lib; {
            description = "Userspace L2 Mesh over Multi-path QUIC Datagrams";
            homepage = "https://github.com/miolini/laminar";
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
    ) // {
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.laminar;
          toml = pkgs.formats.toml { };
          
          peerOpts = { name, ... }: {
            options = {
              name = lib.mkOption {
                type = lib.types.str;
                default = name;
              };
              publicKey = lib.mkOption {
                type = lib.types.str;
              };
              endpoints = lib.mkOption {
                type = lib.types.listOf lib.types.str;
              };
            };
          };

          laminarConfig = {
            node = {
              listen = cfg.listen;
              mtu = cfg.mtu;
              private_key = cfg.privateKey;
              streams = cfg.streams;
              bonding_mode = cfg.bondingMode;
              mac_address = cfg.macAddress;
              dhcp = cfg.dhcp;
              dns = cfg.dns;
              up_script = cfg.upScript;
              down_script = cfg.downScript;
              ipv4_address = cfg.ipv4Address;
              ipv4_mask = cfg.ipv4Mask;
              ipv4_gateway = cfg.ipv4Gateway;
            } // lib.optionalAttrs (cfg.tapName != null) {
              tap_name = cfg.tapName;
            } // lib.optionalAttrs (cfg.bridge != null) {
              bridge = cfg.bridge;
            };
            peers = lib.mapAttrsToList (name: value: {
              name = value.name;
              public_key = value.publicKey;
              endpoints = value.endpoints;
            }) cfg.peers;
          };

          configFile = toml.generate "laminar-config.toml" laminarConfig;
        in {
          options.services.laminar = {
            enable = lib.mkEnableOption "Laminar L2 Overlay Daemon";
            
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
            };

            listen = lib.mkOption {
              type = lib.types.str;
              default = "[::]:9000";
            };

            mtu = lib.mkOption {
              type = lib.types.int;
              default = 1420;
            };

            tapName = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
            };

            privateKey = lib.mkOption {
              type = lib.types.str;
              description = "The private key PEM content for the node.";
            };

            streams = lib.mkOption {
              type = lib.types.int;
              default = 4;
            };

            bondingMode = lib.mkOption {
              type = lib.types.enum [ "water_filling" "random" "sticky" ];
              default = "water_filling";
            };

            bridge = lib.mkOption {
              type = lib.types.nullOr (lib.types.submodule {
                options = {
                  name = lib.mkOption { type = lib.types.str; };
                  external_interface = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
                };
              });
              default = null;
            };

            macAddress = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = "02:00:00:00:00:01";
            };

            dhcp = lib.mkOption {
              type = lib.types.bool;
              default = true;
            };

            dns = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "8.8.8.8" "1.1.1.1" ];
            };

            upScript = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
            };

            downScript = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
            };
            
            ipv4Address = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Static IPv4 address to assign to the interface.";
            };

            ipv4Mask = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Static IPv4 mask to assign to the interface.";
            };

            ipv4Gateway = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Static IPv4 gateway to assign to the interface.";
            };

            peers = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule peerOpts);
              default = { };
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
            };
          };

          config = lib.mkIf cfg.enable {
            networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ 
              (lib.toInt (builtins.elemAt (lib.splitString ":" cfg.listen) ((builtins.length (lib.splitString ":" cfg.listen)) - 1))) 
            ];

            systemd.services.laminar = {
              description = "Laminar Bonded QUIC VPN";
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              wantedBy = [ "multi-user.target" ];
              
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/laminar run --config ${configFile}";
                Restart = "always";
                
                # Security hardening
                CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
                AmbientCapabilities = [ "CAP_NET_ADMIN" ];
                ProtectSystem = "full";
                ProtectHome = "read-only";
                PrivateTmp = true;
              };
            };
          };
        };
    };
}
