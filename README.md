# Laminar: High-Performance L2 Mesh

<div align="center">

![Laminar](https://img.shields.io/badge/status-active-success.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/built_with-Rust-orange.svg)

**A userspace L2 mesh network built on top of multi-path QUIC Datagrams.**

</div>

---

## 📖 Introduction

**Laminar** is a next-generation overlay network designed to bond heterogeneous physical links (WiFi, LTE, Ethernet, Starlink) into a single, resilient, high-bandwidth Ethernet segment. Unlike traditional VPNs that route IP packets over a single tunnel, Laminar operates at **Layer 2 (Ethernet)**, creating a virtual switch that spans across the internet.

It leverages **QUIC Datagrams** to provide a strictly unreliable transport layer, preventing the dreaded "TCP-over-TCP" meltdown. By handling fragmentation and reassembly at the application layer, Laminar supports jumbo frames and transparently bridges local LANs over the mesh.

## ✨ Key Features

- **🌊 Multi-Path Bonding**: Aggregate bandwidth from multiple interfaces (e.g., 5G + Fiber).
- **🕸️ L2 Bridging**: Seamlessly bridge your local Ethernet segment (`eth0`) with the mesh (`tap0`), extending your LAN globally.
- **⚡ Traffic Sieve**: Intelligent packet classification that routes interactive traffic (VoIP, SSH) via the lowest latency link and bulk traffic (File Transfer) via the highest bandwidth pipes.
- **🛡️ Custom Fragmentation**: Handles MTUs larger than the underlying path (1500+ bytes) without relying on IP fragmentation.
- **🔒 Security**: End-to-end encryption using **TLS 1.3** (via QUIC).
- **📊 Observability**: Built-in interactive **TUI** and local **REST API** for real-time monitoring.

## 🏗️ Architecture

### Data Plane: The Sieve & Water-Filling
Laminar implements a sophisticated scheduling algorithm:

1.  **Ingress**: Frames enter via the TAP interface.
2.  **Classification**:
    *   **Interactive**: ARP, ICMP, DNS, TCP SYN/ACK.
    *   **Bulk**: Payload-heavy TCP/UDP packets.
3.  **Scheduling**:
    *   **Interactive** traffic is **always** routed via the link with the lowest RTT.
    *   **Bulk** traffic is distributed based on the **Bonding Mode**.

### Bonding Modes
*   **Water-Filling (Default)**: Stripes fragments across all links, effectively summing their bandwidth. Best for throughput.
*   **Sticky**: Hashes the 5-tuple (IP/Port) to ensure a single flow stays on one link. Best for minimizing jitter/reordering.
*   **Random**: Purely random distribution. High entropy.

## 🚀 Installation

### Prerequisites
*   **Linux** or **macOS**.
*   **Rust** toolchain (stable).
*   **Root privileges** (required for `TUN/TAP` device creation).

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/laminar.git
cd laminar

# Build release binary
cargo build --release

# The binary will be at ./target/release/laminar
```

### Using Nix
Laminar is fully Nix-compatible.

```bash
nix build .
# Result linked to ./result/bin/laminar
```

## ⚙️ Configuration

Laminar uses a `TOML` configuration file.

### 1. Generating Keys
Each node requires a private key for TLS identity.

```bash
./target/release/laminar gen-keys --key key.pem
```

### 2. `config.toml` Reference

```toml
[node]
# Listen address (Dual Stack IPv4/IPv6)
listen = "[::]:9000"

# Virtual Interface settings
tap_name = "laminar0"
mtu = 1420
mac_address = "02:00:00:00:00:01"

# TLS Identity
private_key = "key.pem"

# Bonding Configuration
# "water_filling" | "random" | "sticky"
bonding_mode = "water_filling"
# Multi-stream support (0 = Datagrams only, N = N parallel streams)
streams = 4 

# L2 Bridging (Optional)
# Uncomment to bridge tap0 with a physical interface (e.g., eth1)
#[node.bridge]
#name = "br0"
#external_interface = "eth1"

# Network Setup Hooks
up_script = "ip link set dev laminar0 up && ip addr add 10.100.0.1/24 dev laminar0"
down_script = "echo 'Shutting down'"

# Peer Definitions
[[peers]]
name = "site-b"
# Peer's Public Certificate (Base64 or Path) - Currently checking exact match/pinned
public_key = "..." 
# List of endpoints to connect to (Multi-path)
endpoints = ["192.168.1.5:9000", "[2001:db8::1]:9000"]
```

## 🖥️ Usage

### Running the Daemon
```bash
sudo ./target/release/laminar run --config config.toml
```

### Interactive Monitoring (TUI)
Laminar includes a dashboard to view real-time stats (RTT, Bandwidth, Uptime).

```bash
./target/release/laminar show --watch
```
*(Requires the daemon to be running)*

### One-Shot Status (JSON)
Useful for scripts or external monitoring tools (Zabbix, Prometheus adapters).

```bash
./target/release/laminar show
```
Target API: `http://127.0.0.1:3000/state`.

## 🛠️ Performance Tuning

*   **MTU**: Keep `mtu = 1420` to fit within standard internet limits without fragmentation. Laminar handles larger frames by slicing them, but avoiding this overhead is better.
*   **Streams**: Use `streams = 4` or `8` for high-throughput bulk transfer environments. Use `0` (Datagrams only) for strictly real-time/unreliable needs.
*   **Buffers**: Increase OS UDP buffers (`sysctl -w net.core.rmem_max=2500000`) for high-speed WAN links.

## 🛣️ Roadmap

- [x] Multi-path QUIC Datagrams
- [x] Custom Fragmentation Protocol
- [x] Traffic Sieve (Interactive vs Bulk)
- [x] Bonding Modes (Water-Filling, Sticky)
- [x] L2 Bridging
- [x] Local API & TUI
- [ ] Forward Error Correction (FEC)
- [ ] Dynamic Peer Discovery (DHT)
- [ ] NAT Traversal / Hole Punching

## ❄️ NixOS Integration

Laminar is designed to be a first-class citizen on NixOS.

### 1. Flake Integration
Add to your `flake.nix`:

```nix
{
  inputs.laminar.url = "github:miolini/laminar";

  outputs = { self, nixpkgs, laminar, ... }: {
    nixosConfigurations.my-router = nixpkgs.lib.nixosSystem {
      modules = [
        laminar.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

### 2. Service Configuration (`configuration.nix`)

```nix
{ config, pkgs, ... }: {
  services.laminar = {
    enable = true;
    listenAddress = "[::]";
    listenPort = 9000;
    
    # Path to secret key (should be deployed via sops-nix or agenix)
    privateKeyFile = "/run/secrets/laminar/key.pem";
    
    # Peer Configuration
    peers = {
      "site-b" = {
        publicKey = "...";
        endpoints = [ "192.168.1.5:9000" ];
      };
    };
    
    # Auto-open firewall
    openFirewall = true;
  };
}
```

## 📜 License

MIT License. See `LICENSE` for details.
