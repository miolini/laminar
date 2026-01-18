use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub node: NodeConfig,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AddressConfig {
    pub address: String,
    pub gateway: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct NodeConfig {
    pub listen: SocketAddr,
    pub mtu: u16,
    pub tap_name: Option<String>,
    pub private_key: String,
    pub up_script: Option<String>,
    pub down_script: Option<String>,
    pub mac_address: Option<String>,
    pub dhcp: Option<bool>,
    pub addresses: Option<Vec<AddressConfig>>,
    pub dns: Option<Vec<String>>,
    // Number of parallel streams per connection (0 = Use Datagrams/Unreliable)
    pub streams: Option<usize>,
    pub bridge: Option<BridgeConfig>,
    #[serde(default)]
    pub bonding_mode: BondingMode,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BondingMode {
    #[default]
    WaterFilling,
    Random,
    Sticky,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct BridgeConfig {
    pub name: String,
    pub external_interface: Option<String>, // Physical interface to bridge with (e.g. eth0)
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct PeerConfig {
    pub name: String,
    pub public_key: String, // Base64 or Hex encoded
    pub endpoints: Vec<SocketAddr>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        // Using basic toml deserialization wrapper
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e))?;
        let cfg: Config = toml::from_str(&content).map_err(|e| ConfigError::Parse(e))?;
        Ok(cfg)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] toml::de::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml_str = r#"
            [node]
            listen = "127.0.0.1:9000"
            mtu = 1420
            tap_name = "laminar0"
            private_key = "key.pem"
            mac_address = "02:00:00:00:00:01"
            dhcp = true
            addresses = [
                { address = "127.0.0.1/24", gateway = "127.0.0.1" }
            ]
            dns = ["8.8.8.8"]

            [[peers]]
            name = "peer1"
            public_key = "abc"
            endpoints = ["127.0.0.1:9001", "127.0.0.1:9002"]
        "#;

        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.node.mtu, 1420);
        assert_eq!(cfg.node.private_key, "key.pem");
        assert_eq!(cfg.node.mac_address.unwrap(), "02:00:00:00:00:01");
        assert!(cfg.node.dhcp.unwrap());
        assert_eq!(
            cfg.node.addresses.as_ref().unwrap()[0].address,
            "127.0.0.1/24"
        );
        assert_eq!(
            cfg.node.addresses.as_ref().unwrap()[0]
                .gateway
                .as_ref()
                .unwrap(),
            "127.0.0.1"
        );
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].endpoints.len(), 2);
    }
}
