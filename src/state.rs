use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeState {
    pub uptime_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub peers: Vec<PeerState>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PeerState {
    pub name: String,
    pub endpoints: Vec<String>,
    pub stats: LinkStatsSnapshot,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LinkStatsSnapshot {
    pub rtt_ms: u64,
    pub bandwidth_mbps: f64,
    pub inflight_bytes: usize,
}

// Shared State Container
