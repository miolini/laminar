use crate::config::BondingMode;
use crate::protocol::Fragmenter;
use bytes::Bytes;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Interactive, // ARP, ICMP, TCP SYN/ACK, DNS, small packets
    Bulk,        // Large TCP data, UDP streams
}

pub struct Classifier;

impl Classifier {
    pub fn classify(frame: &[u8]) -> TrafficClass {
        // Simple heuristic based on EthType and size
        if frame.len() < 14 {
            return TrafficClass::Interactive; // Junk/Tiny
        }

        // Ethernet header: Dst(6) + Src(6) + Type(2)
        let eth_type = u16::from_be_bytes([frame[12], frame[13]]);

        // ARP (0x0806) is critical
        if eth_type == 0x0806 {
            return TrafficClass::Interactive;
        }

        // IPv4 (0x0800)
        if eth_type == 0x0800 {
            // Check IP header length
            if frame.len() < 34 {
                return TrafficClass::Interactive;
            }
            let ip_header_len = (frame[14] & 0x0F) * 4;
            let protocol = frame[14 + 9];

            // ICMP (1)
            if protocol == 1 {
                return TrafficClass::Interactive;
            }

            // TCP (6)
            if protocol == 6 {
                // Check flags if we can
                let tcp_offset = 14 + ip_header_len as usize;
                if frame.len() > tcp_offset + 13 {
                    // let flags = frame[tcp_offset + 13];
                    // SYN(0x02), RST(0x04), ACK(0x10) without data?
                    // Heuristic: Small TCP packets are likely control/interactive
                    if frame.len() < 128 {
                        return TrafficClass::Interactive;
                    }
                }
            }
        }

        // Default small packets to interactive
        if frame.len() < 256 {
            return TrafficClass::Interactive;
        }

        TrafficClass::Bulk
    }
}

#[allow(dead_code)]
pub struct LinkStats {
    pub rtt: Duration,
    pub bandwidth_estimate: u64, // bytes per second
    pub inflight: usize,         // bytes currently sent but not acked (approx)
}

use quinn::Connection;

#[allow(dead_code)]
pub struct Link {
    pub id: usize,
    pub name: String,
    pub stats: Arc<StdMutex<LinkStats>>,
    pub connection: Connection,
    pub streams: Vec<Arc<TokioMutex<quinn::SendStream>>>,
    pub next_stream: usize,
}

impl Link {
    pub fn new(
        id: usize,
        name: String,
        connection: Connection,
        streams: Vec<quinn::SendStream>,
    ) -> Self {
        Self {
            id,
            name,
            stats: Arc::new(StdMutex::new(LinkStats {
                rtt: Duration::from_millis(100), // Default start
                bandwidth_estimate: 1_000_000,   // 1MB/s default
                inflight: 0,
            })),
            connection,
            streams: streams
                .into_iter()
                .map(|s| Arc::new(TokioMutex::new(s)))
                .collect(),
            next_stream: 0,
        }
    }
}

pub struct Sieve {
    links: Vec<Link>,
    fragmenter: Fragmenter,
    mode: BondingMode,
}

impl Sieve {
    pub fn new(mode: BondingMode) -> Self {
        Self {
            links: Vec::new(),
            fragmenter: Fragmenter::new(),
            mode,
        }
    }

    pub fn add_link(&mut self, link: Link) {
        self.links.push(link);
    }

    pub async fn send_on_links(&mut self, frame: Bytes) {
        if self.links.is_empty() {
            return;
        }

        let class = Classifier::classify(&frame);
        let mtu = 1200;
        let fragments = self.fragmenter.split(frame.clone(), mtu);

        match class {
            TrafficClass::Interactive => {
                // Interactive always prefers best latency regardless of bonding mode
                if let Some(best_link) = self.get_best_latency_link() {
                    for frag in fragments {
                        let _ = best_link.connection.send_datagram(frag);
                    }
                }
            }
            TrafficClass::Bulk => match self.mode {
                BondingMode::WaterFilling => {
                    let link_indices = self.get_link_ids();
                    for (i, frag) in fragments.into_iter().enumerate() {
                        let link_idx = link_indices[i % link_indices.len()];
                        self.send_frag(link_idx, frag);
                    }
                }
                BondingMode::Random => {
                    let link_indices = self.get_link_ids();
                    let mut rng = rand::thread_rng();
                    for frag in fragments {
                        let random_idx = rng.gen_range(0..link_indices.len());
                        let link_idx = link_indices[random_idx];
                        self.send_frag(link_idx, frag);
                    }
                }
                BondingMode::Sticky => {
                    let link_indices = self.get_link_ids();
                    let hash = self.calculate_flow_hash(&frame);
                    let idx = (hash as usize) % link_indices.len();
                    let link_id = link_indices[idx];

                    for frag in fragments {
                        self.send_frag(link_id, frag);
                    }
                }
            },
        }
    }

    fn send_frag(&mut self, link_id: usize, frag: Bytes) {
        if let Some(link) = self.links.iter_mut().find(|l| l.id == link_id) {
            if !link.streams.is_empty() {
                // Use Stream Bonding (Round Robin within the link)
                let stream_idx = link.next_stream % link.streams.len();
                link.next_stream = link.next_stream.wrapping_add(1);

                let stream_mutex = &link.streams[stream_idx];

                let len = frag.len() as u16;
                let len_bytes = len.to_be_bytes();
                let frag_clone = frag.clone();
                let stream_clone = stream_mutex.clone();

                tokio::spawn(async move {
                    let mut s = stream_clone.lock().await;
                    let _ = s.write_all(&len_bytes).await;
                    let _ = s.write_all(&frag_clone).await;
                });
            } else {
                // Use Datagrams
                let _ = link.connection.send_datagram(frag);
            }
        }
    }

    fn calculate_flow_hash(&self, frame: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        // Hash basic L2/L3/L4 headers for stickiness
        if frame.len() > 14 {
            // Ethernet: Dst(6)+Src(6)
            frame[0..12].hash(&mut hasher);
            // If IPv4 (0x0800 at 12)
            if frame[12] == 0x08 && frame[13] == 0x00 && frame.len() >= 34 {
                // IPv4 Src(4)+Dst(4) at offset 26
                // (14 + 12 = 26)
                frame[26..34].hash(&mut hasher);
                // Protocol at 14+9 = 23
                frame[23].hash(&mut hasher);
                // Ports: TCP/UDP usually at IP headers (20 bytes) -> 14+20 = 34
                if (frame[23] == 6 || frame[23] == 17) && frame.len() >= 38 {
                    frame[34..38].hash(&mut hasher);
                }
            }
        } else {
            frame.hash(&mut hasher);
        }
        hasher.finish()
    }

    fn get_best_latency_link(&self) -> Option<&Link> {
        self.links.iter().min_by(|a, b| {
            let s_a = a.stats.lock().unwrap();
            let s_b = b.stats.lock().unwrap();
            s_a.rtt.cmp(&s_b.rtt)
        })
    }

    pub fn get_link_ids(&self) -> Vec<usize> {
        self.links.iter().map(|l| l.id).collect()
    }

    pub fn get_stats(&self) -> Vec<(String, crate::state::LinkStatsSnapshot)> {
        self.links
            .iter()
            .map(|l| {
                let stats = l.stats.lock().unwrap();
                (
                    l.name.clone(),
                    crate::state::LinkStatsSnapshot {
                        rtt_ms: stats.rtt.as_millis() as u64,
                        bandwidth_mbps: (stats.bandwidth_estimate as f64 * 8.0) / 1_000_000.0,
                        inflight_bytes: stats.inflight,
                    },
                )
            })
            .collect()
    }
}
