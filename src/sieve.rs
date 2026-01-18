use crate::config::BondingMode;
use crate::protocol::Fragmenter;
use bytes::Bytes;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
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

            // ICMP (1), IGMP (2)
            if protocol == 1 || protocol == 2 {
                return TrafficClass::Interactive;
            }

            // TCP (6)
            if protocol == 6 {
                let tcp_offset = 14 + ip_header_len as usize;
                if frame.len() > tcp_offset + 13 {
                    // SYN(0x02), RST(0x04), FIN(0x01) or small packets
                    let flags = frame[tcp_offset + 13];
                    if (flags & 0x07) != 0 || frame.len() < 256 {
                        return TrafficClass::Interactive;
                    }
                }
            }
        }

        // IPv6 (0x86DD)
        if eth_type == 0x86DD {
            if frame.len() < 54 {
                return TrafficClass::Interactive;
            }
            let next_header = frame[14 + 6];
            // ICMPv6 (58)
            if next_header == 58 {
                return TrafficClass::Interactive;
            }
            // Small packets
            if frame.len() < 256 {
                return TrafficClass::Interactive;
            }
        }

        // Default small packets to interactive
        if frame.len() < 512 {
            return TrafficClass::Interactive;
        }

        TrafficClass::Bulk
    }
}

use quinn::Connection;

#[allow(dead_code)]
pub struct Link {
    pub id: usize,
    pub name: String,
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
            connection,
            streams: streams
                .into_iter()
                .map(|s| Arc::new(TokioMutex::new(s)))
                .collect(),
            next_stream: 0,
        }
    }
}

use std::collections::HashMap;

pub struct Sieve {
    peers: HashMap<String, Vec<Link>>,
    mac_table: HashMap<[u8; 6], String>,
    fragmenter: Fragmenter,
    mode: BondingMode,
    mtu: u16,
}

impl Sieve {
    pub fn new(mode: BondingMode, mtu: u16) -> Self {
        Self {
            peers: HashMap::new(),
            mac_table: HashMap::new(),
            fragmenter: Fragmenter::new(),
            mode,
            mtu,
        }
    }

    pub fn add_link(&mut self, peer_name: String, link: Link) {
        self.peers.entry(peer_name).or_default().push(link);
    }

    pub fn learn_mac(&mut self, mac: [u8; 6], peer_name: String) {
        // Only learn if not already mapped or update if changed
        self.mac_table.insert(mac, peer_name);
    }

    pub async fn send_on_links(&mut self, frame: Bytes) {
        if self.peers.is_empty() {
            return;
        }

        let class = Classifier::classify(&frame);
        let frame_hash = self.calculate_flow_hash(&frame);
        let mtu = self.mtu as usize - 40; // Conservative overhead for LaminarHeader + QUIC/UDP/IP
        let fragments = self.fragmenter.split(frame.clone(), mtu);

        // Determine destination peers
        let dst_mac = if frame.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&frame[0..6]);
            Some(mac)
        } else {
            None
        };

        let target_peer = dst_mac.and_then(|mac| {
            if mac == [0xff; 6] {
                None // Broadcast
            } else {
                self.mac_table.get(&mac).cloned()
            }
        });

        match target_peer {
            Some(peer_name) => {
                // Unicast: Send to specific peer
                if let Some(links) = self.peers.get_mut(&peer_name) {
                    Self::send_to_links(links, class, fragments, self.mode, frame_hash).await;
                }
            }
            None => {
                // Broadcast or Unknown: Flood to all peers
                for links in self.peers.values_mut() {
                    // Note: In real mesh, we should avoid loops.
                    // Here we just send to all configured peers.
                    Self::send_to_links(links, class, fragments.clone(), self.mode, frame_hash)
                        .await;
                }
            }
        }
    }

    async fn send_to_links(
        links: &mut Vec<Link>,
        class: TrafficClass,
        fragments: Vec<Bytes>,
        mode: BondingMode,
        frame_hash: u64,
    ) {
        match class {
            TrafficClass::Interactive => {
                if let Some(best_link) = links.iter_mut().min_by(|a, b| {
                    let rtt_a = a.connection.rtt();
                    let rtt_b = b.connection.rtt();
                    rtt_a.cmp(&rtt_b)
                }) {
                    for frag in fragments {
                        let _ = best_link.connection.send_datagram(frag);
                    }
                }
            }
            TrafficClass::Bulk => match mode {
                BondingMode::WaterFilling => {
                    for (i, frag) in fragments.into_iter().enumerate() {
                        let link_idx = i % links.len();
                        Self::send_frag_on_link(&mut links[link_idx], frag).await;
                    }
                }
                BondingMode::Random => {
                    let mut rng = rand::thread_rng();
                    for frag in fragments {
                        let random_idx = rng.gen_range(0..links.len());
                        Self::send_frag_on_link(&mut links[random_idx], frag).await;
                    }
                }
                BondingMode::Sticky => {
                    let idx = (frame_hash as usize) % links.len();
                    for frag in fragments {
                        Self::send_frag_on_link(&mut links[idx], frag).await;
                    }
                }
            },
        }
    }

    async fn send_frag_on_link(link: &mut Link, frag: Bytes) {
        if !link.streams.is_empty() {
            let stream_idx = link.next_stream % link.streams.len();
            link.next_stream = link.next_stream.wrapping_add(1);

            let stream_mutex = &link.streams[stream_idx];
            let len = frag.len() as u16;
            let len_bytes = len.to_be_bytes();

            // CRITICAL FIX: Do NOT spawn task here.
            // Interleaving multiple async write sequences on the same stream
            // without a lock held across the entire sequence will corrupt the stream.
            let mut s = stream_mutex.lock().await;
            if s.write_all(&len_bytes).await.is_err() {
                return;
            }
            let _ = s.write_all(&frag).await;
        } else {
            let _ = link.connection.send_datagram(frag);
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
                frame[26..34].hash(&mut hasher);
                // Protocol at 14+9 = 23
                let proto = frame[23];
                proto.hash(&mut hasher);
                // Ports: TCP/UDP usually at IP headers (20 bytes) -> 14+20 = 34
                if (proto == 6 || proto == 17) && frame.len() >= 38 {
                    frame[34..38].hash(&mut hasher);
                }
            }
            // If IPv6 (0x86DD at 12)
            else if frame[12] == 0x86 && frame[13] == 0xDD && frame.len() >= 54 {
                // IPv6 Src(16)+Dst(16) at offset 14+8 = 22
                frame[22..54].hash(&mut hasher);
                // Next Header at 14+6 = 20
                let proto = frame[20];
                proto.hash(&mut hasher);
                // Ports: TCP/UDP usually after fixed 40-byte header -> 14+40 = 54
                if (proto == 6 || proto == 17) && frame.len() >= 58 {
                    frame[54..58].hash(&mut hasher);
                }
            }
        } else {
            frame.hash(&mut hasher);
        }
        hasher.finish()
    }

    pub fn get_stats(&self) -> Vec<(String, crate::state::LinkStatsSnapshot)> {
        let mut all_stats = Vec::new();
        for peer_links in self.peers.values() {
            for l in peer_links {
                let q_stats = l.connection.stats();
                let rtt = l.connection.rtt();

                all_stats.push((
                    l.name.clone(),
                    crate::state::LinkStatsSnapshot {
                        rtt_ms: rtt.as_millis() as u64,
                        bandwidth_mbps: (q_stats.path.sent_packets as f64 * 8.0) / 1_000_000.0, // Placeholder for actual BW
                        inflight_bytes: q_stats.path.cwnd as usize, // approximate
                    },
                ));
            }
        }
        all_stats
    }

    pub fn send_keepalives(&mut self) {
        let header = crate::protocol::LaminarHeader {
            frame_id: 0,
            total_frags: 1,
            frag_index: 0,
            packet_type: crate::protocol::PacketType::Keepalive,
        };
        let mut buf = bytes::BytesMut::with_capacity(crate::protocol::LaminarHeader::SIZE);
        header.encode(&mut buf);
        let data = buf.freeze();

        for links in self.peers.values_mut() {
            for link in links {
                let _ = link.connection.send_datagram(data.clone());
            }
        }
    }
}
