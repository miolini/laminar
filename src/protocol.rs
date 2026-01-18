use bytes::{Buf, BufMut, Bytes, BytesMut};
// use serde::{Deserialize, Serialize}; // Unused
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Packet too short")]
    PacketTooShort,
    #[error("Invalid magic")]
    InvalidMagic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Ethernet = 0x01,
    Keepalive = 0x02,
    Config = 0x03,
}

impl TryFrom<u8> for PacketType {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(PacketType::Ethernet),
            0x02 => Ok(PacketType::Keepalive),
            0x03 => Ok(PacketType::Config),
            _ => Err(()),
        }
    }
}

/// The header for every Laminar fragment sent over QUIC.
/// Packed to be minimal.
///
/// Layout:
/// - frame_id: u64 (8 bytes)
/// - total_frags: u8 (1 byte)
/// - frag_index: u8 (1 byte)
/// - flags/type: u8 (1 byte)
/// Total: 11 bytes
#[derive(Debug, Clone)]
pub struct LaminarHeader {
    pub frame_id: u64,
    pub total_frags: u8,
    pub frag_index: u8,
    pub packet_type: PacketType,
}

impl LaminarHeader {
    pub const SIZE: usize = 11;

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.frame_id);
        buf.put_u8(self.total_frags);
        buf.put_u8(self.frag_index);
        buf.put_u8(self.packet_type as u8);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        if buf.remaining() < Self::SIZE {
            return Err(ProtocolError::PacketTooShort);
        }
        let frame_id = buf.get_u64();
        let total_frags = buf.get_u8();
        let frag_index = buf.get_u8();
        let type_byte = buf.get_u8();

        let packet_type =
            PacketType::try_from(type_byte).map_err(|_| ProtocolError::InvalidMagic)?;

        Ok(Self {
            frame_id,
            total_frags,
            frag_index,
            packet_type,
        })
    }
}

pub struct Fragmenter {
    next_frame_id: u64,
}

impl Fragmenter {
    pub fn new() -> Self {
        Self { next_frame_id: 0 }
    }

    /// Splits a large payload into smaller chunks, each with a LaminarHeader.
    /// `mtu` is the maximum size of the *payload* of the QUIC Datagram (so max UDP payload - QUIC overhead).
    /// Typically we want the resulting Datagram to be < ~1200-1400 bytes.
    pub fn split(&mut self, payload: Bytes, max_datagram_size: usize) -> Vec<Bytes> {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);

        let header_size = LaminarHeader::SIZE;
        let chunk_size = max_datagram_size.saturating_sub(header_size);

        if chunk_size == 0 {
            // Should verify configuration elsewhere
            return vec![];
        }

        let total_len = payload.len();
        let total_frags = (total_len + chunk_size - 1) / chunk_size;

        // Safety check for u8 overflow
        if total_frags > 255 {
            // Drop oversized frame or handle error.
            // For L2 frames (max 1500-9000), 255 fragments is plenty (255 * 1000 = 255KB).
            return vec![];
        }

        let mut fragments = Vec::with_capacity(total_frags);
        let mut offset = 0;

        for i in 0..total_frags {
            let end = std::cmp::min(offset + chunk_size, total_len);
            let chunk = payload.slice(offset..end);

            let header = LaminarHeader {
                frame_id,
                total_frags: total_frags as u8,
                frag_index: i as u8,
                packet_type: PacketType::Ethernet, // Assuming Ethernet for data
            };

            let mut buf = BytesMut::with_capacity(header_size + chunk.len());
            header.encode(&mut buf);
            buf.put(chunk);

            fragments.push(buf.freeze());
            offset = end;
        }

        fragments
    }
}

pub struct Reassembler {
    // Map frame_id -> (received_count, map of index -> data)
    // We also need a timestamp to GC old partial frames.
    // For simplicity, we'll just use a BTreeMap and maybe clear it periodically or on limits.
    // Real implementation needs robust windowing/GC.
    partial_frames: BTreeMap<u64, PartialFrame>,
}

use std::time::Instant;

struct PartialFrame {
    total_frags: u8,
    received_frags: u8,
    chunks: BTreeMap<u8, Bytes>,
    created_at: Instant,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            partial_frames: BTreeMap::new(),
        }
    }

    /// Processes a packet. If it completes a frame, returns the full frame.
    pub fn accept(&mut self, mut packet: Bytes) -> Result<Option<Bytes>, ProtocolError> {
        let header = LaminarHeader::decode(&mut packet)?;
        let payload = packet; // remaining bytes

        if header.packet_type == PacketType::Keepalive {
            return Ok(None);
        }

        if header.total_frags == 1 {
            // Optimized path for unfragmented
            return Ok(Some(payload));
        }

        let frame = self
            .partial_frames
            .entry(header.frame_id)
            .or_insert_with(|| PartialFrame {
                total_frags: header.total_frags,
                received_frags: 0,
                chunks: BTreeMap::new(),
                created_at: Instant::now(),
            });

        // Duplicate check
        if frame.chunks.contains_key(&header.frag_index) {
            return Ok(None);
        }

        frame.chunks.insert(header.frag_index, payload);
        frame.received_frags += 1;

        if frame.received_frags == frame.total_frags {
            // Reassemble
            // Remove from map
            let frame = self.partial_frames.remove(&header.frame_id).unwrap();

            let mut total_size = 0;
            for chunk in frame.chunks.values() {
                total_size += chunk.len();
            }
            let mut full_frame = BytesMut::with_capacity(total_size);
            for i in 0..frame.total_frags {
                if let Some(chunk) = frame.chunks.get(&i) {
                    full_frame.put(chunk.clone());
                } else {
                    // Should be impossible if logic is correct
                    return Ok(None);
                }
            }
            return Ok(Some(full_frame.freeze()));
        }

        // Cleanup old/stale frames
        self.cleanup();

        Ok(None)
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let timeout = std::time::Duration::from_secs(5);

        // Remove frames older than 5 seconds or if map is too large
        self.partial_frames
            .retain(|_, frame| now.duration_since(frame.created_at) < timeout);

        if self.partial_frames.len() > 1000 {
            // Hard limit to prevent memory bloat if retention is too slow
            if let Some(&first_key) = self.partial_frames.keys().next() {
                self.partial_frames.remove(&first_key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    #[test]
    fn test_fragmentation_simple() {
        let mut frag = Fragmenter::new();
        let mut reasm = Reassembler::new();

        let payload = Bytes::from("Hello World, this is a test of the emergency broadcast system.");
        let mtu = 20; // Small MTU to force fragmentation

        let packets = frag.split(payload.clone(), mtu);
        println!("Split into {} packets", packets.len());
        assert!(packets.len() > 1);

        let mut reconstructed = None;
        for packet in packets {
            let res = reasm.accept(packet).expect("Failed to accept");
            if let Some(data) = res {
                reconstructed = Some(data);
            }
        }

        assert_eq!(reconstructed.unwrap(), payload);
    }

    #[test]
    fn test_fragmentation_shuffled() {
        let mut frag = Fragmenter::new();
        let mut reasm = Reassembler::new();

        let data_len = 5000;
        let mut data = Vec::with_capacity(data_len);
        for i in 0..data_len {
            data.push((i % 255) as u8);
        }
        let payload = Bytes::from(data);
        let mtu = 100;

        let mut packets = frag.split(payload.clone(), mtu);
        assert!(packets.len() > 10);

        // Shuffle
        let mut rng = thread_rng();
        packets.shuffle(&mut rng);

        let mut reconstructed = None;
        for packet in packets {
            let res = reasm.accept(packet).expect("Failed to accept");
            if let Some(data) = res {
                reconstructed = Some(data);
            }
        }

        assert_eq!(reconstructed.unwrap(), payload);
    }
}
