use bytes::{BufMut, BytesMut};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::{AsyncDevice, Configuration, Device, Layer};

pub struct Interface {
    device: AsyncDevice,
    is_l3: bool,
}

impl Interface {
    pub fn new(name: Option<String>, mtu: u16) -> io::Result<Self> {
        let mut config = Configuration::default();
        config.mtu(mtu as i32);

        // Try L2 first
        if let Some(ref n) = name {
            config.name(n);
        }
        config.layer(Layer::L2);
        config.up();

        match tun::create_as_async(&config) {
            Ok(device) => Ok(Self {
                device,
                is_l3: false,
            }),
            Err(e) => {
                // Fallback to L3
                // Warning: We use println here because tracing might not be fully initialized or to ensure visibility
                println!(
                    "L2 Interface creation failed ({}), falling back to L3 (TUN) mode.",
                    e
                );
                let mut config = Configuration::default();
                config.mtu(mtu as i32);
                if let Some(ref n) = name {
                    config.name(n);
                }
                config.layer(Layer::L3);
                config.up();

                let device = tun::create_as_async(&config)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                Ok(Self {
                    device,
                    is_l3: true,
                })
            }
        }
    }

    pub fn split(self) -> (InterfaceReader, InterfaceWriter) {
        let (reader, writer) = tokio::io::split(self.device);
        (
            InterfaceReader {
                reader,
                is_l3: self.is_l3,
            },
            InterfaceWriter {
                writer,
                is_l3: self.is_l3,
            },
        )
    }

    pub fn name(&self) -> io::Result<String> {
        self.device
            .get_ref()
            .name()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

pub struct InterfaceReader {
    reader: tokio::io::ReadHalf<AsyncDevice>,
    is_l3: bool,
}

impl InterfaceReader {
    pub async fn read_packet(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        if self.is_l3 {
            // Read into buffer, assuming it has capacity.
            let start_len = buf.len();
            let n = self.reader.read_buf(buf).await?;
            if n == 0 {
                return Ok(0);
            }

            // Packet is at buf[start_len..start_len+n].
            // To fake L2, we need to inspect IP header at buf[start_len].
            // IPv4: version=4 (0x4X). IPv6: version=6 (0x6X).
            let first_byte = buf[start_len];
            let ip_ver = first_byte >> 4;
            let eth_type: u16 = if ip_ver == 6 { 0x86DD } else { 0x0800 };

            // We need to insert 14 bytes (Eth Header) at start_len.
            // BytesMut doesn't support easy insertion.
            // We strip the read data out, then write header, then write data back.
            let ip_data = buf.split_off(start_len);

            // buf is now truncated to start_len.
            // ip_data contains the packet.
            // Put header into buf.
            let mut header = [0u8; 14];
            // Dst: Broadcast (ff:ff:ff:ff:ff:ff) for Sieve compatibility
            header[0..6].fill(0xff);
            // Src: Zero or random. 00:00:00:00:00:00 is fine.
            // Type:
            header[12] = (eth_type >> 8) as u8;
            header[13] = (eth_type & 0xff) as u8;

            buf.put_slice(&header);
            buf.put(ip_data); // appends the ip_data bytes

            Ok(n + 14)
        } else {
            self.reader.read_buf(buf).await
        }
    }
}

pub struct InterfaceWriter {
    writer: tokio::io::WriteHalf<AsyncDevice>,
    is_l3: bool,
}

impl InterfaceWriter {
    pub async fn write_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.is_l3 {
            // Strip Ethernet header (14 bytes)
            if buf.len() < 14 {
                // Too small, ignore
                return Ok(());
            }
            self.writer.write_all(&buf[14..]).await
        } else {
            self.writer.write_all(buf).await
        }
    }
}
