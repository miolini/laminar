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
            // Zero-copy optimization: Reserve space for Ethernet header
            buf.put_bytes(0, 14);
            let header_len = 14;
            let start_len = buf.len(); // Should be existing_len + 14

            let n = self.reader.read_buf(buf).await?;
            if n == 0 {
                // EOF or empty
                buf.truncate(start_len - header_len);
                return Ok(0);
            }

            if n < 20 {
                // Minimum IPv4 header
                buf.truncate(start_len - header_len);
                return Ok(0);
            }

            // Packet data is at buf[start_len .. start_len + n]
            // Header space is at buf[start_len - 14 .. start_len]

            let first_byte = buf[start_len];
            let ip_ver = first_byte >> 4;

            if ip_ver != 4 && ip_ver != 6 {
                // Not IP, drop
                buf.truncate(start_len - header_len);
                return Ok(0);
            }

            let eth_type: u16 = if ip_ver == 6 { 0x86DD } else { 0x0800 };

            // Fill the reserved header space
            let mut header = [0u8; 14];
            header[0..6].fill(0xff); // Dst: Broadcast
            // Src: 00:00:00:00:00:00
            header[12] = (eth_type >> 8) as u8;
            header[13] = (eth_type & 0xff) as u8;

            // Copy header into the reserved space
            // BytesMut isn't a slice, but we can access via index if mutable?
            // BytesMut implements AsMut<[u8]>. But self.reader.read_buf might have reallocated?
            // "The returned BytesMut shares the underlying memory" -> No, read_buf modifies 'buf' in place.
            // So we can index into it.

            let buf_slice = &mut buf[start_len - 14..start_len];
            buf_slice.copy_from_slice(&header);

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
