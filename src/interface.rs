use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::{AsyncDevice, Configuration, Device};

pub struct Interface {
    device: AsyncDevice,
}

impl Interface {
    pub fn new(name: Option<String>, mtu: u16) -> io::Result<Self> {
        let mut config = Configuration::default();
        config.layer(tun::Layer::L2);
        config.mtu(mtu as i32);

        if let Some(n) = name {
            config.name(n);
        }

        // We need sending/receiving
        config.up();

        let device =
            tun::create_as_async(&config).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self { device })
    }

    pub fn split(self) -> (InterfaceReader, InterfaceWriter) {
        let (reader, writer) = tokio::io::split(self.device);
        (InterfaceReader { reader }, InterfaceWriter { writer })
    }

    pub fn name(&self) -> io::Result<String> {
        // AsyncDevice wraps the actual device. We access it via get_ref().
        // Note: Depending on tun crate version, name() might be directly on AsyncDevice
        // or on the inner device.
        // Assuming AsyncDevice implements AsRef<Device> or get_ref().
        // tun 0.6 AsyncDevice is usually a wrapper.
        // Let's try get_ref().name().
        // If compilation fails, I will check.
        self.device
            .get_ref()
            .name()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

pub struct InterfaceReader {
    reader: tokio::io::ReadHalf<AsyncDevice>,
}

impl InterfaceReader {
    pub async fn read_packet(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        self.reader.read_buf(buf).await
    }
}

pub struct InterfaceWriter {
    writer: tokio::io::WriteHalf<AsyncDevice>,
}

impl InterfaceWriter {
    pub async fn write_packet(&mut self, buf: &[u8]) -> io::Result<()> {
        self.writer.write_all(buf).await
    }
}
