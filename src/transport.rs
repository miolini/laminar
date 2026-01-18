use quinn::{Connection, Endpoint};
// use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct Transport {
    pub endpoint: Endpoint,
}

impl Transport {
    pub fn new(config: &crate::config::NodeConfig) -> anyhow::Result<Self> {
        let server_config = configure_server(config)?;

        // Manual socket creation for dual-stack support
        let addr = config.listen;
        let socket = socket2::Socket::new(
            if addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        // Allow reusing address/port (good for dev/restarts)
        socket.set_reuse_address(true)?;
        #[cfg(not(windows))]
        socket.set_reuse_port(true)?; // Posix only

        // Dual-stack logic:
        // If binding to IPv6 ID_ANY (::), we want to accept both V4 and V6 (Dual Stack).
        // By default, Linux might be 0 (Dual), Windows 1 (V6 Only). We force it.
        // If user wants STRICT V6 Only, they should arguably bind to specific V6 or we'd need a config flag.
        // For now, we assume [::] means "Listen on everything".
        if addr.is_ipv6() {
            // For [::], we want dual stack -> v6_only = false
            // For specific V6, it doesn't matter much but false usually allows v4-mapped if needed?
            // Actually, usually you only disable v6_only if you want to support v4-mapped.
            // Let's enable dual stack.
            socket.set_only_v6(false)?;
        }

        socket.bind(&addr.into())?;
        socket.set_nonblocking(true)?;

        // Convert to std::net::UdpSocket -> tokio::net::UdpSocket -> Endpoint
        let std_socket: std::net::UdpSocket = socket.into();
        let endpoint = Endpoint::new(
            Default::default(),
            Some(server_config),
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )?;

        Ok(Self { endpoint })
    }
    pub async fn connect(&self, addr: SocketAddr, server_name: &str) -> anyhow::Result<Connection> {
        let client_cfg = configure_client();
        // connect_with takes ClientConfig directly? No, Endpoint is configured or we use connect_with
        let connection = self
            .endpoint
            .connect_with(client_cfg, addr, server_name)?
            .await?;
        Ok(connection)
    }
}

fn configure_server(config: &crate::config::NodeConfig) -> anyhow::Result<quinn::ServerConfig> {
    let (cert_chain, key) = load_identity(&config.private_key)?;

    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key)?;

    // Enable datagrams
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(10).try_into().unwrap()));
    transport_config.datagram_receive_buffer_size(Some(1024 * 1024));
    transport_config.datagram_send_buffer_size(1024 * 1024);
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

fn load_identity(
    pem_content: &str,
) -> anyhow::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let key_pair = rcgen::KeyPair::from_pem(pem_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse key: {}", e))?;

    let subject_alt_names = vec!["localhost".to_string(), "laminar-node".to_string()];
    let mut params = rcgen::CertificateParams::new(subject_alt_names);
    params.key_pair = Some(key_pair);

    let cert = rcgen::Certificate::from_params(params)?;
    let cert_der = cert.serialize_der()?;
    let priv_key_der = cert.serialize_private_key_der();

    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key_der.into());
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];

    Ok((cert_chain, priv_key))
}

fn configure_client() -> quinn::ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    // Skip verification for dev (for now, eventually replace with pinning)
    crypto
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification));

    // Fix: Wrap into QuicClientConfig
    // QuicClientConfig needs to be created from rustls::ClientConfig
    // Note: unwrap is safe here as long as crypto is valid for QUIC (TLS 1.3)
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(1024 * 1024));
    transport_config.datagram_send_buffer_size(1024 * 1024);
    client_config.transport_config(Arc::new(transport_config));

    client_config
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
