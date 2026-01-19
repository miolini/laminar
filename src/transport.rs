use base64::prelude::*;
use quinn::{Connection, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;
use x509_parser::prelude::*;

pub struct Transport {
    pub endpoint: Endpoint,
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Transport {
    pub fn new(config: &crate::config::NodeConfig, peer_keys: Vec<String>) -> anyhow::Result<Self> {
        let mut pinned_keys = HashSet::new();
        for key_b64 in peer_keys {
            if let Ok(der) = BASE64_STANDARD.decode(key_b64.trim()) {
                pinned_keys.insert(der);
            }
        }
        let verifier = Arc::new(PeerVerifier { pinned_keys });
        let (cert_chain, key) = load_identity(&config.private_key)?;
        let server_config =
            configure_server(cert_chain.clone(), key.clone_key(), verifier.clone())?;

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

        Ok(Self {
            endpoint,
            cert_chain,
            key,
        })
    }

    // Client-only constructor that binds to an ephemeral port
    pub fn new_client(
        private_key: &str,
        listen_addr: std::net::SocketAddr,
    ) -> anyhow::Result<Self> {
        let (cert_chain, key) = load_identity(private_key)?;

        let socket = socket2::Socket::new(
            if listen_addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        // Bind to ephemeral port on same IP family as daemon
        let bind_addr: std::net::SocketAddr = if listen_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        socket.bind(&bind_addr.into())?;
        socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket.into();

        // Client config with increased timeout
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            )?));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        client_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::new(
            Default::default(),
            None,
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        // Ideally we'd set the client config on the endpoint, but Endpoint::new takes server config.
        // For client connections, we pass config to connect().
        // Wait, Endpoint::new defaults don't apply to outgoing?
        // Actually, we need to set the default client config on the endpoint, OR pass it during connect.
        // Let's set it as default.
        let mut endpoint = endpoint;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            cert_chain,
            key,
        })
    }
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
        peer_keys: Vec<String>,
    ) -> anyhow::Result<Connection> {
        let mut pinned_keys = HashSet::new();
        for key_b64 in peer_keys {
            if let Ok(der) = BASE64_STANDARD.decode(key_b64.trim()) {
                pinned_keys.insert(der);
            }
        }
        let verifier = Arc::new(PeerVerifier { pinned_keys });
        let client_cfg = configure_client(verifier, self.cert_chain.clone(), self.key.clone_key())?;
        // connect_with takes ClientConfig directly? No, Endpoint is configured or we use connect_with
        let connection = self
            .endpoint
            .connect_with(client_cfg, addr, server_name)?
            .await?;
        Ok(connection)
    }
}

fn configure_server(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    verifier: Arc<PeerVerifier>,
) -> anyhow::Result<quinn::ServerConfig> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)?;

    server_crypto.alpn_protocols = vec![b"laminar".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    // Enable datagrams
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport_config.datagram_receive_buffer_size(Some(1024 * 1024));
    transport_config.datagram_send_buffer_size(1024 * 1024);
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

fn load_identity(
    base64_content: &str,
) -> anyhow::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let der = BASE64_STANDARD
        .decode(base64_content.trim())
        .map_err(|e| anyhow::anyhow!("Failed to decode base64 key: {}", e))?;

    let key_pair = rcgen::KeyPair::from_der(&der)
        .map_err(|e| anyhow::anyhow!("Failed to parse DER key: {}", e))?;

    let subject_alt_names = vec!["localhost".to_string(), "laminar-node".to_string()];
    let mut params = rcgen::CertificateParams::new(subject_alt_names);
    params.alg = &rcgen::PKCS_ED25519;
    params.key_pair = Some(key_pair);

    let cert = rcgen::Certificate::from_params(params)?;
    let cert_der = cert.serialize_der()?;
    let priv_key_der = cert.serialize_private_key_der();

    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key_der.into());
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];

    Ok((cert_chain, priv_key))
}

fn configure_client(
    verifier: Arc<PeerVerifier>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<quinn::ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("Failed to set client auth: {}", e))?;

    crypto.dangerous().set_certificate_verifier(verifier);
    crypto.alpn_protocols = vec![b"laminar".to_vec()];

    // Fix: Wrap into QuicClientConfig
    // QuicClientConfig needs to be created from rustls::ClientConfig
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(1024 * 1024));
    transport_config.datagram_send_buffer_size(1024 * 1024);
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

#[derive(Debug)]
struct PeerVerifier {
    pinned_keys: HashSet<Vec<u8>>,
}

impl PeerVerifier {
    fn verify_pin(&self, cert_der: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Extract SPKI (Subject Public Key Info)
        let spki = cert.tbs_certificate.subject_pki.raw;

        // Debug: log the SPKI and pinned keys
        use base64::prelude::*;
        let spki_b64 = BASE64_STANDARD.encode(spki);
        warn!("Verifying certificate with SPKI: {}", spki_b64);
        warn!("Have {} pinned keys", self.pinned_keys.len());
        for (i, key) in self.pinned_keys.iter().enumerate() {
            let key_b64 = BASE64_STANDARD.encode(key);
            warn!("  Pinned key {}: {}", i, key_b64);
        }

        // We compare the raw SPKI bytes with our pinned keys
        if self.pinned_keys.iter().any(|pinned| pinned == spki) {
            warn!("Certificate pinning SUCCESS!");
            Ok(())
        } else {
            warn!("Certificate pinning failed! Unknown public key.");
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify_pin(end_entity)
            .map(|_| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for PeerVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_pin(end_entity)
            .map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}
