use crate::config::Config;
use crate::interface::Interface;
use crate::protocol::Reassembler;
use crate::sieve::{Link, Sieve};
use crate::state::{NodeState, PeerState};
use crate::transport::Transport;
use base64::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

mod config;
mod interface;
mod protocol;
mod sieve;
mod state;
mod transport; // New module

use clap::{Parser, Subcommand};

// TUI Imports
use crossterm::{
    ExecutableCommand,
    event::{self, KeyCode, KeyEventKind},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table},
};

/// Laminar: Userspace L2 Mesh over Multi-path QUIC Datagrams
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the Laminar daemon
    Run {
        /// Path to the configuration file
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Generate a new private key
    GenKeys,
    /// Validate configuration file
    Validate {
        /// Path to the configuration file
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Show current node state
    Show {
        /// Watch mode (interactive TUI)
        #[arg(short, long)]
        watch: bool,
        /// Path to the configuration file
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Run speedtest against a peer
    Speedtest {
        /// Path to the configuration file
        #[arg(short, long, default_value = "config.toml")]
        config: String,
        /// Peer name to test against
        #[arg(short, long)]
        peer: String,
        /// Number of parallel threads
        #[arg(short, long, default_value = "4")]
        threads: usize,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Initialize logic
    // Check if we are running in TUI mode
    let is_tui = match &cli.command {
        Some(Commands::Show { watch: true, .. }) => true,
        _ => false,
    };

    if !is_tui {
        tracing_subscriber::fmt::init();
    }

    match cli.command.unwrap_or(Commands::Run {
        config: "config.toml".to_string(),
    }) {
        Commands::Run { config } => run_daemon(&config).await,
        Commands::GenKeys => generate_keys(),
        Commands::Validate { config } => validate_config(&config),
        Commands::Show { watch, config } => show_state(watch, &config).await,
        Commands::Speedtest {
            config,
            peer,
            threads,
        } => speedtest_client(&config, &peer, threads).await,
    }
}

// API Message Structures
#[derive(serde::Serialize, serde::Deserialize, Debug)]
enum ApiRequest {
    GetState,
    Speedtest { peer: String, threads: usize },
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
enum ApiResponse {
    State(NodeState),
    SpeedtestResult { bps: f64, mbps: f64 },
    Error(String),
}

fn generate_keys() -> anyhow::Result<()> {
    // Generate a new Ed25519 key pair
    let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ED25519)
        .map_err(|e| anyhow::anyhow!("Failed to generate key: {}", e))?;

    let priv_der = key_pair.serialize_der();
    let priv_b64 = BASE64_STANDARD.encode(&priv_der);

    let pub_der = key_pair.public_key_der();
    let pub_b64 = BASE64_STANDARD.encode(&pub_der);

    println!("Private Key: {}", priv_b64);
    println!("Public Key:  {}", pub_b64);

    Ok(())
}

fn validate_config(path: &str) -> anyhow::Result<()> {
    match Config::load(path) {
        Ok(cfg) => {
            info!("Configuration '{}' is valid.", path);
            info!("Node Listen: {}", cfg.node.listen);
            info!("Peers: {}", cfg.peers.len());
            Ok(())
        }
        Err(e) => {
            error!("Configuration '{}' is INVALID: {}", path, e);
            Err(anyhow::anyhow!("Invalid config"))
        }
    }
}

async fn run_daemon(config_path: &str) -> anyhow::Result<()> {
    // 1. Load Config
    let config = Config::load(config_path).unwrap_or_else(|e| {
        warn!("Config error: {}. Proceeding with panic for now.", e);
        panic!("Config load failed");
    });

    info!("Starting Laminar on {}", config.node.listen);

    // State Tracking
    let state = Arc::new(Mutex::new(NodeState {
        uptime_secs: 0,
        rx_bytes: 0,
        tx_bytes: 0,
        peers: Vec::new(),
    }));
    let start_time = std::time::Instant::now();
    let global_rx = Arc::new(AtomicU64::new(0));
    let global_tx = Arc::new(AtomicU64::new(0));

    // 3. Setup Transport
    // Extract our own public key from private key for localhost API connections
    let own_public_key = {
        let der = BASE64_STANDARD.decode(config.node.private_key.trim())?;
        let key_pair = rcgen::KeyPair::from_der(&der)?;
        let pub_der = key_pair.public_key_der();
        BASE64_STANDARD.encode(&pub_der)
    };

    let mut peer_public_keys: Vec<String> =
        config.peers.iter().map(|p| p.public_key.clone()).collect();
    peer_public_keys.push(own_public_key); // Allow connections from ourselves (for API)

    let transport = Arc::new(Transport::new(&config.node, peer_public_keys.clone())?);
    let endpoint = transport.endpoint.clone();

    // 4. Mesh State (Central Sieve for all peers)
    let sieve_state = Arc::new(Mutex::new(Sieve::new(
        config.node.bonding_mode,
        config.node.mtu,
    )));

    // API removed - will be served over QUIC in future implementation

    // 2. Setup TAP
    let interface = Interface::new(config.node.tap_name.clone(), config.node.mtu)?;
    let tap_name = interface.name().unwrap_or_else(|_| "laminar0".to_string());
    info!("TAP interface up: {}", tap_name);

    let (mut tap_reader, tap_writer) = interface.split();

    // Apply MAC address if configured
    if let Some(mac) = &config.node.mac_address {
        info!("Setting MAC address to {}", mac);

        #[cfg(target_os = "linux")]
        run_shell_command(
            &format!("ip link set dev {} address {}", tap_name, mac),
            Some(&tap_name),
            &config.node,
        )?;

        #[cfg(target_os = "macos")]
        if let Err(e) = run_shell_command(
            &format!("ifconfig {} ether {}", tap_name, mac),
            Some(&tap_name),
            &config.node,
        ) {
            warn!(
                "Failed to set MAC on {}: {} (Note: macOS utun devices might not support custom MACs)",
                tap_name, e
            );
        }
    }

    // Bridge Setup
    if let Some(bridge_cfg) = &config.node.bridge {
        let br_name = &bridge_cfg.name;
        info!("Configuring bridge: {}", br_name);

        #[cfg(target_os = "linux")]
        {
            // Create bridge if not exists (ignore error)
            let _ = run_shell_command(
                &format!("ip link add name {} type bridge", br_name),
                Some(&tap_name),
                &config.node,
            );
            // Set up
            run_shell_command(
                &format!("ip link set dev {} up", br_name),
                Some(&tap_name),
                &config.node,
            )?;
            // Add TAP
            run_shell_command(
                &format!("ip link set dev {} master {}", tap_name, br_name),
                Some(&tap_name),
                &config.node,
            )?;

            if let Some(ext) = &bridge_cfg.external_interface {
                // Warning: This often removes IP from physical interface.
                // User is expected to handle IP re-assignment via up_script or external config.
                run_shell_command(
                    &format!("ip link set dev {} master {}", ext, br_name),
                    Some(&tap_name),
                    &config.node,
                )?;
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Try create (ignore error if exists)
            // Note: macOS bridges are usually bridge0, bridge1. User should probably use "bridge0".
            let _ = run_shell_command(
                &format!("ifconfig {} create", br_name),
                Some(&tap_name),
                &config.node,
            );

            // Add TAP
            run_shell_command(
                &format!("ifconfig {} addm {}", br_name, tap_name),
                Some(&tap_name),
                &config.node,
            )?;

            if let Some(ext) = &bridge_cfg.external_interface {
                run_shell_command(
                    &format!("ifconfig {} addm {}", br_name, ext),
                    Some(&tap_name),
                    &config.node,
                )?;
            }
            // Up
            run_shell_command(
                &format!("ifconfig {} up", br_name),
                Some(&tap_name),
                &config.node,
            )?;
        }
    }

    // Execute Up Script
    if let Some(cmd) = &config.node.up_script {
        info!("Running up script: {}", cmd);
        run_shell_command(cmd, Some(&tap_name), &config.node)?;
    }

    // IP -> Logical Name mapping for incoming connections
    let mut ip_to_peer = HashMap::new();
    for peer in &config.peers {
        for addr in &peer.endpoints {
            ip_to_peer.insert(addr.ip(), peer.name.clone());
        }
    }
    let ip_to_peer = Arc::new(ip_to_peer);

    for peer_cfg in config.peers {
        let sieve_clone = sieve_state.clone();
        let node_streams = config.node.streams;
        let peer_pub_key = peer_cfg.public_key.clone();
        let peer_name = peer_cfg.name.clone();
        let endpoints = peer_cfg.endpoints.clone();
        let transport_clone = transport.clone();

        for (idx, peer_addr) in endpoints.into_iter().enumerate() {
            let s_inner = sieve_clone.clone();
            let t_inner = transport_clone.clone();
            let p_name = peer_name.clone();
            let p_key = vec![peer_pub_key.clone()];

            tokio::spawn(async move {
                match t_inner.connect(peer_addr, "localhost", p_key).await {
                    Ok(conn) => {
                        info!("Connected to peer {} at {}", p_name, peer_addr);

                        let mut streams = Vec::new();
                        if let Some(n) = node_streams {
                            for _ in 0..n {
                                if let Ok(s) = conn.open_uni().await {
                                    streams.push(s);
                                }
                            }
                        }

                        let link = Link::new(idx, format!("{}-{}", p_name, idx), conn, streams);
                        let mut s = s_inner.lock().await;
                        s.add_link(p_name, link);
                    }
                    Err(e) => {
                        error!(
                            "Failed to connect to peer {} at {}: {}",
                            p_name, peer_addr, e
                        );
                    }
                }
            });
        }
    }

    // Stats Updater
    let stats_state = state.clone();
    let stats_sieve = sieve_state.clone();
    let stats_rx = global_rx.clone();
    let stats_tx = global_tx.clone();

    tokio::spawn(async move {
        let mut keepalive_counter = 0;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            let mut s = stats_state.lock().await;
            s.uptime_secs = start_time.elapsed().as_secs();
            s.rx_bytes = stats_rx.load(Ordering::Relaxed);
            s.tx_bytes = stats_tx.load(Ordering::Relaxed);

            let mut peers = Vec::new();
            {
                let mut sieve_inner = stats_sieve.lock().await;
                let link_stats = sieve_inner.get_stats();

                for (l_name, s_snap) in link_stats {
                    peers.push(PeerState {
                        name: l_name,
                        endpoints: vec![], // Details already in name/stats
                        stats: s_snap,
                    });
                }

                keepalive_counter += 1;
                if keepalive_counter >= 5 {
                    sieve_inner.send_keepalives();
                    keepalive_counter = 0;
                }
            }
            s.peers = peers;
        }
    });

    // Shared Writer for Reassembly loop
    let tap_writer = Arc::new(Mutex::new(tap_writer));

    // 5. Incoming Datagram Loop (Quinn -> Reassembler -> TAP)
    let endpoint_clone = endpoint.clone();
    let tap_writer_clone = tap_writer.clone();
    let rx_counter_base = global_rx.clone();
    let sieve_incoming = sieve_state.clone();
    let state_incoming = state.clone();

    tokio::spawn(async move {
        while let Some(conn) = endpoint_clone.accept().await {
            let connection = match conn.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Handshake failed: {}", e);
                    continue;
                }
            };

            info!(
                "Accepted incoming connection from {}",
                connection.remote_address()
            );
            let tap_writer = tap_writer_clone.clone();
            let rx_counter_conn = rx_counter_base.clone();
            let sieve_conn = sieve_incoming.clone();
            let state_conn = state_incoming.clone();
            let remote_addr = connection.remote_address();
            let ip_to_peer_inner = ip_to_peer.clone();

            // Spawn per-connection handler
            tokio::spawn(async move {
                // Find logical peer name by IP
                let logical_peer_name = ip_to_peer_inner
                    .get(&remote_addr.ip())
                    .cloned()
                    .unwrap_or_else(|| format!("{}", remote_addr.ip()));

                let reassembler = Arc::new(Mutex::new(Reassembler::new()));

                // 1. Datagram Handler
                let conn_dgram = connection.clone();
                let r_dgram = reassembler.clone();
                let tw_dgram = tap_writer.clone();
                let rx_dgram = rx_counter_conn.clone();
                let sieve_dgram = sieve_conn.clone(); // Clone for datagram handler

                tokio::spawn(async move {
                    loop {
                        match conn_dgram.read_datagram().await {
                            Ok(data) => {
                                rx_dgram.fetch_add(data.len() as u64, Ordering::Relaxed);
                                let mut r = r_dgram.lock().await;
                                match r.accept(data) {
                                    Ok(Some(frame)) => {
                                        let mut writer_lock = tw_dgram.lock().await;
                                        if let Err(e) = writer_lock.write_packet(&frame).await {
                                            error!("Failed to write to TAP: {}", e);
                                        }
                                        // Learning MAC
                                        if frame.len() >= 12 {
                                            let mut src_mac = [0u8; 6];
                                            src_mac.copy_from_slice(&frame[6..12]);
                                            let mut s = sieve_dgram.lock().await; // Use sieve_dgram
                                            s.learn_mac(src_mac, logical_peer_name.clone());
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => warn!("Protocol error: {}", e),
                                }
                            }
                            Err(e) => {
                                match e {
                                    quinn::ConnectionError::ApplicationClosed(e) => {
                                        tracing::debug!("Connection closed usually: {}", e);
                                    }
                                    quinn::ConnectionError::ConnectionClosed(e) => {
                                        tracing::debug!("Connection closed: {}", e);
                                    }
                                    _ => {
                                        error!("Datagram connection error: {}", e);
                                    }
                                }
                                break;
                            }
                        }
                    }
                });

                // 2. Stream Handler (Incoming Uni streams)
                let conn_stream = connection.clone();
                let r_stream = reassembler.clone();
                let tw_stream = tap_writer.clone();
                let rx_stream_base = rx_counter_conn.clone();

                tokio::spawn(async move {
                    while let Ok(mut stream) = conn_stream.accept_uni().await {
                        let r_inner = r_stream.clone();
                        let tw_inner = tw_stream.clone();
                        let rx_stream = rx_stream_base.clone();
                        tokio::spawn(async move {
                            loop {
                                // Frame format: [u16 length][payload]
                                match stream.read_u16().await {
                                    Ok(len) => {
                                        let mut buf = vec![0u8; len as usize];
                                        match stream.read_exact(&mut buf).await {
                                            Ok(_) => {
                                                rx_stream.fetch_add(len as u64, Ordering::Relaxed);
                                                let data = bytes::Bytes::from(buf);

                                                // Check if this is an API packet
                                                if let Ok(header) =
                                                    crate::protocol::LaminarHeader::decode(
                                                        &mut data.clone(),
                                                    )
                                                {
                                                    if header.packet_type
                                                        == crate::protocol::PacketType::ApiRequest
                                                    {
                                                        // Handle API request
                                                        // TODO: Implement API handler
                                                        info!("Received API request");
                                                        continue;
                                                    }
                                                }

                                                let mut r = r_inner.lock().await;
                                                match r.accept(data) {
                                                    Ok(Some(frame)) => {
                                                        let mut writer = tw_inner.lock().await;
                                                        let _ = writer.write_packet(&frame).await;
                                                    }
                                                    Ok(None) => {}
                                                    Err(e) => warn!("Stream Protocol error: {}", e),
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                });

                // 3. API Handler (Incoming Bi streams)
                let conn_api = connection.clone();
                let sieve_api = sieve_conn.clone();
                let state_api = state_conn.clone();

                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn_api.accept_bi().await {
                        let sieve_inner = sieve_api.clone();
                        let state_inner = state_api.clone();

                        tokio::spawn(async move {
                            // Read request header first
                            let len = match recv.read_u16().await {
                                Ok(l) => l,
                                Err(_) => return,
                            };

                            let mut buf = vec![0u8; len as usize];
                            if recv.read_exact(&mut buf).await.is_err() {
                                return;
                            }

                            let data = bytes::Bytes::from(buf);
                            let mut data_clone = data.clone();

                            if let Ok(header) =
                                crate::protocol::LaminarHeader::decode(&mut data_clone)
                            {
                                if header.packet_type == crate::protocol::PacketType::ApiRequest {
                                    // Payload follows header
                                    // The remaining bytes in 'data_clone' (which is a Slice of 'data')
                                    // should be the JSON payload.
                                    // However, decode() advances the buffer.

                                    if let Ok(req) =
                                        serde_json::from_slice::<ApiRequest>(&data_clone)
                                    {
                                        info!("Handling API Request: {:?}", req);
                                        match req {
                                            ApiRequest::GetState => {
                                                let s = state_inner.lock().await;
                                                let response = ApiResponse::State(s.clone());
                                                // Send response
                                                if let Ok(resp_bytes) =
                                                    serde_json::to_vec(&response)
                                                {
                                                    let _ = send.write_all(&resp_bytes).await;
                                                }
                                                let _ = send.finish();
                                            }
                                            ApiRequest::Speedtest { peer, threads } => {
                                                // Run speedtest logic
                                                info!("Starting speedtest for peer {}", peer);
                                                let links = {
                                                    let s = sieve_inner.lock().await;
                                                    s.get_peer_links(&peer)
                                                };

                                                if let Some(links) = links {
                                                    if links.is_empty() {
                                                        let _ = send
                                                            .write_all(
                                                                &serde_json::to_vec(
                                                                    &ApiResponse::Error(
                                                                        "No active links to peer"
                                                                            .into(),
                                                                    ),
                                                                )
                                                                .unwrap(),
                                                            )
                                                            .await;
                                                        let _ = send.finish();
                                                        return;
                                                    }

                                                    // Run the speedtest
                                                    let start = std::time::Instant::now();
                                                    let total_bytes = Arc::new(
                                                        std::sync::atomic::AtomicU64::new(0),
                                                    );
                                                    let mut tasks = Vec::new();

                                                    let dummy_data = vec![0u8; 32768];
                                                    let dummy_bytes =
                                                        bytes::Bytes::from(dummy_data);

                                                    for i in 0..threads {
                                                        let conn = links[i % links.len()].clone();
                                                        let bytes_acc = total_bytes.clone();
                                                        let payload = dummy_bytes.clone();

                                                        tasks.push(tokio::spawn(async move {
                                                            if let Ok(mut stream) = conn.open_uni().await {
                                                                let mut header_buf =
                                                                    bytes::BytesMut::with_capacity(crate::protocol::LaminarHeader::SIZE);
                                                                let header = crate::protocol::LaminarHeader {
                                                                    frame_id: 0,
                                                                    total_frags: 1,
                                                                    frag_index: 0,
                                                                    packet_type: crate::protocol::PacketType::Speedtest,
                                                                };
                                                                header.encode(&mut header_buf);
                                                                let header_bytes = header_buf.freeze();

                                                                let len = (header_bytes.len() + payload.len()) as u16;
                                                                let len_bytes = len.to_be_bytes();

                                                                // 10 seconds test
                                                                while start.elapsed().as_secs() < 10 {
                                                                    let _ = stream.write_all(&len_bytes).await;
                                                                    let _ = stream.write_all(&header_bytes).await;
                                                                    let _ = stream.write_all(&payload).await;
                                                                    bytes_acc.fetch_add(len as u64, std::sync::atomic::Ordering::Relaxed);
                                                                }
                                                                let _ = stream.finish();
                                                            }
                                                        }));
                                                    }

                                                    for t in tasks {
                                                        let _ = t.await;
                                                    }

                                                    let elapsed = start.elapsed().as_secs_f64();
                                                    let total = total_bytes
                                                        .load(std::sync::atomic::Ordering::Relaxed)
                                                        as f64;
                                                    let bps = total / elapsed;
                                                    let mbps = (bps * 8.0) / 1_000_000.0;

                                                    let response =
                                                        ApiResponse::SpeedtestResult { bps, mbps };
                                                    if let Ok(resp_bytes) =
                                                        serde_json::to_vec(&response)
                                                    {
                                                        let _ = send.write_all(&resp_bytes).await;
                                                    }
                                                    let _ = send.finish();
                                                } else {
                                                    let _ = send
                                                        .write_all(
                                                            &serde_json::to_vec(
                                                                &ApiResponse::Error(
                                                                    "Peer not found".into(),
                                                                ),
                                                            )
                                                            .unwrap(),
                                                        )
                                                        .await;
                                                    let _ = send.finish();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                });
            });
        }
    });

    // 6. Outgoing Loop (TAP -> Sieve -> QUIC)
    let mut buf = bytes::BytesMut::with_capacity(65535);
    let tx_counter = global_tx.clone();

    // Signal handling
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            res = tap_reader.read_packet(&mut buf) => {
                match res {
                    Ok(n) => {
                        if n == 0 { continue; }
                        tx_counter.fetch_add(n as u64, Ordering::Relaxed);
                        let frame = buf.split().freeze();
                        let mut s = sieve_state.lock().await;
                        s.send_on_links(frame).await;
                        buf.reserve(65535);
                    }
                    Err(e) => {
                        error!("Failed to read from TAP: {}", e);
                        break;
                    }
                }
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down...");
                break;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                break;
            }
        }
    }

    // Execute Down Script
    if let Some(cmd) = &config.node.down_script {
        info!("Running down script: {}", cmd);
        let _ = run_shell_command(cmd, Some(&tap_name), &config.node); // Ignore error on shutdown?
    }

    Ok(())
}

async fn get_node_state(config: &crate::config::NodeConfig) -> anyhow::Result<NodeState> {
    // Create client transport
    let transport = crate::transport::Transport::new_client(&config.private_key, config.listen)?;

    // Connect logic
    let local_port = config.listen.port();
    let local_addr: std::net::SocketAddr = format!("127.0.0.1:{}", local_port).parse()?;

    // Extract own public key
    let own_public_key = {
        let der = BASE64_STANDARD.decode(config.private_key.trim())?;
        let key_pair = rcgen::KeyPair::from_der(&der)?;
        let pub_der = key_pair.public_key_der();
        BASE64_STANDARD.encode(&pub_der)
    };

    let connection = transport
        .connect(local_addr, "localhost", vec![own_public_key])
        .await?;
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send Request
    let request = ApiRequest::GetState;
    let request_json = serde_json::to_vec(&request)?;

    let mut header_buf = bytes::BytesMut::with_capacity(crate::protocol::LaminarHeader::SIZE);
    let header = crate::protocol::LaminarHeader {
        frame_id: 0,
        total_frags: 1,
        frag_index: 0,
        packet_type: crate::protocol::PacketType::ApiRequest,
    };
    header.encode(&mut header_buf);
    let header_bytes = header_buf.freeze();

    let total_len = (header_bytes.len() + request_json.len()) as u16;
    send.write_all(&total_len.to_be_bytes()).await?;
    send.write_all(&header_bytes).await?;
    send.write_all(&request_json).await?;
    send.finish()?;

    // Read Response
    let resp_bytes = recv.read_to_end(1024 * 1024).await?;
    if resp_bytes.is_empty() {
        anyhow::bail!("Empty response");
    }

    let response: ApiResponse = serde_json::from_slice(&resp_bytes)?;
    match response {
        ApiResponse::State(s) => Ok(s),
        ApiResponse::Error(e) => anyhow::bail!("API Error: {}", e),
        _ => anyhow::bail!("Unexpected response type"),
    }
}

async fn show_state(watch: bool, config_path: &str) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;

    if watch {
        run_tui(&config.node).await
    } else {
        match get_node_state(&config.node).await {
            Ok(state) => {
                println!("{}", serde_json::to_string_pretty(&state)?);
            }
            Err(e) => eprintln!("Failed to connect to API: {}", e),
        }
        Ok(())
    }
}

async fn run_tui(config: &crate::config::NodeConfig) -> anyhow::Result<()> {
    std::io::stdout().execute(EnterAlternateScreen)?;
    enable_raw_mode()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    loop {
        let state_opt = get_node_state(config).await.ok();

        terminal.draw(|frame| {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints(vec![Constraint::Length(3), Constraint::Min(0)])
                .split(frame.area());

            if let Some(state) = &state_opt {
                let title = Paragraph::new(format!(
                    "🌊 Laminar Node | Uptime: {}s | Rx: {} | Tx: {}",
                    state.uptime_secs, state.rx_bytes, state.tx_bytes
                ))
                .block(Block::default().borders(Borders::ALL).title("Status"));
                frame.render_widget(title, layout[0]);

                let rows: Vec<Row> = state
                    .peers
                    .iter()
                    .map(|p| {
                        Row::new(vec![
                            p.name.clone(),
                            format!("{} ms", p.stats.rtt_ms),
                            format!("{:.2} Mbps", p.stats.bandwidth_mbps),
                            format!("{}", p.stats.inflight_bytes),
                        ])
                    })
                    .collect();

                let table = Table::new(
                    rows,
                    [
                        Constraint::Percentage(20),
                        Constraint::Percentage(20),
                        Constraint::Percentage(20),
                        Constraint::Percentage(20),
                    ],
                )
                .header(Row::new(vec!["Peer", "RTT", "Est. BW", "Inflight"]))
                .block(Block::default().borders(Borders::ALL).title("Peers"));

                frame.render_widget(table, layout[1]);
            } else {
                frame.render_widget(Paragraph::new("Connecting to Node API..."), layout[0]);
            }
        })?;

        if event::poll(std::time::Duration::from_millis(1000))? {
            if let event::Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    std::io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

// Old HTTP API code removed - will implement QUIC-based API in future

async fn speedtest_client(
    config_path: &str,
    peer_name: &str,
    threads: usize,
) -> anyhow::Result<()> {
    // Load configuration
    let config = Config::load(config_path)?;

    // Find the target peer (just for validation)
    let _peer = config
        .peers
        .iter()
        .find(|p| p.name == peer_name)
        .ok_or_else(|| anyhow::anyhow!("Peer '{}' not found in config", peer_name))?;

    info!(
        "Starting speedtest against peer: {} with {} threads",
        peer_name, threads
    );

    // Create transport with our identity (client-only, ephemeral port)
    let transport =
        crate::transport::Transport::new_client(&config.node.private_key, config.node.listen)?;

    // Connect to LOCAL daemon (not remote peer!)
    // Extract port from listen address
    let local_port = config.node.listen.port();
    let local_addr: std::net::SocketAddr = format!("127.0.0.1:{}", local_port).parse()?;

    info!("Connecting to local daemon at {}", local_addr);

    // Extract our own public key for localhost verification
    let own_public_key = {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
        let der = BASE64_STANDARD.decode(config.node.private_key.trim())?;
        let key_pair = rcgen::KeyPair::from_der(&der)?;
        let pub_der = key_pair.public_key_der();
        BASE64_STANDARD.encode(&pub_der)
    };

    // Connect to localhost with our own public key for verification
    let connection = transport
        .connect(local_addr, "localhost", vec![own_public_key])
        .await?;

    info!("Connected to local daemon");

    // Send API request
    let request = ApiRequest::Speedtest {
        peer: peer_name.to_string(),
        threads,
    };

    let request_json = serde_json::to_vec(&request)?;

    // Open a bidirectional stream for request/response
    let (mut send, mut recv) = connection.open_bi().await?;

    // Send request with header
    let mut header_buf = bytes::BytesMut::with_capacity(crate::protocol::LaminarHeader::SIZE);
    let header = crate::protocol::LaminarHeader {
        frame_id: 0,
        total_frags: 1,
        frag_index: 0,
        packet_type: crate::protocol::PacketType::ApiRequest,
    };
    header.encode(&mut header_buf);
    let header_bytes = header_buf.freeze();

    let total_len = (header_bytes.len() + request_json.len()) as u16;
    send.write_all(&total_len.to_be_bytes()).await?;
    send.write_all(&header_bytes).await?;
    send.write_all(&request_json).await?;
    send.finish()?;

    info!("Sent API request, waiting for response...");

    // Read response
    let resp_bytes = recv.read_to_end(1024 * 1024).await?;
    if resp_bytes.is_empty() {
        anyhow::bail!("Daemon closed connection without response");
    }

    let response: ApiResponse = serde_json::from_slice(&resp_bytes)?;
    match response {
        ApiResponse::SpeedtestResult { bps, mbps } => {
            println!("\n=== Speedtest Results ===");
            println!("  Throughput: {:.2} Mbps", mbps);
            println!("  Raw Rate:   {:.2} bps", bps);
            println!("=========================\n");
        }
        ApiResponse::Error(e) => {
            eprintln!("\nError from daemon: {}\n", e);
        }
        _ => {
            eprintln!("\nUnexpected response type: {:?}\n", response);
        }
    }

    Ok(())
}

fn run_shell_command(
    cmd: &str,
    iface: Option<&str>,
    config: &crate::config::NodeConfig,
) -> anyhow::Result<()> {
    let mut command = std::process::Command::new("sh");
    command.arg("-c").arg(cmd);
    if let Some(i) = iface {
        command.env("LAMINAR_IFACE", i);
    }
    if let Some(addrs) = &config.addresses {
        let addr_list: Vec<String> = addrs.iter().map(|a| a.address.clone()).collect();
        let gw_list: Vec<String> = addrs
            .iter()
            .map(|a| a.gateway.clone().unwrap_or_default())
            .collect();
        command.env("LAMINAR_ADDRS", addr_list.join(" "));
        command.env("LAMINAR_GATEWAYS", gw_list.join(" "));
    }
    if let Some(mac) = &config.mac_address {
        command.env("LAMINAR_MAC", mac);
    }
    if let Some(dns) = &config.dns {
        command.env("LAMINAR_DNS", dns.join(" "));
    }

    let status = command.status()?;

    if !status.success() {
        return Err(anyhow::anyhow!("Command failed with status: {}", status));
    }
    Ok(())
}
