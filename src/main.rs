use crate::config::Config;
use crate::interface::Interface;
use crate::protocol::Reassembler;
use crate::sieve::{Link, Sieve};
use crate::state::{NodeState, PeerState, SharedState};
use crate::transport::Transport;
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
use rcgen::generate_simple_self_signed;

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
    GenKeys {
        /// Output path for private key
        #[arg(long, default_value = "key.pem")]
        key: String,
    },
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
        /// API URL (default: http://127.0.0.1:3000)
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        api: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Run {
        config: "config.toml".to_string(),
    }) {
        Commands::Run { config } => run_daemon(&config).await,
        Commands::GenKeys { key } => generate_keys(&key),
        Commands::Validate { config } => validate_config(&config),
        Commands::Show { watch, api } => show_state(watch, &api).await,
    }
}

fn generate_keys(key_path: &str) -> anyhow::Result<()> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;

    std::fs::write(key_path, cert.serialize_private_key_pem())?;

    info!("Generated private key at '{}'", key_path);
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

    // Spawn API
    let api_state = state.clone();
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/state", axum::routing::get(get_state))
            .with_state(api_state);
        // Bind to 127.0.0.1:3000
        match tokio::net::TcpListener::bind("127.0.0.1:3000").await {
            Ok(listener) => {
                if let Err(e) = axum::serve(listener, app).await {
                    error!("API Server Error: {}", e);
                }
            }
            Err(e) => error!("Failed to bind API port: {}", e),
        }
    });
    info!("API Server running at http://127.0.0.1:3000");

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

    // 3. Setup Transport
    let transport = Arc::new(Transport::new(&config.node)?);
    let endpoint = transport.endpoint.clone();

    // 4. Mesh State (Central Sieve for all peers)
    let sieve = Arc::new(Mutex::new(Sieve::new(
        config.node.bonding_mode,
        config.node.mtu,
    )));

    // IP -> Logical Name mapping for incoming connections
    let mut ip_to_peer = HashMap::new();
    for peer in &config.peers {
        for addr in &peer.endpoints {
            ip_to_peer.insert(addr.ip(), peer.name.clone());
        }
    }
    let ip_to_peer = Arc::new(ip_to_peer);

    for peer_cfg in config.peers {
        let sieve_clone = sieve.clone();
        let node_streams = config.node.streams;
        let peer_name = peer_cfg.name.clone();
        let endpoints = peer_cfg.endpoints.clone();
        let transport_clone = transport.clone();

        for (idx, peer_addr) in endpoints.into_iter().enumerate() {
            let s_inner = sieve_clone.clone();
            let t_inner = transport_clone.clone();
            let p_name = peer_name.clone();

            tokio::spawn(async move {
                match t_inner.connect(peer_addr, "localhost").await {
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
    let stats_sieve = sieve.clone();
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
    let sieve_incoming = sieve.clone();

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
                                            let mut s = sieve_conn.lock().await;
                                            s.learn_mac(src_mac, logical_peer_name.clone());
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => warn!("Protocol error: {}", e),
                                }
                            }
                            Err(e) => {
                                error!("Datagram connection error: {}", e);
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
                        let mut s = sieve.lock().await;
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

async fn show_state(watch: bool, api_url: &str) -> anyhow::Result<()> {
    if watch {
        run_tui(api_url).await
    } else {
        match reqwest::get(format!("{}/state", api_url)).await {
            Ok(resp) => {
                let state = resp.json::<NodeState>().await?;
                println!("{}", serde_json::to_string_pretty(&state)?);
            }
            Err(e) => eprintln!("Failed to connect to API: {}", e),
        }
        Ok(())
    }
}

async fn run_tui(api_url: &str) -> anyhow::Result<()> {
    std::io::stdout().execute(EnterAlternateScreen)?;
    enable_raw_mode()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    loop {
        let state_opt = match reqwest::get(format!("{}/state", api_url)).await {
            Ok(r) => r.json::<NodeState>().await.ok(),
            Err(_) => None,
        };

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

async fn get_state(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<NodeState> {
    let s = state.lock().await;
    axum::Json(s.clone())
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
    if let Some(ip) = &config.ipv4_address {
        command.env("LAMINAR_IP", ip);
    }
    if let Some(mask) = &config.ipv4_mask {
        command.env("LAMINAR_MASK", mask);
    }
    if let Some(gw) = &config.ipv4_gateway {
        command.env("LAMINAR_GW", gw);
    }

    let status = command.status()?;

    if !status.success() {
        return Err(anyhow::anyhow!("Command failed with status: {}", status));
    }
    Ok(())
}
