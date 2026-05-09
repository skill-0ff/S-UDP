use anyhow::Result;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use dashmap::DashMap;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc, watch};
use tokio::time::interval;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

// S-UDP Protocol Flags
pub const SUDP_INIT: u8 = 0x01;
pub const SUDP_RESP: u8 = 0x02;
pub const SUDP_AUTH_REQ: u8 = 0x03;
pub const SUDP_AUTH_RESP: u8 = 0x04;
pub const SUDP_DATA: u8 = 0x05;
pub const SUDP_DISCONNECT: u8 = 0x06;
pub const SUDP_ACK: u8 = 0x08;

// S-UDP Transport Constants
const SUDP_MTU: usize = 1400;
const SUDP_OVERHEAD: usize = 25; // 1 (flag) + 8 (seq) + 16 (Poly1305 tag)
const SUDP_RTO_MIN: u64 = 50;
const SUDP_RTO_MAX: u64 = 2000;
const SUDP_RTO_DEFAULT: u64 = 300;
const SUDP_PEER_TTL: u64 = 600; // 10 Minutes
const SUDP_HANDSHAKE_TIMEOUT: u64 = 2;
const SUDP_SESSION_TIMEOUT: u64 = 600; // 10 Minutes
const SUDP_MAX_WINDOW_SIZE: u32 = 2048;
const SUDP_WINDOW_RETRIES: u32 = 5;

// S-UDP Direction Bit: Separates client/server nonce spaces
const SUDP_DIR_BIT: u64 = 1u64 << 63;
const SUDP_SEQ_MASK: u64 = !(1u64 << 63);

// S-UDP Sequence Mapping (64-bit)
// [63] - Direction Bit
// [13-62] - Window Index (50 bits)
// [2-12] - Packet Index (11 bits, max 2048 packets per window)
// [1] - End Window Flag
// [0] - End Stream Flag
const SUDP_PACKET_IDX_BITS: u32 = 11;
const SUDP_PACKET_IDX_SHIFT: u32 = 2;
const SUDP_PACKET_IDX_MASK: u64 = (1 << SUDP_PACKET_IDX_BITS) - 1;
const SUDP_WINDOW_IDX_SHIFT: u32 = SUDP_PACKET_IDX_SHIFT + SUDP_PACKET_IDX_BITS; // 13

// S-UDP Reserved Nonce Space:
// Handshake encryption (03/04) uses nonce 0 (client) and DIR_BIT (server).
// Data packets (05) start at window_idx=1, so the minimum data nonce is 128.
// This guarantees zero overlap between handshake and data nonce spaces.

// S-UDP Security Constants
const SUDP_FLAG_MIN: u8 = 0x01;
const SUDP_FLAG_MAX: u8 = 0x08;
const SUDP_MAX_HANDSHAKES_PER_MIN: u32 = 3;
const SUDP_INITIAL_BLOCK_MINS: u32 = 3;
const SUDP_MAX_BLOCK_MINS: u32 = 1440; // 24 Hours

#[derive(Clone)]
struct PeerReputation {
    offenses: u32,
    blocked_until: Option<Instant>,
    handshake_count: u32,
    window_start: Instant,
    last_window_sent_at: Option<Instant>,
    srtt: Option<Duration>,
    rttvar: Duration,
    current_rto: Duration,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct TokenGuard {
    masked_blob: Vec<u8>,
    random_mask: Vec<u8>,
}

impl TokenGuard {
    pub fn new(mut raw_token: Vec<u8>) -> Self {
        let mut random_mask = Vec::with_capacity(raw_token.len());
        for _ in 0..raw_token.len() {
            random_mask.push(rand::random::<u8>());
        }

        let mut masked_blob = Vec::with_capacity(raw_token.len());
        for i in 0..raw_token.len() {
            masked_blob.push(raw_token[i] ^ random_mask[i]);
        }

        // ️ Zeroize memory
        raw_token.zeroize();

        Self {
            masked_blob,
            random_mask,
        }
    }

    pub fn verify(&self, incoming: &[u8]) -> bool {
        if incoming.len() != self.masked_blob.len() {
            return false;
        }

        // Ghost Comparison: (Incoming ^ Mask) == Masked_Blob
        incoming
            .iter()
            .zip(&self.random_mask)
            .zip(&self.masked_blob)
            .all(|((&inc, &mask), &blob)| (inc ^ mask) == blob)
    }

    /// Transiently reveal the token for client-side transmission
    pub fn reveal(&self) -> Vec<u8> {
        self.masked_blob
            .iter()
            .zip(&self.random_mask)
            .map(|(&b, &m)| b ^ m)
            .collect()
    }
}

struct SessionIdentity {
    peer: TokenGuard,
    server: TokenGuard,
}

impl SessionIdentity {
    pub fn verify_peer(&self, incoming: &[u8]) -> bool {
        self.peer.verify(incoming)
    }

    pub fn reveal_server_proof(&self) -> Vec<u8> {
        self.server.reveal()
    }
}

struct UnackedPacket {
    data: Vec<u8>,
    sent_at: Instant,
    retries: u32,
    last_gasp_tried: bool,
}

struct HandshakeState {
    shared_secret: Option<[u8; 32]>,
    created_at: Instant,
}

struct Session {
    cipher_key: [u8; 32],

    socket: Arc<UdpSocket>,
    last_activity: Instant,
    is_server: bool,
    recovery_started_at: Option<Instant>,
    next_send_seq: u64,
    last_recv_seq: u64,
    // Receiver: per-window packet buffer
    recv_window_packets: std::collections::HashMap<u64, std::collections::HashMap<u16, Vec<u8>>>,
    // Receiver: window_idx → (last_pos, is_end_stream) — set when end_window packet arrives
    recv_window_end_info: std::collections::HashMap<u64, (u16, bool)>,
    // Receiver: window_idx → count of ACKs sent (for nonce uniqueness)
    recv_window_ack_count: std::collections::HashMap<u64, u16>,
    last_acked_window: u64,
    // Receiver: highest window fully reassembled (duplicate rejection)
    recv_complete_window: u64,
    // Receiver: per-stream metrics (reset after each reassembly)
    recv_stream_start: Option<Instant>,
    recv_partial_acks: u32,
    recv_duplicates: u32,
    // Session-level metrics (cumulative, never reset)
    created_at: Instant,
    total_bytes_sent: usize,
    total_bytes_received: usize,
    pub streams_sent: u64,
    pub streams_received: u64,

    // ADAPTIVE WINDOW SCALING
    pub current_window_size: u32,
    pub consecutive_success: u32,
}

/// Events emitted by the S-UDP engine via the listener or connection stream.
#[derive(Debug)]
pub enum Event {
    /// A new session has been established and authenticated.
    Connected,
    /// A full data stream has been reassembled and is ready for processing.
    Data(RecvReport),
    /// a peer has disconnected gracefully or the session has timed out.
    Disconnected(DisconnectInfo),
}

/// Info returned when a peer sends a graceful disconnect (flag 0x06)
#[derive(Debug, Clone)]
pub struct DisconnectInfo {
    /// The peer that disconnected
    pub peer_addr: SocketAddr,
    /// Reason provided by the peer
    pub reason: String,
    /// Session snapshot at time of disconnect
    pub session: SessionInfo,
}

/// Final report returned with reassembled payload on receive.
#[derive(Debug, Clone)]
pub struct RecvReport {
    /// The reassembled payload.
    pub payload: Vec<u8>,
    /// Total payload size in bytes.
    pub total_bytes: usize,
    /// Total number of chunks reassembled.
    pub total_chunks: usize,
    /// Number of sliding windows used.
    pub windows_used: u64,
    /// Time from first packet to full reassembly.
    pub elapsed: Duration,
    /// Number of partial ACKs (gap reports) sent during receive.
    pub partial_acks_sent: u32,
    /// Number of duplicate packets rejected.
    pub duplicates_rejected: u32,
    /// Effective throughput in bytes per second.
    pub throughput_bps: f64,
}

/// The current phase of a data transmission.
#[derive(Debug, Clone, PartialEq)]
pub enum SendPhase {
    /// Packets are actively being sent.
    Sending,
    /// All packets sent, waiting for final ACKs (gap filling).
    Draining,
    /// Transmission confirmed and complete.
    Complete,
}

/// Real-time progress snapshot — subscribe via `watch::Receiver<SendProgress>`
#[derive(Debug, Clone)]
pub struct SendProgress {
    pub total_bytes: usize,
    pub bytes_sent: usize,
    pub bytes_remaining: usize,
    pub total_chunks: usize,
    pub chunks_sent: usize,
    pub chunks_remaining: usize,
    pub windows_used: u64,
    pub elapsed: Duration,
    pub eta: Duration,
    pub send_percent: f64,
    pub throttle_stalls: u32,
    pub phase: SendPhase,
}

/// Final report returned by `send_data` after full ACK confirmation.
#[derive(Debug, Clone)]
pub struct SendReport {
    /// Total bytes in the stream.
    pub total_bytes: usize,
    /// Total chunks transmitted.
    pub total_chunks: usize,
    /// Number of sliding windows used.
    pub windows_used: u64,
    /// Total time for the entire send operation (Send + Drain).
    pub elapsed: Duration,
    /// Time spent in the active sending phase.
    pub send_elapsed: Duration,
    /// Time spent waiting for final ACKs.
    pub drain_elapsed: Duration,
    /// Number of times the sender was throttled due to window limits.
    pub throttle_stalls: u32,
    /// Effective throughput in bytes per second.
    pub throughput_bps: f64,
}

/// Snapshot of a live session — returned by `get_session_info()` and `list_sessions()`
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Remote peer address
    pub peer_addr: SocketAddr,
    /// Role in this session
    pub role: SessionRole,
    /// When the session was established (as Duration since creation)
    pub uptime: Duration,
    /// Time since last send or receive activity
    pub idle: Duration,
    /// Total bytes sent across all streams in this session
    pub total_bytes_sent: usize,
    /// Total bytes received across all streams in this session
    pub total_bytes_received: usize,
    /// Number of completed send_data calls
    pub streams_sent: u64,
    /// Number of fully reassembled receive streams
    pub streams_received: u64,
    /// Whether the session is in recovery mode
    pub in_recovery: bool,
}

/// The role of the local engine in a specific session.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionRole {
    /// Local engine initiated the connection.
    Client,
    /// Local engine accepted the connection.
    Server,
}

/// Structured log entry emitted by the S-UDP engine
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub elapsed_ms: f64,
    pub level: LogLevel,
    pub category: LogCategory,
    pub message: String,
    pub peer: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogCategory {
    Handshake,
    Data,
    Ack,
    Disconnect,
    Security,
    Session,
    Retransmit,
    Reassembly,
}

impl std::fmt::Display for LogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let peer_str = self.peer.map_or(String::new(), |p| format!(" [{}]", p));
        write!(
            f,
            "[{:>10.2}ms] [{:?}] [{:?}]{} {}",
            self.elapsed_ms, self.level, self.category, peer_str, self.message
        )
    }
}

/// Internal macro for zero-cost logging when disabled
macro_rules! slog {
    ($engine:expr, $level:expr, $cat:expr, $peer:expr, $($arg:tt)*) => {
        if let Ok(guard) = $engine.log_tx.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(LogEntry {
                    elapsed_ms: $engine.boot_time.elapsed().as_secs_f64() * 1000.0,
                    level: $level,
                    category: $cat,
                    message: format!($($arg)*),
                    peer: $peer,
                });
            }
        }
    };
}

/// The core S-UDP protocol engine.
///
/// Handles encryption, handshakes, sliding window retransmission, and session management.
#[derive(Clone)]
pub struct Engine {
    handshakes: Arc<DashMap<SocketAddr, HandshakeState>>,
    sessions: Arc<DashMap<SocketAddr, Session>>,
    unacked: Arc<DashMap<(SocketAddr, u64), UnackedPacket>>,
    reputations: Arc<DashMap<IpAddr, PeerReputation>>,
    identity: Arc<RwLock<Option<SessionIdentity>>>,
    log_tx: Arc<StdMutex<Option<mpsc::UnboundedSender<LogEntry>>>>,
    boot_time: Instant,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// Creates a new instance of the S-UDP Engine.
    pub fn new() -> Self {
        Self {
            handshakes: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            unacked: Arc::new(DashMap::new()),
            reputations: Arc::new(DashMap::new()),
            identity: Arc::new(RwLock::new(None)),
            log_tx: Arc::new(StdMutex::new(None)),
            boot_time: Instant::now(),
        }
    }

    /// Enable protocol logging. Returns a receiver for structured log events.
    /// Logs are only generated while this is active — zero cost when off.
    pub fn enable_logging(&self) -> mpsc::UnboundedReceiver<LogEntry> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut guard) = self.log_tx.lock() {
            *guard = Some(tx);
        }
        rx
    }

    /// Disable protocol logging. Drops the sender, receiver will get None.
    pub fn disable_logging(&self) {
        if let Ok(mut guard) = self.log_tx.lock() {
            *guard = None;
        }
    }

    /// Binds to the specified address and starts listening for incoming S-UDP connections.
    ///
    /// # Arguments
    /// * `addr` - Local address to bind to (e.g., "0.0.0.0:5001").
    /// * `peer_token` - Authentication token required from clients.
    /// * `serv_token` - Authentication token provided by this server to clients.
    pub async fn listen(
        &self,
        addr: &str,
        peer_token: String,
        serv_token: String,
    ) -> Result<mpsc::Receiver<Event>> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);

        {
            let mut id = self.identity.write().await;
            *id = Some(SessionIdentity {
                peer: TokenGuard::new(peer_token.into_bytes()),
                server: TokenGuard::new(serv_token.into_bytes()),
            });
        }

        self.start_background_tasks(Arc::clone(&socket)).await;

        slog!(
            self,
            LogLevel::Info,
            LogCategory::Session,
            None,
            "Listener active on: {}",
            addr
        );

        let (tx, rx) = mpsc::channel::<Event>(256);
        let engine = self.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, peer_addr)) = socket.recv_from(&mut buf).await {
                if let Ok(Some(event)) = engine.process_packet(&socket, peer_addr, &buf, len).await
                    && tx.send(event).await.is_err()
                {
                    break; // Receiver dropped — dev no longer listening
                }
            }
        });

        Ok(rx)
    }

    /// Initiates an authenticated S-UDP connection to a remote server.
    ///
    /// # Arguments
    /// * `addr` - Remote server address (e.g., "1.2.3.4:5001").
    /// * `src_port` - Local port to bind the source socket to.
    /// * `peer_token` - Authentication token to provide to the server.
    /// * `serv_token` - Authentication token expected from the server.
    pub async fn connect(
        &self,
        addr: &str,
        src_port: u16,
        peer_token: String,
        serv_token: String,
    ) -> Result<mpsc::Receiver<Event>> {
        let local_addr = format!("0.0.0.0:{}", src_port);
        let socket = Arc::new(UdpSocket::bind(&local_addr).await?);
        let target_addr: SocketAddr = addr.parse()?;

        // Setup Identity to verify Server Proof during handshake
        {
            let mut id = self.identity.write().await;
            *id = Some(SessionIdentity {
                peer: TokenGuard::new(peer_token.clone().into_bytes()),
                server: TokenGuard::new(serv_token.clone().into_bytes()),
            });
        }

        // ️ Initiate handshake
        let my_secret = EphemeralSecret::random_from_rng(OsRng);
        let my_public = PublicKey::from(&my_secret);
        // Client handshake seq: all zeros, bit 63 = 0
        let mut packet = Vec::with_capacity(41);
        packet.push(SUDP_INIT);
        packet.extend_from_slice(&0u64.to_be_bytes());
        packet.extend_from_slice(my_public.as_bytes());

        let mut buf = [0u8; 2048];
        let mut dyn_rto = Duration::from_millis(SUDP_RTO_DEFAULT);
        let mut srtt: Option<Duration> = None;
        let mut rttvar = Duration::from_millis(SUDP_RTO_DEFAULT / 2);
        let mut stage1_success = false;
        let mut server_pub_bytes = [0u8; 32];

        // Stage 1: Send INIT, wait for INIT_RESP
        for _ in 0..3 {
            let try_start = Instant::now();
            socket.send_to(&packet, target_addr).await?;
            if let Ok(Ok((len, peer_addr))) =
                tokio::time::timeout(dyn_rto, socket.recv_from(&mut buf)).await
                && peer_addr == target_addr
                && len >= 41
                && buf[0] == SUDP_RESP
            {
                let recv_seq = u64::from_be_bytes(buf[1..9].try_into().unwrap_or([0u8; 8]));
                if recv_seq == SUDP_DIR_BIT {
                    // Server response: all zeros, bit 63 = 1
                    server_pub_bytes.copy_from_slice(&buf[9..41]);
                    stage1_success = true;

                    // Update RTT estimation (Stage 1)
                    let sample = try_start.elapsed();
                    srtt = Some(sample);
                    rttvar = sample / 2;
                    dyn_rto = srtt.unwrap() + (rttvar * 4);
                    dyn_rto = dyn_rto.clamp(
                        Duration::from_millis(SUDP_RTO_MIN),
                        Duration::from_millis(SUDP_RTO_MAX),
                    );
                    break;
                }
            }
        }

        if !stage1_success {
            return Err(anyhow::anyhow!("Server is not responding in stage 1"));
        }

        // Shared secret derivation
        let server_public = PublicKey::from(server_pub_bytes);
        let shared = my_secret.diffie_hellman(&server_public);
        let shared_key = *shared.as_bytes();
        let key = self.derive_cipher_key(&shared_key);

        // Handshake step 2
        let mut token_clear = peer_token.into_bytes();
        let plaintext = token_clear.clone();
        token_clear.zeroize();

        let mut ad_03 = [0u8; 9];
        ad_03[0] = SUDP_AUTH_REQ;
        // Bytes 1-8 already zero: client handshake nonce = 0
        let encrypted = self.encrypt_payload(&key, 0u64, &ad_03, &plaintext)?; // Nonce 0: reserved for client handshake

        let mut resp_03 = Vec::with_capacity(9 + encrypted.len());
        resp_03.extend_from_slice(&ad_03);
        resp_03.extend_from_slice(&encrypted);

        let mut stage2_success = false;
        let mut auth_ok = false;

        // Stage 2: Send AUTH_REQ, wait for AUTH_RESP
        for _ in 0..3 {
            let try_start = Instant::now();
            socket.send_to(&resp_03, target_addr).await?;
            if let Ok(Ok((len, peer_addr))) =
                tokio::time::timeout(dyn_rto, socket.recv_from(&mut buf)).await
                && peer_addr == target_addr
                && len >= 9
                && buf[0] == SUDP_AUTH_RESP
            {
                let recv_seq = u64::from_be_bytes(buf[1..9].try_into().unwrap_or([0u8; 8]));
                if recv_seq == SUDP_DIR_BIT {
                    // Server response: all zeros, bit 63 = 1
                    if let Some(decrypted) =
                        self.decrypt_payload(&key, SUDP_DIR_BIT, &buf[0..9], &buf[9..len])
                    {
                        // Nonce DIR_BIT: reserved for server handshake
                        // Check server proof (decrypt with server's full seq including dir bit)
                        let expected_proof = self
                            .identity
                            .read()
                            .await
                            .as_ref()
                            .map(|id| id.reveal_server_proof());

                        if let Some(mut expected) = expected_proof {
                            if decrypted == expected {
                                auth_ok = true;
                            }
                            expected.zeroize();
                        } else if !decrypted.is_empty() && decrypted[0] == 1 {
                            auth_ok = true;
                        }
                        stage2_success = true;

                        // Update RTT estimation (Stage 2)
                        let raw_sample = try_start.elapsed();
                        // Subtract the Server's mandatory 50ms time-gate from the sample math
                        let sample = if raw_sample > Duration::from_millis(50) {
                            raw_sample - Duration::from_millis(50)
                        } else {
                            Duration::from_millis(1)
                        };

                        let current_srtt = srtt.unwrap();
                        let delta = sample.max(current_srtt) - sample.min(current_srtt);
                        rttvar = (rttvar.mul_f32(0.75)) + (delta.mul_f32(0.25));
                        srtt = Some((current_srtt.mul_f32(0.875)) + (sample.mul_f32(0.125)));
                        dyn_rto = srtt.unwrap() + (rttvar * 4);
                        dyn_rto = dyn_rto.clamp(
                            Duration::from_millis(SUDP_RTO_MIN),
                            Duration::from_millis(SUDP_RTO_MAX),
                        );

                        break;
                    }
                }
            }
        }

        if !stage2_success {
            return Err(anyhow::anyhow!("Server is not responding in stage 2"));
        }

        if !auth_ok {
            return Err(anyhow::anyhow!("Invalid server proof during stage 2"));
        }

        // Cache established RTO for immediate fast pipeline data bursts!
        self.reputations.insert(
            target_addr.ip(),
            PeerReputation {
                offenses: 0,
                blocked_until: None,
                handshake_count: 1,
                window_start: Instant::now(),
                last_window_sent_at: None,
                srtt,
                rttvar,
                current_rto: dyn_rto,
            },
        );

        // Authentication successful. Insert session into map.
        let ck = self.derive_cipher_key(&shared_key);
        self.sessions.insert(
            target_addr,
            Session {
                cipher_key: ck,

                socket: Arc::clone(&socket),
                last_activity: Instant::now(),
                is_server: false, // Client side
                recovery_started_at: None,
                next_send_seq: 0,
                last_recv_seq: 0,
                recv_window_packets: std::collections::HashMap::new(),
                recv_window_end_info: std::collections::HashMap::new(),
                recv_window_ack_count: std::collections::HashMap::new(),
                last_acked_window: 0,
                recv_complete_window: 0,
                recv_stream_start: None,
                recv_partial_acks: 0,
                recv_duplicates: 0,
                created_at: Instant::now(),
                total_bytes_sent: 0,
                total_bytes_received: 0,
                streams_sent: 0,
                streams_received: 0,
                current_window_size: 128, // Start at 128
                consecutive_success: 1,
            },
        );

        slog!(
            self,
            LogLevel::Info,
            LogCategory::Session,
            Some(target_addr),
            "Connection established: {}",
            target_addr
        );

        // Start background tasks post-handshake
        self.start_background_tasks(Arc::clone(&socket)).await;

        let (tx, rx) = mpsc::channel::<Event>(256);
        let _ = tx.send(Event::Connected).await;
        let engine = self.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, peer_addr)) = socket.recv_from(&mut buf).await {
                if let Ok(Some(event)) = engine.process_packet(&socket, peer_addr, &buf, len).await
                    && tx.send(event).await.is_err()
                {
                    break; // Receiver dropped
                }
            }
        });

        Ok(rx)
    }

    pub async fn process_packet(
        &self,
        socket: &Arc<UdpSocket>,
        addr: SocketAddr,
        buf: &[u8],
        len: usize,
    ) -> Result<Option<Event>> {
        if len < 9 {
            return Ok(None);
        }

        let flags = buf[0];
        let seq = u64::from_be_bytes(buf[1..9].try_into().unwrap_or([0u8; 8]));

        // ️ Validate flag range
        if !(SUDP_FLAG_MIN..=SUDP_FLAG_MAX).contains(&flags) {
            slog!(
                self,
                LogLevel::Warn,
                LogCategory::Security,
                Some(addr),
                "Invalid packet flag: 0x{:02X} rejected",
                flags
            );
            return Ok(None);
        }

        let ip = addr.ip();
        let now = Instant::now();

        // ️ Check IP reputation and apply rate limiting
        if let Some(mut rep) = self.reputations.get_mut(&ip) {
            // Check if currently blocked
            if let Some(blocked_until) = rep.blocked_until {
                if now < blocked_until {
                    slog!(
                        self,
                        LogLevel::Trace,
                        LogCategory::Security,
                        Some(addr),
                        "Dropped blocked IP ({}s left)",
                        (blocked_until - now).as_secs()
                    );
                    return Ok(None);
                } else {
                    rep.blocked_until = None; // Block expired
                }
            }

            // Rate limit handshakes
            if flags == SUDP_INIT || flags == SUDP_AUTH_REQ {
                if rep.window_start.elapsed().as_secs() >= 60 {
                    rep.window_start = now;
                    rep.handshake_count = 1;
                } else {
                    rep.handshake_count += 1;
                    if rep.handshake_count > SUDP_MAX_HANDSHAKES_PER_MIN {
                        // Rate limit violation
                        let penalty_mins = (SUDP_INITIAL_BLOCK_MINS * 2u32.pow(rep.offenses))
                            .min(SUDP_MAX_BLOCK_MINS);

                        rep.blocked_until =
                            Some(now + Duration::from_secs(penalty_mins as u64 * 60));
                        rep.offenses += 1;
                        slog!(
                            self,
                            LogLevel::Warn,
                            LogCategory::Security,
                            Some(addr),
                            "Rate limited peer {}min (offense #{})",
                            penalty_mins,
                            rep.offenses
                        );
                        return Ok(None);
                    }
                }
            }
        } else if flags == SUDP_INIT || flags == SUDP_AUTH_REQ {
            // New IP sending handshake
            self.reputations.insert(
                ip,
                PeerReputation {
                    offenses: 0,
                    blocked_until: None,
                    handshake_count: 1,
                    window_start: now,
                    last_window_sent_at: None,
                    srtt: None,
                    rttvar: Duration::from_millis(SUDP_RTO_DEFAULT / 2),
                    current_rto: Duration::from_millis(SUDP_RTO_DEFAULT),
                },
            );
        }

        // Ensure peer exists (Standard S-UDP Logic)
        if !self.handshakes.contains_key(&addr) && !self.sessions.contains_key(&addr) {
            if flags != SUDP_INIT {
                return Ok(None);
            } // Ignore non-init for new peers
            self.handshakes.insert(
                addr,
                HandshakeState {
                    shared_secret: None,
                    created_at: Instant::now(),
                },
            );
        }

        match flags {
            SUDP_INIT => {
                if len >= 41 {
                    let remote_pub_bytes: [u8; 32] = buf[9..41].try_into().unwrap_or([0u8; 32]);
                    let remote_public = PublicKey::from(remote_pub_bytes);
                    let local_secret = EphemeralSecret::random_from_rng(OsRng);
                    let local_public = PublicKey::from(&local_secret);
                    let shared = local_secret.diffie_hellman(&remote_public);

                    if let Some(mut p) = self.handshakes.get_mut(&addr) {
                        p.shared_secret = Some(*shared.as_bytes());
                    }

                    let server_seq = seq | SUDP_DIR_BIT; // Server: bit 63 = 1
                    let mut resp = Vec::with_capacity(41);
                    resp.push(SUDP_RESP);
                    resp.extend_from_slice(&server_seq.to_be_bytes());
                    resp.extend_from_slice(local_public.as_bytes());
                    let _ = socket.send_to(&resp, addr).await;
                    slog!(
                        self,
                        LogLevel::Debug,
                        LogCategory::Handshake,
                        Some(addr),
                        "INIT received, RESP sent (stage 1)"
                    );
                    return Ok(None);
                }
            }
            SUDP_AUTH_REQ => {
                let handshake_start = Instant::now();
                if self.sessions.contains_key(&addr) {
                    let server_seq = SUDP_DIR_BIT; // Server handshake seq: all zeros, bit 63 = 1
                    let mut resp = Vec::with_capacity(25);
                    resp.push(SUDP_AUTH_RESP);
                    resp.extend_from_slice(&server_seq.to_be_bytes());
                    if let Some(peer) = self.sessions.get_mut(&addr) {
                        let mut ad_04 = [0u8; 9];
                        ad_04[0] = SUDP_AUTH_RESP;
                        ad_04[1..9].copy_from_slice(&server_seq.to_be_bytes());
                        let encrypted = self.encrypt_payload(
                            &peer.cipher_key,
                            SUDP_DIR_BIT,
                            &ad_04,
                            &[0u8; 1],
                        )?; // Nonce DIR_BIT: reserved for server handshake
                        resp.extend_from_slice(&encrypted);
                    }
                    let _ = socket.send_to(&resp, addr).await;
                    return Ok(None);
                }

                if len >= 25
                    && let Some(p) = self.handshakes.get_mut(&addr)
                    && let Some(shared) = p.shared_secret
                {
                    let key = self.derive_cipher_key(&shared);
                    if let Some(decrypted) =
                        self.decrypt_payload(&key, 0u64, &buf[0..9], &buf[9..len])
                    {
                        // Nonce 0: reserved for client handshake
                        if !decrypted.is_empty() {
                            let peer_token = String::from_utf8_lossy(&decrypted).to_string();
                            let peer_token = peer_token.trim_matches(char::from(0)).to_string(); // Clean null padding

                            let mut auth_ok = false;
                            if let Some(ref id) = *self.identity.read().await
                                && id.verify_peer(peer_token.as_bytes())
                            {
                                auth_ok = true;
                            }

                            drop(p);
                            if let Some((_, handshake_data)) = self.handshakes.remove(&addr) {
                                if auth_ok {
                                    let ss = handshake_data.shared_secret.unwrap();
                                    let ck = self.derive_cipher_key(&ss);
                                    self.sessions.insert(
                                        addr,
                                        Session {
                                            cipher_key: ck,

                                            socket: Arc::clone(socket),
                                            last_activity: Instant::now(),
                                            is_server: true, // Server side
                                            recovery_started_at: None,
                                            next_send_seq: 0,
                                            last_recv_seq: 0,
                                            recv_window_packets: std::collections::HashMap::new(),
                                            recv_window_end_info: std::collections::HashMap::new(),
                                            recv_window_ack_count: std::collections::HashMap::new(),
                                            last_acked_window: 0,
                                            recv_complete_window: 0,
                                            recv_stream_start: None,
                                            recv_partial_acks: 0,
                                            recv_duplicates: 0,
                                            created_at: Instant::now(),
                                            total_bytes_sent: 0,
                                            total_bytes_received: 0,
                                            streams_sent: 0,
                                            streams_received: 0,
                                            current_window_size: 128,
                                            consecutive_success: 1,
                                        },
                                    );
                                    slog!(
                                        self,
                                        LogLevel::Info,
                                        LogCategory::Session,
                                        Some(addr),
                                        "Session established (server-side)"
                                    );
                                } else {
                                    slog!(
                                        self,
                                        LogLevel::Warn,
                                        LogCategory::Handshake,
                                        Some(addr),
                                        "Auth rejected: invalid peer token"
                                    );
                                    let ip_addr = addr.ip();
                                    if let Some(mut rep) = self.reputations.get_mut(&ip_addr) {
                                        let penalty_mins = (SUDP_INITIAL_BLOCK_MINS
                                            * 2u32.pow(rep.offenses))
                                        .min(SUDP_MAX_BLOCK_MINS);
                                        rep.blocked_until = Some(
                                            Instant::now()
                                                + Duration::from_secs(penalty_mins as u64 * 60),
                                        );
                                        rep.offenses += 1;
                                    }
                                }

                                // Flag 04: Gated Handshake
                                let engine = self.clone();
                                let socket = Arc::clone(socket);
                                let addr_c = addr;
                                let seq_c = SUDP_DIR_BIT; // Server handshake seq: all zeros, bit 63 = 1
                                let key_c = key;

                                tokio::spawn(async move {
                                    // 1. Determine payload
                                    let mut payload_data = if auth_ok {
                                        if let Some(id) = engine.identity.read().await.as_ref() {
                                            id.reveal_server_proof()
                                        } else {
                                            return;
                                        }
                                    } else {
                                        b"invalid_token".to_vec()
                                    };

                                    // 2. 50ms Time-Gate (Relative to handshake start)
                                    let elapsed = handshake_start.elapsed();
                                    if elapsed < Duration::from_millis(50) {
                                        tokio::time::sleep(Duration::from_millis(50) - elapsed)
                                            .await;
                                    }

                                    // 3. Encrypt and Send (with server direction bit)
                                    let mut resp = Vec::with_capacity(9 + payload_data.len() + 16);
                                    resp.push(SUDP_AUTH_RESP);
                                    resp.extend_from_slice(&seq_c.to_be_bytes());

                                    let mut ad = [0u8; 9];
                                    ad[0] = SUDP_AUTH_RESP;
                                    ad[1..9].copy_from_slice(&seq_c.to_be_bytes());

                                    let encrypted = match engine.encrypt_payload(
                                        &key_c,
                                        SUDP_DIR_BIT,
                                        &ad,
                                        &payload_data,
                                    ) {
                                        Ok(enc) => enc,
                                        Err(_) => return,
                                    }; // Nonce DIR_BIT: reserved for server handshake
                                    resp.extend_from_slice(&encrypted);

                                    let _ = socket.send_to(&resp, addr_c).await;

                                    // 4. Ghost Zeroize
                                    payload_data.zeroize();
                                });

                                if auth_ok {
                                    return Ok(Some(Event::Connected));
                                }
                            }
                        }
                    }
                }
            }
            SUDP_DATA => {
                if let Some(mut peer) = self.sessions.get_mut(&addr) {
                    peer.last_activity = Instant::now();

                    if let Some(decrypted_payload) =
                        self.decrypt_payload(&peer.cipher_key, seq, &buf[0..9], &buf[9..len])
                    {
                        // DECODE SEQ FIELDS
                        let sender_dir = seq & SUDP_DIR_BIT; // bit 63
                        
                        let window_idx = (seq & SUDP_SEQ_MASK) >> SUDP_WINDOW_IDX_SHIFT; // bits 13+
                        let packet_pos = ((seq >> SUDP_PACKET_IDX_SHIFT) & SUDP_PACKET_IDX_MASK) as u16; // bits 2-12 (0-2047)
                        
                        let end_window = ((seq >> 1) & 1) == 1; // bit 1
                        let end_stream = (seq & 1) == 1; // bit 0

                        // ️ Direction validation: sender must be the opposite side
                        let expected_dir = if peer.is_server { 0u64 } else { SUDP_DIR_BIT };
                        if sender_dir != expected_dir {
                            slog!(
                                self,
                                LogLevel::Warn,
                                LogCategory::Security,
                                Some(addr),
                                "Direction mismatch: got {:016X}, expected {:016X}",
                                sender_dir,
                                expected_dir
                            );
                            return Ok(None);
                        }

                        // ️ Duplicate rejection: skip packets for already-reassembled windows
                        if window_idx <= peer.recv_complete_window {
                            peer.recv_duplicates += 1;
                            slog!(
                                self,
                                LogLevel::Trace,
                                LogCategory::Data,
                                Some(addr),
                                "Rejected duplicate packet: window {} <= watermark {}",
                                window_idx,
                                peer.recv_complete_window
                            );
                            return Ok(None);
                        }

                        // ⏱️ Start timing on first packet of a new stream
                        if peer.recv_stream_start.is_none() {
                            peer.recv_stream_start = Some(Instant::now());
                        }

                        peer.last_recv_seq = seq;

                        slog!(
                            self,
                            LogLevel::Trace,
                            LogCategory::Data,
                            Some(addr),
                            "DATA: w={} p={} end_w={} end_s={} ({}B)",
                            window_idx,
                            packet_pos,
                            end_window,
                            end_stream,
                            decrypted_payload.len()
                        );

                        // Buffer incoming payload
                        peer.recv_window_packets
                            .entry(window_idx)
                            .or_insert_with(std::collections::HashMap::new)
                            .insert(packet_pos, decrypted_payload); // owned, no clone needed

                        // Record end info when end_window arrives
                        if end_window {
                            peer.recv_window_end_info
                                .insert(window_idx, (packet_pos, end_stream));
                        }

                        // Detect older incomplete windows
                        // Check the CONTIGUOUS range from our lowest buffered window to current.
                        // This catches 100%-lost windows that have zero packets in our buffer.
                        let min_window = peer
                            .recv_window_packets
                            .keys()
                            .chain(peer.recv_window_end_info.keys())
                            .min()
                            .copied()
                            .unwrap_or(window_idx);

                        let my_dir: u64 = if peer.is_server { SUDP_DIR_BIT } else { 0 };

                        for old_w in min_window..window_idx {
                            if peer.recv_window_end_info.contains_key(&old_w) {
                                continue;
                            }

                            // Build Bitmask ACK for missing window
                            let mut ack_payload = vec![0u8; (SUDP_PACKET_IDX_MASK >> 3) as usize + 1];
                            let old_data = peer.recv_window_packets.get(&old_w);
                            let mut lost_count = 0;
                            for p in 0..=SUDP_PACKET_IDX_MASK as u16 {
                                if old_data.is_some_and(|d| d.contains_key(&p)) {
                                    ack_payload[(p >> 3) as usize] |= 1 << (p & 7);
                                } else {
                                    lost_count += 1;
                                }
                            }

                            // Increment ACK count for this window (unique nonce)
                            let ack_count = peer.recv_window_ack_count.entry(old_w).or_insert(0);
                            let current_ack_count = *ack_count;
                            *ack_count = (*ack_count + 1) & SUDP_PACKET_IDX_MASK as u16;

                            let old_ack_seq = my_dir | (old_w << SUDP_WINDOW_IDX_SHIFT) | ((current_ack_count as u64) << SUDP_PACKET_IDX_SHIFT) | 0b01;
                            let mut old_ad = [0u8; 9];
                            old_ad[0] = SUDP_ACK;
                            old_ad[1..9].copy_from_slice(&old_ack_seq.to_be_bytes());

                            let old_enc = self.encrypt_payload(&peer.cipher_key, old_ack_seq, &old_ad, &ack_payload)?;
                            let mut old_resp = Vec::with_capacity(9 + old_enc.len());
                            old_resp.extend_from_slice(&old_ad);
                            old_resp.extend_from_slice(&old_enc);
                            let _ = socket.send_to(&old_resp, addr).await;
                            
                            if lost_count > 0 {
                                peer.recv_partial_acks += 1;
                                slog!(
                                    self,
                                    LogLevel::Debug,
                                    LogCategory::Ack,
                                    Some(addr),
                                    "Gap Bitmask ACK sent: window {} ({} missing) seq={:016X} len={}",
                                    old_w,
                                    lost_count,
                                    old_ack_seq,
                                    ack_payload.len()
                                );
                            }
                        }

                        // ️ ACK CHECK (TRIGGER 1): Trigger if we know this window's end
                        let should_ack = peer.recv_window_end_info.contains_key(&window_idx);

                        if should_ack {
                            let (end_pos, _is_end_stream) =
                                *peer.recv_window_end_info.get(&window_idx).unwrap();
                            let received = peer.recv_window_packets.get(&window_idx);

                            // Build Bitmask ACK
                            let mut ack_payload = vec![0u8; (end_pos >> 3) as usize + 1];
                            let mut lost_count = 0;
                            if let Some(window_data) = received {
                                for p in 0..=end_pos {
                                    if window_data.contains_key(&p) {
                                        ack_payload[(p >> 3) as usize] |= 1 << (p & 7);
                                    } else {
                                        lost_count += 1;
                                    }
                                }
                            } else {
                                lost_count = end_pos + 1;
                            }

                            // FULL ACK Shortcut: If all packets received, send empty payload
                            if lost_count == 0 {
                                ack_payload.clear();
                            }

                            // Increment ACK count for this window (unique nonce)
                            let ack_count = peer.recv_window_ack_count.entry(window_idx).or_insert(0);
                            let current_ack_count = *ack_count;
                            *ack_count = (*ack_count + 1) & SUDP_PACKET_IDX_MASK as u16;

                            let ack_seq = my_dir | (window_idx << SUDP_WINDOW_IDX_SHIFT) | ((current_ack_count as u64) << SUDP_PACKET_IDX_SHIFT) | 0b01;

                            let mut ad = [0u8; 9];
                            ad[0] = SUDP_ACK;
                            ad[1..9].copy_from_slice(&ack_seq.to_be_bytes());

                            let encrypted = self.encrypt_payload(&peer.cipher_key, ack_seq, &ad, &ack_payload)?;
                            let mut resp = Vec::with_capacity(9 + encrypted.len());
                            resp.extend_from_slice(&ad);
                            resp.extend_from_slice(&encrypted);
                            let _ = socket.send_to(&resp, addr).await;

                            if lost_count > 0 {
                                peer.recv_partial_acks += 1;
                                slog!(
                                    self,
                                    LogLevel::Debug,
                                    LogCategory::Ack,
                                    Some(addr),
                                    "Partial Bitmask ACK sent: window {} ({} missing) seq={:016X} len={}",
                                    window_idx,
                                    lost_count,
                                    ack_seq,
                                    ack_payload.len()
                                );
                            } else {
                                slog!(
                                    self,
                                    LogLevel::Debug,
                                    LogCategory::Ack,
                                    Some(addr),
                                    "Full ACK sent: window {} seq={:016X}",
                                    window_idx,
                                    ack_seq
                                );
                            }
                        }

                        // STREAM REASSEMBLY: If end_stream seen + all windows complete
                        let mut stream_end_window: Option<u64> = None;
                        for (_w_idx, (_end_pos, is_es)) in &peer.recv_window_end_info {
                            if *is_es {
                                stream_end_window = Some(*_w_idx);
                                break;
                            }
                        }

                        if let Some(last_window) = stream_end_window {
                            // Determine the first expected window in this stream
                            let first_window = peer.recv_complete_window + 1;

                            if first_window <= last_window {
                                // Check CONTIGUOUS range: every window from first to last must be complete
                                let mut all_complete = true;
                            for w in first_window..=last_window {
                                if let Some((ep, _)) = peer.recv_window_end_info.get(&w) {
                                    if let Some(data) = peer.recv_window_packets.get(&w) {
                                        for p in 0..=*ep {
                                            if !data.contains_key(&p) {
                                                all_complete = false;
                                                break;
                                            }
                                        }
                                    } else {
                                        all_complete = false;
                                    }
                                } else {
                                    all_complete = false;
                                }
                                if !all_complete {
                                    break;
                                }
                            }

                            if all_complete {
                                // REASSEMBLE: Concatenate all chunks in order
                                let mut full_payload = Vec::new();
                                for w in first_window..=last_window {
                                    if let Some((ep, _)) = peer.recv_window_end_info.get(&w)
                                        && let Some(data) = peer.recv_window_packets.get(&w)
                                    {
                                        for p in 0..=*ep {
                                            if let Some(chunk) = data.get(&p) {
                                                full_payload.extend_from_slice(chunk);
                                            }
                                        }
                                    }
                                }

                                // Compute total chunks across all windows
                                let mut total_chunks: usize = 0;
                                for w in first_window..=last_window {
                                    if let Some((ep, _)) = peer.recv_window_end_info.get(&w) {
                                        total_chunks += (*ep as usize) + 1;
                                    }
                                }
                                // Clean up receiver buffers & advance watermark
                                let elapsed = peer
                                    .recv_stream_start
                                    .map(|t| t.elapsed())
                                    .unwrap_or(Duration::ZERO);
                                let total_bytes = full_payload.len();
                                let throughput_bps = if elapsed.as_secs_f64() > 0.0 {
                                    total_bytes as f64 / elapsed.as_secs_f64()
                                } else {
                                    0.0
                                };
                                let windows_used = last_window - first_window + 1;
                                let partial_acks_sent = peer.recv_partial_acks;
                                let duplicates_rejected = peer.recv_duplicates;

                                for w in first_window..=last_window {
                                    peer.recv_window_packets.remove(&w);
                                    peer.recv_window_end_info.remove(&w);
                                }
                                peer.recv_complete_window = last_window;
                                // Reset per-stream metrics
                                peer.recv_stream_start = None;
                                peer.recv_partial_acks = 0;
                                peer.recv_duplicates = 0;
                                // Update session-level counters
                                peer.total_bytes_received += total_bytes;
                                peer.streams_received += 1;

                                slog!(
                                    self,
                                    LogLevel::Info,
                                    LogCategory::Reassembly,
                                    Some(addr),
                                    "Stream reassembled: {} bytes in {} windows ({:.1}ms)",
                                    total_bytes,
                                    windows_used,
                                    elapsed.as_secs_f64() * 1000.0
                                );

                                return Ok(Some(Event::Data(RecvReport {
                                    total_chunks,
                                    total_bytes,
                                    windows_used,
                                    elapsed,
                                    partial_acks_sent,
                                    duplicates_rejected,
                                    throughput_bps,
                                    payload: full_payload,
                                })));
                            }
                        }
                    }
                }
            }
        }
        SUDP_ACK => {
                // S-UDP Windowed ACK (Flag 08)
                // Payload empty  = all packets received (full confirmation)
                // Payload present = list of LOST packet seqs (8 bytes each)
                if let Some(mut peer) = self.sessions.get_mut(&addr)
                    && let Some(payload) =
                        self.decrypt_payload(&peer.cipher_key, seq, &buf[0..9], &buf[9..len])
                {
                    let acked_window = (seq & SUDP_SEQ_MASK) >> SUDP_WINDOW_IDX_SHIFT; // Strip direction bit
                    let ip = addr.ip();
                    let now = Instant::now();

                    // ACK received — connection is alive, cancel recovery mode
                    peer.recovery_started_at = None;

                    if payload.is_empty() {
                        // FULL ACK: Every packet in this window was received
                        slog!(
                            self,
                            LogLevel::Debug,
                            LogCategory::Ack,
                            Some(addr),
                            "Full ACK received: window {} cleared",
                            acked_window
                        );
                        // Clear all unacked entries belonging to this window
                        let keys_to_remove: Vec<(SocketAddr, u64)> = self
                            .unacked
                            .iter()
                            .filter(|e| {
                                e.key().0 == addr
                                    && ((e.key().1 & SUDP_SEQ_MASK) >> SUDP_WINDOW_IDX_SHIFT) == acked_window
                            })
                            .map(|e| *e.key())
                            .collect();
                        for k in keys_to_remove {
                            self.unacked.remove(&k);
                        }

                        // Advance last_acked_window (unblocks sender throttle)
                        if acked_window > peer.last_acked_window {
                            peer.last_acked_window = acked_window;
                        }
                    } else {
                        // ️ BITMASK ACK: Payload bits indicate received packets
                        let mut lost_count = 0;
                        let mut acked_count = 0;

                        // Collect all unacked entries for this window
                        let window_entries: Vec<(SocketAddr, u64)> = self
                            .unacked
                            .iter()
                            .filter(|e| {
                                e.key().0 == addr
                                    && ((e.key().1 & SUDP_SEQ_MASK) >> SUDP_WINDOW_IDX_SHIFT) == acked_window
                            })
                            .map(|e| *e.key())
                            .collect();

                        for (addr, seq) in window_entries {
                            let packet_idx = ((seq >> SUDP_PACKET_IDX_SHIFT) & SUDP_PACKET_IDX_MASK) as usize;
                            let byte_idx = packet_idx >> 3;
                            let bit_idx = packet_idx & 7;

                            let mut received = false;
                            if byte_idx < payload.len() {
                                received = (payload[byte_idx] & (1 << bit_idx)) != 0;
                            }

                            if received {
                                self.unacked.remove(&(addr, seq));
                                acked_count += 1;
                            } else {
                                // Retransmit lost packet
                                if let Some(mut pending) = self.unacked.get_mut(&(addr, seq)) {
                                    pending.retries += 1;
                                    pending.sent_at = Instant::now();
                                    let _ = socket.send_to(&pending.data, addr).await;
                                    lost_count += 1;
                                }
                            }
                        }

                        slog!(
                            self,
                            LogLevel::Debug,
                            LogCategory::Ack,
                            Some(addr),
                            "Bitmask ACK: window {} ({} acked, {} retransmitted) seq={:016X} len={}",
                            acked_window,
                            acked_count,
                            lost_count,
                            seq,
                            payload.len()
                        );

                        // DYNAMIC WINDOW SCALING
                        if payload.is_empty() {
                            // 0% LOSS: Accelerated Growth
                            let growth = 32 * peer.consecutive_success;
                            if (SUDP_MAX_WINDOW_SIZE - peer.current_window_size) < growth {
                                peer.current_window_size = SUDP_MAX_WINDOW_SIZE;
                            } else {
                                peer.current_window_size += growth;
                                peer.consecutive_success += 1;
                            }
                        } else {
                            // > 0% LOSS: Proportional Shrink
                            peer.consecutive_success = 1; // Reset accelerator
                            
                            // Calculate loss percentage based on the unacked entries we just checked
                            let total_tracked = acked_count + lost_count;
                            if total_tracked > 0 {
                                let loss_ratio = lost_count as f32 / total_tracked as f32;
                                let shrink_factor = 1.0 - loss_ratio;
                                peer.current_window_size = ((peer.current_window_size as f32 * shrink_factor) as u32).max(32);
                            }
                        }

                        slog!(
                            self,
                            LogLevel::Debug,
                            LogCategory::Session,
                            Some(addr),
                            "Adaptive Window: {} (consecutive_success: {})",
                            peer.current_window_size,
                            peer.consecutive_success
                        );
                    }

                    // RTO CALIBRATION (valid for both full and partial ACKs)
                    if let Some(mut rep) = self.reputations.get_mut(&ip)
                        && let Some(last_sent) = rep.last_window_sent_at
                    {
                        let sample = now.duration_since(last_sent);

                        if let Some(srtt) = rep.srtt {
                            // Continuous Smoothing (Alpha=1/8, Beta=1/4)
                            let delta = sample.max(srtt) - sample.min(srtt);
                            rep.rttvar = (rep.rttvar.mul_f32(0.75)) + (delta.mul_f32(0.25));
                            rep.srtt = Some((srtt.mul_f32(0.875)) + (sample.mul_f32(0.125)));
                        } else {
                            // First Window Bootstrap
                            rep.srtt = Some(sample);
                            rep.rttvar = sample / 2;
                        }

                        // RTO = SRTT + 4 * RTTVAR
                        let new_rto = rep.srtt.unwrap() + (rep.rttvar * 4);
                        rep.current_rto = new_rto.clamp(
                            Duration::from_millis(SUDP_RTO_MIN),
                            Duration::from_millis(SUDP_RTO_MAX),
                        );
                        rep.last_window_sent_at = None; // Reset for next window
                    }
                }
            }

            SUDP_DISCONNECT => {
                // Graceful disconnect
                // seq = dir_bit | SUDP_SEQ_MASK (all 1s) — unique, can never collide with data
                // Payload = encrypted reason string
                if let Some(peer) = self.sessions.get_mut(&addr)
                    && let Some(payload) =
                        self.decrypt_payload(&peer.cipher_key, seq, &buf[0..9], &buf[9..len])
                {
                    let reason = String::from_utf8_lossy(&payload).to_string();
                    slog!(
                        self,
                        LogLevel::Info,
                        LogCategory::Disconnect,
                        Some(addr),
                        "Peer disconnected: {}",
                        reason
                    );

                    // Build session snapshot before cleanup
                    let now = Instant::now();
                    let session_info = SessionInfo {
                        peer_addr: addr,
                        role: if peer.is_server {
                            SessionRole::Server
                        } else {
                            SessionRole::Client
                        },
                        uptime: now.duration_since(peer.created_at),
                        idle: now.duration_since(peer.last_activity),
                        total_bytes_sent: peer.total_bytes_sent,
                        total_bytes_received: peer.total_bytes_received,
                        streams_sent: peer.streams_sent,
                        streams_received: peer.streams_received,
                        in_recovery: peer.recovery_started_at.is_some(),
                    };

                    // Send ACK for disconnect
                    let my_dir: u64 = if peer.is_server { SUDP_DIR_BIT } else { 0 };
                    let ack_seq = my_dir | SUDP_SEQ_MASK;
                    let mut ad = [0u8; 9];
                    ad[0] = SUDP_ACK;
                    ad[1..9].copy_from_slice(&ack_seq.to_be_bytes());
                    if let Ok(encrypted) = self.encrypt_payload(&peer.cipher_key, ack_seq, &ad, &[])
                    {
                        let mut resp = Vec::with_capacity(9 + encrypted.len());
                        resp.extend_from_slice(&ad);
                        resp.extend_from_slice(&encrypted);
                        let _ = socket.send_to(&resp, addr).await;
                    }

                    // Drop the lock before cleanup
                    drop(peer);

                    // Clean up all state for this peer
                    self.sessions.remove(&addr);
                    let keys_to_remove: Vec<(SocketAddr, u64)> = self
                        .unacked
                        .iter()
                        .filter(|e| e.key().0 == addr)
                        .map(|e| *e.key())
                        .collect();
                    for k in keys_to_remove {
                        self.unacked.remove(&k);
                    }
                    self.handshakes.remove(&addr);

                    return Ok(Some(Event::Disconnected(DisconnectInfo {
                        peer_addr: addr,
                        reason,
                        session: session_info,
                    })));
                }
            }

            _ => {}
        }
        Ok(None)
    }

    pub async fn start_background_tasks(&self, socket: Arc<UdpSocket>) {
        let pc_gc = Arc::clone(&self.handshakes);
        let oc_gc = Arc::clone(&self.sessions);
        let ac_gc = Arc::clone(&self.unacked);
        let rc_gc = Arc::clone(&self.reputations);

        // GC Task (Standardized Timeouts & Security)
        let pc_gc_c = Arc::clone(&pc_gc);
        let oc_gc_c = Arc::clone(&oc_gc);
        let ac_gc_c = Arc::clone(&ac_gc);
        let _rc_gc = Arc::clone(&rc_gc);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            let _ = _rc_gc;
            loop {
                interval.tick().await;
                let now = Instant::now();
                pc_gc_c.retain(|_, p| p.created_at.elapsed().as_secs() < SUDP_HANDSHAKE_TIMEOUT);
                let mut expired = Vec::new();
                oc_gc_c.retain(|addr, o| {
                    if o.last_activity.elapsed().as_secs() < SUDP_SESSION_TIMEOUT {
                        true
                    } else {
                        expired.push(*addr);
                        false
                    }
                });

                // DEEP CLEAN: Wipe all pending packets for dead sessions
                for addr in expired {
                    ac_gc_c.retain(|(peer_addr, _), _| *peer_addr != addr);
                }

                // Cleanup Reputation: Only keep blocked IPs or those in an active handshake window
                rc_gc.retain(|_, r| {
                    if let Some(blocked_until) = r.blocked_until
                        && now < blocked_until
                    {
                        return true;
                    }
                    r.window_start.elapsed().as_secs() < SUDP_PEER_TTL
                });
            }
        });

        // Retransmission Task (Windowed)
        let ac_re = Arc::clone(&self.unacked);
        let oc_re = Arc::clone(&self.sessions);
        let rc_re = Arc::clone(&self.reputations);
        let socket_re = Arc::clone(&socket);
        let engine_re = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Group pending packets by (addr, window_idx) — scoped retransmit
                type RetransmitGroups =
                    std::collections::HashMap<(SocketAddr, u64), Vec<(u64, Instant, u32, bool)>>;
                let mut window_groups: RetransmitGroups = std::collections::HashMap::new();
                for entry in ac_re.iter() {
                    let ((addr, seq), pending) = entry.pair();
                    let window_idx = (*seq & SUDP_SEQ_MASK) >> SUDP_WINDOW_IDX_SHIFT;
                    window_groups.entry((*addr, window_idx)).or_default().push((
                        *seq,
                        pending.sent_at,
                        pending.retries,
                        pending.last_gasp_tried,
                    ));
                }

                // Check for 10-minute session kill (per peer)
                let mut expired: Vec<SocketAddr> = Vec::new();
                for entry in oc_re.iter() {
                    if let Some(recovery_start) = entry.recovery_started_at
                        && recovery_start.elapsed().as_secs() >= 600
                    {
                        expired.push(*entry.key());
                    }
                }
                for addr in &expired {
                    oc_re.remove(addr);
                    ac_re.retain(|(a, _), _| a != addr);
                }

                for ((addr, window_idx), packets) in &window_groups {
                    if expired.contains(addr) {
                        continue;
                    }

                    // Adaptive RTO for this peer
                    let ip = addr.ip();
                    let rto = if let Some(rep) = rc_re.get(&ip) {
                        rep.current_rto
                    } else {
                        Duration::from_millis(SUDP_RTO_DEFAULT)
                    };

                    // Check timeout from LATEST sent_at in this window
                    // (= when we finished sending/resending this window)
                    let latest_sent = packets.iter().map(|p| p.1).max().unwrap();
                    if latest_sent.elapsed() < rto {
                        continue;
                    }

                    let min_retries = packets.iter().map(|p| p.2).min().unwrap_or(0);
                    let any_last_gasp = packets.iter().any(|p| p.3);

                    // Enter recovery mode on first retry
                    if let Some(mut peer) = oc_re.get_mut(addr) {
                        if peer.recovery_started_at.is_none() {
                            peer.recovery_started_at = Some(Instant::now());
                        }

                        let recovery_elapsed = peer
                            .recovery_started_at
                            .map(|t| t.elapsed().as_secs())
                            .unwrap_or(0);

                        if min_retries < SUDP_WINDOW_RETRIES {
                            // NORMAL RETRY: Resend only THIS window
                            for mut entry in ac_re.iter_mut() {
                                let ((a, s), pending) = entry.pair_mut();
                                let w = (*s & SUDP_SEQ_MASK) >> SUDP_WINDOW_IDX_SHIFT;
                                if *a == *addr
                                    && w == *window_idx
                                    && pending.retries < SUDP_WINDOW_RETRIES
                                {
                                    pending.retries += 1;
                                    pending.sent_at = Instant::now();
                                    let _ = socket_re.send_to(&pending.data, *addr).await;
                                }
                            }
                            slog!(
                                engine_re,
                                LogLevel::Info,
                                LogCategory::Retransmit,
                                Some(*addr),
                                "Retransmit: window {} (RTO: {}ms)",
                                window_idx,
                                rto.as_millis()
                            );
                        } else if recovery_elapsed >= 480 && !any_last_gasp {
                            // LAST GASP (8 minutes): Resend ALL unACKed windows for this peer
                            for mut entry in ac_re.iter_mut() {
                                let ((a, _), pending) = entry.pair_mut();
                                if *a == *addr {
                                    pending.retries = 0;
                                    pending.last_gasp_tried = true;
                                    pending.sent_at = Instant::now();
                                    let _ = socket_re.send_to(&pending.data, *addr).await;
                                }
                            }
                        }
                        // else: PARKED — retries >= 5, waiting for 8-min mark or ACK
                    }
                }
            }
        });
    }

    fn derive_cipher_key(&self, shared_secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.finalize().into()
    }

    fn encrypt_payload(
        &self,
        key: &[u8; 32],
        seq: u64,
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };
        cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow::anyhow!("S-UDP encrypt failed: {}", e))
    }

    fn decrypt_payload(
        &self,
        key: &[u8; 32],
        seq: u64,
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&seq.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad: ad,
        };
        cipher.decrypt(nonce, payload).ok()
    }

    /// Transmits data.
    /// Use `send_data()` for full report or live progress.
    pub async fn send(&self, addr: SocketAddr, data: &[u8]) -> Result<()> {
        self.send_data(addr, data, None).await?;
        Ok(())
    }

    /// Transmits data and returns a SendReport.
    /// Pass a `watch::Sender<SendProgress>` for real-time progress updates.
    ///
    /// # API Tiers
    /// | Need                        | Call                                        |
    /// |-----------------------------|---------------------------------------------|
    /// | Just success/fail           | `engine.send(addr, &data).await?`           |
    /// | Final report (no live)      | `engine.send_data(addr, &data, None).await` |
    /// | Live progress + report      | `engine.send_data(addr, &data, Some(&tx))…` |
    /// Transmits a raw payload to a connected peer with full retransmission and flow control.
    ///
    /// # Arguments
    /// * `addr` - The remote peer's address.
    /// * `data` - The byte array to transmit.
    /// * `progress_tx` - Optional watcher to receive real-time transmission progress.
    pub async fn send_data(
        &self,
        addr: SocketAddr,
        data: &[u8],
        progress_tx: Option<&watch::Sender<SendProgress>>,
    ) -> Result<SendReport> {
        let start_time = Instant::now();
        let total_bytes = data.len();
        let chunk_limit = SUDP_MTU - SUDP_OVERHEAD;
        let total_chunks = total_bytes.div_ceil(chunk_limit);

        // Metrics
        let mut bytes_sent: usize = 0;
        let mut chunks_sent: usize = 0;
        let mut windows_used: u64 = 0;
        let mut throttle_stalls: u32 = 0;

        // Derive cipher key once for the entire stream
        let mut key = if let Some(peer) = self.sessions.get(&addr) {
            peer.cipher_key
        } else {
            return Err(anyhow::anyhow!("No active session for target"));
        };

        // Emit initial progress
        if let Some(tx) = &progress_tx {
            let _ = tx.send(SendProgress {
                total_bytes,
                bytes_sent: 0,
                bytes_remaining: total_bytes,
                total_chunks,
                chunks_sent: 0,
                chunks_remaining: total_chunks,
                windows_used: 0,
                elapsed: Duration::ZERO,
                eta: Duration::ZERO,
                send_percent: 0.0,
                throttle_stalls: 0,
                phase: SendPhase::Sending,
            });
        }

        let mut i = 0;
        while i < total_chunks {
            let start = i * chunk_limit;
            let end = (start + chunk_limit).min(total_bytes);
            let chunk_data = &data[start..end];
            let chunk_size = end - start;

            let current_window_size = if let Some(peer) = self.sessions.get(&addr) {
                peer.current_window_size
            } else {
                128 // Fallback
            };

            let packet_idx = (i as u64) % (current_window_size as u64);

            let mut throttle = false;
            let mut throttled_window_check = 0;

            let target = addr;

            // Check throttle BEFORE touching peer state
            if packet_idx == 0 && i != 0 {
                let (pending_window, last_acked) = if let Some(peer) = self.sessions.get(&addr) {
                    (peer.next_send_seq, peer.last_acked_window)
                } else {
                    return Err(anyhow::anyhow!("Connection lost during send"));
                };

                let unacked = pending_window.saturating_sub(last_acked);
                if unacked >= 2 { // Keep throttle at 2 windows of current size
                    throttle = true;
                    throttled_window_check = pending_window - 1;
                }
            }

            if throttle {
                throttle_stalls += 1;
                loop {
                    let acked = if let Some(peer) = self.sessions.get(&addr) {
                        peer.last_acked_window
                    } else {
                        return Err(anyhow::anyhow!("Connection lost during send"));
                    };
                    if acked >= throttled_window_check {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                continue;
            }

            let (seq, packet) = {
                if let Some(mut peer) = self.sessions.get_mut(&addr) {
                    if packet_idx == 0 {
                        peer.next_send_seq += 1;
                        windows_used += 1;
                    }
                    let window_idx = peer.next_send_seq;
                    let dir_bit: u64 = if peer.is_server { SUDP_DIR_BIT } else { 0 };

                    let is_end_stream = i == total_chunks - 1;
                    let is_end_window = (packet_idx == (current_window_size as u64 - 1)) || is_end_stream;

                    let seq: u64 = dir_bit
                        | (window_idx << SUDP_WINDOW_IDX_SHIFT)
                        | ((packet_idx & SUDP_PACKET_IDX_MASK) << SUDP_PACKET_IDX_SHIFT)
                        | ((is_end_window as u64) << 1)
                        | (is_end_stream as u64);

                    let mut ad = [0u8; 9];
                    ad[0] = SUDP_DATA;
                    ad[1..9].copy_from_slice(&seq.to_be_bytes());

                    let encrypted = self.encrypt_payload(&key, seq, &ad, chunk_data)?;
                    let mut packet = Vec::with_capacity(9 + encrypted.len());
                    packet.extend_from_slice(&ad);
                    packet.extend_from_slice(&encrypted);

                    if is_end_window
                        && let Some(mut rep) = self.reputations.get_mut(&addr.ip())
                    {
                        rep.last_window_sent_at = Some(Instant::now());
                    }
                    (seq, packet)
                } else {
                    return Err(anyhow::anyhow!("Connection lost during send"));
                }
            }; // Lock released

            self.unacked.insert(
                (target, seq),
                UnackedPacket {
                    data: packet.clone(),
                    sent_at: Instant::now(),
                    retries: 0,
                    last_gasp_tried: false,
                },
            );

            let socket = if let Some(peer) = self.sessions.get(&target) {
                Arc::clone(&peer.socket)
            } else {
                return Err(anyhow::anyhow!("Connection lost during send"));
            };

            if let Err(e) = socket.send_to(&packet, target).await {
                self.unacked.remove(&(target, seq));
                return Err(e.into());
            }

            // Update metrics
            bytes_sent += chunk_size;
            chunks_sent += 1;

            // Emit progress
            if let Some(tx) = &progress_tx {
                let elapsed = start_time.elapsed();
                let send_percent = (chunks_sent as f64 / total_chunks as f64) * 100.0;
                let eta = if chunks_sent > 0 {
                    let rate = elapsed.as_secs_f64() / chunks_sent as f64;
                    Duration::from_secs_f64(rate * (total_chunks - chunks_sent) as f64)
                } else {
                    Duration::ZERO
                };

                let _ = tx.send(SendProgress {
                    total_bytes,
                    bytes_sent,
                    bytes_remaining: total_bytes - bytes_sent,
                    total_chunks,
                    chunks_sent,
                    chunks_remaining: total_chunks - chunks_sent,
                    windows_used,
                    elapsed,
                    eta,
                    send_percent,
                    throttle_stalls,
                    phase: SendPhase::Sending,
                });
            }

            i += 1;
        }

        let send_elapsed = start_time.elapsed();

        // ️ Zeroize cipher key — no longer needed
        key.zeroize();

        // Emit drain phase
        if let Some(tx) = &progress_tx {
            let _ = tx.send(SendProgress {
                total_bytes,
                bytes_sent,
                bytes_remaining: 0,
                total_chunks,
                chunks_sent,
                chunks_remaining: 0,
                windows_used,
                elapsed: send_elapsed,
                eta: Duration::ZERO,
                send_percent: 100.0,
                throttle_stalls,
                phase: SendPhase::Draining,
            });
        }

        // STREAM DRAIN: Do not return until every packet for this stream is confirmed
        // The background retransmit task handles resending lost packets.
        // If session dies (10-min recovery timeout), return error.
        loop {
            let mut has_pending = false;
            for entry in self.unacked.iter() {
                if entry.key().0 == addr {
                    has_pending = true;
                    break;
                }
            }
            if !has_pending {
                break;
            }

            // Session killed by recovery timeout → return failure
            if !self.sessions.contains_key(&addr) {
                return Err(anyhow::anyhow!("Connection lost: recovery timeout"));
            }

            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let total_elapsed = start_time.elapsed();
        let drain_elapsed = total_elapsed - send_elapsed;
        let throughput_bps = if total_elapsed.as_secs_f64() > 0.0 {
            total_bytes as f64 / total_elapsed.as_secs_f64()
        } else {
            0.0
        };

        // Emit complete
        if let Some(tx) = &progress_tx {
            let _ = tx.send(SendProgress {
                total_bytes,
                bytes_sent,
                bytes_remaining: 0,
                total_chunks,
                chunks_sent,
                chunks_remaining: 0,
                windows_used,
                elapsed: total_elapsed,
                eta: Duration::ZERO,
                send_percent: 100.0,
                throttle_stalls,
                phase: SendPhase::Complete,
            });
        }

        // Update session-level counters
        if let Some(mut peer) = self.sessions.get_mut(&addr) {
            peer.total_bytes_sent += total_bytes;
            peer.streams_sent += 1;
        }

        Ok(SendReport {
            total_bytes,
            total_chunks,
            windows_used,
            elapsed: total_elapsed,
            send_elapsed,
            drain_elapsed,
            throttle_stalls,
            throughput_bps,
        })
    }

    // ─── Session Management APIs ─────────────────────────────────────

    /// Get info for a specific session
    pub fn get_session_info(&self, addr: SocketAddr) -> Option<SessionInfo> {
        self.sessions.get(&addr).map(|peer| {
            let now = Instant::now();
            SessionInfo {
                peer_addr: addr,
                role: if peer.is_server {
                    SessionRole::Server
                } else {
                    SessionRole::Client
                },
                uptime: now.duration_since(peer.created_at),
                idle: now.duration_since(peer.last_activity),
                total_bytes_sent: peer.total_bytes_sent,
                total_bytes_received: peer.total_bytes_received,
                streams_sent: peer.streams_sent,
                streams_received: peer.streams_received,
                in_recovery: peer.recovery_started_at.is_some(),
            }
        })
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let now = Instant::now();
        self.sessions
            .iter()
            .map(|entry| {
                let addr = *entry.key();
                let peer = entry.value();
                SessionInfo {
                    peer_addr: addr,
                    role: if peer.is_server {
                        SessionRole::Server
                    } else {
                        SessionRole::Client
                    },
                    uptime: now.duration_since(peer.created_at),
                    idle: now.duration_since(peer.last_activity),
                    total_bytes_sent: peer.total_bytes_sent,
                    total_bytes_received: peer.total_bytes_received,
                    streams_sent: peer.streams_sent,
                    streams_received: peer.streams_received,
                    in_recovery: peer.recovery_started_at.is_some(),
                }
            })
            .collect()
    }

    /// Graceful disconnect — sends flag 0x06 with encrypted reason, then cleans up.
    /// Returns a session snapshot from before cleanup.
    pub async fn disconnect(&self, addr: SocketAddr, reason: &str) -> Result<SessionInfo> {
        let (cipher_key, session_info) = if let Some(peer) = self.sessions.get(&addr) {
            let now = Instant::now();
            let info = SessionInfo {
                peer_addr: addr,
                role: if peer.is_server {
                    SessionRole::Server
                } else {
                    SessionRole::Client
                },
                uptime: now.duration_since(peer.created_at),
                idle: now.duration_since(peer.last_activity),
                total_bytes_sent: peer.total_bytes_sent,
                total_bytes_received: peer.total_bytes_received,
                streams_sent: peer.streams_sent,
                streams_received: peer.streams_received,
                in_recovery: peer.recovery_started_at.is_some(),
            };
            (peer.cipher_key, info)
        } else {
            return Err(anyhow::anyhow!("No active session for {}", addr));
        };

        // Build disconnect packet: flag 0x06, seq = all 1s
        let dir_bit: u64 = match session_info.role {
            SessionRole::Server => SUDP_DIR_BIT,
            SessionRole::Client => 0,
        };
        let disconnect_seq = dir_bit | SUDP_SEQ_MASK; // All 1s in data portion

        let mut ad = [0u8; 9];
        ad[0] = SUDP_DISCONNECT;
        ad[1..9].copy_from_slice(&disconnect_seq.to_be_bytes());

        let encrypted =
            self.encrypt_payload(&cipher_key, disconnect_seq, &ad, reason.as_bytes())?;
        let mut packet = Vec::with_capacity(9 + encrypted.len());
        packet.extend_from_slice(&ad);
        packet.extend_from_slice(&encrypted);

        // Send disconnect — use the session's socket
        let socket = if let Some(peer) = self.sessions.get(&addr) {
            Arc::clone(&peer.socket)
        } else {
            return Err(anyhow::anyhow!("Connection lost"));
        };
        let _ = socket.send_to(&packet, addr).await;

        // Clean up all state immediately
        self.sessions.remove(&addr);
        let keys_to_remove: Vec<(SocketAddr, u64)> = self
            .unacked
            .iter()
            .filter(|e| e.key().0 == addr)
            .map(|e| *e.key())
            .collect();
        for k in keys_to_remove {
            self.unacked.remove(&k);
        }
        self.handshakes.remove(&addr);

        Ok(session_info)
    }

    /// Close a specific session locally (no network message sent)
    pub fn close_session(&self, addr: SocketAddr) -> bool {
        // Remove session
        let removed = self.sessions.remove(&addr).is_some();
        // Clean up all unacked packets for this peer
        let keys_to_remove: Vec<(SocketAddr, u64)> = self
            .unacked
            .iter()
            .filter(|e| e.key().0 == addr)
            .map(|e| *e.key())
            .collect();
        for k in keys_to_remove {
            self.unacked.remove(&k);
        }
        // Clean up handshake state
        self.handshakes.remove(&addr);
        removed
    }

    /// Number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
