//! Checks that the OnetDNS TLS parser accepts what rustls accepts. It mutates seeds, feeds both and
//! reports inputs where they disagree: accepted only by OnetDNS means OnetDNS lets through what
//! others reject, rejected only by OnetDNS means real clients cannot connect. A ClientHello
//! accepted only by OnetDNS is retried in rustls without the extensions OnetDNS does not interpret;
//! if rustls still rejects it, it goes into a real server handshake to see whether the server
//! answers with a ServerHello.
//!
//! This is a separate workspace so its dependencies stay out of the root workspace.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::message::{Message, MessagePayload, PlainMessage};
use rustls::{ContentType, ProtocolVersion};

use onetdns_tls::handshake::{HandshakeMsg, HandshakeType};
use onetdns_tls::msg::{ClientHello, ServerHello};
use onetdns_tls::{server_handshake, ServerConfig};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().take(400).map(|x| format!("{x:02x}")).collect()
}

/// Matches the scope of our parser: anything that is not a client or server first message, or whose
/// declared length differs from the body, counts as rejected. rustls accepts Finished and unknown
/// bodies without parsing them and ignores bytes past the declared length; without this filter
/// those would show up as rustls-only accepts.
fn rustls_accepts(data: &[u8]) -> bool {
    let [typ, l0, l1, l2, body @ ..] = data else {
        return false;
    };
    let declared = usize::from(*l0) << 16 | usize::from(*l1) << 8 | usize::from(*l2);
    let first_flight = *typ == HandshakeType::ClientHello.0 || *typ == HandshakeType::ServerHello.0;
    if !first_flight || declared != body.len() {
        return false;
    }
    let plain = PlainMessage {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: Payload::Owned(data.to_vec()),
    };
    matches!(Message::try_from(plain), Ok(m) if matches!(m.payload, MessagePayload::Handshake { .. }))
}

/// RFC 8446 has unknown extensions ignored. rustls parses some extensions OnetDNS does not, so
/// inputs that break only those are rejected by rustls alone; the implementations truly disagree
/// only if rustls still rejects with them removed.
fn rustls_accepts_interpreted_part(hello: &ClientHello) -> bool {
    let mut interpreted = hello.clone();
    interpreted
        .extensions
        .retain(|extension| extension.client_hello_syntax_ok().is_some());
    rustls_accepts(&interpreted.to_handshake().encode())
}

fn ours_accepts(data: &[u8]) -> bool {
    let (m, consumed) = match HandshakeMsg::parse(data) {
        Ok(Some(v)) => v,
        _ => return false,
    };
    if consumed != data.len() {
        return false;
    }
    if m.msg_type == HandshakeType::ClientHello {
        ClientHello::parse(&m.body).is_ok()
    } else if m.msg_type == HandshakeType::ServerHello {
        ServerHello::parse(&m.body).is_ok()
    } else {
        false
    }
}

/// Connection that serves fixed input and collects the output.
struct Replay {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for Replay {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Replay {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Only checks whether the server answers the first message. The certificate and signature just
/// need to be well-formed: the server uses them after it has already sent ServerHello.
fn probe_server() -> ServerConfig {
    ServerConfig {
        cert_chain: vec![vec![0x30, 0x00]],
        sign_scheme: onetdns_tls::msg::consts::ECDSA_SECP256R1_SHA256,
        sign: Arc::new(|_| Vec::new()),
        alpn: Vec::new(),
        client_ca: None,
        resumption: None,
    }
}

/// Sends the message as one plaintext handshake record and checks that the first record written is
/// a handshake. A HelloRetryRequest has the same form and counts as an answer.
fn ours_server_answers(data: &[u8], cfg: &ServerConfig) -> bool {
    let Ok(len) = u16::try_from(data.len()) else {
        return false;
    };
    let handshake = onetdns_tls::ContentType::Handshake.0;
    let mut record = vec![handshake, 3, 1];
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(data);
    let mut conn = Replay {
        input: Cursor::new(record),
        output: Vec::new(),
    };
    let _ = server_handshake(&mut conn, cfg);
    conn.output.first() == Some(&handshake)
}

fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(8) {
        if b.is_empty() {
            break;
        }
        match rng.below(6) {
            0 => {
                let i = rng.below(b.len());
                b[i] = rng.byte();
            }
            1 => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            2 => {
                let i = rng.below(b.len());
                b.insert(i, rng.byte());
            }
            3 => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            4 => {
                let i = rng.below(b.len());
                b.truncate(i);
            }
            _ => b.push(rng.byte()),
        }
    }
    b
}

/// Exits with 1 when our server answered a ClientHello that rustls rejects even without the
/// extensions OnetDNS does not interpret.
fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let ch_seed = sample_client_hello();
    let sh_seed = sample_server_hello();

    let server = probe_server();

    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let (mut both_accept, mut both_reject, mut we_only, mut rustls_only) = (0u64, 0u64, 0u64, 0u64);
    let (mut uninterpreted_only, mut still_rejected, mut answered) = (0u64, 0u64, 0u64);
    let mut answered_examples: Vec<String> = Vec::new();

    for i in 0..iters {
        let data = match i % 5 {
            0 => {
                let n = rng.below(300);
                (0..n).map(|_| rng.byte()).collect::<Vec<u8>>()
            }
            1 | 2 => havoc(&mut rng, &ch_seed),
            _ => havoc(&mut rng, &sh_seed),
        };
        match (ours_accepts(&data), rustls_accepts(&data)) {
            (true, true) => both_accept += 1,
            (false, false) => both_reject += 1,
            (true, false) => {
                we_only += 1;
                let Ok(Some((message, _))) = HandshakeMsg::parse(&data) else {
                    continue;
                };
                let Ok(hello) = ClientHello::from_handshake(&message) else {
                    continue;
                };
                if rustls_accepts_interpreted_part(&hello) {
                    uninterpreted_only += 1;
                    continue;
                }
                still_rejected += 1;
                if ours_server_answers(&data, &server) {
                    answered += 1;
                    if answered_examples.len() < 20 {
                        answered_examples.push(format!("data({}B)={}", data.len(), hex(&data)));
                    }
                }
            }
            (false, true) => rustls_only += 1,
        }
    }

    println!("=== TLS first-message parser differential (ours vs rustls 0.23) ===");
    println!("iterations: {iters}");
    println!("both accept : {both_accept}");
    println!("both reject : {both_reject}");
    println!("rustls-only (rustls accepts, we reject): {rustls_only}");
    println!("we-only (we accept, rustls rejects): {we_only}");
    println!(
        "  client hellos rustls accepts without the extensions we ignore: {uninterpreted_only}"
    );
    println!("  client hellos rustls still rejects: {still_rejected}");
    println!("    answered by our server with a ServerHello: {answered}");
    if !answered_examples.is_empty() {
        println!("--- answered client hellos (hex) ---");
        for e in &answered_examples {
            println!("  {e}");
        }
        std::process::exit(1);
    }
}

fn sample_client_hello() -> Vec<u8> {
    use onetdns_tls::msg::{consts::*, Extension};
    let ch = ClientHello {
        legacy_version: TLS12,
        random: [0x11; 32],
        session_id: vec![0xAA; 32],
        cipher_suites: vec![TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256],
        compression_methods: vec![0],
        extensions: vec![
            Extension::supported_versions_client(&[TLS13, TLS12]),
            Extension::supported_groups(&[X25519, SECP256R1]),
            Extension::signature_algorithms(&[ECDSA_SECP256R1_SHA256, RSA_PSS_RSAE_SHA256]),
            Extension::key_share_client(&[(X25519, vec![0x22; 32])]),
            Extension::server_name("example.com"),
        ],
    };
    ch.to_handshake().encode()
}

fn sample_server_hello() -> Vec<u8> {
    use onetdns_tls::msg::{consts::*, Extension};
    let sh = ServerHello {
        legacy_version: TLS12,
        random: [0x33; 32],
        session_id_echo: vec![0xBB; 32],
        cipher_suite: TLS_AES_128_GCM_SHA256,
        extensions: vec![
            Extension::supported_versions_server(TLS13),
            Extension::key_share_server(X25519, &[0x44; 32]),
        ],
    };
    sh.to_handshake().encode()
}
