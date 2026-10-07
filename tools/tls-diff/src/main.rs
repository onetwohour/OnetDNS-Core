/*!
 * @brief OnetDNS TLS 파서와 널리 쓰이는 구현이 같은 것을 받아들이는지 대조한다.
 *
 * @details 시드를 망가뜨려 양쪽에 넣고 판정이 갈리는 입력을 찾는다. OnetDNS만 받아들이면
 *          남이 거부하는 것을 OnetDNS는 통과시키는 것이고, OnetDNS만 거부하면 정상 클라이언트가
 *          붙지 못한다. OnetDNS만 받아들인 클라이언트 첫 메시지는 OnetDNS가 해석하지 않는 확장을
 *          빼고 rustls에 다시 묻는다. 그래도 rustls가 거부하면 실제 서버 핸드셰이크에 넣어
 *          서버가 ServerHello로 답하는지 확인한다.
 * @note 이 도구는 별도 작업 공간이다. 루트 작업 공간에는 이 외부 의존성이 들어가지 않는다.
 */

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::message::{Message, MessagePayload, PlainMessage};
use rustls::{ContentType, ProtocolVersion};

use onetdns_tls::handshake::{HandshakeMsg, HandshakeType};
use onetdns_tls::msg::{ClientHello, ServerHello};
use onetdns_tls::{server_handshake, ServerConfig};

/** @brief 시드에서 되풀이 가능한 난수. */
struct Rng(u64);
impl Rng {
    /** @brief 다음 난수. */
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /** @brief 이 값보다 작은 수 하나. */
    fn below(&mut self, n: usize) -> usize { if n == 0 { 0 } else { (self.next() % n as u64) as usize } }
    /** @brief 바이트 하나. */
    fn byte(&mut self) -> u8 { (self.next() & 0xff) as u8 }
}

/** @brief 바이트열을 16진 문자열로. 갈린 입력을 그대로 찍는다. */
fn hex(b: &[u8]) -> String {
    b.iter().take(400).map(|x| format!("{x:02x}")).collect()
}

/**
 * @brief 비교 대상 구현이 이 바이트열을 첫 메시지 하나로 받아들이는지.
 * @details 이쪽 판정과 범위를 맞춘다. 형식이 클라이언트나 서버의 첫 메시지가 아니거나 선언한
 *          길이가 본문 길이와 다르면 거부로 친다. rustls는 Finished나 모르는 형식의 본문을 해석
 *          없이 받아들이고 선언한 길이 뒤에 남은 바이트를 보지 않는다. 이것을 거르지 않으면
 *          판정 차이가 아닌 입력이 rustls만 받아들인 쪽으로 잡힌다.
 */
fn rustls_accepts(data: &[u8]) -> bool {
    let [typ, l0, l1, l2, body @ ..] = data else { return false };
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

/**
 * @brief OnetDNS가 해석하지 않는 확장을 뺀 클라이언트 첫 메시지를 rustls가 받아들이는지.
 * @details RFC 8446 은 모르는 확장을 무시하게 한다. rustls는 OnetDNS가 해석하지 않는 확장도
 *          일부 해석하므로, 그런 확장의 형식만 깨진 입력은 rustls만 거부한다. 이 확장들을 빼도
 *          rustls가 거부해야 두 구현의 판정이 실제로 갈린 것이다.
 */
fn rustls_accepts_interpreted_part(hello: &ClientHello) -> bool {
    let mut interpreted = hello.clone();
    interpreted
        .extensions
        .retain(|extension| extension.client_hello_syntax_ok().is_some());
    rustls_accepts(&interpreted.to_handshake().encode())
}

/** @brief OnetDNS 구현이 이 바이트열을 받아들이는지. */
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

/** @brief 정해 둔 바이트만 읽히고 쓴 바이트는 모아 두는 연결. */
struct Replay {
    /** @brief 서버가 읽을 바이트. */
    input: Cursor<Vec<u8>>,
    /** @brief 서버가 쓴 바이트. */
    output: Vec<u8>,
}

impl Read for Replay {
    /** @brief 정해 둔 바이트를 내준다. 다 내주면 연결이 닫힌 것과 같다. */
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Replay {
    /** @brief 쓴 바이트를 모은다. */
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    /** @brief 모으기만 하므로 할 일이 없다. */
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/**
 * @brief 첫 메시지에 답하는지만 볼 서버 설정.
 * @details 인증서와 서명은 형식만 갖춘다. 서버가 그것을 쓰는 시점에는 ServerHello를 이미
 *          보냈으므로 판정에 영향이 없다.
 */
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

/**
 * @brief 이쪽 서버가 이 클라이언트 첫 메시지에 ServerHello로 답하는지.
 * @details 메시지를 평문 핸드셰이크 레코드 하나에 담아 넣고, 서버가 처음 쓴 레코드가
 *          핸드셰이크인지 본다. HelloRetryRequest도 같은 형식이므로 답한 것으로 친다.
 */
fn ours_server_answers(data: &[u8], cfg: &ServerConfig) -> bool {
    let Ok(len) = u16::try_from(data.len()) else { return false };
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

/** @brief 시드를 조금씩 망가뜨린다. */
fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(8) {
        if b.is_empty() { break; }
        match rng.below(6) {
            0 => { let i = rng.below(b.len()); b[i] = rng.byte(); }
            1 => { let i = rng.below(b.len()); b[i] ^= 1 << rng.below(8); }
            2 => { let i = rng.below(b.len()); b.insert(i, rng.byte()); }
            3 => { let i = rng.below(b.len()); b.remove(i); }
            4 => { let i = rng.below(b.len()); b.truncate(i); }
            _ => b.push(rng.byte()),
        }
    }
    b
}

/**
 * @brief 두 구현의 판정이 갈리는 입력을 찾아 찍는다.
 * @details OnetDNS가 해석하지 않는 확장을 빼도 rustls가 거부하는 클라이언트 첫 메시지에 이쪽
 *          서버가 답했으면 종료 코드 1로 끝난다.
 */
fn main() {
    let iters: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let ch_seed = sample_client_hello();
    let sh_seed = sample_server_hello();

    let server = probe_server();

    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let (mut both_accept, mut both_reject, mut we_only, mut rustls_only) = (0u64, 0u64, 0u64, 0u64);
    let (mut uninterpreted_only, mut still_rejected, mut answered) = (0u64, 0u64, 0u64);
    let mut answered_examples: Vec<String> = Vec::new();

    for i in 0..iters {
        let data = match i % 5 {
            0 => { let n = rng.below(300); (0..n).map(|_| rng.byte()).collect::<Vec<u8>>() }
            1 | 2 => havoc(&mut rng, &ch_seed),
            _ => havoc(&mut rng, &sh_seed),
        };
        match (ours_accepts(&data), rustls_accepts(&data)) {
            (true, true) => both_accept += 1,
            (false, false) => both_reject += 1,
            (true, false) => {
                we_only += 1;
                let Ok(Some((message, _))) = HandshakeMsg::parse(&data) else { continue };
                let Ok(hello) = ClientHello::from_handshake(&message) else { continue };
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
    println!("  client hellos rustls accepts without the extensions we ignore: {uninterpreted_only}");
    println!("  client hellos rustls still rejects: {still_rejected}");
    println!("    answered by our server with a ServerHello: {answered}");
    if !answered_examples.is_empty() {
        println!("--- answered client hellos (hex) ---");
        for e in &answered_examples { println!("  {e}"); }
        std::process::exit(1);
    }
}

/** @brief 클라이언트 첫 메시지 시드. */
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

/** @brief 서버 첫 메시지 시드. */
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
