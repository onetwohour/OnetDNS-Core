//! Parsers of external input must not panic on any bytes. Seeds are mutated and fed in repeatedly;
//! pure random input fails the first check and never reaches deeper code.
//!
//! A panic prints the input that caused it, so it can be reproduced. An environment variable sets
//! the iteration count.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;

/// The input being fed, printed if it panics.
static CAP: Mutex<String> = Mutex::new(String::new());

/// Deterministic from its seed.
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
    fn len(&mut self) -> usize {
        match self.below(10) {
            0..=5 => self.below(64),
            6..=8 => self.below(256),
            _ => self.below(1500),
        }
    }
    fn rand_bytes(&mut self) -> Vec<u8> {
        let n = self.len();
        (0..n).map(|_| self.byte()).collect()
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b.iter().take(512) {
        s.push_str(&format!("{x:02x}"));
    }
    if b.len() > 512 {
        s.push_str("..(truncated)");
    }
    s
}

struct Rec {
    fails: Vec<String>,
}
impl Rec {
    fn run<F: FnOnce()>(&mut self, cat: &str, input: &[u8], f: F) {
        CAP.lock().unwrap().clear();
        if panic::catch_unwind(AssertUnwindSafe(f)).is_err() && self.fails.len() < 30 {
            let msg = CAP.lock().unwrap().clone();
            self.fails.push(format!(
                "[{cat}] {msg}\n      input({}B)={}",
                input.len(),
                hex(input)
            ));
        }
    }
}

fn havoc(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(10) {
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

fn dns_query_seed() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'w', b'w',
        b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01,
        0x00, 0x01,
    ]
}
fn dns_response_seed() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 3, b'w', b'w',
        b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93,
        184, 216, 34, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// Valid shape, wrong values.
fn dns_structured(rng: &mut Rng) -> Vec<u8> {
    let mut b = rng.next().to_be_bytes()[..4].to_vec();
    for _ in 0..4 {
        let c = if rng.below(4) == 0 {
            rng.below(0x4000)
        } else {
            rng.below(12)
        };
        b.extend_from_slice(&(c as u16).to_be_bytes());
    }
    for _ in 0..rng.below(220) {
        b.push(rng.byte());
    }
    b
}

/// Valid shape, wrong values.
fn tls_record(rng: &mut Rng) -> Vec<u8> {
    let mut b = vec![if rng.below(4) == 0 {
        rng.byte()
    } else {
        [20u8, 21, 22, 23][rng.below(4)]
    }];
    b.extend_from_slice(&[0x03, 0x03]);
    let plen = if rng.below(3) == 0 {
        rng.below(0xffff)
    } else {
        rng.below(300)
    };
    b.extend_from_slice(&(plen as u16).to_be_bytes());
    for _ in 0..rng.below(300) {
        b.push(rng.byte());
    }
    b
}

/// Valid shape, wrong values.
fn tls_handshake(rng: &mut Rng) -> Vec<u8> {
    let mut b = vec![if rng.below(4) == 0 {
        rng.byte()
    } else {
        [1u8, 2, 4, 8, 11, 13, 15][rng.below(7)]
    }];
    let l = if rng.below(3) == 0 {
        rng.below(0xff_ffff)
    } else {
        rng.below(400)
    };
    b.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
    for _ in 0..rng.below(400) {
        b.push(rng.byte());
    }
    b
}

/// Valid shape, wrong values.
fn http2_frame(rng: &mut Rng) -> Vec<u8> {
    let l = if rng.below(3) == 0 {
        rng.below(0xff_ffff)
    } else {
        rng.below(300)
    };
    let mut b = vec![
        (l >> 16) as u8,
        (l >> 8) as u8,
        l as u8,
        rng.byte(),
        rng.byte(),
    ];
    b.extend_from_slice(&rng.next().to_be_bytes()[..4]);
    for _ in 0..rng.below(300) {
        b.push(rng.byte());
    }
    b
}

/// Valid shape, wrong values.
fn quic_frame(rng: &mut Rng) -> Vec<u8> {
    let mut b = vec![if rng.below(4) == 0 {
        rng.byte()
    } else {
        rng.below(0x20) as u8
    }];
    for _ in 0..rng.below(6) {
        match rng.below(4) {
            0 => b.push(rng.byte() & 0x3f),
            1 => {
                b.push(0x40 | (rng.byte() & 0x3f));
                b.push(rng.byte());
            }
            2 => {
                b.push(0x80 | (rng.byte() & 0x3f));
                for _ in 0..3 {
                    b.push(rng.byte());
                }
            }
            _ => {
                b.push(0xc0 | (rng.byte() & 0x3f));
                for _ in 0..7 {
                    b.push(rng.byte());
                }
            }
        }
    }
    for _ in 0..rng.below(200) {
        b.push(rng.byte());
    }
    b
}

const PROXY_V1_SEED: &[u8] = b"PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\nDNSDATA";
const PROXY_V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Valid shape, wrong values.
fn proxy_prologue(rng: &mut Rng) -> Vec<u8> {
    match rng.below(5) {
        0 => havoc(rng, PROXY_V1_SEED),
        1 => {
            let mut b = b"PROXY ".to_vec();
            for _ in 0..rng.below(120) {
                b.push(rng.byte());
            }
            if rng.below(2) == 0 {
                b.extend_from_slice(b"\r\n");
            }
            b
        }
        2 => {
            let mut b = PROXY_V2_SIG.to_vec();
            for _ in 0..rng.below(60) {
                b.push(rng.byte());
            }
            b
        }

        3 => PROXY_V2_SIG[..rng.below(PROXY_V2_SIG.len())].to_vec(),
        _ => rng.rand_bytes(),
    }
}

const ZONE_SEED: &str = "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. (2024010101 7200 3600 1209600 3600)\n@ IN NS ns1.example.com.\nwww IN A 93.184.216.34\nwww IN AAAA 2606:2800:220:1:248:1893:25c8:1946\nmail IN MX 10 mail.example.com.\ntxt IN TXT \"v=spf1 -all\"\n_sip._tcp IN SRV 0 5 5060 sipserver.example.com.\n";
const CONFIG_SEED: &str = "listen = [\"127.0.0.1:53\"]\ncache_size = 10000\nupstreams = [\"udp://1.1.1.1:53\", \"tls://8.8.8.8:853\"]\nacl_allow = [\"10.0.0.0/8\"]\nblocklist_urls = [\"https://example.com/list.txt\"]\nrecursion_limit = 16\n\n[[zones]]\norigin = \"example.com\"\nfile = \"/etc/zones/example.com\"\n";

const RULES_SEED: &str = "! Title: seed\n||ads.example.com^\n@@||ok.ads.example.com^$important\n||track.example^$dnsrewrite=NOERROR;A;127.0.0.1\n||c.example^$client=10.0.0.0/8,denyallow=a.example\n||d.example^$ctag=device_pc|user_admin\n||e.example^$dnstype=~A|AAAA,badfilter\n0.0.0.0 bad.example\n127.0.0.1 tracker.example other.example\n/^ad[0-9]+\\.example$/\n||f.example^$important,third-party\n";

const WASM_SEED: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, 0x03,
    0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x0A, 0x01, 0x06, 0x6D, 0x65, 0x6D, 0x6F,
    0x72, 0x79, 0x02, 0x00, 0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,
];

const RPZ_SEED: &str = "$ORIGIN rpz.example.\n@ SOA ns1.rpz.example. a.rpz.example. 1 2 3 4 5\nbad.example CNAME .\nnodata.example CNAME *.\npassthru.example CNAME rpz-passthru.\n32.1.0.0.127.rpz-client-ip CNAME .\n24.0.0.0.10.rpz-ip CNAME .\nrewrite.example A 127.0.0.1\n";

#[test]
fn parsers_never_panic_on_malformed_input() {
    panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "?".into());
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic>".into());
        *CAP.lock().unwrap() = format!("{msg}  @ {loc}");
    }));

    let iters: u64 = std::env::var("ONETDNS_SWEEP_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25_000);
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let mut rec = Rec { fails: Vec::new() };
    let (q_seed, r_seed) = (dns_query_seed(), dns_response_seed());
    let provider =
        onetdns_dnscrypt::Provider::with_signing_seed(&[7u8; 32], "2.dnscrypt-cert.test", 86_400);

    let raft_seed = onetdns_cluster::encode_msg(&onetdns_cluster::Msg::AppendEntries {
        term: 7,
        leader: 3,
        prev_log_index: 11,
        prev_log_term: 6,
        entries: vec![
            onetdns_cluster::LogEntry {
                term: 7,
                index: 12,
                data: b"key=value".to_vec(),
            },
            onetdns_cluster::LogEntry {
                term: 7,
                index: 13,
                data: Vec::new(),
            },
        ],
        leader_commit: 11,
    });

    for i in 0..iters {
        let dns = match i % 4 {
            0 => rng.rand_bytes(),
            1 => dns_structured(&mut rng),
            2 => havoc(&mut rng, &q_seed),
            _ => havoc(&mut rng, &r_seed),
        };
        rec.run("dns", &dns, || {
            if let Ok(m) = onetdns_proto::Message::parse(&dns) {
                let encoded = m
                    .try_encode()
                    .expect("파싱에 성공한 DNS 메시지는 엄격하게 재인코딩");
                onetdns_proto::Message::parse(&encoded)
                    .expect("엄격하게 인코딩한 DNS 메시지는 재파싱");
            }
        });

        let tls = match i % 3 {
            0 => rng.rand_bytes(),
            1 => tls_record(&mut rng),
            _ => tls_handshake(&mut rng),
        };
        {
            use onetdns_tls::cert::{CertificateMsg, CertificateRequestMsg, CertificateVerify};
            use onetdns_tls::handshake::HandshakeMsg;
            use onetdns_tls::msg::{ClientHello, Extension, NewSessionTicket, ServerHello};
            use onetdns_tls::record::TlsRecord;
            use onetdns_tls::x509::X509;
            let t = &tls;
            rec.run("tls", t, || {
                let _ = TlsRecord::parse(t);
                let _ = HandshakeMsg::parse(t);
                let _ = ClientHello::parse(t);
                let _ = ServerHello::parse(t);
                let _ = Extension::parse_list(t);
                let _ = NewSessionTicket::parse(t);
                let _ = CertificateMsg::parse(t);
                let _ = CertificateRequestMsg::parse(t);
                let _ = CertificateVerify::parse(t);
                let _ = X509::parse(t);

                let _ = onetdns_tls::tls12::parse_server_key_exchange(t);
                let _ = onetdns_tls::tls12::parse_certificate(t);
                let _ = onetdns_tls::tls12::parse_client_key_exchange(t);
            });
        }

        let q = if i % 2 == 0 {
            rng.rand_bytes()
        } else {
            quic_frame(&mut rng)
        };
        {
            let qq = &q;
            rec.run("quic", qq, || {
                let _ = onetdns_quic::frame::parse(qq);
                let _ = onetdns_quic::varint::read(qq);
                let _ = onetdns_quic::qpack::decode_field_section(qq);
                let _ = onetdns_quic::h3::parse_frames(qq);
                let _ = onetdns_quic::params::TransportParams::decode(qq);
                let mut d = onetdns_quic::qpack::Decoder::new(4096);
                let _ = d.decode_field_section(0, qq);
            });
        }

        let h = if i % 2 == 0 {
            rng.rand_bytes()
        } else {
            http2_frame(&mut rng)
        };
        {
            let hh = &h;
            rec.run("http2", hh, || {
                let _ = onetdns_http2::frame::FrameHeader::parse(hh);
                let _ = onetdns_http2::hpack::decode_int(hh, 5);
                let _ = onetdns_http2::huffman::decode(hh);
                let mut d = onetdns_http2::hpack::Decoder::new(4096);
                let _ = d.decode(hh);
            });
        }

        let proxy = proxy_prologue(&mut rng);
        {
            let pp = &proxy;
            rec.run("proxy", pp, || {
                let _ = onetdns_runtime::proxy::parse(pp);
            });
        }

        let z = if i % 3 == 0 {
            rng.rand_bytes()
        } else {
            havoc(&mut rng, ZONE_SEED.as_bytes())
        };

        let ss = String::from_utf8_lossy(&z).into_owned();
        rec.run("zone", &z, || {
            let _ = onetdns_authority::parse_zone(&ss, "example.com");
        });

        let c = if i % 3 == 0 {
            rng.rand_bytes()
        } else {
            havoc(&mut rng, CONFIG_SEED.as_bytes())
        };
        let ss = String::from_utf8_lossy(&c).into_owned();
        rec.run("config", &c, || {
            let _ = onetdns_config::Config::from_toml_str(&ss);
        });

        let r = if i % 3 == 0 {
            rng.rand_bytes()
        } else {
            havoc(&mut rng, RULES_SEED.as_bytes())
        };
        let ss = String::from_utf8_lossy(&r).into_owned();
        rec.run("rules", &r, || {
            for line in ss.lines() {
                let _ = onetdns_filter::validate_rule(line, false);
            }
            let _ = onetdns_filter::build_from_str(&ss, "", onetdns_core::BlockResponse::NxDomain);
            let _ = onetdns_filter::build_from_str("", &ss, onetdns_core::BlockResponse::NxDomain);
        });

        let rpz = if i % 3 == 1 {
            rng.rand_bytes()
        } else {
            havoc(&mut rng, RPZ_SEED.as_bytes())
        };
        let ss = String::from_utf8_lossy(&rpz).into_owned();
        rec.run("rpz", &rpz, || {
            let mut parts = onetdns_filter::EngineParts::default();
            onetdns_filter::parse_rpz_text(&ss, &mut parts);
            let _ = onetdns_filter::BlockEngine::new(parts, onetdns_core::BlockResponse::NxDomain);
        });

        let dc = match i % 3 {
            0 => rng.rand_bytes(),
            1 => havoc(&mut rng, &q_seed),
            _ => havoc(&mut rng, &r_seed),
        };
        {
            let dd = &dc;
            rec.run("dnscrypt", dd, || {
                let _ = provider.cert_txt_response(dd);
                let _ = onetdns_dnscrypt::unpad(dd);
                let mut nonce = [0u8; 12];
                for (slot, byte) in nonce.iter_mut().zip(dd.iter()) {
                    *slot = *byte;
                }
                let _ = onetdns_dnscrypt::decrypt_query(&[0x5a; 32], &nonce, dd);
                // Sorts packet kinds; UDP and TCP both call it, with different size budgets.
                let peer: std::net::SocketAddr = "127.0.0.1:1".parse().expect("고정 주소");
                let answer = |_query: Vec<u8>, _src: std::net::SocketAddr, _budget: usize| None;
                let allow = |_src: std::net::SocketAddr| true;
                for over_udp in [true, false] {
                    let _ = onetdns_dnscrypt::server::respond(
                        &provider, dd, peer, over_udp, &answer, &allow,
                    );
                }
            });
        }

        let wasm = if i % 3 == 0 {
            rng.rand_bytes()
        } else {
            havoc(&mut rng, WASM_SEED)
        };
        {
            let ww = &wasm;
            rec.run("wasm", ww, || {
                let _ = onetdns_policy::WasmPolicy::from_wasm(ww);
            });
        }

        let raft = if i % 3 == 1 {
            rng.rand_bytes()
        } else {
            havoc(&mut rng, &raft_seed)
        };
        {
            let rr = &raft;
            rec.run("raft", rr, || {
                let _ = onetdns_cluster::decode_msg(rr);
            });
        }
    }

    let _ = panic::take_hook();
    assert!(
        rec.fails.is_empty(),
        "parser panicked on malformed input ({} distinct):\n{}",
        rec.fails.len(),
        rec.fails.join("\n")
    );
}
