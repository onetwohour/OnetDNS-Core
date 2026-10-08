/*!
 * @brief 밖에서 들어오는 것을 읽는 파서들이 어떤 바이트열에도 패닉하지 않는지.
 *
 * @details 시드를 조금씩 망가뜨려 수백만 번 넣는다. 시드를 두는 이유는 완전한 난수는
 *          거의 첫 검사에서 걸려 정작 깊은 코드에 닿지 않기 때문이다.
 * @warning 패닉하면 그 자리에서 멈추고 다시 만들 수 있는 입력을 그대로 찍는다. 찍지
 *          않으면 몇 번째 반복이었는지만 남아 재현할 수 없다.
 * @note 반복 횟수는 환경 변수로 정한다. 개발 중에는 짧게, CI에서는 백만 번 돌린다.
 */

use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;

/** @brief 지금 넣고 있는 입력. 패닉했을 때 찍기 위해 둔다. */
static CAP: Mutex<String> = Mutex::new(String::new());

/** @brief 시드에서 되풀이 가능한 난수. 같은 시드면 같은 순서가 나온다. */
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
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    /** @brief 바이트 하나. */
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    /** @brief 만들 입력의 길이. */
    fn len(&mut self) -> usize {
        match self.below(10) {
            0..=5 => self.below(64),
            6..=8 => self.below(256),
            _ => self.below(1500),
        }
    }
    /** @brief 아무 바이트열. */
    fn rand_bytes(&mut self) -> Vec<u8> {
        let n = self.len();
        (0..n).map(|_| self.byte()).collect()
    }
}

/** @brief 바이트열을 16진 문자열로. 재현용으로 찍는다. */
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

/** @brief 어떤 분류를 몇 번 돌렸는지. */
struct Rec {
    /** @brief 패닉한 분류들. */
    fails: Vec<String>,
}
impl Rec {
    /**
     * @brief 입력 하나를 파서에 넣는다.
     * @warning 넣기 전에 입력을 남겨 둔다. 패닉하면 그 입력을 그대로 찍어야 재현할 수 있다.
     */
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

/** @brief 시드를 조금씩 망가뜨린다. 완전한 난수는 첫 검사에서 걸려 깊은 코드에 닿지 못한다. */
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

/** @brief 질의 시드. */
fn dns_query_seed() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'w', b'w',
        b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01,
        0x00, 0x01,
    ]
}
/** @brief 응답 시드. */
fn dns_response_seed() -> Vec<u8> {
    vec![
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 3, b'w', b'w',
        b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93,
        184, 216, 34, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

/** @brief 형태는 갖췄지만 값이 어긋난 DNS 메시지. */
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

/** @brief 형태는 갖췄지만 값이 어긋난 TLS 레코드. */
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

/** @brief 형태는 갖췄지만 값이 어긋난 TLS 핸드셰이크. */
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

/** @brief 형태는 갖췄지만 값이 어긋난 HTTP/2 프레임. */
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

/** @brief 형태는 갖췄지만 값이 어긋난 QUIC 프레임. */
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

/** @brief 프록시 프로토콜 v1 시드. */
const PROXY_V1_SEED: &[u8] = b"PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\nDNSDATA";
/** @brief 프록시 프로토콜 v2의 첫 바이트들. */
const PROXY_V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/** @brief 형태는 갖췄지만 값이 어긋난 프록시 헤더. */
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

/** @brief 영역 파일 시드. */
const ZONE_SEED: &str = "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. (2024010101 7200 3600 1209600 3600)\n@ IN NS ns1.example.com.\nwww IN A 93.184.216.34\nwww IN AAAA 2606:2800:220:1:248:1893:25c8:1946\nmail IN MX 10 mail.example.com.\ntxt IN TXT \"v=spf1 -all\"\n_sip._tcp IN SRV 0 5 5060 sipserver.example.com.\n";
/** @brief 설정 파일 시드. */
const CONFIG_SEED: &str = "listen = [\"127.0.0.1:53\"]\ncache_size = 10000\nupstreams = [\"udp://1.1.1.1:53\", \"tls://8.8.8.8:853\"]\nacl_allow = [\"10.0.0.0/8\"]\nblocklist_urls = [\"https://example.com/list.txt\"]\nrecursion_limit = 16\n\n[[zones]]\norigin = \"example.com\"\nfile = \"/etc/zones/example.com\"\n";

/** @brief 차단 규칙 시드. */
const RULES_SEED: &str = "! Title: seed\n||ads.example.com^\n@@||ok.ads.example.com^$important\n||track.example^$dnsrewrite=NOERROR;A;127.0.0.1\n||c.example^$client=10.0.0.0/8,denyallow=a.example\n||d.example^$ctag=device_pc|user_admin\n||e.example^$dnstype=~A|AAAA,badfilter\n0.0.0.0 bad.example\n127.0.0.1 tracker.example other.example\n/^ad[0-9]+\\.example$/\n||f.example^$important,third-party\n";

/** @brief 정책 플러그인 시드. */
const WASM_SEED: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F, 0x03,
    0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x0A, 0x01, 0x06, 0x6D, 0x65, 0x6D, 0x6F,
    0x72, 0x79, 0x02, 0x00, 0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,
];

/** @brief 영역 형식 차단 목록 시드. */
const RPZ_SEED: &str = "$ORIGIN rpz.example.\n@ SOA ns1.rpz.example. a.rpz.example. 1 2 3 4 5\nbad.example CNAME .\nnodata.example CNAME *.\npassthru.example CNAME rpz-passthru.\n32.1.0.0.127.rpz-client-ip CNAME .\n24.0.0.0.10.rpz-ip CNAME .\nrewrite.example A 127.0.0.1\n";

#[test]
/** @brief 밖에서 들어오는 모든 파서를 망가진 입력으로 두드린다. */
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
                let _ = onetdns_filter::validate_rule(line);
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
                /* 패킷 종류를 나누는 진입점. UDP 와 TCP 가 함께 부르고 크기 예산만 다르다. */
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
