use super::*;
use crate::native::response::{base_response, now_unix};
use onetdns_core::{BlockResponse, MutexExt, RateDecision};
use onetdns_filter::BlockEngine;
use onetdns_proto::{DnsClass, Edns, RecordType, ResponseCode};
use onetdns_runtime::{Handler, RequestCtx, Transport as RtTransport};
use onetdns_security::IpAcl;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[test]
fn gated_swap_tracks_emptiness() {
    let views: GatedSwap<Vec<NativeView>> = GatedSwap::from_pointee(Vec::new());
    assert!(!views.present(), "빈 값은 present=false");

    views.store(Arc::new(vec![NativeView::default()]));
    assert!(views.present(), "채워지면 present=true");
    assert_eq!(views.load().len(), 1);

    views.store(Arc::new(Vec::new()));
    assert!(!views.present(), "다시 비우면 present=false");

    let seeded = GatedSwap::from_pointee(vec![NativeView::default()]);
    assert!(seeded.present(), "비어 있지 않게 생성하면 처음부터 true");

    let policy = GatedSwap::from_pointee(onetdns_policy::PolicyEngine::default());
    assert!(!policy.present(), "기본 정책 엔진은 비어 있다");
}

struct FailBackend;

impl Resolver for FailBackend {
    fn resolve(&self, _req: &Message) -> Option<Message> {
        None
    }
}

#[test]
fn native_server_passes_authority_referral_to_client() {
    let root_text = "$TTL 3600\n. IN SOA ns.root. host.root. 1 3600 900 604800 3600\n. IN NS ns.root.\nns.root. IN A 127.0.1.1\ntest. IN NS ns.test.\nns.test. IN A 127.0.2.1\n";
    let zone = onetdns_authority::parse_zone(root_text, ".").unwrap();
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(zone);
    let store = Arc::new(ArcSwap::new(Arc::new(zs)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FailBackend) as Arc<dyn Resolver>,
        store,
    ));
    let srv = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    );
    let resp = srv.handle(&q("a00.z0007.test"), &ctx()).expect("응답");
    assert_eq!(
        resp.header.rcode,
        ResponseCode::NoError.0,
        "위임 아래 이름은 SERVFAIL이 아니라 권한 리퍼럴이어야 함"
    );
    assert!(resp
        .authorities
        .iter()
        .any(|a| matches!(&a.rdata, ApRData::Ns(t) if t.eq_ignore_case(&ApName::from_str("ns.test").unwrap()))));
}

fn mock_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut m = base_response(&req);
                m.header.rcode = ResponseCode::NoError.0;
                if let Some(q) = req.questions.first() {
                    m.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                    ));
                }
                let _ = sock.send_to(&m.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

fn mock_upstream_authoritative() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut response = base_response(&req);
                response.header.authoritative = true;
                response.header.authentic_data = true;
                if let Some(q) = req.questions.first() {
                    response.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                    ));
                }
                let _ = sock.send_to(&response.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

fn mock_upstream_with_untrusted_ad() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let req = Message::parse(&buf[..n]).unwrap();
            let q = req.questions.first().unwrap();
            let mut response = base_response(&req);
            response.header.authentic_data = true;
            response.answers.push(ApRecord::new(
                q.name.clone(),
                60,
                ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
            ));
            response.answers.push(ApRecord::new(
                q.name.clone(),
                60,
                ApRData::Unknown(RecordType::RRSIG.0, vec![0; 32]),
            ));
            let _ = sock.send_to(&response.try_encode().unwrap(), from);
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    addr
}

#[test]
fn forward_backend_never_reasserts_unvalidated_ad() {
    let backend = NativeBackend::Forward(Forwarder::new(
        vec![mock_upstream_with_untrusted_ad()],
        Duration::from_secs(2),
    ));
    let response = backend
        .resolve(&q("signed.example"))
        .expect("업스트림 응답");
    assert!(!response.header.authentic_data, "로컬 검증 전에는 AD=0");
    assert!(
        response
            .answers
            .iter()
            .any(|record| record.rtype == RecordType::RRSIG),
        "클라이언트 자체 검증용 DNSSEC 레코드는 보존"
    );
}

pub(crate) fn server(block_list: &str) -> NativeServer {
    server_with_chain(block_list, |base| base)
}

/// Includes the local-only cut that sits right before the upstream, as in real assembly; without it
/// the test would measure something else.
fn server_with_chain(
    block_list: &str,
    wrap: impl FnOnce(Arc<dyn Resolver>) -> Arc<dyn Resolver>,
) -> NativeServer {
    let engine = onetdns_filter::build_from_str(block_list, "", BlockResponse::NxDomain);
    let base: Arc<dyn Resolver> = Arc::new(NativeBackend::Forward(Forwarder::new(
        vec![mock_upstream()],
        Duration::from_secs(2),
    )));
    NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        wrap(base),
        60,
    )
}

fn server_local_only(domain_needed: bool, bogus_priv: bool, empty_zones: bool) -> NativeServer {
    let names = Arc::new(crate::layers::LocalOnlyNames::new(
        domain_needed,
        bogus_priv,
        empty_zones,
    ));
    let ttl = Arc::new(std::sync::atomic::AtomicU32::new(60));
    server_with_chain("", move |base| {
        Arc::new(crate::layers::LocalOnlyLayer::new(base, names, ttl))
    })
}

/// Stands in for the authority slot.
struct StaticAnswer {
    name: ApName,
}

impl Resolver for StaticAnswer {
    fn resolve(&self, request: &Message) -> Option<Message> {
        let question = request.questions.first()?;
        if !question.name.eq_ignore_case(&self.name) {
            return None;
        }
        let mut response = Message::default();
        response.header.id = request.header.id;
        response.header.response = true;
        response.questions = request.questions.clone();
        response.answers.push(ApRecord::new(
            question.name.clone(),
            60,
            ApRData::A(std::net::Ipv4Addr::new(192, 168, 1, 50)),
        ));
        Some(response)
    }
}

struct StaticFirst {
    local: Arc<dyn Resolver>,
    inner: Arc<dyn Resolver>,
}

impl Resolver for StaticFirst {
    fn resolve(&self, request: &Message) -> Option<Message> {
        match self.resolve_outcome(request) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self.local.resolve(request) {
            Some(response) => ResolveOutcome::Response(response),
            None => self.inner.resolve_outcome(request),
        }
    }
}

pub(crate) fn update_features(server: &NativeServer, update: impl FnOnce(&mut NativeFeatures)) {
    let mut features = (*server.features.load()).clone();
    update(&mut features);
    server.features.store(Arc::new(features));
}

pub(crate) fn shared_filter(filter: ArcSwap<BlockEngine>) -> Arc<SharedFilter> {
    Arc::new(SharedFilter::new(filter.load()))
}

#[test]
#[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
fn bench_native_feature_snapshot_reuse() {
    use std::hint::black_box;

    const ITERS: u64 = 4_000_000;
    const ROUNDS: usize = 6;

    fn once(swap: &ArcSwap<NativeFeatures>, iters: u64) -> f64 {
        let mut sink = 0usize;
        let started = Instant::now();
        for _ in 0..iters {
            let features = black_box(swap.load());
            sink ^= black_box(features.edns_buffer as usize);
            sink ^= black_box(features.ddr_enabled as usize);
        }
        black_box(sink);
        started.elapsed().as_nanos() as f64 / iters as f64
    }

    fn twice(swap: &ArcSwap<NativeFeatures>, iters: u64) -> f64 {
        let mut sink = 0usize;
        let started = Instant::now();
        for _ in 0..iters {
            let first = black_box(swap.load());
            sink ^= black_box(first.edns_buffer as usize);
            let second = black_box(swap.load());
            sink ^= black_box(second.ddr_enabled as usize);
        }
        black_box(sink);
        started.elapsed().as_nanos() as f64 / iters as f64
    }

    let swap = ArcSwap::from_pointee(NativeFeatures::default());
    black_box(once(&swap, 100_000));
    black_box(twice(&swap, 100_000));
    let mut one = Vec::with_capacity(ROUNDS);
    let mut two = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        if round % 2 == 0 {
            one.push(once(&swap, ITERS));
            two.push(twice(&swap, ITERS));
        } else {
            two.push(twice(&swap, ITERS));
            one.push(once(&swap, ITERS));
        }
    }
    let range = |values: &[f64]| {
        values
            .iter()
            .fold((f64::INFINITY, 0.0f64), |(low, high), value| {
                (low.min(*value), high.max(*value))
            })
    };
    let (one_low, one_high) = range(&one);
    let (two_low, two_high) = range(&two);
    let ratios: Vec<_> = two.iter().zip(&one).map(|(old, new)| old / new).collect();
    let (ratio_low, ratio_high) = range(&ratios);
    println!(
        "feature snapshot: twice={two_low:.2}..{two_high:.2} ns/query \
         once={one_low:.2}..{one_high:.2} ns/query ratio={ratio_low:.2}..{ratio_high:.2}x"
    );
}

#[test]
/// Dropping it would leave the client waiting until its deadline before retrying. Parsing failed
/// before the normal path's two gates, so they are checked here; otherwise a refused client would
/// learn a server is there.
fn an_unparsable_query_is_answered_with_formerr_behind_the_usual_gates() {
    // The header claims two questions but holds one, so the parser rejects it.
    let mut packet = vec![0u8; 12];
    packet[0..2].copy_from_slice(&0xbeefu16.to_be_bytes());
    packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    packet[4..6].copy_from_slice(&2u16.to_be_bytes());
    packet.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1]);
    assert!(
        Message::parse(&packet).is_err(),
        "대조군이 무효입니다. 이 패킷은 파싱되면 안 됩니다"
    );

    let allowed = server_with_chain("", |base| base);
    let response = allowed
        .handle_unparsable(&packet, &ctx())
        .expect("읽지 못한 질의를 버렸습니다");
    assert_eq!(response.header.rcode, ResponseCode::FormErr.0);
    assert_eq!(response.header.id, 0xbeef);
    assert!(response.header.response);
    assert!(response.header.recursion_desired);
    assert!(response.questions.is_empty());

    let denied = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::new(vec![], vec![], false)),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream()],
            Duration::from_secs(2),
        ))),
        60,
    );
    assert!(
        denied.handle_unparsable(&packet, &ctx()).is_none(),
        "거부한 클라이언트에게 서버가 있다고 알렸습니다"
    );

    let mut dropped = server_with_chain("", |base| base);
    dropped.acl = Arc::new(IpAcl::allow_all().with_drop(vec!["127.0.0.1/32".parse().unwrap()]));
    assert!(
        dropped.handle_unparsable(&packet, &ctx()).is_none(),
        "버린 클라이언트에게 서버가 있다고 알렸습니다"
    );
}

#[test]
/// The upstream is the authority, not this server. Echoing it would claim authority for names this
/// server does not serve, and since cache hits lose the bit, two paths of one server would answer
/// differently. The authority layer above sets it for this server's zones.
fn the_forward_backend_does_not_echo_the_upstream_authoritative_bit() {
    let backend = NativeBackend::Forward(Forwarder::new(
        vec![mock_upstream_authoritative()],
        Duration::from_secs(2),
    ));
    let request = Message::query(7, ApName::from_str("www.mock.test").unwrap(), ApRt::A);
    let outcome = backend.resolve_outcome(&request);
    let ResolveOutcome::Response(response) = outcome else {
        panic!("업스트림이 답하지 않았습니다");
    };
    assert!(
        !response.header.authoritative,
        "업스트림의 권한 표시를 그대로 되울렸습니다"
    );
    assert!(!response.header.authentic_data);
}

pub(crate) fn ctx<'a>() -> RequestCtx<'a> {
    RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Udp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    }
}

pub(crate) fn q(name: &str) -> Message {
    Message::query(0x1234, ApName::from_str(name).unwrap(), RecordType::A)
}

pub(crate) fn negative_soa_ttl(message: &Message) -> u32 {
    message
        .authorities
        .iter()
        .find(|record| record.rtype == RecordType::SOA)
        .expect("합성 부정 응답 SOA")
        .ttl
}

struct FixedRcode(u16);

impl Resolver for FixedRcode {
    fn resolve(&self, request: &Message) -> Option<Message> {
        let mut response = base_response(request);
        response.header.rcode = self.0;
        Some(response)
    }
}

struct FixedAnswer;

impl Resolver for FixedAnswer {
    fn resolve(&self, request: &Message) -> Option<Message> {
        let mut response = base_response(request);
        let name = request.questions.first().unwrap().name.clone();
        response.answers.push(ApRecord::new(
            name,
            300,
            ApRData::A(Ipv4Addr::new(1, 2, 3, 4)),
        ));
        Some(response)
    }
}

fn fixed_answer_cache() -> (Arc<dyn Resolver>, crate::cache::CacheHandle) {
    let layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let handle = layer.handle();
    (Arc::new(layer), handle)
}

#[test]
/// Both bits mean nothing in a query. Left in, they would split the cache key, so such queries
/// would always go upstream, and an answer the upstream gave because of the bits could land under
/// the normal key.
fn ra_and_rcode_query_bits_share_the_normal_cache() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting(Arc<AtomicUsize>);
    impl Resolver for Counting {
        fn resolve(&self, request: &Message) -> Option<Message> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let mut response = base_response(request);
            let name = request.questions.first().unwrap().name.clone();
            response.answers.push(ApRecord::new(
                name,
                300,
                ApRData::A(Ipv4Addr::new(1, 2, 3, 4)),
            ));
            Some(response)
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let backend: Arc<dyn Resolver> = Arc::new(crate::cache::CacheLayer::new(
        Arc::new(Counting(calls.clone())),
        64,
        1,
        0,
        86_400,
        0,
        86_400,
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    );

    let plain = Message::query(
        0x1001,
        ApName::from_str("ra.example").unwrap(),
        RecordType::A,
    );
    server.handle(&plain, &ctx()).expect("정상 질의 응답");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "대조군: 첫 질의가 백엔드를 한 번 부릅니다"
    );

    let mut ra = Message::query(
        0x1002,
        ApName::from_str("ra.example").unwrap(),
        RecordType::A,
    );
    ra.header.recursion_available = true;
    let response = server.handle(&ra, &ctx()).expect("RA 질의 응답");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "RA 비트가 선 질의도 정상 질의가 담은 캐시를 써서 백엔드를 다시 부르지 않아야 합니다"
    );
    assert_eq!(response.answers.len(), 1, "캐시에서 답을 돌려받아야 합니다");
    assert!(
        response.header.recursion_available,
        "응답의 RA 는 서버가 세웁니다"
    );

    let mut other = Message::query(
        0x1003,
        ApName::from_str("other.example").unwrap(),
        RecordType::A,
    );
    other.header.recursion_available = true;
    server.handle(&other, &ctx()).expect("다른 이름 응답");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "대조군: 캐시에 없는 이름은 RA 질의라도 백엔드를 부릅니다"
    );
}

#[test]
fn wire_lane_hits_patch_id_and_respect_filter_generation() {
    use onetdns_runtime::WireDisposition;

    let engine = onetdns_filter::build_from_str("||blocked.example^", "", BlockResponse::NxDomain);
    let (backend, cache) = fixed_answer_cache();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        cache,
    )));

    let first_wire = Message::query(0x0101, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&first_wire, &ctx(), &mut out, std::time::Instant::now()),
        WireDisposition::Respond
    );
    let first = Message::parse(&out.buf).expect("미스 경로 응답");
    assert_eq!(first.header.id, 0x0101);
    assert_eq!(first.answers.len(), 1);

    let second_wire = Message::query(0x0202, ApName::from_str("OK.EXAMPLE").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out2 = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&second_wire, &ctx(), &mut out2, std::time::Instant::now()),
        WireDisposition::Respond
    );
    let second = Message::parse(&out2.buf).expect("히트 경로 응답");
    assert_eq!(second.header.id, 0x0202);
    assert_eq!(second.answers[0].rdata, first.answers[0].rdata);
    assert_eq!(
        second.questions[0].name.to_ascii_lower(),
        "ok.example",
        "질의 이름은 요청 케이스 구간으로 패치"
    );

    let blocked_wire = Message::query(
        0x0303,
        ApName::from_str("blocked.example").unwrap(),
        ApRt::A,
    )
    .try_encode()
    .unwrap();
    let mut out3 = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&blocked_wire, &ctx(), &mut out3, std::time::Instant::now()),
        WireDisposition::Respond,
        "차단 응답은 빠른 경로가 직접 만듭니다"
    );
    let blocked = Message::parse(&out3.buf).unwrap();
    assert_eq!(blocked.header.id, 0x0303);
    assert_eq!(blocked.header.rcode, ResponseCode::NXDomain.0);

    server.filter.store(Arc::new(onetdns_filter::build_from_str(
        "||other.example^",
        "",
        BlockResponse::NxDomain,
    )));
    let third_wire = Message::query(0x0404, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out4 = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&third_wire, &ctx(), &mut out4, std::time::Instant::now()),
        WireDisposition::Respond
    );
    assert_eq!(Message::parse(&out4.buf).unwrap().header.id, 0x0404);

    update_features(&server, |features| features.lanes.wire = false);
    let mut out5 = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&third_wire, &ctx(), &mut out5, std::time::Instant::now()),
        WireDisposition::Fallback,
        "경로 조건이 닫히면 담아 둔 답이 있어도 내보내지 않습니다"
    );
}

#[test]
fn wire_cache_hits_are_timed_from_the_datagram_arrival() {
    use onetdns_runtime::WireDisposition;

    let (recorder, stats) = onetdns_control::channel(
        64,
        64,
        3600,
        onetdns_control::RecorderOpts {
            querylog: true,
            anonymize: false,
            ignored: vec![],
            stats_retention_secs: 3600,
        },
        onetdns_control::PersistOpts::default(),
    );
    let (backend, cache) = fixed_answer_cache();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        cache,
    )))
    .with_recorder(Some(recorder));
    let wire = Message::query(0x0303, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&wire, &ctx(), &mut out, Instant::now()),
        WireDisposition::Respond
    );

    std::thread::sleep(Duration::from_millis(5));
    let arrived = Instant::now();
    std::thread::sleep(Duration::from_millis(20));
    out.clear();
    assert_eq!(
        server.handle_udp_wire(&wire, &ctx(), &mut out, arrived),
        WireDisposition::Respond
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    let hit = loop {
        let recent = stats.recent(8);
        if recent.len() >= 2 || Instant::now() >= deadline {
            break recent.first().cloned().expect("적중 기록이 없습니다");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        hit.latency_us >= 20_000,
        "캐시 적중 처리시간을 받은 시각이 아니라 답을 찾은 뒤부터 쟀습니다: {} us",
        hit.latency_us
    );
}

#[test]
fn wire_lane_long_key_falls_back_to_structured_response() {
    use onetdns_runtime::WireDisposition;

    let server = shaped_server(true);
    let name = ApName::from_str(&"a".repeat(55)).expect("정상 55바이트 라벨");
    let request = Message::query(0x5151, name.clone(), ApRt::A);
    let packet = request.try_encode().expect("정상 DNS 질의");
    let mut output = onetdns_proto::Writer::with_limit(1232);

    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        WireDisposition::Fallback,
        "긴 키는 할당 없는 wire 레인 대신 구조화 경로가 맡습니다"
    );
    let response = server.handle(&request, &ctx()).expect("구조화 응답");
    assert_eq!(response.header.id, 0x5151);
    assert!(response
        .answers
        .iter()
        .any(|record| record.name.eq_ignore_case(&name) && record.rtype == ApRt::A));
}

struct ShapedAnswer;

impl Resolver for ShapedAnswer {
    fn resolve(&self, request: &Message) -> Option<Message> {
        let q = request.questions.first()?;
        let mut response = base_response(request);
        match q.name.to_ascii_lower().as_str() {
            "nodata.example" => response.authorities.push(ApRecord::new(
                ApName::from_str("example.").unwrap(),
                60,
                ApRData::soa(onetdns_proto::Soa {
                    mname: ApName::from_str("ns.example.").unwrap(),
                    rname: ApName::from_str("hostmaster.example.").unwrap(),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 86_400,
                    minimum: 60,
                }),
            )),
            "multi.example" => {
                for last in [10u8, 11, 12] {
                    response.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(192, 0, 2, last)),
                    ));
                }
            }
            "alias.example" => {
                let target = ApName::from_str("target.example.").unwrap();
                response.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::Cname(target.clone()),
                ));
                response.answers.push(ApRecord::new(
                    target,
                    60,
                    ApRData::A(Ipv4Addr::new(192, 0, 2, 20)),
                ));
            }
            _ => response.answers.push(ApRecord::new(
                q.name.clone(),
                60,
                ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )),
        }
        Some(response)
    }
}

pub(crate) fn shaped_server(with_wire: bool) -> NativeServer {
    let layer = crate::cache::CacheLayer::new(Arc::new(ShapedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let cache = layer.handle();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(layer),
        60,
    );
    if with_wire {
        server.with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            cache,
        )))
    } else {
        server
    }
}

#[test]
#[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
fn bench_split_local_outside_cache_vs_cached_wire_hit() {
    fn local_server(mode: u8) -> NativeServer {
        let ttl = Arc::new(AtomicU32::new(300));
        let addresses = Arc::new(
            crate::layers::LocalAddressTable::new(
                &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
                &[],
                ttl,
            )
            .unwrap(),
        );
        let empty_filter = || {
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            )))
        };

        if mode < 2 {
            let cache =
                crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
            let handle = cache.handle();
            let wire_cache = (mode == 1).then(|| {
                let slot = Arc::new(std::sync::OnceLock::new());
                let _ = slot.set(handle.clone());
                slot
            });
            let local =
                crate::layers::LocalAddressLayer::new(Arc::new(cache), addresses, wire_cache);
            NativeServer::new(
                empty_filter(),
                Arc::new(IpAcl::allow_all()),
                vec![],
                Arc::new(local),
                60,
            )
            .with_wire_fast_path(Some((
                crate::wirecache::WireEntryFactory::new(0, 86_400),
                handle,
            )))
        } else {
            let local =
                crate::layers::LocalAddressLayer::new(Arc::new(FixedAnswer), addresses, None);
            let cache = crate::cache::CacheLayer::new(Arc::new(local), 64, 1, 0, 86_400, 0, 86_400);
            let handle = cache.handle();
            NativeServer::new(
                empty_filter(),
                Arc::new(IpAcl::allow_all()),
                vec![],
                Arc::new(cache),
                60,
            )
            .with_wire_fast_path(Some((
                crate::wirecache::WireEntryFactory::new(0, 86_400),
                handle,
            )))
        }
    }

    const ITERS: u32 = 1_000_000;
    let packet = Message::query(
        0x1234,
        ApName::from_str("router.lan").unwrap(),
        RecordType::A,
    )
    .try_encode()
    .unwrap();
    for (label, server) in [
        ("outside-cache", local_server(0)),
        ("fixed-local-wire", local_server(1)),
        ("cached-wire", local_server(2)),
    ] {
        let mut output = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
            onetdns_runtime::WireDisposition::Respond
        );
        let started = Instant::now();
        for _ in 0..ITERS {
            assert_eq!(
                server.handle_udp_wire(
                    std::hint::black_box(&packet),
                    &ctx(),
                    &mut output,
                    Instant::now(),
                ),
                onetdns_runtime::WireDisposition::Respond
            );
            std::hint::black_box(&output.buf);
        }
        println!(
            "{label}: {:.2} ns/query",
            started.elapsed().as_nanos() as f64 / f64::from(ITERS)
        );
    }
}

#[test]
fn split_local_fixed_wire_rejects_late_old_ttl_generation() {
    let ttl = Arc::new(AtomicU32::new(17));
    let addresses = Arc::new(
        crate::layers::LocalAddressTable::new(
            &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
            &[],
            ttl.clone(),
        )
        .unwrap(),
    );
    let cache = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let handle = cache.handle();
    let wire_cache = Arc::new(std::sync::OnceLock::new());
    let _ = wire_cache.set(handle.clone());
    let local = crate::layers::LocalAddressLayer::new(Arc::new(cache), addresses, Some(wire_cache));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(local),
        60,
    )
    .with_ttl_sources(Arc::new(AtomicU32::new(60)), ttl.clone())
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        handle.clone(),
    )));

    let request = Message::query(
        0x1234,
        ApName::from_str("router.lan").unwrap(),
        RecordType::A,
    );
    let packet = request.try_encode().unwrap();
    let now = Instant::now();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, now),
        onetdns_runtime::WireDisposition::Respond
    );
    assert_eq!(Message::parse(&output.buf).unwrap().answers[0].ttl, 17);
    let old_wire = handle.wire_entry_for(&request).expect("고정 로컬 wire");

    assert_eq!(
        server.handle_udp_wire(
            &packet,
            &ctx(),
            &mut output,
            now + Duration::from_secs(3_600),
        ),
        onetdns_runtime::WireDisposition::Respond
    );
    assert_eq!(
        Message::parse(&output.buf).unwrap().answers[0].ttl,
        17,
        "로컬 설정 TTL은 캐시 나이만큼 감소하지 않음"
    );

    ttl.store(0, Ordering::Release);
    update_features(&server, |features| features.wire_epoch += 1);
    assert!(handle.install_local_wire_for_test(&request, old_wire.clone()));
    assert_eq!(
        server.handle_udp_wire(
            &packet,
            &ctx(),
            &mut output,
            now + Duration::from_secs(7_200),
        ),
        onetdns_runtime::WireDisposition::Respond
    );
    assert_eq!(
        Message::parse(&output.buf).unwrap().answers[0].ttl,
        0,
        "늦게 삽입된 이전 세대 wire가 TTL 0 핫 변경을 가리면 안 됨"
    );
    let zero_wire = handle.wire_entry_for(&request).expect("TTL 0 고정 wire");
    assert!(!crate::wirecache::WireEntry::ptr_eq(&old_wire, &zero_wire));

    assert_eq!(
        server.handle_udp_wire(
            &packet,
            &ctx(),
            &mut output,
            now + Duration::from_secs(86_400),
        ),
        onetdns_runtime::WireDisposition::Respond
    );
    assert_eq!(Message::parse(&output.buf).unwrap().answers[0].ttl, 0);
    let zero_hit = handle.wire_entry_for(&request).expect("TTL 0 wire hit");
    assert!(crate::wirecache::WireEntry::ptr_eq(&zero_wire, &zero_hit));

    ttl.store(u32::MAX, Ordering::Release);
    update_features(&server, |features| features.wire_epoch += 1);
    assert_eq!(
        server.handle_udp_wire(
            &packet,
            &ctx(),
            &mut output,
            now + Duration::from_secs(172_800),
        ),
        onetdns_runtime::WireDisposition::Respond
    );
    assert_eq!(
        Message::parse(&output.buf).unwrap().answers[0].ttl,
        u32::MAX
    );

    let txt = Message::query(
        0x2345,
        ApName::from_str("router.lan").unwrap(),
        RecordType::TXT,
    );
    let txt_packet = txt.try_encode().unwrap();
    assert_eq!(
        server.handle_udp_wire(
            &txt_packet,
            &ctx(),
            &mut output,
            now + Duration::from_secs(172_801),
        ),
        onetdns_runtime::WireDisposition::Respond
    );
    assert!(Message::parse(&output.buf).unwrap().answers.is_empty());
    assert!(
        handle.wire_entry_for(&txt).is_some(),
        "빈 로컬 NODATA도 업스트림으로 떨어뜨리지 않고 wire 재사용"
    );
}

#[test]
/// Mistaking it would stop its TTLs from aging.
fn outer_override_is_not_mislabeled_as_local_wire() {
    let ttl = Arc::new(AtomicU32::new(17));
    let addresses = Arc::new(
        crate::layers::LocalAddressTable::new(
            &[("router.lan".to_string(), Ipv4Addr::new(192, 168, 0, 1))],
            &[],
            ttl,
        )
        .unwrap(),
    );
    let cache = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let handle = cache.handle();
    let wire_cache = Arc::new(std::sync::OnceLock::new());
    let _ = wire_cache.set(handle.clone());
    let local = crate::layers::LocalAddressLayer::new(Arc::new(cache), addresses, Some(wire_cache));
    let stub = crate::layers::StubLayer::new(
        Arc::new(local),
        vec![(
            "router.lan".to_string(),
            Arc::new(FixedAnswer) as Arc<dyn Resolver>,
        )],
    )
    .unwrap();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(stub),
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        handle.clone(),
    )));

    let request = Message::query(
        0x3456,
        ApName::from_str("router.lan").unwrap(),
        RecordType::A,
    );
    let packet = request.try_encode().unwrap();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond
    );
    let response = Message::parse(&output.buf).unwrap();
    assert_eq!(response.answers[0].ttl, 300, "바깥 Stub 응답이 우선");
    assert!(
        handle.wire_entry_for(&request).is_none(),
        "실제 로컬 합성 계층을 지나지 않은 응답은 고정 TTL로 저장하지 않음"
    );
}

#[test]
fn authoritative_wire_exact_address_is_direct_and_optional_features_fall_back() {
    let zone_text = "$ORIGIN fast.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.9\n*.wild IN A 192.0.2.99\n";
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(zone_text, "fast.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store.clone(),
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    )
    .with_authority_wire_path(Some(store), true);
    let mut request = Message::query(
        0x4567,
        ApName::from_str("WWW.fast.test").unwrap(),
        RecordType::A,
    );
    request.header.checking_disabled = true;
    let packet = request.try_encode().unwrap();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond
    );
    let response = Message::parse(&output.buf).unwrap();
    assert_eq!(response.header.id, 0x4567);
    assert!(response.header.authoritative);
    assert!(response.header.recursion_available);
    assert!(response.header.checking_disabled);
    assert!(matches!(
        response.answers.as_slice(),
        [ApRecord {
            rdata: ApRData::A(address),
            ..
        }] if *address == Ipv4Addr::new(192, 0, 2, 9)
    ));
    let direct_wire = output.buf.clone();
    let tcp_context = RequestCtx {
        transport: RtTransport::Do53Tcp,
        ..ctx()
    };
    output.clear();
    assert_eq!(
        server.handle_tcp_wire(&packet, &tcp_context, &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond
    );
    assert_eq!(output.buf, direct_wire, "TCP와 UDP direct wire가 동일함");
    let structured = server.handle(&request, &ctx()).unwrap();
    let mut structured_wire = onetdns_proto::Writer::with_limit(1232);
    onetdns_runtime::encode_limited(&request, &structured, &mut structured_wire);
    assert_eq!(direct_wire, structured_wire.buf);

    let missing = Message::query(
        0x5678,
        ApName::from_str("missing.fast.test").unwrap(),
        RecordType::A,
    );
    let missing_packet = missing.try_encode().unwrap();
    output.clear();
    assert_eq!(
        server.handle_udp_wire(&missing_packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond
    );
    let negative = Message::parse(&output.buf).unwrap();
    assert_eq!(negative.header.rcode, ResponseCode::NXDomain.0);
    assert!(negative.header.authoritative);
    assert!(negative.answers.is_empty());
    assert!(matches!(
        negative.authorities.as_slice(),
        [ApRecord {
            rdata: ApRData::Soa(_),
            ..
        }]
    ));

    let wildcard = Message::query(
        0x6789,
        ApName::from_str("hit.wild.fast.test").unwrap(),
        RecordType::A,
    );
    let wildcard_packet = wildcard.try_encode().unwrap();
    output.clear();
    assert_eq!(
        server.handle_udp_wire(&wildcard_packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond
    );
    let wildcard_response = Message::parse(&output.buf).unwrap();
    assert!(matches!(
        wildcard_response.answers.as_slice(),
        [ApRecord {
            rdata: ApRData::A(address),
            ..
        }] if *address == Ipv4Addr::new(192, 0, 2, 99)
    ));

    // A query with one empty OPT is the fast path's, but its bytes must match the structured path
    // exactly; almost every real client asks this way.
    let mut with_edns = request.clone();
    with_edns
        .additionals
        .push(Edns::default().try_to_record().unwrap());
    let packet = with_edns.try_encode().unwrap();
    output.clear();
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond,
        "옵션 없는 EDNS 질의는 빠른 경로가 맡아야 합니다"
    );
    let edns_wire = output.buf.clone();
    let structured = server.handle(&with_edns, &ctx()).unwrap();
    let mut structured_wire = onetdns_proto::Writer::with_limit(1232);
    onetdns_runtime::encode_limited(&with_edns, &structured, &mut structured_wire);
    assert_eq!(
        edns_wire, structured_wire.buf,
        "EDNS 질의의 빠른 경로 응답이 구조적 경로와 다릅니다"
    );
    let edns_response = Message::parse(&edns_wire).unwrap();
    let opt = edns_response.opt().expect("응답에 OPT가 없습니다");
    let echoed = Edns::from_record(opt).expect("응답 OPT를 읽지 못했습니다");
    assert_eq!(echoed.version, 0);
    assert!(
        !echoed.dnssec_ok,
        "요청이 DO를 안 켰으면 응답도 꺼야 합니다"
    );
    assert!(echoed.options.is_empty());

    // Every shape that needs something in the response or the truncation ladder falls back.
    let mut with_do = request.clone();
    let mut do_edns = Edns::default();
    do_edns.dnssec_ok = true;
    with_do.additionals.push(do_edns.try_to_record().unwrap());
    output.clear();
    assert_eq!(
        server.handle_udp_wire(
            &with_do.try_encode().unwrap(),
            &ctx(),
            &mut output,
            Instant::now()
        ),
        onetdns_runtime::WireDisposition::Fallback,
        "DO를 켠 질의는 구조적 경로가 맡아야 합니다"
    );
    assert!(output.buf.is_empty());

    let mut with_option = request.clone();
    let mut padded = Edns::default();
    padded
        .options
        .push((onetdns_proto::EDNS_PADDING, vec![0; 4]));
    with_option
        .additionals
        .push(padded.try_to_record().unwrap());
    output.clear();
    assert_eq!(
        server.handle_udp_wire(
            &with_option.try_encode().unwrap(),
            &ctx(),
            &mut output,
            Instant::now()
        ),
        onetdns_runtime::WireDisposition::Fallback,
        "옵션이 붙은 질의는 구조적 경로가 맡아야 합니다"
    );
    assert!(output.buf.is_empty());

    let mut small_buffer = request;
    let mut tiny = Edns::default();
    tiny.udp_payload = 512;
    small_buffer.additionals.push(tiny.try_to_record().unwrap());
    output.clear();
    assert_eq!(
        server.handle_udp_wire(
            &small_buffer.try_encode().unwrap(),
            &ctx(),
            &mut output,
            Instant::now()
        ),
        onetdns_runtime::WireDisposition::Fallback,
        "이 서버의 상한보다 작게 알린 질의는 절단 사다리가 필요합니다"
    );
    assert!(output.buf.is_empty());

    update_features(&server, |features| features.lanes.authority = false);
    output.clear();
    assert_eq!(
        server.handle_udp_wire(&wildcard_packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Fallback,
        "권한 경로 조건이 닫히면 단순 질의도 구조적 경로가 맡아야 합니다"
    );
    assert_eq!(
        server.handle_tcp_wire(&wildcard_packet, &tcp_context, &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Fallback,
        "권한 경로 조건이 닫히면 TCP 질의도 구조적 경로가 맡아야 합니다"
    );
    assert!(output.buf.is_empty());
}

#[test]
fn ddr_only_preempts_its_owner_in_the_authority_wire_lane() {
    let zone_text = "$ORIGIN resolver.arpa.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n_dns IN A 192.0.2.9\nwww IN A 192.0.2.10\n";
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(zone_text, "resolver.arpa").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store.clone(),
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    )
    .with_features(NativeFeatures {
        ddr_enabled: true,
        ..NativeFeatures::default()
    })
    .with_authority_wire_path(Some(store), true);

    let special = Message::query(
        1,
        ApName::from_str("_DNS.Resolver.ARPA").unwrap(),
        RecordType::A,
    )
    .try_encode()
    .unwrap();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&special, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Fallback,
        "DDR 계층이 NODATA로 닫아야 할 이름을 권한 A 레코드가 가로채면 안 됩니다"
    );

    let ordinary = Message::query(
        2,
        ApName::from_str("www.resolver.arpa").unwrap(),
        RecordType::A,
    )
    .try_encode()
    .unwrap();
    assert_eq!(
        server.handle_udp_wire(&ordinary, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond,
        "DDR 때문에 관계없는 권한 이름까지 느린 경로로 보내면 안 됩니다"
    );
}

#[test]
/// A local-only layer blocking every name sits inside the authority layer, with NSID and padding
/// on. Queries without options get the same bytes from the fast path; queries asking for NSID or
/// TXT go to the structured path.
fn authority_lane_answers_ignore_settings_that_leave_it_open() {
    use onetdns_runtime::WireDisposition;

    let mut zones = onetdns_authority::ZoneStore::new();
    for (origin, text) in [
        (
            "lan",
            "$ORIGIN lan.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\n@ IN A 192.0.2.10\nns IN A 192.0.2.53\n",
        ),
        (
            "home.arpa",
            "$ORIGIN home.arpa.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nnas IN A 192.0.2.11\n",
        ),
    ] {
        zones.add(onetdns_authority::parse_zone(text, origin).unwrap());
    }
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let local_only = Arc::new(crate::layers::LocalOnlyLayer::new(
        Arc::new(FixedAnswer),
        Arc::new(crate::layers::LocalOnlyNames::new(true, true, true)),
        Arc::new(std::sync::atomic::AtomicU32::new(60)),
    ));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        local_only,
        store.clone(),
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    )
    .with_features(NativeFeatures {
        nsid: Some(b"ns1".to_vec()),
        padding_block: 128,
        ..NativeFeatures::default()
    })
    .with_authority_wire_path(Some(store), true);

    let outside = Message::query(1, ApName::from_str("wpad").unwrap(), RecordType::A);
    assert_eq!(
        server.handle(&outside, &ctx()).unwrap().header.rcode,
        ResponseCode::NXDomain.0,
        "영역 밖의 점 없는 이름은 로컬 전용 계층이 막아야 합니다"
    );

    let mut output = onetdns_proto::Writer::with_limit(1232);
    for (id, name) in [(2, "lan"), (3, "nas.home.arpa")] {
        let mut request = Message::query(id, ApName::from_str(name).unwrap(), RecordType::A);
        request
            .additionals
            .push(Edns::default().try_to_record().unwrap());
        output.clear();
        assert_eq!(
            server.handle_udp_wire(
                &request.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
            WireDisposition::Respond,
            "{name}: 옵션 없는 권한 질의는 빠른 경로가 맡아야 합니다"
        );
        let structured = server.handle(&request, &ctx()).unwrap();
        let mut structured_wire = onetdns_proto::Writer::with_limit(1232);
        onetdns_runtime::encode_limited(&request, &structured, &mut structured_wire);
        assert_eq!(
            output.buf, structured_wire.buf,
            "{name}: 빠른 경로의 답이 구조적 경로와 다릅니다"
        );
        assert_eq!(structured.header.rcode, ResponseCode::NoError.0);
        assert_eq!(
            structured.answers.len(),
            1,
            "{name}: 영역의 주소가 답이어야 합니다"
        );
    }

    let mut asks_nsid = Message::query(4, ApName::from_str("lan").unwrap(), RecordType::A);
    let mut edns = Edns::default();
    edns.options.push((OPT_NSID, Vec::new()));
    asks_nsid.additionals.push(edns.try_to_record().unwrap());
    output.clear();
    assert_eq!(
        server.handle_udp_wire(
            &asks_nsid.try_encode().unwrap(),
            &ctx(),
            &mut output,
            Instant::now()
        ),
        WireDisposition::Fallback,
        "NSID 를 묻는 질의는 구조적 경로가 맡아야 합니다"
    );
    let answered = server.handle(&asks_nsid, &ctx()).unwrap();
    let echoed = Edns::from_record(answered.opt().expect("응답에 OPT가 없습니다")).unwrap();
    assert!(echoed
        .options
        .iter()
        .any(|(code, value)| *code == OPT_NSID && value == b"ns1"));

    let challenge = Message::query(
        5,
        ApName::from_str("_acme-challenge.lan").unwrap(),
        RecordType::TXT,
    );
    output.clear();
    assert_eq!(
        server.handle_udp_wire(
            &challenge.try_encode().unwrap(),
            &ctx(),
            &mut output,
            Instant::now()
        ),
        WireDisposition::Fallback,
        "TXT 질의는 구조적 경로가 맡아야 합니다"
    );
}

#[test]
fn authoritative_external_alias_is_not_replaced_with_servfail() {
    let zone_text = "$ORIGIN alias.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nalias IN CNAME outside.example.\nold IN DNAME target.example.\n";
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(zone_text, "alias.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store,
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    );

    let cname = server
        .handle(
            &Message::query(
                1,
                ApName::from_str("alias.alias.test").unwrap(),
                RecordType::A,
            ),
            &ctx(),
        )
        .unwrap();
    assert_eq!(cname.header.rcode, ResponseCode::NoError.0);
    assert!(cname.header.authoritative);
    assert!(matches!(
        cname.answers.as_slice(),
        [ApRecord {
            rdata: ApRData::Cname(target),
            ..
        }] if target.eq_ignore_case(&ApName::from_str("outside.example").unwrap())
    ));

    let dname = server
        .handle(
            &Message::query(
                2,
                ApName::from_str("host.old.alias.test").unwrap(),
                RecordType::A,
            ),
            &ctx(),
        )
        .unwrap();
    assert_eq!(dname.header.rcode, ResponseCode::NoError.0);
    assert!(dname.header.authoritative);
    assert!(dname
        .answers
        .iter()
        .any(|record| matches!(record.rdata, ApRData::Dname(_))));
    assert!(dname
        .answers
        .iter()
        .any(|record| matches!(record.rdata, ApRData::Cname(_))));
}

#[test]
#[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
fn bench_authoritative_exact_wire_vs_structured_path() {
    fn authority_server(
        store: Arc<ArcSwap<onetdns_authority::ZoneStore>>,
        direct: bool,
    ) -> NativeServer {
        let authority = Arc::new(crate::layers::AuthorityLayer::new(
            Arc::new(FixedAnswer),
            store.clone(),
        ));
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            authority,
            60,
        );
        if direct {
            server.with_authority_wire_path(Some(store), true)
        } else {
            server
        }
    }

    fn serve(
        server: &NativeServer,
        packet: &[u8],
        context: &RequestCtx<'_>,
        output: &mut onetdns_proto::Writer,
        now: Instant,
    ) {
        if server.handle_udp_wire(packet, context, output, now)
            == onetdns_runtime::WireDisposition::Fallback
        {
            let request = Message::parse(packet).unwrap();
            let response = server.handle(&request, context).unwrap();
            onetdns_runtime::encode_limited(&request, &response, output);
        }
    }

    let store = big_zone_store(100_000);
    let structured = authority_server(store.clone(), false);
    let direct = authority_server(store, true);
    let request = Message::query(
        0x1234,
        ApName::from_str("host-99999-with-a-rather-long-owner-label.big.test").unwrap(),
        RecordType::A,
    );
    let packet = request.try_encode().unwrap();
    let context = ctx();
    let now = Instant::now();
    let mut structured_out = onetdns_proto::Writer::with_limit(1232);
    let mut direct_out = onetdns_proto::Writer::with_limit(1232);
    serve(&structured, &packet, &context, &mut structured_out, now);
    serve(&direct, &packet, &context, &mut direct_out, now);
    assert_eq!(direct_out.buf, structured_out.buf);

    for _ in 0..10_000 {
        serve(&structured, &packet, &context, &mut structured_out, now);
        serve(&direct, &packet, &context, &mut direct_out, now);
    }
    const ITERATIONS: usize = 500_000;
    let measure = |server: &NativeServer, packet: &[u8], output: &mut onetdns_proto::Writer| {
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            serve(server, std::hint::black_box(packet), &context, output, now);
            std::hint::black_box(&output.buf);
        }
        started.elapsed().as_nanos() as f64 / ITERATIONS as f64
    };
    let direct_1 = measure(&direct, &packet, &mut direct_out);
    let structured_1 = measure(&structured, &packet, &mut structured_out);
    let structured_2 = measure(&structured, &packet, &mut structured_out);
    let direct_2 = measure(&direct, &packet, &mut direct_out);
    println!(
        "authority exact end-to-end: structured={structured_1:.1}/{structured_2:.1}ns direct={direct_1:.1}/{direct_2:.1}ns"
    );

    let missing = Message::query(
        0x2345,
        ApName::from_str("deep.missing.big.test").unwrap(),
        RecordType::A,
    );
    let missing_packet = missing.try_encode().unwrap();
    serve(
        &structured,
        &missing_packet,
        &context,
        &mut structured_out,
        now,
    );
    serve(&direct, &missing_packet, &context, &mut direct_out, now);
    let structured_negative = Message::parse(&structured_out.buf).unwrap();
    let direct_negative = Message::parse(&direct_out.buf).unwrap();
    assert_eq!(
        direct_negative.header.rcode,
        structured_negative.header.rcode
    );
    assert_eq!(direct_negative.authorities.len(), 1);
    assert_eq!(
        direct_negative.authorities[0].rdata,
        structured_negative.authorities[0].rdata
    );
    let direct_1 = measure(&direct, &missing_packet, &mut direct_out);
    let structured_1 = measure(&structured, &missing_packet, &mut structured_out);
    let structured_2 = measure(&structured, &missing_packet, &mut structured_out);
    let direct_2 = measure(&direct, &missing_packet, &mut direct_out);
    println!(
        "authority nxdomain end-to-end: structured={structured_1:.1}/{structured_2:.1}ns direct={direct_1:.1}/{direct_2:.1}ns"
    );
}

#[test]
/// Otherwise answers would depend on whether the cache hit.
fn wire_fast_path_answers_match_the_normal_path() {
    use onetdns_runtime::WireDisposition;

    let mut compared = 0usize;
    for name in [
        "ok.example",
        "multi.example",
        "alias.example",
        "nodata.example",
    ] {
        let wire_server = shaped_server(true);
        let plain_server = shaped_server(false);
        let request = Message::query(0x51, ApName::from_str(name).unwrap(), ApRt::A);
        let packet = request.try_encode().unwrap();

        let mut warm = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            wire_server.handle_udp_wire(&packet, &ctx(), &mut warm, std::time::Instant::now()),
            WireDisposition::Respond,
            "{name}: 미스도 응답해야 한다"
        );
        plain_server
            .handle(&request, &ctx())
            .expect("일반 경로 미스");

        let mut hit = onetdns_proto::Writer::with_limit(1232);
        let disposition =
            wire_server.handle_udp_wire(&packet, &ctx(), &mut hit, std::time::Instant::now());
        let plain = plain_server
            .handle(&request, &ctx())
            .expect("일반 경로 히트");
        if disposition != WireDisposition::Respond {
            continue;
        }
        let fast = Message::parse(&hit.buf).expect("wire 히트 응답");
        compared += 1;

        assert_eq!(
            fast.header.rcode, plain.header.rcode,
            "{name}: rcode 불일치"
        );
        assert_eq!(fast.header.id, request.header.id, "{name}: 요청 ID 에코");
        assert_eq!(
            (
                fast.header.authentic_data,
                fast.header.authoritative,
                fast.header.truncated,
                fast.header.recursion_available,
            ),
            (
                plain.header.authentic_data,
                plain.header.authoritative,
                plain.header.truncated,
                plain.header.recursion_available,
            ),
            "{name}: 헤더 비트 불일치"
        );
        assert_eq!(
            record_keys(&fast.answers),
            record_keys(&plain.answers),
            "{name}: 답변 구획 불일치"
        );
        assert_eq!(
            record_keys(&fast.authorities),
            record_keys(&plain.authorities),
            "{name}: 권한 구획 불일치"
        );
        assert_eq!(
            record_keys(&fast.additionals),
            record_keys(&plain.additionals),
            "{name}: 부가 구획 불일치"
        );
    }

    assert_eq!(compared, 4, "wire 고속 경로로 실제 대조한 형태 수");
}

#[test]
fn wire_lane_trivial_filter_serves_hit_via_fast_path() {
    use onetdns_runtime::WireDisposition;

    let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
    assert!(engine.is_trivially_allow(), "빈 필터는 자명-허용");
    let (backend, cache) = fixed_answer_cache();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        cache,
    )));

    let miss = Message::query(0x0111, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&miss, &ctx(), &mut out, std::time::Instant::now()),
        WireDisposition::Respond
    );
    let first = Message::parse(&out.buf).expect("미스 응답");
    assert_eq!(first.answers.len(), 1);

    let hit = Message::query(0x0222, ApName::from_str("OK.EXAMPLE").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out2 = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&hit, &ctx(), &mut out2, std::time::Instant::now()),
        WireDisposition::Respond
    );
    let second = Message::parse(&out2.buf).expect("히트 응답");
    assert_eq!(second.header.id, 0x0222);
    assert_eq!(second.answers[0].rdata, first.answers[0].rdata);
    assert_eq!(second.questions[0].name.to_ascii_lower(), "ok.example");
}

#[test]
/// Splitting it would store the same answer twice.
fn wire_fast_path_uses_the_response_cache_as_its_only_index() {
    use onetdns_runtime::WireDisposition;

    let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
    let cache_layer =
        crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let response_cache = cache_layer.handle();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(cache_layer),
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        response_cache.clone(),
    )));

    let request = Message::query(0x1111, ApName::from_str("shared.example").unwrap(), ApRt::A);
    let request_wire = request.try_encode().unwrap();
    let scanned = crate::wirecache::scan_query(&request_wire).unwrap();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&request_wire, &ctx(), &mut out, std::time::Instant::now()),
        WireDisposition::Respond
    );

    let filter = server.filter.load();
    let filter_tag = server.features.load().wire_tag(&filter);
    let (wire_entry, _) = response_cache
        .wire_get(scanned.key(), filter_tag, std::time::Instant::now())
        .expect("응답 LRU의 wire 항목");
    let response_entry = response_cache
        .wire_entry_for(&request)
        .expect("구조화 LRU가 wire 표현으로 승격되어야 합니다");
    assert!(
        crate::wirecache::WireEntry::ptr_eq(&wire_entry, &response_entry),
        "UDP fast path와 일반 응답 경로가 같은 단일 할당 payload를 사용해야 합니다"
    );

    let parsed = response_cache
        .lane_response(&request)
        .expect("UDP 이외 경로는 공유 wire를 필요할 때 파싱합니다");
    assert_eq!(parsed.answers.len(), 1);
    assert_eq!(
        parsed.answers[0].rdata,
        Message::parse(&out.buf).unwrap().answers[0].rdata
    );
}

#[test]
fn lane_runtime_replacement_is_generation_atomic() {
    let old_layer =
        crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 16, 1, 0, 86_400, 0, 86_400);
    let old_cache = old_layer.handle();
    let new_layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 32, 1, 0, 300, 0, 300);
    let new_cache = new_layer.handle();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(old_layer),
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        old_cache.clone(),
    )));

    let old_snapshot = server
        .features
        .load()
        .lane_runtime
        .clone()
        .expect("시작 세대");
    assert!(old_snapshot.cache.ptr_eq(&old_cache));

    update_features(&server, |features| {
        features.adopt_chain(
            crate::wirecache::WireEntryFactory::new(0, 300),
            new_cache.clone(),
            None,
        );
        features.ddr_enabled = true;
    });
    let new_snapshot = server
        .features
        .load()
        .lane_runtime
        .clone()
        .expect("교체 세대");
    assert!(!Arc::ptr_eq(&old_snapshot, &new_snapshot));
    assert!(old_snapshot.cache.ptr_eq(&old_cache));
    assert!(new_snapshot.cache.ptr_eq(&new_cache));
    assert!(!new_snapshot.cache.ptr_eq(&old_cache));
    assert!(server.features.load().ddr_enabled);
}

#[test]
fn lane_runtime_replacement_applies_the_new_ttl_policy() {
    use onetdns_runtime::WireDisposition;

    let old_layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 16, 1, 0, 7, 0, 7);
    let old_cache = old_layer.handle();
    let slot = Arc::new(ResolverSlot::new(Arc::new(old_layer)));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        slot.clone(),
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 7),
        old_cache,
    )));
    let packet = Message::query(1, ApName::from_str("ttl-swap.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        WireDisposition::Respond
    );
    assert_eq!(Message::parse(&output.buf).unwrap().answers[0].ttl, 7);

    let new_layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 16, 1, 0, 31, 0, 31);
    let new_cache = new_layer.handle();
    slot.replace(Arc::new(new_layer));
    update_features(&server, |features| {
        features.wire_epoch += 1;
        features.adopt_chain(
            crate::wirecache::WireEntryFactory::new(0, 31),
            new_cache,
            None,
        );
    });

    output.clear();
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        WireDisposition::Respond
    );
    assert_eq!(
        Message::parse(&output.buf).unwrap().answers[0].ttl,
        31,
        "이전 wire factory나 이전 응답 캐시가 남으면 7이 나옵니다"
    );
}

#[test]
fn wire_lane_hit_charges_rate_limit_once_across_fallback() {
    use onetdns_runtime::WireDisposition;

    struct CountingLimiter(AtomicUsize);
    impl RateLimiter for CountingLimiter {
        fn check(&self, _client: &ClientInfo) -> RateDecision {
            self.0.fetch_add(1, Ordering::Relaxed);
            RateDecision::Permit
        }
    }

    let limiter = Arc::new(CountingLimiter(AtomicUsize::new(0)));

    let engine =
        onetdns_filter::build_from_str("", "", BlockResponse::NxDomain).with_clients(vec![
            onetdns_filter::ClientPolicy::with_options(
                vec!["10.0.0.0/8".parse().unwrap()],
                vec![],
                vec![],
                &[],
                &[],
                false,
                Some(true),
            ),
        ]);
    let (backend, cache) = fixed_answer_cache();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![limiter.clone()],
        backend,
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        cache,
    )));

    let miss = Message::query(0x1, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&miss, &ctx(), &mut out, std::time::Instant::now()),
        WireDisposition::Respond
    );

    limiter.0.store(0, Ordering::Relaxed);

    let hit = Message::query(0x2, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out2 = onetdns_proto::Writer::with_limit(1232);
    let ss_ctx = RequestCtx {
        src: "10.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Udp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    assert_eq!(
        server.handle_udp_wire(&hit, &ss_ctx, &mut out2, std::time::Instant::now()),
        WireDisposition::Fallback
    );
    assert_eq!(
        limiter.0.load(Ordering::Relaxed),
        0,
        "폴백하는 히트는 wire 경로에서 rate limit 토큰을 소비하지 않아야 한다"
    );
}

#[test]
fn resolver_slot_replaces_new_requests_without_invalidating_old_handles() {
    let slot = ResolverSlot::new(Arc::new(FixedRcode(ResponseCode::ServFail.0)));
    let previous = slot.load();
    slot.replace(Arc::new(FixedRcode(ResponseCode::NoError.0)));

    assert_eq!(
        previous.resolve(&q("old.example")).unwrap().header.rcode,
        ResponseCode::ServFail.0
    );
    assert_eq!(
        slot.resolve(&q("new.example")).unwrap().header.rcode,
        ResponseCode::NoError.0
    );
}

fn mock_empty_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut response = base_response(&req);
                response.header.rcode = ResponseCode::NoError.0;
                let _ = sock.send_to(&response.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

/// What real upstreams send when a CNAME chain ends without the requested type, such as AAAA for a
/// name with no IPv6 address; several public resolvers leave out the SOA.
fn mock_alias_only_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut response = base_response(&req);
                response.header.rcode = ResponseCode::NoError.0;
                if let Some(question) = req.questions.first() {
                    response.answers.push(ApRecord::new(
                        question.name.clone(),
                        60,
                        ApRData::Cname(ApName::from_str("target.example.").unwrap()),
                    ));
                }
                let _ = sock.send_to(&response.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

fn mock_private_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut response = base_response(&req);
                response.header.rcode = ResponseCode::NoError.0;
                if let Some(question) = req.questions.first() {
                    response.answers.push(ApRecord::new(
                        question.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(10, 0, 0, 7)),
                    ));
                }
                let _ = sock.send_to(&response.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

fn server_with_upstream(upstream: SocketAddr) -> NativeServer {
    NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![upstream],
            Duration::from_secs(2),
        ))),
        60,
    )
}

fn mock_upstream_ede() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut m = base_response(&req);
                m.header.rcode = ResponseCode::NoError.0;
                if let Some(qq) = req.questions.first() {
                    m.answers.push(ApRecord::new(
                        qq.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                    ));
                }
                let mut e = onetdns_proto::Edns::default();
                e.push_ede(onetdns_proto::ede_code::STALE_ANSWER, "stale");
                m.additionals.push(e.try_to_record().unwrap());
                let _ = sock.send_to(&m.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

#[test]
fn resolved_address_survives_client_wire_roundtrip() {
    let srv = server("");
    let mut request = q("wire.example.");
    request.header.checking_disabled = true;
    let response = srv.handle(&request, &ctx()).expect("응답");
    let parsed = Message::parse(&response.try_encode().unwrap()).expect("클라이언트 wire parse");

    assert_eq!(parsed.header.id, request.header.id);
    assert!(parsed.header.response);
    assert!(parsed.header.recursion_available);
    assert!(parsed.header.recursion_desired);
    assert!(parsed.header.checking_disabled);
    assert_eq!(parsed.questions.len(), 1);
    assert!(parsed.questions[0]
        .name
        .eq_ignore_case(&request.questions[0].name));
    assert_eq!(parsed.questions[0].qtype, request.questions[0].qtype);
    assert_eq!(parsed.questions[0].qclass, request.questions[0].qclass);
    assert!(parsed
        .answers
        .iter()
        .any(|record| { record.rdata == ApRData::A(Ipv4Addr::new(7, 7, 7, 7)) }));
}

#[test]
/// Upstreams answer such a chain with a CNAME and NOERROR, often without a negative SOA; failing it
/// would fail AAAA for every name behind a CNAME.
fn an_alias_only_answer_is_not_turned_into_a_failure() {
    let srv = server_with_upstream(mock_alias_only_upstream());
    let response = srv.handle(&q("alias.example."), &ctx()).expect("응답");
    assert_eq!(
        response.header.rcode,
        ResponseCode::NoError.0,
        "별칭만 온 응답을 실패로 바꿨습니다"
    );
    assert!(
        response
            .answers
            .iter()
            .any(|record| matches!(&record.rdata, ApRData::Cname(_))),
        "별칭을 그대로 전달해야 합니다"
    );
}

#[test]
/// RFC 2308 lists all-empty sections as one form of NODATA. Without an SOA the standard says not to
/// cache it, not to refuse it; the cache layer handles not caching
/// (`unproven_empty_noerror_is_not_cached`).
///
/// SERVFAIL here is the behavior RFC 4074 warns about: for AAAA of a name without IPv6, the client
/// cannot fall back to A and keeps retrying.
fn unproven_empty_noerror_is_passed_through_not_failed() {
    let srv = server_with_upstream(mock_empty_upstream());
    let response = srv.handle(&q("empty.example."), &ctx()).expect("응답");
    assert_eq!(
        response.header.rcode,
        ResponseCode::NoError.0,
        "규격이 인정한 NODATA를 실패로 바꿨습니다"
    );
    assert!(
        response.answers.is_empty(),
        "없는 레코드를 지어내면 안 됩니다"
    );
}

#[test]
/// A leftover empty success would claim the name has no addresses.
fn rebind_filter_never_leaves_empty_success() {
    let srv = server_with_upstream(mock_private_upstream()).with_features(NativeFeatures {
        rebind_protection: true,
        ..NativeFeatures::default()
    });
    let mut request = q("private.example.");
    request
        .additionals
        .push(onetdns_proto::Edns::default().try_to_record().unwrap());
    let response = srv.handle(&request, &ctx()).expect("응답");
    assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
    assert!(response.answers.is_empty());
    assert_eq!(negative_soa_ttl(&response), 60);
    let ede = response
        .opt()
        .and_then(onetdns_proto::Edns::from_record)
        .and_then(|edns| edns.ede());
    assert!(ede.is_some(), "필터 이유를 EDE로 전달");
}

#[test]
/// RFC 7871 binds both directions: a server using ECS must not add the option when the query had
/// none, and must when it had one. A downstream forwarder sets its cache scope from it, so leaving
/// it out makes a cache that gives per-subnet answers to everyone.
///
/// SCOPE is 0: this server asks upstream with a fixed configured subnet, so every client gets the
/// same answer, and a nonzero value would make downstream cache it for that subnet only.
fn client_subnet_is_echoed_only_when_the_query_carried_one() {
    let with_ecs = |raw: Option<Vec<u8>>| {
        let mut request = q("a.example.");
        let mut edns = onetdns_proto::Edns::default();
        if let Some(raw) = raw {
            edns.set_client_subnet(raw);
        }
        request.additionals.push(edns.try_to_record().unwrap());
        request
    };
    let echoed = |response: &Message| {
        response
            .opt()
            .and_then(onetdns_proto::Edns::from_record)
            .and_then(|edns| edns.client_subnet().map(<[u8]>::to_vec))
    };
    let using = |on: bool| {
        server("").with_features(NativeFeatures {
            ecs_in_use: on,
            ..NativeFeatures::default()
        })
    };

    // FAMILY 1, SOURCE 24, SCOPE 0, 192.0.2.0
    let asked = vec![0, 1, 24, 0, 192, 0, 2];
    let response = using(true)
        .handle(&with_ecs(Some(asked.clone())), &ctx())
        .unwrap();
    assert_eq!(
        echoed(&response),
        Some(asked.clone()),
        "FAMILY, SOURCE, ADDRESS 는 질의의 것과 같고 SCOPE 는 0 입니다"
    );

    // Even with a wrong SCOPE from the client, this server's response carries 0.
    let bad_scope = vec![0, 1, 24, 24, 192, 0, 2];
    let response = using(true)
        .handle(&with_ecs(Some(bad_scope)), &ctx())
        .unwrap();
    assert_eq!(echoed(&response), Some(asked.clone()));

    let response = using(true).handle(&with_ecs(None), &ctx()).unwrap();
    assert_eq!(
        echoed(&response),
        None,
        "요청하지 않은 클라이언트에게는 넣지 않습니다"
    );

    let response = using(false).handle(&with_ecs(Some(asked)), &ctx()).unwrap();
    assert_eq!(
        echoed(&response),
        None,
        "대역 정보를 쓰지 않으면 그대로 돌려줄 것도 없습니다"
    );

    // SOURCE 24 with only two address octets is malformed; echoing it would pass a broken option
    // downstream.
    let short = vec![0, 1, 24, 0, 192, 0];
    let response = using(true).handle(&with_ecs(Some(short)), &ctx()).unwrap();
    assert_eq!(
        echoed(&response),
        None,
        "형식이 깨진 옵션은 그대로 돌려주지 않습니다"
    );
}

#[test]
fn ede_passthrough_from_upstream() {
    let srv = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream_ede()],
            Duration::from_secs(2),
        ))),
        60,
    );

    let mut req = q("a.example.");
    req.additionals
        .push(onetdns_proto::Edns::default().try_to_record().unwrap());
    let resp = srv.handle(&req, &ctx()).unwrap();
    let opt = resp.opt().expect("EDNS 클라엔 OPT");
    let (code, _) = onetdns_proto::Edns::from_record(opt)
        .unwrap()
        .ede()
        .expect("EDE 전달");
    assert_eq!(code, onetdns_proto::ede_code::STALE_ANSWER);

    let resp2 = srv.handle(&q("b.example."), &ctx()).unwrap();
    assert!(resp2.opt().is_none(), "비EDNS 클라엔 OPT 강제 안 함");
}

#[test]
fn resolver_failure_carries_diagnostic_ede() {
    struct FailBackend(ResolveFailure);
    impl Resolver for FailBackend {
        fn resolve(&self, _req: &Message) -> Option<Message> {
            None
        }
        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            ResolveOutcome::Failure(match self.0 {
                ResolveFailure::TransportExhausted => ResolveFailure::TransportExhausted,
                ResolveFailure::Permanent(code) => ResolveFailure::Permanent(code),
            })
        }
    }

    let srv = |failure: ResolveFailure| {
        NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(FailBackend(failure)),
            60,
        )
    };
    let ede_of = |resp: &Message| -> Option<u16> {
        resp.opt()
            .and_then(onetdns_proto::Edns::from_record)
            .and_then(|e| e.ede())
            .map(|(code, _)| code)
    };

    let s = srv(ResolveFailure::Permanent(Some(
        onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY,
    )));
    let mut req = q("fail.example.");
    req.additionals
        .push(onetdns_proto::Edns::default().try_to_record().unwrap());
    let resp = s.handle(&req, &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
    assert_eq!(
        ede_of(&resp),
        Some(onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY)
    );

    let s = srv(ResolveFailure::Permanent(Some(
        onetdns_proto::ede_code::DNSSEC_BOGUS,
    )));
    let resp = s.handle(&req, &ctx()).unwrap();
    assert_eq!(ede_of(&resp), Some(onetdns_proto::ede_code::DNSSEC_BOGUS));

    let s = srv(ResolveFailure::TransportExhausted);
    let resp = s.handle(&req, &ctx()).unwrap();
    assert_eq!(ede_of(&resp), Some(onetdns_proto::ede_code::NETWORK_ERROR));

    let s = srv(ResolveFailure::Permanent(Some(
        onetdns_proto::ede_code::OTHER,
    )));
    let resp = s.handle(&req, &ctx()).unwrap();
    let ede = resp
        .opt()
        .and_then(onetdns_proto::Edns::from_record)
        .and_then(|e| e.ede());
    assert_eq!(ede.as_ref().map(|(code, _)| *code), Some(0));
    assert_eq!(
        ede.map(|(_, text)| text),
        Some("recursion limit exceeded".to_string())
    );

    let s = srv(ResolveFailure::Permanent(None));
    let resp = s.handle(&q("fail.example."), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
    assert!(resp.opt().is_none());
}

#[test]
fn acl_denied_query_carries_prohibited_ede() {
    let srv = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::new(vec![], vec![], false)),
        vec![],
        Arc::new(FixedRcode(ResponseCode::NoError.0)),
        60,
    );
    let ede_of = |resp: &Message| -> Option<u16> {
        resp.opt()
            .and_then(onetdns_proto::Edns::from_record)
            .and_then(|e| e.ede())
            .map(|(code, _)| code)
    };

    let mut req = q("denied.example.");
    req.additionals
        .push(onetdns_proto::Edns::default().try_to_record().unwrap());
    let resp = srv.handle(&req, &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::Refused.0);
    assert_eq!(ede_of(&resp), Some(onetdns_proto::ede_code::PROHIBITED));

    let resp2 = srv.handle(&q("denied.example."), &ctx()).unwrap();
    assert_eq!(resp2.header.rcode, ResponseCode::Refused.0);
    assert!(resp2.opt().is_none());
}

#[test]
fn ede_on_filter_block() {
    let srv = server("||blocked.test^\n");

    let mut req = q("blocked.test.");
    req.additionals
        .push(onetdns_proto::Edns::default().try_to_record().unwrap());
    let resp = srv.handle(&req, &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0);
    let opt = resp.opt().expect("EDNS 클라엔 OPT 에코");
    let (code, text) = onetdns_proto::Edns::from_record(opt)
        .unwrap()
        .ede()
        .expect("EDE");
    assert_eq!(code, onetdns_proto::ede_code::BLOCKED);
    assert_eq!(text, "blocked by filter");

    let resp2 = srv.handle(&q("blocked.test."), &ctx()).unwrap();
    assert_eq!(resp2.header.rcode, ResponseCode::NXDomain.0);
    assert!(resp2.opt().is_none(), "비EDNS 클라엔 OPT 강제 안 함");
}

#[test]
fn rpz_ip_blocks_resolved_answer() {
    let mut parts = onetdns_filter::EngineParts::default();
    parts.rpz_ip.push(onetdns_filter::RpzIpRule::new(
        "7.7.7.7/32".parse().unwrap(),
        FilterVerdict::Block(BlockResponse::NxDomain),
    ));
    let engine = onetdns_filter::BlockEngine::new(parts, BlockResponse::NxDomain);
    let srv = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream()],
            Duration::from_secs(2),
        ))),
        60,
    );
    let resp = srv.handle(&q("anything.example."), &ctx()).unwrap();
    assert_eq!(
        resp.header.rcode,
        ResponseCode::NXDomain.0,
        "응답 IP가 rpz-ip 트리거에 걸려 NXDOMAIN"
    );

    let resp2 = server("").handle(&q("anything.example."), &ctx()).unwrap();
    assert_eq!(resp2.header.rcode, ResponseCode::NoError.0);
    assert!(resp2
        .answers
        .iter()
        .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(7, 7, 7, 7))));
}

pub(crate) fn big_zone_store(n: usize) -> Arc<ArcSwap<onetdns_authority::ZoneStore>> {
    let mut zone_text = String::from(
        "$ORIGIN big.test.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n",
    );
    for i in 0..n {
        zone_text.push_str(&format!(
            "host-{i:05}-with-a-rather-long-owner-label IN A 10.{}.{}.{}\n",
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        ));
    }
    let zone = onetdns_authority::parse_zone(&zone_text, "big.test").unwrap();
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(zone);
    Arc::new(ArcSwap::new(Arc::new(zs)))
}

struct ActivePermitLimiter;

impl RateLimiter for ActivePermitLimiter {
    fn check(&self, _client: &ClientInfo) -> RateDecision {
        RateDecision::Permit
    }
}

/// Deterministically mimics `DynamicRateLimiter::replace` installing a limiter mid-dispatch, where
/// a control plane thread would cut in.
struct LateActivatingLimiter {
    asked: std::sync::atomic::AtomicUsize,
}

impl RateLimiter for LateActivatingLimiter {
    fn check(&self, _client: &ClientInfo) -> RateDecision {
        RateDecision::Permit
    }

    /// Off only on the first call.
    fn is_active(&self) -> bool {
        self.asked.fetch_add(1, Ordering::Relaxed) != 0
    }
}

#[test]
fn authority_wire_survives_limiter_activating_mid_dispatch() {
    let zone_text = "$ORIGIN fast.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.9\n";
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(zone_text, "fast.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store.clone(),
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![Arc::new(LateActivatingLimiter {
            asked: std::sync::atomic::AtomicUsize::new(0),
        })],
        authority,
        60,
    )
    .with_authority_wire_path(Some(store), true);
    let request = Message::query(
        0x4567,
        ApName::from_str("www.fast.test").unwrap(),
        RecordType::A,
    );
    let packet = request.try_encode().unwrap();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    // The limiter came on after being seen off, so no client was built. This must fall back rather
    // than panic; falling back is always correct.
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Fallback
    );
    assert!(
        output.buf.is_empty(),
        "물러설 때 절반 쓴 응답을 남기면 안 됩니다"
    );
}

#[test]
/// TCP has no such limit, so it must answer there. This path has no truncation ladder: without
/// falling back, a datagram past the RFC 1035 size goes out, and the client sees no TC, so it never
/// retries over TCP.
fn the_allocation_free_path_declines_a_non_edns_udp_answer_over_512_bytes() {
    let mut zone_text = String::from(
        "$ORIGIN wide.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n",
    );
    for index in 1..=60 {
        zone_text.push_str(&format!("many IN A 198.51.100.{index}\n"));
    }
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(&zone_text, "wide.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store.clone(),
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    )
    .with_authority_wire_path(Some(store), true);

    let request = Message::query(
        0x5150,
        ApName::from_str("many.wide.test").unwrap(),
        RecordType::A,
    );
    let packet = request.try_encode().unwrap();

    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Fallback,
        "512바이트를 넘는 답을 EDNS 없는 UDP 로 그대로 내보냈습니다"
    );
    assert!(output.buf.is_empty(), "물러설 때 절반 쓴 응답을 남겼습니다");

    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let mut tcp_output = onetdns_proto::Writer::with_limit(65535);
    assert_eq!(
        server.handle_tcp_wire(&packet, &tcp, &mut tcp_output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond,
        "TCP 에는 512바이트 상한이 없습니다"
    );
    assert!(tcp_output.buf.len() > 512);
}

#[test]
/// RFC 8482 allows the minimal response only in the answer section and otherwise requires the
/// standard algorithms. Synthesizing before resolution would turn a missing name into NOERROR,
/// revealing existence, and set neither a negative cache nor AA. Synthesis is also skipped when
/// QNAME has a CNAME, per RFC 8482.
fn minimal_any_follows_the_standard_algorithm_inside_our_own_zones() {
    let zone_text = concat!(
        "$ORIGIN any.test.\n$TTL 300\n",
        "@ IN SOA ns admin 1 300 60 3600 60\n",
        "@ IN NS ns\n",
        "ns IN A 192.0.2.53\n",
        "host IN A 192.0.2.9\n",
        "host IN TXT \"two rrsets\"\n",
        "alias IN CNAME host\n",
    );
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(zone_text, "any.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store.clone(),
    ));
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    )
    .with_authority_wire_path(Some(store), true);

    let ask = |name: &str| -> Message {
        let request = Message::query(0x7788, ApName::from_str(name).unwrap(), ApRt::ANY);
        server.handle(&request, &ctx()).expect("응답")
    };

    let existing = ask("host.any.test");
    assert_eq!(existing.header.rcode, ResponseCode::NoError.0);
    assert!(
        existing.header.authoritative,
        "권한 표시를 설정하지 않았습니다"
    );
    assert_eq!(existing.answers.len(), 1);
    assert_eq!(existing.answers[0].rtype, ApRt(13), "합성 HINFO여야 합니다");

    let missing = ask("nosuch.any.test");
    assert_eq!(
        missing.header.rcode,
        ResponseCode::NXDomain.0,
        "없는 이름에 NOERROR를 주면 있다고 알리는 것입니다"
    );
    assert!(missing.answers.is_empty());
    assert!(missing.header.authoritative);

    let aliased = ask("alias.any.test");
    assert!(
        aliased
            .answers
            .iter()
            .any(|record| record.rtype == ApRt::CNAME),
        "QNAME에 CNAME이 있으면 합성하지 않습니다"
    );
}

#[test]
fn axfr_large_zone_streams_multiple_envelopes() {
    let store = big_zone_store(2000);
    let mut srv = server("").with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()]);
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,

        authenticated: false,
        auth_identity: None,
    };
    let axfr = Message::query(7, ApName::from_str("BiG.test").unwrap(), ApRt(252));
    let msgs = srv.handle_multi(&axfr, &tcp).expect("AXFR 응답");
    assert!(msgs.len() > 1, "다중 envelope이어야: {}", msgs.len());

    let mut all: Vec<ApRecord> = Vec::new();
    for (i, m) in msgs.iter().enumerate() {
        let wire = m.try_encode().unwrap();
        assert!(
            wire.len() <= 0xffff,
            "각 envelope은 64KB 이하: {}",
            wire.len()
        );
        assert!(m.header.authoritative);
        if i == 0 {
            assert_eq!(m.questions.len(), 1, "첫 envelope에만 질문");
        } else {
            assert!(m.questions.is_empty(), "후속 envelope은 질문 생략");
        }
        all.extend(m.answers.iter().cloned());
    }

    assert_eq!(all.first().unwrap().rtype, RecordType::SOA);
    assert_eq!(all.last().unwrap().rtype, RecordType::SOA);
    assert_eq!(all.len(), 2000 + 2 + 2);
    let rebuilt = onetdns_authority::Zone::from_records(all).expect("재조립 영역 구성");
    assert_eq!(rebuilt.soa().serial, 1);

    let mut streamed = 0usize;
    let completed = srv.handle_stream(&axfr, &tcp, &mut |_| {
        streamed += 1;
        false
    });
    assert!(!completed, "전송 중단을 즉시 전파");
    assert_eq!(streamed, 1, "나머지 AXFR envelope을 미리 생성하지 않음");

    let first = srv.handle(&axfr, &tcp).unwrap();
    assert_eq!(first.answers.first().unwrap().rtype, RecordType::SOA);

    let mut cached_writer = onetdns_proto::Writer::new();
    let mut cached_wires = Vec::new();
    assert_eq!(
        srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |wire| {
            cached_wires.push(wire.to_vec());
            true
        }),
        Some(true)
    );
    assert!(cached_wires.len() > 1);
    let mut cached_records = 0usize;
    for (index, wire) in cached_wires.iter().enumerate() {
        let message = Message::parse(wire).expect("cached AXFR wire parse");
        assert_eq!(message.header.id, axfr.header.id);
        assert!(message.header.authoritative);
        assert_eq!(message.questions.len(), usize::from(index == 0));
        if index == 0 {
            assert_eq!(
                message.questions[0].name.as_uncompressed_wire(),
                axfr.questions[0].name.as_uncompressed_wire(),
                "cached AXFR preserves question case"
            );
        }
        cached_records += message.answers.len();
    }
    assert_eq!(cached_records, 2000 + 2 + 2);
    let first_cached = cached_wires.clone();
    cached_wires.clear();
    assert_eq!(
        srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |wire| {
            cached_wires.push(wire.to_vec());
            true
        }),
        Some(true)
    );
    assert_eq!(cached_wires, first_cached, "lazy AXFR wire cache is reused");

    // No path records a successful zone transfer, so falling back because a recorder exists would
    // only rebuild the zone and record nothing.
    {
        let (recorder, _stats) = onetdns_control::channel(
            8,
            8,
            60,
            onetdns_control::RecorderOpts::default(),
            onetdns_control::PersistOpts::default(),
        );
        srv.recorder = Some(recorder);
        cached_wires.clear();
        assert_eq!(
            srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |wire| {
                cached_wires.push(wire.to_vec());
                true
            }),
            Some(true),
            "기록기가 있다고 미리 만들어 둔 영역 전송 경로가 전부 죽었습니다"
        );
        assert_eq!(
            cached_wires, first_cached,
            "기록기가 응답 바이트를 바꿨습니다"
        );
    }

    srv.rate_limiters.push(Arc::new(ActivePermitLimiter));
    assert_eq!(
        srv.handle_preencoded_stream(&axfr, &tcp, &mut cached_writer, &mut |_| true),
        None,
        "an active limiter keeps AXFR on the policy-aware Message path"
    );

    let doq = RequestCtx {
        transport: RtTransport::DoQ,
        ..tcp
    };
    let refused = srv.handle(&axfr, &doq).unwrap();
    assert_eq!(refused.header.rcode, ResponseCode::Refused.0);
}

#[test]
fn ddns_update_applies_and_bumps_serial() {
    let (store, srv, _file) = ddns_server(
        "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n",
        "example.com",
    );
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };

    let mut up = Message::default();
    up.header.id = 0x77;
    up.header.opcode = 5;
    up.questions = vec![onetdns_proto::Question {
        name: ApName::from_str("example.com").unwrap(),
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    }];

    up.answers.push(ApRecord {
        name: ApName::from_str("ns1.example.com").unwrap(),
        rtype: ApRt::A,
        class: DnsClass(255),
        ttl: 0,
        rdata: ApRData::Unknown(ApRt::A.0, vec![]),
    });

    up.authorities.push(ApRecord::new(
        ApName::from_str("www.example.com").unwrap(),
        120,
        ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
    ));
    let resp = srv.handle(&up, &tcp).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NoError.0, "UPDATE 성공");

    let z = store.load();
    let zone = z.zones().first().unwrap().clone();
    assert_eq!(zone.soa().serial, 2, "serial+1");
    let q = zone.query(&ApName::from_str("www.example.com").unwrap(), ApRt::A);
    assert!(q
        .answers
        .iter()
        .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 9))));

    let other = RequestCtx {
        src: "192.168.1.9:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let resp = srv.handle(&up, &other).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::Refused.0, "ACL 밖 거부");

    let mut bad = up.clone();
    bad.answers[0].name = ApName::from_str("nope.example.com").unwrap();
    let resp = srv.handle(&bad, &tcp).unwrap();
    assert_eq!(resp.header.rcode, 8, "전제 실패 NXRRSET");
}

#[test]
/// A malformed one getting through would break the zone.
fn ddns_enforces_prerequisite_sets_and_update_record_shape() {
    let (store, srv, file) = ddns_server(
        "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 10 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nmulti IN A 10.0.0.2\nmulti IN A 10.0.0.3\n",
        "example.com",
    );
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let mut update = Message::default();
    update.header.opcode = 5;
    update.questions.push(onetdns_proto::Question {
        name: ApName::from_str("example.com").unwrap(),
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    });
    update.answers.push(ApRecord::new(
        ApName::from_str("multi.example.com").unwrap(),
        0,
        ApRData::A(Ipv4Addr::new(10, 0, 0, 2)),
    ));
    assert_eq!(
        srv.handle(&update, &tcp).unwrap().header.rcode,
        8,
        "부분집합은 value-dependent prerequisite를 만족하지 않음"
    );

    update.answers.push(ApRecord::new(
        ApName::from_str("multi.example.com").unwrap(),
        0,
        ApRData::A(Ipv4Addr::new(10, 0, 0, 3)),
    ));
    assert_eq!(
        srv.handle(&update, &tcp).unwrap().header.rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(store.load().zones()[0].soa().serial, 10, "무변경 UPDATE");

    update.answers[0].name = ApName::from_str("outside.test").unwrap();
    assert_eq!(srv.handle(&update, &tcp).unwrap().header.rcode, 10);

    update.answers.clear();
    update.authorities.push(ApRecord {
        name: ApName::from_str("multi.example.com").unwrap(),
        rtype: ApRt::A,
        class: DnsClass(255),
        ttl: 1,
        rdata: ApRData::Unknown(ApRt::A.0, vec![]),
    });
    assert_eq!(
        srv.handle(&update, &tcp).unwrap().header.rcode,
        ResponseCode::FormErr.0,
        "CLASS=ANY 삭제는 TTL=0이어야 함"
    );
    assert_eq!(store.load().zones()[0].soa().serial, 10);

    update.authorities[0].ttl = 0;
    update.authorities[0].rtype = ApRt(252);
    update.authorities[0].rdata = ApRData::Unknown(252, vec![]);
    assert_eq!(
        srv.handle(&update, &tcp).unwrap().header.rcode,
        ResponseCode::FormErr.0,
        "QTYPE/meta-type은 UPDATE 레코드로 사용할 수 없습니다"
    );

    let secondary = server("")
        .with_xfr(store, vec!["127.0.0.0/8".parse().unwrap()])
        .with_ddns(
            vec!["127.0.0.0/8".parse().unwrap()],
            false,
            vec![UpdateTarget {
                origin: ApName::from_str("primary-only.test").unwrap(),
                file: file.dir.join("primary-only.test.zone"),
            }],
        );
    update.answers.clear();
    update.authorities.clear();
    assert_eq!(
        secondary.handle(&update, &tcp).unwrap().header.rcode,
        9,
        "secondary 복제 zone은 로컬 DDNS 수정 불가"
    );
}

#[test]
/// An update arriving before the watcher noticed a file change would write the old in-memory zone
/// plus the update, losing the outside edit, and the watcher would later read the overwritten file.
fn ddns_refuses_to_overwrite_an_externally_edited_zone_file() {
    let dir = std::env::temp_dir().join(format!(
        "onetdns-ddns-digest-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("example.com.zone");
    std::fs::write(
        &path,
        "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n",
    )
    .unwrap();
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(onetdns_authority::source::load_zone_file(&path, "example.com").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zs)));
    let origin = ApName::from_str("example.com").unwrap();
    let srv = server("")
        .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
        .with_ddns(
            vec!["127.0.0.0/8".parse().unwrap()],
            false,
            vec![UpdateTarget {
                origin: origin.clone(),
                file: path.clone(),
            }],
        );
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let add = |name: &str, last: u8| {
        let mut up = Message::default();
        up.header.opcode = 5;
        up.questions.push(onetdns_proto::Question {
            name: origin.clone(),
            qtype: ApRt::SOA,
            qclass: DnsClass::IN,
        });
        up.authorities.push(ApRecord::new(
            ApName::from_str(name).unwrap(),
            120,
            ApRData::A(Ipv4Addr::new(10, 0, 0, last)),
        ));
        up
    };

    let first = srv.handle(&add("www.example.com", 9), &tcp).unwrap();
    assert_eq!(first.header.rcode, ResponseCode::NoError.0);
    let second = srv.handle(&add("api.example.com", 10), &tcp).unwrap();
    assert_eq!(
        second.header.rcode,
        ResponseCode::NoError.0,
        "the server's own write must not count as an outside edit"
    );
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("api.example.com"));

    let edited = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 20 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nhand IN A 10.0.0.20\n";
    std::fs::write(&path, edited).unwrap();
    let refused = srv.handle(&add("late.example.com", 11), &tcp).unwrap();
    assert_eq!(refused.header.rcode, ResponseCode::ServFail.0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    assert_eq!(store.load().zones()[0].soa().serial, 3);

    std::fs::remove_dir_all(dir).unwrap();
}

/// Deletes the file on drop.
struct UpdateZoneFile {
    dir: std::path::PathBuf,
    target: UpdateTarget,
}

impl UpdateZoneFile {
    /// Writes the zone text to a temporary file and returns the zone read back from it.
    fn new(text: &str, origin: &str) -> (Self, onetdns_authority::Zone) {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "onetdns-ddns-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{origin}.zone"));
        std::fs::write(&file, text).unwrap();
        let zone = onetdns_authority::source::load_zone_file(&file, origin).unwrap();
        let target = UpdateTarget {
            origin: ApName::from_str(origin).unwrap(),
            file,
        };
        (Self { dir, target }, zone)
    }
}

impl Drop for UpdateZoneFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ddns_server(
    text: &str,
    origin: &str,
) -> (
    Arc<ArcSwap<onetdns_authority::ZoneStore>>,
    NativeServer,
    UpdateZoneFile,
) {
    let (file, zone) = UpdateZoneFile::new(text, origin);
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(zone);
    let store = Arc::new(ArcSwap::new(Arc::new(zs)));
    let srv = server("")
        .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
        .with_ddns(
            vec!["127.0.0.0/8".parse().unwrap()],
            false,
            vec![file.target.clone()],
        );
    (store, srv, file)
}

fn ddns_fixture() -> (
    Arc<ArcSwap<onetdns_authority::ZoneStore>>,
    NativeServer,
    UpdateZoneFile,
) {
    ddns_server(
        "$ORIGIN skip.test.\n$TTL 300\n@ IN SOA ns admin 10 300 60 86400 60\n@ IN NS ns\nns IN A 10.0.0.1\nmulti IN A 10.0.0.2\nsub IN NS ns.sub\nns.sub IN A 10.0.0.5\n",
        "skip.test",
    )
}

fn ddns_update(records: Vec<ApRecord>) -> Message {
    let mut m = Message::default();
    m.header.opcode = 5;
    m.questions.push(onetdns_proto::Question {
        name: ApName::from_str("skip.test").unwrap(),
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    });
    m.authorities = records;
    m
}

fn ddns_count(
    store: &Arc<ArcSwap<onetdns_authority::ZoneStore>>,
    name: &str,
    rtype: ApRt,
) -> usize {
    store.load().zones()[0]
        .query(&ApName::from_str(name).unwrap(), rtype)
        .answers
        .iter()
        .filter(|r| r.rtype == rtype)
        .count()
}

#[test]
/// RFC 2136 says an add that would make a CNAME coexist with other data, or a delete of the apex's
/// last NS, skips only that RR, processes the rest, and answers NOERROR; failing the whole message
/// would drop the valid updates with it.
///
/// The last NS of a delegation must be deletable; applying the apex rule would make a delegation
/// impossible to remove.
fn ddns_skips_only_the_conflicting_record() {
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };

    let (store, srv, _file) = ddns_fixture();
    let resp = srv
        .handle(
            &ddns_update(vec![
                ApRecord::new(
                    ApName::from_str("multi.skip.test").unwrap(),
                    60,
                    ApRData::Cname(ApName::from_str("t.skip.test").unwrap()),
                ),
                ApRecord::new(
                    ApName::from_str("fresh.skip.test").unwrap(),
                    60,
                    ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
                ),
            ]),
            &tcp,
        )
        .unwrap();
    assert_eq!(
        resp.header.rcode,
        ResponseCode::NoError.0,
        "공존할 수 없는 CNAME 하나 때문에 메시지 전체를 실패시키지 않습니다"
    );
    assert_eq!(
        ddns_count(&store, "multi.skip.test", ApRt::CNAME),
        0,
        "다른 데이터가 있는 이름에는 CNAME 을 넣지 않습니다"
    );
    assert_eq!(ddns_count(&store, "multi.skip.test", ApRt::A), 1);
    assert_eq!(
        ddns_count(&store, "fresh.skip.test", ApRt::A),
        1,
        "같은 메시지의 멀쩡한 갱신은 그대로 적용합니다"
    );

    let (store, srv, _file) = ddns_fixture();
    let cname = ApRecord::new(
        ApName::from_str("c1.skip.test").unwrap(),
        60,
        ApRData::Cname(ApName::from_str("t1.skip.test").unwrap()),
    );
    assert_eq!(
        srv.handle(&ddns_update(vec![cname]), &tcp)
            .unwrap()
            .header
            .rcode,
        ResponseCode::NoError.0
    );
    let resp = srv
        .handle(
            &ddns_update(vec![
                ApRecord::new(
                    ApName::from_str("c1.skip.test").unwrap(),
                    60,
                    ApRData::A(Ipv4Addr::new(10, 0, 0, 8)),
                ),
                ApRecord::new(
                    ApName::from_str("c1.skip.test").unwrap(),
                    60,
                    ApRData::Cname(ApName::from_str("t2.skip.test").unwrap()),
                ),
            ]),
            &tcp,
        )
        .unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
    assert_eq!(
        ddns_count(&store, "c1.skip.test", ApRt::A),
        0,
        "CNAME 이 있는 이름에는 다른 종류를 넣지 않습니다"
    );
    let cnames = store.load().zones()[0]
        .query(&ApName::from_str("c1.skip.test").unwrap(), ApRt::CNAME)
        .answers
        .iter()
        .filter_map(|r| match &r.rdata {
            ApRData::Cname(target) => Some(target.to_ascii_lower()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        cnames,
        vec!["t2.skip.test".to_string()],
        "CNAME 은 하나만 둘 수 있어 새 값이 이전 값을 대체합니다"
    );

    let (store, srv, _file) = ddns_fixture();
    let drop_ns = |owner: &str, target: &str| ApRecord {
        name: ApName::from_str(owner).unwrap(),
        rtype: ApRt::NS,
        class: DnsClass(254),
        ttl: 0,
        rdata: ApRData::Ns(ApName::from_str(target).unwrap()),
    };
    assert_eq!(
        srv.handle(
            &ddns_update(vec![drop_ns("skip.test", "ns.skip.test")]),
            &tcp
        )
        .unwrap()
        .header
        .rcode,
        ResponseCode::NoError.0,
        "정점의 마지막 NS 삭제는 건너뛰되 실패로 답하지 않습니다"
    );
    assert_eq!(
        ddns_count(&store, "skip.test", ApRt::NS),
        1,
        "정점에 권한 서버가 하나도 없는 영역을 만들지 않습니다"
    );

    assert_eq!(
        srv.handle(
            &ddns_update(vec![drop_ns("sub.skip.test", "ns.sub.skip.test")]),
            &tcp
        )
        .unwrap()
        .header
        .rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(
        store.load().zones()[0]
            .query(&ApName::from_str("sub.skip.test").unwrap(), ApRt::NS)
            .answers
            .len(),
        0,
        "위임의 마지막 NS 는 지워야 위임을 걷을 수 있습니다"
    );

    let (store, srv, _file) = ddns_fixture();
    let wks = |bitmap: u8| ApRecord {
        name: ApName::from_str("wks.skip.test").unwrap(),
        rtype: ApRt(11),
        class: DnsClass::IN,
        ttl: 60,
        rdata: ApRData::Unknown(11, vec![10, 0, 0, 7, 6, 0, 0, 0, bitmap]),
    };
    assert_eq!(
        srv.handle(&ddns_update(vec![wks(0x02)]), &tcp)
            .unwrap()
            .header
            .rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(
        srv.handle(&ddns_update(vec![wks(0x04)]), &tcp)
            .unwrap()
            .header
            .rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(
        ddns_count(&store, "wks.skip.test", ApRt(11)),
        1,
        "주소와 프로토콜이 같은 WKS 는 하나만 둘 수 있어 덧붙지 않습니다"
    );
}

#[test]
/// RFC 2136 treats only the zone count and ZTYPE as format errors, and answers NOTAUTH when ZCLASS
/// differs from the zone this server serves; FORMERR would make the requester think its message was
/// broken when it picked the wrong server. Prerequisites check TTL before zone scope, per the RFC
/// 2136 pseudocode.
fn ddns_reports_a_foreign_zone_class_as_notauth() {
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let (store, srv, _file) = ddns_fixture();

    let mut foreign = ddns_update(vec![ApRecord::new(
        ApName::from_str("x.skip.test").unwrap(),
        60,
        ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
    )]);
    foreign.questions[0].qclass = DnsClass(3);
    assert_eq!(
        srv.handle(&foreign, &tcp).unwrap().header.rcode,
        9,
        "이 서버가 맡지 않은 클래스의 영역은 NOTAUTH 입니다"
    );
    assert_eq!(
        ddns_count(&store, "x.skip.test", ApRt::A),
        0,
        "다른 클래스의 요청으로 IN 영역을 고치지 않습니다"
    );

    let outside = |ttl: u32| {
        let mut m = ddns_update(vec![]);
        m.answers.push(ApRecord {
            name: ApName::from_str("x.other.test").unwrap(),
            rtype: ApRt::A,
            class: DnsClass(255),
            ttl,
            rdata: ApRData::Unknown(ApRt::A.0, vec![]),
        });
        m
    };
    assert_eq!(
        srv.handle(&outside(0), &tcp).unwrap().header.rcode,
        10,
        "영역 밖 선행조건은 NOTZONE 입니다"
    );
    assert_eq!(
        srv.handle(&outside(300), &tcp).unwrap().header.rcode,
        ResponseCode::FormErr.0,
        "TTL 을 영역 범위보다 먼저 보므로 둘 다 어긋나면 FORMERR 입니다"
    );
}

#[test]
/// RFC 2136 ignores only an SOA replacement that goes backward, and when an update sets the serial
/// itself, the server must not bump it again. Comparison uses RFC 1982 serial arithmetic.
fn ddns_keeps_an_explicit_soa_serial() {
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let soa_add = |serial: u32| {
        let soa = onetdns_proto::Soa {
            mname: ApName::from_str("ns.skip.test").unwrap(),
            rname: ApName::from_str("admin.skip.test").unwrap(),
            serial,
            refresh: 300,
            retry: 60,
            expire: 86400,
            minimum: 60,
        };
        ApRecord::new(
            ApName::from_str("skip.test").unwrap(),
            300,
            ApRData::Soa(Box::new(soa)),
        )
    };

    let (store, srv, _file) = ddns_fixture();
    assert_eq!(
        srv.handle(&ddns_update(vec![soa_add(500)]), &tcp)
            .unwrap()
            .header
            .rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(
        store.load().zones()[0].soa().serial,
        500,
        "갱신이 지정한 일련번호 위에 서버가 또 올리지 않습니다"
    );

    let (store, srv, _file) = ddns_fixture();
    assert_eq!(
        srv.handle(
            &ddns_update(vec![
                soa_add(500),
                ApRecord::new(
                    ApName::from_str("fresh.skip.test").unwrap(),
                    60,
                    ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
                ),
            ]),
            &tcp
        )
        .unwrap()
        .header
        .rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(
        store.load().zones()[0].soa().serial,
        500,
        "다른 변경이 함께 와도 지정한 일련번호를 씁니다"
    );

    let (store, srv, _file) = ddns_fixture();
    assert_eq!(
        srv.handle(&ddns_update(vec![soa_add(1)]), &tcp)
            .unwrap()
            .header
            .rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(
        store.load().zones()[0].soa().serial,
        10,
        "되돌리는 일련번호는 조용히 무시합니다"
    );
}

#[test]
/// Records metrics like the structured path. Refusing the path whenever a recorder exists would
/// disable it in every deployment with a control plane, and answering without recording would drop
/// authoritative answers from the dashboard. The feature set is read once per query, even when the
/// ACL needs a client as in Personal mode.
fn authority_wire_answers_are_recorded_like_the_structured_path() {
    let zone_text = "$ORIGIN rec.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.9\n";
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(zone_text, "rec.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store.clone(),
    ));
    let (recorder, stats) = onetdns_control::channel(
        256,
        256,
        0,
        onetdns_control::RecorderOpts {
            querylog: true,
            anonymize: false,
            ignored: Vec::new(),
            stats_retention_secs: 0,
        },
        onetdns_control::PersistOpts::default(),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::new(
            vec!["127.0.0.0/8".parse().unwrap()],
            vec![],
            false,
        )),
        vec![],
        authority,
        60,
    )
    .with_recorder(Some(recorder))
    .with_authority_wire_path(Some(store), true);

    let mut output = onetdns_proto::Writer::with_limit(1232);
    let arrived = Instant::now();
    std::thread::sleep(Duration::from_millis(20));
    for (name, expected) in [
        ("www.rec.test", ResponseCode::NoError),
        ("nope.rec.test", ResponseCode::NXDomain),
    ] {
        let request = Message::query(0x1234, ApName::from_str(name).unwrap(), RecordType::A);
        output.clear();
        server.features.take_test_loads();
        assert_eq!(
            server.handle_udp_wire(&request.try_encode().unwrap(), &ctx(), &mut output, arrived),
            onetdns_runtime::WireDisposition::Respond,
            "{name}은 무할당 경로가 맡아야 합니다"
        );
        assert_eq!(
            Message::parse(&output.buf).unwrap().header.rcode,
            expected.0
        );
        assert_eq!(
            server.features.take_test_loads(),
            1,
            "무할당 경로가 질의 하나에 기능 세트를 한 번만 읽어야 합니다"
        );
    }

    for _ in 0..200 {
        if stats.metrics.snapshot().total >= 2 && stats.recent(8).len() >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let snapshot = stats.metrics.snapshot();
    assert_eq!(
        snapshot.total, 2,
        "무할당 경로로 답한 질의가 지표에 남지 않았습니다"
    );
    assert!(
        snapshot.avg_latency_ms >= 20.0,
        "무할당 경로가 받은 시각부터 잰 처리시간을 평균에 넣지 않았습니다: {}",
        snapshot.avg_latency_ms
    );
    let recent = stats.recent(8);
    assert_eq!(recent.len(), 2, "무할당 경로의 질의 기록이 없습니다");
    for event in recent {
        assert!(
            event.latency_us >= 20_000,
            "무할당 경로의 질의 기록에 처리시간이 없습니다: {} us",
            event.latency_us
        );
    }
}

#[test]
/// The recursive resolver asks upstream with DO set either way, to hold signatures for clients that
/// want them; sending them to clients that did not ask only grows the response toward truncation.
/// DNSKEY and DS stay, since clients ask for them directly.
fn dnssec_records_go_only_to_clients_that_asked_for_them() {
    let name = ApName::from_str("signed.example").unwrap();
    let signed_response = || {
        let mut response = Message::query(1, name.clone(), ApRt::A);
        response.header.response = true;
        for (rtype, section) in [
            (ApRt::A, 0usize),
            (ApRt::RRSIG, 0),
            (ApRt::DNSKEY, 0),
            (ApRt::NSEC, 1),
            (ApRt::RRSIG, 1),
            (ApRt::DS, 1),
        ] {
            let record = ApRecord::new(
                name.clone(),
                60,
                ApRData::Unknown(rtype.0, vec![1, 2, 3, 4]),
            );
            let mut record = record;
            record.rtype = rtype;
            if section == 0 {
                response.answers.push(record);
            } else {
                response.authorities.push(record);
            }
        }
        response
    };
    let count = |message: &Message, rtype: ApRt| {
        message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .filter(|record| record.rtype == rtype)
            .count()
    };

    let mut plain_request = Message::query(1, name.clone(), ApRt::A);
    plain_request.additionals.push(
        Edns::default()
            .try_to_record()
            .expect("OPT를 만들 수 있어야 합니다"),
    );
    assert!(!wants_dnssec(&plain_request));
    let mut plain = signed_response();
    strip_dnssec_unless_requested(&plain_request, &mut plain);
    assert_eq!(count(&plain, ApRt::RRSIG), 0, "서명을 걷어내지 않았습니다");
    assert_eq!(
        count(&plain, ApRt::NSEC),
        0,
        "부재 증명을 걷어내지 않았습니다"
    );
    assert_eq!(count(&plain, ApRt::A), 1, "답까지 걷어냈습니다");
    assert_eq!(
        count(&plain, ApRt::DNSKEY),
        1,
        "직접 물을 수 있는 종류를 걷어냈습니다"
    );
    assert_eq!(
        count(&plain, ApRt::DS),
        1,
        "직접 물을 수 있는 종류를 걷어냈습니다"
    );

    // Control: a DO client gets them, so stripping cannot be unconditional.
    let mut do_request = Message::query(1, name.clone(), ApRt::A);
    let mut edns = Edns::default();
    edns.dnssec_ok = true;
    do_request
        .additionals
        .push(edns.try_to_record().expect("OPT를 만들 수 있어야 합니다"));
    assert!(wants_dnssec(&do_request));
    let mut asked = signed_response();
    strip_dnssec_unless_requested(&do_request, &mut asked);
    assert_eq!(
        count(&asked, ApRt::RRSIG),
        2,
        "물어본 쪽의 서명을 걷어냈습니다"
    );
    assert_eq!(
        count(&asked, ApRt::NSEC),
        1,
        "물어본 쪽의 증명을 걷어냈습니다"
    );
}

#[test]
/// RFC 6891 makes both MUST. Without it the peer assumes no EDNS and drops to 512 bytes, losing
/// room for cookies, NSID, padding, and EDE; adding one to a plain request makes old clients reject
/// the response.
fn edns_request_gets_an_opt_back_and_a_plain_one_does_not() {
    let srv = server("");
    let ctx = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Udp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let name = ApName::from_str("allowed.test").unwrap();

    let mut with_edns = Message::query(1, name.clone(), ApRt::A);
    with_edns
        .additionals
        .push(Edns::default().try_to_record().unwrap());
    let response = srv.handle(&with_edns, &ctx).expect("응답이 없습니다");
    let opt = response.opt().expect("EDNS 질의인데 응답에 OPT가 없습니다");
    let echoed = Edns::from_record(opt).expect("OPT를 읽지 못했습니다");
    assert_eq!(echoed.version, 0, "응답 OPT의 버전 번호는 0이어야 합니다");
    assert!(
        echoed.udp_payload >= 512,
        "이 서버의 UDP 크기를 알려야 합니다: {}",
        echoed.udp_payload
    );

    let plain = Message::query(2, name, ApRt::A);
    let response = srv.handle(&plain, &ctx).expect("응답이 없습니다");
    assert!(
        response.opt().is_none(),
        "EDNS 없는 질의에 OPT를 붙이면 안 됩니다"
    );
}

#[test]
/// RFC 9619 forbids QDCOUNT above 1 for opcode 0, and the response is opcode 0 too, so echoing the
/// question section would break the same rule. BIND clears it here as well.
fn a_multi_question_query_gets_formerr_without_echoing_it() {
    let srv = server("");
    let ctx = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Udp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };

    let mut request = Message::query(1, ApName::from_str("a.example.com").unwrap(), ApRt::A);
    let second = request.questions[0].clone();
    request.questions.push(second);

    let response = srv.handle(&request, &ctx).expect("응답이 없습니다");
    assert_eq!(
        response.header.rcode,
        ResponseCode::FormErr.0,
        "질문이 둘이면 FORMERR입니다"
    );
    assert!(
        response.questions.is_empty(),
        "1보다 큰 QDCOUNT를 그대로 돌려주면 응답이 같은 규칙을 어깁니다"
    );

    // A query with no question takes the same branch, so clearing must be harmless.
    let mut empty = Message::default();
    empty.header.id = 7;
    let response = srv.handle(&empty, &ctx).expect("응답이 없습니다");
    assert_eq!(response.header.rcode, ResponseCode::FormErr.0);
    assert!(response.questions.is_empty());
}

#[test]
/// FORMERR means the request is broken, so the sender fixes and resends it. An unknown opcode means
/// the request is fine but this server cannot do it, and diagnostics need to tell the two apart.
fn unimplemented_opcodes_answer_not_implemented() {
    let srv = server("");
    let ctx = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Udp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };

    for opcode in [1u8, 2, 3, 6, 15] {
        let mut request = Message::query(1, ApName::from_str("example.com").unwrap(), ApRt::A);
        request.header.opcode = opcode;
        let response = srv.handle(&request, &ctx).expect("응답이 없습니다");
        assert_eq!(
            response.header.rcode,
            ResponseCode::NotImp.0,
            "opcode {opcode}에 NOTIMP가 아닌 답을 냈습니다"
        );
        assert_eq!(
            response.header.opcode, opcode,
            "opcode {opcode}를 그대로 되돌려야 합니다"
        );
    }

    let empty = Message::default();
    assert_eq!(
        srv.handle(&empty, &ctx)
            .expect("응답이 없습니다")
            .header
            .rcode,
        ResponseCode::FormErr.0,
        "질문이 없는 QUERY는 FORMERR로 남아야 합니다"
    );
}

#[test]
fn special_opcodes_require_exactly_one_well_formed_zone_question() {
    let srv = server("");
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let zone_question = onetdns_proto::Question {
        name: ApName::from_str("example.com").unwrap(),
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    };

    let mut update = Message::default();
    update.header.opcode = 5;
    update.questions = vec![zone_question.clone(), zone_question.clone()];
    assert_eq!(
        srv.handle(&update, &tcp).unwrap().header.rcode,
        ResponseCode::FormErr.0
    );

    let mut notify = Message::default();
    notify.header.opcode = 4;
    notify.questions.push(onetdns_proto::Question {
        qtype: ApRt::A,
        ..zone_question.clone()
    });
    assert_eq!(
        srv.handle(&notify, &tcp).unwrap().header.rcode,
        ResponseCode::FormErr.0
    );

    let mut axfr = Message::query(1, zone_question.name.clone(), ApRt(252));
    axfr.questions.push(zone_question);
    let responses = srv.handle_multi(&axfr, &tcp).unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].header.rcode, ResponseCode::FormErr.0);
}

#[test]
fn notify_uses_the_secondary_specific_tsig_identity() {
    use onetdns_dnssec::tsig;

    let origin = ApName::from_str("signed-secondary.test").unwrap();
    let key = tsig::TsigKey::new(
        ApName::from_str("notify-key.test").unwrap(),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let kick = Arc::new(NotifyKick::default());
    let srv = server("")
        .with_tsig(vec![key.clone()], false)
        .with_notify_secondaries(
            vec![(
                origin.clone(),
                "127.0.0.1".parse().unwrap(),
                Some(key.name.clone()),
            )],
            kick.clone(),
        );
    let mut request = Message::default();
    request.header.id = 0x5453;
    request.header.opcode = 4;
    request.header.authoritative = true;
    request.questions.push(onetdns_proto::Question {
        name: origin,
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    });
    let unsigned_context = RequestCtx {
        src: "127.0.0.1:53000".parse().unwrap(),
        transport: RtTransport::Do53Udp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    assert_eq!(
        srv.handle(&request, &unsigned_context)
            .expect("unsigned refusal")
            .header
            .rcode,
        ResponseCode::Refused.0
    );
    assert!(kick.wait_take(Duration::ZERO).is_empty());

    let request_mac = tsig::sign_message(&mut request, &key, now_unix(), None).unwrap();
    let wire = request.try_encode().unwrap();
    let signed_context = RequestCtx {
        raw: Some(&wire),
        ..unsigned_context
    };
    let response = srv.handle(&request, &signed_context).expect("signed ACK");
    assert_eq!(response.header.rcode, ResponseCode::NoError.0);
    tsig::verify_message(&response, &key, now_unix(), Some(&request_mac))
        .expect("NOTIFY ACK TSIG 검증");
    assert!(kick
        .wait_take(Duration::ZERO)
        .contains("signed-secondary.test"));
}

#[test]
fn ixfr_returns_incremental_after_ddns() {
    let zone_text = "$ORIGIN ix.test.\n$TTL 300\n@ IN SOA ns1 admin 10 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nold IN A 10.0.0.5\nkeep1 IN A 10.0.0.11\nkeep2 IN A 10.0.0.12\nkeep3 IN A 10.0.0.13\nkeep4 IN A 10.0.0.14\nkeep5 IN A 10.0.0.15\nkeep6 IN A 10.0.0.16\nkeep7 IN A 10.0.0.17\nkeep8 IN A 10.0.0.18\n";
    let (file, zone) = UpdateZoneFile::new(zone_text, "ix.test");
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(zone);
    let store = Arc::new(ArcSwap::new(Arc::new(zs)));
    let notified = Arc::new(std::sync::Mutex::new(Vec::new()));
    let notified_sink = notified.clone();
    let srv = server("")
        .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
        .with_ddns(
            vec!["127.0.0.0/8".parse().unwrap()],
            false,
            vec![file.target.clone()],
        )
        .with_update_notify(Arc::new(move |origin, serial| {
            notified_sink
                .lock_recover()
                .push((origin.to_ascii_lower(), serial));
        }));
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };

    let mut up = Message::default();
    up.header.opcode = 5;
    up.questions = vec![onetdns_proto::Question {
        name: ApName::from_str("ix.test").unwrap(),
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    }];
    up.authorities.push(ApRecord::new(
        ApName::from_str("new.ix.test").unwrap(),
        120,
        ApRData::A(Ipv4Addr::new(10, 0, 0, 9)),
    ));
    assert_eq!(
        srv.handle(&up, &tcp).unwrap().header.rcode,
        ResponseCode::NoError.0
    );
    assert_eq!(
        *notified.lock_recover(),
        vec![("ix.test".to_string(), 11)],
        "실제 변경을 적용한 DDNS 경로도 NOTIFY를 발행해야 함"
    );

    let mut ixfr = Message::query(5, ApName::from_str("ix.test").unwrap(), ApRt(251));
    ixfr.authorities.push(ApRecord {
        name: ApName::from_str("ix.test").unwrap(),
        rtype: ApRt::SOA,
        class: DnsClass::IN,
        ttl: 300,
        rdata: ApRData::soa(onetdns_proto::Soa {
            mname: ApName::from_str("ns1.ix.test").unwrap(),
            rname: ApName::from_str("admin.ix.test").unwrap(),
            serial: 10,
            refresh: 300,
            retry: 60,
            expire: 86400,
            minimum: 60,
        }),
    });
    let resp = srv.handle(&ixfr, &tcp).unwrap();

    let soas = resp.answers.iter().filter(|r| r.rtype == ApRt::SOA).count();
    assert_eq!(soas, 4, "증분 SOA 경계 4개(전 영역 AXFR 아님)");
    assert!(
        resp.answers
            .iter()
            .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 9))),
        "추가분 new A 포함"
    );

    assert!(
        !resp
            .answers
            .iter()
            .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 5))),
        "미변경 레코드(old)는 증분에 없습니다"
    );

    let mut ixfr0 = ixfr.clone();
    if let ApRData::Soa(s) = &mut ixfr0.authorities[0].rdata {
        s.serial = 1;
    }
    let resp = srv.handle(&ixfr0, &tcp).unwrap();
    assert!(
        resp.answers
            .iter()
            .any(|r| r.rdata == ApRData::A(Ipv4Addr::new(10, 0, 0, 5))),
        "미보유 serial → 전 영역 폴백(old 포함)"
    );

    let mut malformed = ixfr.clone();
    malformed.authorities[0].name = ApName::from_str("other.test").unwrap();
    assert_eq!(
        srv.handle(&malformed, &tcp).unwrap().header.rcode,
        ResponseCode::FormErr.0
    );

    let udp = RequestCtx {
        transport: RtTransport::Do53Udp,
        ..tcp
    };
    let stale = srv.handle(&ixfr, &udp).unwrap();
    assert!(stale.header.truncated, "오래된 UDP IXFR은 TCP 재시도 지시");
    assert_eq!(stale.answers.len(), 1);

    let mut current = ixfr;
    if let ApRData::Soa(soa) = &mut current.authorities[0].rdata {
        soa.serial = 11;
    }
    let current = srv.handle(&current, &udp).unwrap();
    assert!(!current.header.truncated);
    assert_eq!(current.answers.len(), 1, "최신 client에는 SOA 하나만 반환");

    let missing = Message::query(7, ApName::from_str("missing.test").unwrap(), ApRt(252));
    let tcp = RequestCtx {
        transport: RtTransport::Do53Tcp,
        ..udp
    };
    assert_eq!(
        srv.handle(&missing, &tcp).unwrap().header.rcode,
        9,
        "미보유 zone XFR은 timeout이 아니라 NOTAUTH"
    );
}

#[test]
fn chaos_id_version_respects_hide_flags() {
    let mut feat = NativeFeatures::default();
    feat.server_identity = b"onetdns".to_vec();
    feat.server_version = b"onetdns".to_vec();
    let srv_open = server("").with_features(feat.clone());
    let ch = |name: &str| {
        let mut m = Message::query(7, ApName::from_str(name).unwrap(), ApRt::TXT);
        m.questions[0].qclass = DnsClass(3);
        m
    };
    let resp = srv_open.handle(&ch("version.server"), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
    assert!(
        resp.answers.iter().any(|r| r.rtype == RecordType::TXT),
        "version.server TXT 응답"
    );

    let mut hidden = feat.clone();
    hidden.hide_identity = true;
    hidden.hide_version = true;
    let srv_hidden = server("").with_features(hidden);
    assert_eq!(
        srv_hidden
            .handle(&ch("version.server"), &ctx())
            .unwrap()
            .header
            .rcode,
        ResponseCode::Refused.0,
        "hide_version → REFUSED"
    );
    assert_eq!(
        srv_hidden
            .handle(&ch("id.server"), &ctx())
            .unwrap()
            .header
            .rcode,
        ResponseCode::Refused.0,
        "hide_identity → REFUSED"
    );
}

#[test]
fn per_client_upstream_match_prefers_specific_resolver() {
    let default = mock_upstream();
    let specific = mock_upstream();
    let s = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![default],
            Duration::from_secs(2),
        ))),
        60,
    )
    .with_client_upstreams(vec![ClientUpstream::new(
        vec!["127.0.0.1/32".parse().unwrap()],
        vec![],
        vec![specific.to_string()],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![specific],
            Duration::from_secs(2),
        ))),
    )]);
    update_features(&s, |features| features.rrset_roundrobin = false);
    let resp = s.handle(&q("client-route.test"), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
    assert_eq!(resp.answers.len(), 1);
}

#[test]
fn allowed_forwards_to_upstream() {
    let s = server("||blocked.test^\n");
    let resp = s.handle(&q("allowed.test"), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        ApRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(7, 7, 7, 7)),
        _ => panic!("A 기대"),
    }
}

#[test]
fn blocked_returns_nxdomain() {
    let s = server("||blocked.test^\n");
    let resp = s.handle(&q("blocked.test"), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0);
    assert!(resp.answers.is_empty());
}

#[test]
/// The query log shows which subscription blocked from this value and picks the allow button from
/// it. Rules added directly, outside any list, must record no list.
fn filter_block_records_the_subscription_list() {
    let lines = vec!["||listed.test^".to_string()];
    let subscriptions = [onetdns_filter::SubscriptionSource {
        name: "https://lists.example/ads.txt",
        rules: onetdns_filter::SubscriptionRules::Lines(&lines),
    }];
    let parts = onetdns_filter::load_parts_with_subscriptions(
        &[] as &[&str],
        &[] as &[&str],
        &subscriptions,
        &["||typed.test^"],
        &[],
    )
    .expect("구독 규칙");
    let (recorder, stats) = onetdns_control::channel(
        64,
        64,
        3600,
        onetdns_control::RecorderOpts {
            querylog: true,
            anonymize: false,
            ignored: vec![],
            stats_retention_secs: 3600,
        },
        onetdns_control::PersistOpts::default(),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::new(
            parts,
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream()],
            Duration::from_secs(2),
        ))),
        60,
    )
    .with_recorder(Some(recorder));

    for (name, list) in [
        ("listed.test", "https://lists.example/ads.txt"),
        ("typed.test", ""),
    ] {
        let response = server.handle(&q(name), &ctx()).unwrap();
        assert_eq!(response.header.rcode, ResponseCode::NXDomain.0, "{name}");
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let event = loop {
            let found = stats.recent(8).into_iter().find(|event| {
                event.name.as_ref().map(ApName::to_string).as_deref() == Some(&format!("{name}."))
            });
            if let Some(event) = found {
                break event;
            }
            assert!(std::time::Instant::now() < deadline, "{name}: 기록이 없다");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(event.action, "blocked", "{name}");
        assert_eq!(event.rule, name, "{name}");
        assert_eq!(event.list, list, "{name}");
    }
}

#[test]
fn rewrite_uses_local_ttl_instead_of_block_ttl() {
    let mut parts = onetdns_filter::EngineParts::default();
    parts.block.add_exact("blocked.test");
    parts.rewrites.add_exact(
        "rewrite.test",
        RewriteTarget::ip(Ipv4Addr::new(192, 0, 2, 17).into()),
    );
    let engine = onetdns_filter::BlockEngine::new(parts, BlockResponse::NxDomain);
    let block_ttl = Arc::new(AtomicU32::new(60));
    let local_ttl = Arc::new(AtomicU32::new(17));
    let s = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![mock_upstream()],
            Duration::from_secs(2),
        ))),
        60,
    )
    .with_ttl_sources(block_ttl.clone(), local_ttl.clone());

    let response = s.handle(&q("rewrite.test"), &ctx()).unwrap();
    assert_eq!(response.answers[0].ttl, 17);
    local_ttl.store(23, Ordering::Release);
    let response = s.handle(&q("rewrite.test"), &ctx()).unwrap();
    assert_eq!(response.answers[0].ttl, 23, "로컬 TTL 핫 변경");

    let blocked = s.handle(&q("blocked.test"), &ctx()).unwrap();
    assert_eq!(blocked.authorities[0].ttl, 60, "차단 TTL은 독립 설정");
    block_ttl.store(29, Ordering::Release);
    let blocked = s.handle(&q("blocked.test"), &ctx()).unwrap();
    assert_eq!(blocked.authorities[0].ttl, 29, "차단 TTL 핫 변경");
}

#[test]
fn safe_search_cname_uses_local_ttl() {
    let s = server("");
    s.local_ttl.store(41, Ordering::Release);
    s.safe_search.store(true, Ordering::Release);

    let response = s.handle(&q("google.com"), &ctx()).unwrap();
    let cname = response
        .answers
        .iter()
        .find(|record| record.rtype == RecordType::CNAME)
        .expect("safe-search CNAME");
    assert_eq!(cname.ttl, 41);
}

#[test]
fn query_policy_block_uses_blocked_response_ttl() {
    let rules = onetdns_policy::RuleEngine::new(vec![onetdns_policy::Rule::new(
        onetdns_policy::Action::Block,
    )
    .with_suffixes(&["policy-block.test".to_string()])]);
    let s = server("").with_policy(Arc::new(GatedSwap::from_pointee(
        onetdns_policy::PolicyEngine::new(rules, vec![]),
    )));
    s.block_ttl.store(71, Ordering::Release);

    let response = s.handle(&q("policy-block.test"), &ctx()).unwrap();
    assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
    assert_eq!(negative_soa_ttl(&response), 71);
}

#[test]
/// A full ANY answer invites amplification. RFC 8482 lists only three ways to not answer and
/// otherwise requires the standard algorithm, so a synthesized HINFO is the specified form, not a
/// refusal.
///
/// Clients with DO set get the conventional answer: a signed zone would need RRSIGs, and a
/// synthesized record has none.
fn any_query_answers_with_the_minimal_hinfo() {
    let s = server("");
    let mut query = q("any.test");
    query.questions[0].qtype = RecordType::ANY;
    let resp = s.handle(&query, &ctx()).unwrap();

    assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
    assert!(!resp.header.truncated, "잘린 것이 아니라 이것이 답이다");
    assert_eq!(resp.answers.len(), 1, "RRSet 하나만 실는다");
    let answer = &resp.answers[0];
    assert_eq!(answer.rtype, RecordType(13), "HINFO");
    assert!(answer
        .name
        .eq_ignore_case(&ApName::from_str("any.test").unwrap()));
    match &answer.rdata {
        ApRData::Unknown(13, wire) => {
            assert_eq!(
                wire.as_slice(),
                b"\x07RFC8482\x00",
                "CPU는 RFC8482, OS는 빈 문자열"
            );
        }
        other => panic!("HINFO wire를 기대했습니다: {other:?}"),
    }

    // With DO, no synthesis; no any.test zone exists here, so it takes the conventional path.
    let mut signed_query = query.clone();
    signed_query.additionals.push(ApRecord {
        name: ApName::root(),
        rtype: ApRt::OPT,
        class: DnsClass(1232),
        ttl: 0x0000_8000,
        rdata: ApRData::Unknown(ApRt::OPT.0, Vec::new()),
    });
    let resp = s.handle(&signed_query, &ctx()).unwrap();
    assert!(
        resp.answers
            .iter()
            .all(|record| record.rtype != RecordType(13)),
        "DO를 설정한 질의에는 합성 HINFO를 주지 않는다"
    );
}

#[test]
fn view_local_overrides_for_matching_client() {
    let s = server("").with_views(vec![NativeView {
        nets: vec!["127.0.0.1/32".parse().unwrap()],
        ids: vec![],
        local_a: vec![(
            ApName::from_str("printer.lan").unwrap().canonical_key(),
            Ipv4Addr::new(192, 168, 1, 5),
        )],
        local_aaaa: vec![],
    }]);
    s.local_ttl.store(27, Ordering::Release);

    let resp = s.handle(&q("printer.lan"), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
    assert_eq!(resp.answers[0].ttl, 27);
    match &resp.answers[0].rdata {
        ApRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 5)),
        other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
    }
    s.local_ttl.store(33, Ordering::Release);
    assert_eq!(
        s.handle(&q("printer.lan"), &ctx()).unwrap().answers[0].ttl,
        33,
        "뷰도 로컬 TTL 핫 변경을 공유"
    );

    let resp = s.handle(&q("other.example"), &ctx()).unwrap();
    match &resp.answers[0].rdata {
        ApRData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(7, 7, 7, 7)),
        other => panic!("A 레코드를 예상했지만 실제 값은 {other:?}입니다"),
    }
}

#[test]
fn view_local_key_preserves_raw_name_octets() {
    let configured = ApName::from_str("�").unwrap();
    let s = server("").with_views(vec![NativeView {
        nets: vec!["127.0.0.1/32".parse().unwrap()],
        ids: vec![],
        local_a: vec![(configured.canonical_key(), Ipv4Addr::new(192, 168, 1, 5))],
        local_aaaa: vec![],
    }]);

    let configured_query = Message::query(1, configured, RecordType::A);
    let configured_response = s.handle(&configured_query, &ctx()).unwrap();
    assert!(matches!(
        configured_response.answers[0].rdata,
        ApRData::A(ip) if ip == Ipv4Addr::new(192, 168, 1, 5)
    ));

    let raw_query = Message::query(
        2,
        ApName::from_labels(vec![vec![0xff]]).unwrap(),
        RecordType::A,
    );
    let raw_response = s.handle(&raw_query, &ctx()).unwrap();
    assert!(matches!(
        raw_response.answers[0].rdata,
        ApRData::A(ip) if ip == Ipv4Addr::new(7, 7, 7, 7)
    ));
}

#[test]
fn acl_deny_refuses() {
    let mut s = server("");
    s.acl = Arc::new(IpAcl::new(
        vec![],
        vec!["127.0.0.1/32".parse().unwrap()],
        true,
    ));
    let resp = s.handle(&q("x.test"), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::Refused.0);
}

/// Drops 127.0.0.1, the test context's source.
fn dropping_loopback() -> Arc<IpAcl> {
    Arc::new(IpAcl::allow_all().with_drop(vec!["127.0.0.1/32".parse().unwrap()]))
}

#[test]
/// Drop wins even over the allow list. UPDATE is admitted elsewhere than ordinary queries, and an
/// IPv4-mapped IPv6 address must become IPv4 before the check, so both are covered.
fn acl_drop_answers_nothing_even_to_allowed_clients() {
    let mut s = server("");
    s.acl = Arc::new(
        IpAcl::new(vec!["127.0.0.0/8".parse().unwrap()], vec![], false)
            .with_drop(vec!["127.0.0.1/32".parse().unwrap()]),
    );
    assert!(
        s.handle(&q("x.test"), &ctx()).is_none(),
        "버린 클라이언트에게 답했습니다"
    );
    let mapped = RequestCtx {
        src: "[::ffff:127.0.0.1]:5555".parse().unwrap(),
        ..ctx()
    };
    assert!(
        s.handle(&q("x.test"), &mapped).is_none(),
        "IPv6 형태로 들어온 IPv4 주소를 놓쳤습니다"
    );

    let mut update = Message::default();
    update.header.id = 0x77;
    update.header.opcode = 5;
    update.questions = vec![onetdns_proto::Question {
        name: ApName::from_str("example.com").unwrap(),
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    }];
    assert!(
        s.handle(&update, &ctx()).is_none(),
        "버린 클라이언트의 UPDATE 에 답했습니다"
    );
}

#[test]
/// The path sending stored answers checks access control again; filtering only refusals would leak
/// drop as allow.
fn acl_drop_withholds_cached_wire_answers() {
    use onetdns_runtime::WireDisposition;

    let (backend, cache) = fixed_answer_cache();
    let mut server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        cache,
    )));
    let request = Message::query(0x0101, ApName::from_str("ok.example").unwrap(), ApRt::A);
    let packet = request.try_encode().unwrap();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut out, Instant::now()),
        WireDisposition::Respond,
        "대조군이 무효입니다. 허용된 클라이언트의 답이 담기지 않았습니다"
    );

    server.acl = dropping_loopback();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_ne!(
        server.handle_udp_wire(&packet, &ctx(), &mut out, Instant::now()),
        WireDisposition::Respond,
        "담아 둔 답을 버린 클라이언트에게 내보냈습니다"
    );
    assert!(
        server.handle(&request, &ctx()).is_none(),
        "빠른 경로가 넘긴 질의에 느린 경로가 답했습니다"
    );
}

#[test]
fn acl_drop_withholds_authoritative_wire_answers() {
    let zone_text = "$ORIGIN fast.test.\n$TTL 300\n@ IN SOA ns admin 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\nwww IN A 192.0.2.9\n";
    let mut zones = onetdns_authority::ZoneStore::new();
    zones.add(onetdns_authority::parse_zone(zone_text, "fast.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zones)));
    let authority = Arc::new(crate::layers::AuthorityLayer::new(
        Arc::new(FixedAnswer),
        store.clone(),
    ));
    let mut server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        authority,
        60,
    )
    .with_authority_wire_path(Some(store), true);
    let request = Message::query(
        0x4567,
        ApName::from_str("www.fast.test").unwrap(),
        RecordType::A,
    );
    let packet = request.try_encode().unwrap();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond,
        "대조군이 무효입니다. 허용된 클라이언트에게 권한 영역의 답이 나가지 않았습니다"
    );

    server.acl = dropping_loopback();
    let mut output = onetdns_proto::Writer::with_limit(1232);
    assert_ne!(
        server.handle_udp_wire(&packet, &ctx(), &mut output, Instant::now()),
        onetdns_runtime::WireDisposition::Respond,
        "권한 영역의 답을 버린 클라이언트에게 내보냈습니다"
    );
    assert!(
        server.handle(&request, &ctx()).is_none(),
        "빠른 경로가 넘긴 질의에 느린 경로가 답했습니다"
    );
}

#[test]
fn acl_drop_withholds_zone_transfers() {
    let mut srv = server("").with_xfr(big_zone_store(10), vec!["127.0.0.0/8".parse().unwrap()]);
    srv.acl = dropping_loopback();
    let tcp = RequestCtx {
        transport: RtTransport::Do53Tcp,
        ..ctx()
    };
    let axfr = Message::query(7, ApName::from_str("big.test").unwrap(), ApRt(252));
    let mut emitted = 0usize;
    let mut writer = onetdns_proto::Writer::new();
    let preencoded = srv.handle_preencoded_stream(&axfr, &tcp, &mut writer, &mut |_| {
        emitted += 1;
        true
    });
    assert_ne!(
        preencoded,
        Some(true),
        "버린 클라이언트의 영역 전송을 미리 인코딩한 경로가 처리했습니다"
    );
    let completed = srv.handle_stream(&axfr, &tcp, &mut |_| {
        emitted += 1;
        true
    });
    assert!(
        !completed,
        "버린 클라이언트의 영역 전송을 끝까지 보냈습니다"
    );
    assert_eq!(
        emitted, 0,
        "버린 클라이언트에게 영역 전송 응답을 보냈습니다"
    );
}

#[test]
/// Clients on the deny list were chosen for refusal by the operator and keep getting REFUSED.
/// UPDATE and the FORMERR for unparsable queries go out elsewhere than ordinary queries, so both
/// are covered.
fn acl_unlisted_drop_answers_nothing_outside_the_allow_list() {
    let acl = |allow: &str, deny: &str, drop_unlisted: bool| {
        Arc::new(
            IpAcl::new(
                vec![allow.parse().unwrap()],
                vec![deny.parse().unwrap()],
                false,
            )
            .with_unlisted_drop(drop_unlisted),
        )
    };
    let mut s = server("");
    s.acl = acl("10.0.0.0/8", "192.0.2.0/24", false);
    let refused = s
        .handle(&q("x.test"), &ctx())
        .expect("대조군이 무효입니다: 끄면 거부 응답이 나가야 합니다");
    assert_eq!(refused.header.rcode, ResponseCode::Refused.0);

    s.acl = acl("10.0.0.0/8", "192.0.2.0/24", true);
    assert!(
        s.handle(&q("x.test"), &ctx()).is_none(),
        "규칙에 없는 클라이언트에게 답했습니다"
    );
    let mut update = Message::default();
    update.header.id = 0x78;
    update.header.opcode = 5;
    update.questions = vec![onetdns_proto::Question {
        name: ApName::from_str("example.com").unwrap(),
        qtype: ApRt::SOA,
        qclass: DnsClass::IN,
    }];
    assert!(
        s.handle(&update, &ctx()).is_none(),
        "규칙에 없는 클라이언트의 UPDATE 에 답했습니다"
    );
    // The header claims two questions but holds one, so the parser rejects it.
    let mut packet = vec![0u8; 12];
    packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    packet[4..6].copy_from_slice(&2u16.to_be_bytes());
    packet.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1]);
    assert!(Message::parse(&packet).is_err());
    assert!(
        s.handle_unparsable(&packet, &ctx()).is_none(),
        "규칙에 없는 클라이언트에게 FORMERR 를 보냈습니다"
    );

    s.acl = acl("127.0.0.0/8", "192.0.2.0/24", true);
    let answered = s
        .handle(&q("x.test"), &ctx())
        .expect("허용 목록의 클라이언트를 버렸습니다");
    assert_eq!(answered.header.rcode, ResponseCode::NoError.0);

    s.acl = acl("10.0.0.0/8", "127.0.0.0/8", true);
    let denied = s
        .handle(&q("x.test"), &ctx())
        .expect("거부 목록의 클라이언트를 버렸습니다");
    assert_eq!(denied.header.rcode, ResponseCode::Refused.0);
}

#[test]
/// With ID rules, the address alone cannot decide a drop, since dropping before the handshake would
/// also cut off clients with allowed IDs; the gate after the query is read drops by ID. TSIG errors
/// go out before admission, so they are covered too.
fn acl_unlisted_drop_with_client_ids_checks_the_id_before_any_answer() {
    use onetdns_dnssec::tsig;

    let secret = b"0123456789abcdef0123456789abcdef".to_vec();
    let known = tsig::TsigKey::new(ApName::from_str("query-key").unwrap(), secret.clone()).unwrap();
    let unknown = tsig::TsigKey::new(ApName::from_str("unknown-key").unwrap(), secret).unwrap();
    let mut signed = q("signed.test");
    tsig::sign_message(&mut signed, &unknown, now_unix(), None).unwrap();
    let wire = signed.try_encode().unwrap();
    let anonymous = RequestCtx {
        raw: Some(&wire),
        ..ctx()
    };
    let acl = |drop_unlisted: bool| {
        Arc::new(
            IpAcl::new(vec![], vec![], false)
                .with_ids(vec!["vip".into()], vec![])
                .with_unlisted_drop(drop_unlisted),
        )
    };

    let mut s = server("").with_tsig(vec![known], false);
    s.acl = acl(false);
    let error = s
        .handle(&signed, &anonymous)
        .expect("대조군이 무효입니다: TSIG 오류가 입장 단계보다 먼저 나가야 합니다");
    assert_eq!(error.header.rcode, 9);

    s.acl = acl(true);
    assert!(
        !s.drops_source("127.0.0.1".parse().unwrap()),
        "ID 를 보기 전에 주소만 보고 버렸습니다"
    );
    assert!(
        s.handle(&signed, &anonymous).is_none(),
        "규칙에 없는 클라이언트에게 TSIG 오류를 보냈습니다"
    );
    assert!(
        s.handle(&q("x.test"), &ctx()).is_none(),
        "규칙에 없는 클라이언트에게 답했습니다"
    );
    let vip = RequestCtx {
        transport: RtTransport::DoT,
        client_id: Some("vip".into()),
        authenticated: true,
        ..ctx()
    };
    let answered = s
        .handle(&q("x.test"), &vip)
        .expect("허용된 ID 를 가진 클라이언트를 버렸습니다");
    assert_eq!(answered.header.rcode, ResponseCode::NoError.0);
}

fn querylog_recorder() -> (onetdns_control::Recorder, onetdns_control::Stats) {
    onetdns_control::channel(
        64,
        64,
        3600,
        onetdns_control::RecorderOpts {
            querylog: true,
            anonymize: false,
            ignored: vec![],
            stats_retention_secs: 3600,
        },
        onetdns_control::PersistOpts::default(),
    )
}

/// Events are collected on another thread.
fn wait_for_event(stats: &onetdns_control::Stats, name: &str) -> onetdns_control::QueryEvent {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let found = stats
            .recent(8)
            .into_iter()
            .find(|event| event.name.as_ref().map(ApName::to_string).as_deref() == Some(name));
        if let Some(event) = found {
            return event;
        }
        assert!(Instant::now() < deadline, "{name} 의 질의 기록이 없습니다");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
/// The same name under an ordinary block rule must get an answer, which shows the silence comes
/// from the rule. A log entry with the block response's code would make the operator believe the
/// client received that answer.
fn filter_noresponse_answers_nothing_and_logs_the_drop() {
    let blocked = server("||quiet.test^\n")
        .handle(&q("quiet.test"), &ctx())
        .expect("대조군이 무효입니다: 일반 차단 규칙은 답해야 합니다");
    assert_eq!(blocked.header.rcode, ResponseCode::NXDomain.0);

    let (recorder, stats) = querylog_recorder();
    let s = server("||quiet.test^$dnsrewrite=NORESPONSE\n").with_recorder(Some(recorder));
    assert!(
        s.handle(&q("quiet.test"), &ctx()).is_none(),
        "무응답 규칙에 걸린 이름에 답했습니다"
    );
    assert!(
        s.handle(&q("www.quiet.test"), &ctx()).is_none(),
        "무응답 규칙에 걸린 이름의 하위 이름에 답했습니다"
    );
    let other = s
        .handle(&q("other.test"), &ctx())
        .expect("규칙에 없는 이름에 답하지 않았습니다");
    assert_eq!(other.header.rcode, ResponseCode::NoError.0);

    let event = wait_for_event(&stats, "quiet.test.");
    assert_eq!(event.action, "blocked");
    assert_eq!(event.rcode, "DROPPED");
    assert_eq!(event.reason, "FILTER_BLOCKED");
    assert_eq!(event.rule, "quiet.test");
}

#[test]
/// A query of a type the rule has no records for gets none, so only the detail shows the target.
fn rewrite_log_names_the_rule_target() {
    let (recorder, stats) = querylog_recorder();
    let s = server("||rw.test^$dnsrewrite=192.0.2.7\n").with_recorder(Some(recorder));
    s.handle(&q("a.rw.test"), &ctx()).unwrap();
    let aaaa = Message::query(
        0x1234,
        ApName::from_str("aaaa.rw.test").unwrap(),
        RecordType::AAAA,
    );
    let response = s.handle(&aaaa, &ctx()).unwrap();
    assert_eq!(response.header.rcode, ResponseCode::NoError.0);
    assert!(response.answers.is_empty());

    for (name, answers) in [("a.rw.test.", "A 192.0.2.7"), ("aaaa.rw.test.", "")] {
        let event = wait_for_event(&stats, name);
        assert_eq!(event.action, "rewritten", "{name}");
        assert_eq!(event.answers, answers, "{name}");
        assert_eq!(event.detail, "A 192.0.2.7", "{name}");
    }
}

#[test]
/// Answering after the alias would let one alias extract an answer for a name meant to get none.
fn cname_to_a_noresponse_name_answers_nothing() {
    let with_rules = |rules: &str| {
        NativeServer::new(
            shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
                rules,
                "",
                BlockResponse::NxDomain,
            ))),
            Arc::new(IpAcl::allow_all()),
            vec![],
            Arc::new(ShapedAnswer),
            60,
        )
    };
    let blocked = with_rules("||target.example^\n")
        .handle(&q("alias.example"), &ctx())
        .expect("대조군이 무효입니다: 별칭 뒤의 일반 차단은 차단 응답으로 답해야 합니다");
    assert_eq!(blocked.header.rcode, ResponseCode::NXDomain.0);

    let (recorder, stats) = querylog_recorder();
    let s = with_rules("||target.example^$dnsrewrite=NORESPONSE\n").with_recorder(Some(recorder));
    assert!(
        s.handle(&q("alias.example"), &ctx()).is_none(),
        "별칭 뒤에 숨은 무응답 이름에 답했습니다"
    );
    let event = wait_for_event(&stats, "alias.example.");
    assert_eq!(event.action, "blocked");
    assert_eq!(event.rcode, "DROPPED");
}

#[test]
/// If the fast path kept answering, the hidden name would be answered until the stored answer
/// expires. Falling back or dropping are both fine, as long as nothing goes out.
fn wire_fast_path_stops_answering_a_cached_name_that_gets_noresponse() {
    use onetdns_runtime::WireDisposition;

    let server = shaped_server(true);
    let request = Message::query(0x0606, ApName::from_str("multi.example").unwrap(), ApRt::A);
    let wire = request.try_encode().unwrap();
    for attempt in ["담는 질의", "담아 둔 답을 쓰는 질의"] {
        let mut out = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.handle_udp_wire(&wire, &ctx(), &mut out, Instant::now()),
            WireDisposition::Respond,
            "대조군이 무효입니다: {attempt}가 고속 경로로 답하지 않았습니다"
        );
    }

    server.filter.store(Arc::new(onetdns_filter::build_from_str(
        "||multi.example^$dnsrewrite=NORESPONSE",
        "",
        BlockResponse::NxDomain,
    )));
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_ne!(
        server.handle_udp_wire(&wire, &ctx(), &mut out, Instant::now()),
        WireDisposition::Respond,
        "무응답 규칙을 건 이름에 고속 경로가 답했습니다"
    );
    assert!(
        server.handle(&request, &ctx()).is_none(),
        "무응답 규칙을 건 이름에 보통 경로가 답했습니다"
    );
}

#[test]
fn block_aaaa_returns_nodata() {
    let s = server("");
    update_features(&s, |features| features.block_aaaa = true);
    let mut query = q("ipv6.test");
    query.questions[0].qtype = RecordType::AAAA;
    let resp = s.handle(&query, &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NoError.0);
    assert!(resp.answers.is_empty(), "AAAA 비활성 → NODATA");
    assert!(
        resp.authorities
            .iter()
            .any(|record| matches!(&record.rdata, ApRData::Soa(_))),
        "정책 NODATA에는 음성 캐시용 SOA가 필요"
    );
}

#[test]
fn response_hook_verdict_blocks_final_answer() {
    const HOOK_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $p))
          (func (export "evaluate") (param i32 i32) (result i32) (i32.const 0))
          (func (export "on_response") (param $ptr i32) (param $len i32) (result i32)
            (local $addr0 i32)
            (if (result i32)
                (i32.eqz (i32.load8_u (i32.add (local.get $ptr) (i32.const 6))))
              (then (i32.const 0))
              (else
                (local.set $addr0
                  (i32.add (i32.add (local.get $ptr) (i32.const 10))
                           (i32.load16_u (i32.add (local.get $ptr) (i32.const 8)))))
                (if (result i32)
                    (i32.eq (i32.load8_u (i32.add (local.get $addr0) (i32.const 1)))
                            (i32.const 7))
                  (then (i32.const 2))
                  (else (i32.const 0)))))))
    "#;
    let wasm = wat::parse_str(HOOK_WAT).unwrap();
    let plugin = onetdns_policy::WasmPolicy::from_wasm(&wasm).unwrap();
    let engine =
        onetdns_policy::PolicyEngine::new(onetdns_policy::RuleEngine::new(vec![]), vec![plugin]);
    let s = server("");
    s.policy.store(Arc::new(engine));

    let mut req = q("hooked.example.");
    req.additionals
        .push(onetdns_proto::Edns::default().try_to_record().unwrap());
    let resp = s.handle(&req, &ctx()).expect("응답");
    assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0, "verdict 차단");
    assert_eq!(negative_soa_ttl(&resp), 60);
    let ede = resp
        .opt()
        .and_then(onetdns_proto::Edns::from_record)
        .and_then(|e| e.ede())
        .map(|(code, _)| code);
    assert_eq!(ede, Some(onetdns_proto::ede_code::FILTERED));
}

#[test]
fn rebind_protection_strips_private() {
    let s = server("");
    update_features(&s, |features| features.rebind_protection = true);
    let resp = s.handle(&q("pub.test"), &ctx()).unwrap();
    assert_eq!(resp.answers.len(), 1, "공인 IP는 보존");
}

#[test]
fn response_address_blocks_use_blocked_response_ttl() {
    let bogus = server("");
    bogus.block_ttl.store(73, Ordering::Release);
    update_features(&bogus, |features| {
        features.bogus_nxdomain = vec!["7.7.7.7/32".parse().unwrap()]
    });
    let response = bogus.handle(&q("bogus-address.test"), &ctx()).unwrap();
    assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
    assert_eq!(negative_soa_ttl(&response), 73);

    let denied = server("");
    denied.block_ttl.store(79, Ordering::Release);
    update_features(&denied, |features| {
        features.recurse_deny_answers = vec!["7.7.7.7/32".parse().unwrap()]
    });
    let response = denied.handle(&q("denied-address.test"), &ctx()).unwrap();
    assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
    assert_eq!(negative_soa_ttl(&response), 79);
}

#[cfg(unix)]
#[test]
fn reactor_lane_defers_dropped_clients_to_sync_path() {
    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(
            vec!["127.0.0.1:5399".parse().unwrap()],
            std::time::Duration::from_millis(50),
        )
        .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all().with_drop(vec!["127.0.0.1/32".parse().unwrap()])),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache, 32);
    let packet = Message::query(0x7, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.reactor_submit(&packet, &ctx(), &mut out, Instant::now()),
        onetdns_runtime::ReactorDisposition::Fallback,
        "버린 클라이언트의 질의를 리액터가 맡았습니다"
    );
}

#[cfg(unix)]
#[test]
fn reactor_lane_caps_pending_clients() {
    use onetdns_runtime::ReactorDisposition;

    // The thread-local lane may hold leftovers from an earlier test.
    crate::native::lane::LANE.with(|slot| *slot.borrow_mut() = None);

    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(
            vec!["127.0.0.1:5399".parse().unwrap()],
            std::time::Duration::from_millis(50),
        )
        .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache, 32);

    let packet = Message::query(0x7, ApName::from_str("slow.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let submit = || {
        let mut out = onetdns_proto::Writer::with_limit(1232);
        server.reactor_submit(&packet, &ctx(), &mut out, std::time::Instant::now())
    };

    // Repeated submits of one name take one slot, and the rest become singleflight followers that
    // pile up in the pending map while nothing pumps. The lane accepts them up to the cap.
    for _ in 0..crate::native::lane::MAX_LANE_PENDING {
        assert_eq!(submit(), ReactorDisposition::Submitted);
    }
    crate::native::lane::LANE.with(|slot| {
        assert_eq!(
            slot.borrow().as_ref().unwrap().clients.len(),
            crate::native::lane::MAX_LANE_PENDING,
            "대기 맵은 상한까지 찬다"
        );
    });

    assert_eq!(submit(), ReactorDisposition::Fallback);
    crate::native::lane::LANE.with(|slot| {
        assert_eq!(
            slot.borrow().as_ref().unwrap().clients.len(),
            crate::native::lane::MAX_LANE_PENDING,
            "넘친 질의는 대기 맵을 늘리지 않는다"
        );
    });

    // Leaving 1024 behind would block the lane in later tests.
    crate::native::lane::LANE.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(unix)]
#[test]
/// Otherwise answers would go out as if the feature did not exist. Which settings close the gate is
/// checked by the config key table tests.
fn reactor_lane_defers_closed_gate_and_ns_rpz_to_sync_path() {
    use onetdns_runtime::ReactorDisposition;

    let lane_server = |engine: onetdns_filter::BlockEngine| {
        let (backend, cache) = lane_backend_and_cache();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(
                vec!["127.0.0.1:5399".parse().unwrap()],
                std::time::Duration::from_millis(50),
            )
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_reactor_lane(recursor, cache, 32)
    };
    let plain = || onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
    let packet = Message::query(0x7, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let submit = |server: &NativeServer| {
        let mut out = onetdns_proto::Writer::with_limit(1232);
        server.reactor_submit(&packet, &ctx(), &mut out, std::time::Instant::now())
    };

    assert_eq!(
        submit(&lane_server(plain())),
        ReactorDisposition::Submitted,
        "필터가 없으면 레인에 제출된다"
    );

    let closed = lane_server(plain());
    update_features(&closed, |features| features.lanes.reactor = false);
    assert_eq!(submit(&closed), ReactorDisposition::Fallback);

    let mut parts = onetdns_filter::EngineParts::default();
    parts.rpz_nsdname.push(
        onetdns_filter::RpzNameRule::new(
            "evil-ns.example",
            FilterVerdict::Block(BlockResponse::NxDomain),
        )
        .unwrap(),
    );
    assert_eq!(
        submit(&lane_server(onetdns_filter::BlockEngine::new(
            parts,
            BlockResponse::NxDomain
        ))),
        ReactorDisposition::Fallback
    );
}

#[cfg(unix)]
#[test]
fn ddr_only_preempts_its_owner_in_the_reactor_lane() {
    use onetdns_runtime::ReactorDisposition;

    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(
            vec!["127.0.0.1:5399".parse().unwrap()],
            std::time::Duration::from_millis(50),
        )
        .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache, 32);
    update_features(&server, |features| features.ddr_enabled = true);

    let submit = |name: &str| {
        let packet = Message::query(7, ApName::from_str(name).unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut out = onetdns_proto::Writer::with_limit(1232);
        server.reactor_submit(&packet, &ctx(), &mut out, std::time::Instant::now())
    };
    assert_eq!(submit("_DNS.Resolver.ARPA"), ReactorDisposition::Fallback);
    assert_eq!(submit("ordinary.example"), ReactorDisposition::Submitted);
}

#[cfg(unix)]
#[test]
fn lenient_cookie_keeps_plain_reactor_and_defers_cookie_requests() {
    use onetdns_runtime::ReactorDisposition;

    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(
            vec!["127.0.0.1:5399".parse().unwrap()],
            std::time::Duration::from_millis(50),
        )
        .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache, 32);
    update_features(&server, |features| {
        features.cookies = CookiePolicy {
            keeper: Some(Arc::new(CookieKeeper::from_secret(&[3; 16]))),
            strict: false,
        };
    });

    let mut with_cookie = q("cookie-reactor.example");
    let mut edns = Edns::default();
    edns.options.push((OPT_COOKIE, vec![1; 8]));
    with_cookie.additionals.push(edns.try_to_record().unwrap());
    let submit = |request: &Message| {
        let packet = request.try_encode().unwrap();
        let mut out = onetdns_proto::Writer::with_limit(1232);
        server.reactor_submit(&packet, &ctx(), &mut out, Instant::now())
    };
    assert_eq!(
        submit(&with_cookie),
        ReactorDisposition::Fallback,
        "COOKIE 질의는 서버 쿠키를 발급하는 구조적 경로가 맡습니다"
    );
    assert_eq!(
        submit(&q("plain-reactor.example")),
        ReactorDisposition::Submitted,
        "쿠키 없는 질의는 lenient 때문에 콜드 경로를 잃지 않습니다"
    );
}

#[cfg(unix)]
#[test]
fn reactor_submit_charges_rate_limit_once_across_fallback() {
    use onetdns_runtime::ReactorDisposition;

    struct CountingLimiter(AtomicUsize);
    impl RateLimiter for CountingLimiter {
        fn check(&self, _client: &ClientInfo) -> RateDecision {
            self.0.fetch_add(1, Ordering::Relaxed);
            RateDecision::Permit
        }
    }

    let packet = Message::query(0x31, ApName::from_str("ok.example").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let build = |engine: onetdns_filter::BlockEngine, limiter: Arc<CountingLimiter>| {
        let (backend, cache) = lane_backend_and_cache();
        let recursor = Arc::new(
            onetdns_recurse::Recursor::new(
                vec!["127.0.0.1:5399".parse().unwrap()],
                std::time::Duration::from_millis(50),
            )
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
        );
        NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![limiter],
            backend,
            60,
        )
        .with_reactor_lane(recursor, cache, 32)
    };

    let mut parts = onetdns_filter::EngineParts::default();
    parts.rpz_nsdname.push(
        onetdns_filter::RpzNameRule::new(
            "evil-ns.example",
            FilterVerdict::Block(BlockResponse::NxDomain),
        )
        .unwrap(),
    );
    let falling = Arc::new(CountingLimiter(AtomicUsize::new(0)));
    let server = build(
        onetdns_filter::BlockEngine::new(parts, BlockResponse::NxDomain),
        falling.clone(),
    );
    let mut out = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.reactor_submit(&packet, &ctx(), &mut out, std::time::Instant::now()),
        ReactorDisposition::Fallback
    );
    assert_eq!(
        falling.0.load(Ordering::Relaxed),
        0,
        "동기 경로로 넘기는 질의는 레인에서 토큰을 소비하지 않아야 한다"
    );

    let taking = Arc::new(CountingLimiter(AtomicUsize::new(0)));
    let plain = build(
        onetdns_filter::build_from_str("", "", BlockResponse::NxDomain),
        taking.clone(),
    );
    let mut out2 = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        plain.reactor_submit(&packet, &ctx(), &mut out2, std::time::Instant::now()),
        ReactorDisposition::Submitted
    );
    assert_eq!(
        taking.0.load(Ordering::Relaxed),
        1,
        "떠맡을 때는 한 번 소비한다"
    );
}

#[cfg(unix)]
fn spawn_parity_authority() -> std::net::SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(req) = Message::parse(&buf[..n]) else {
                continue;
            };
            let Some(q) = req.questions.first().cloned() else {
                continue;
            };
            let mut resp = base_response(&req);
            resp.header.authoritative = true;
            resp.questions = vec![q.clone()];
            let soa = || {
                ApRecord::new(
                    ApName::root(),
                    60,
                    ApRData::soa(onetdns_proto::Soa {
                        mname: ApName::from_str("ns.").unwrap(),
                        rname: ApName::from_str("hostmaster.").unwrap(),
                        serial: 1,
                        refresh: 3600,
                        retry: 600,
                        expire: 86_400,
                        minimum: 60,
                    }),
                )
            };
            match q.name.to_ascii_lower().as_str() {
                "dead" => continue,

                "alias2" => resp.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::Cname(ApName::from_str("alias.").unwrap()),
                )),
                "nodata" => resp.authorities.push(soa()),
                "nx" => {
                    resp.header.rcode = ResponseCode::NXDomain.0;
                    resp.authorities.push(soa());
                }
                "alias" => resp.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::Cname(ApName::from_str("ok.").unwrap()),
                )),
                "extra" => {
                    resp.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    ));

                    resp.answers.push(ApRecord::new(
                        ApName::from_str("bank.").unwrap(),
                        60,
                        ApRData::A(Ipv4Addr::new(198, 51, 100, 66)),
                    ));
                    resp.authorities.push(ApRecord::new(
                        ApName::from_str("unrelated.").unwrap(),
                        60,
                        ApRData::Ns(ApName::from_str("ns.evil.").unwrap()),
                    ));
                    resp.additionals.push(ApRecord::new(
                        ApName::from_str("ns.evil.").unwrap(),
                        60,
                        ApRData::A(Ipv4Addr::new(198, 51, 100, 67)),
                    ));
                }
                "forgedad" => {
                    resp.header.authentic_data = true;
                    resp.answers.push(ApRecord::new(
                        q.name.clone(),
                        60,
                        ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
                    ));
                }
                _ => resp.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::A(Ipv4Addr::new(192, 0, 2, 1)),
                )),
            }
            let _ = sock.send_to(&resp.try_encode().unwrap(), from);
        }
    });
    addr
}

#[cfg(unix)]
fn parity_server_recording(
    authority: std::net::SocketAddr,
    with_lane: bool,
) -> (NativeServer, onetdns_control::Stats) {
    let (recorder, stats) = onetdns_control::channel(
        64,
        64,
        3600,
        onetdns_control::RecorderOpts {
            querylog: true,
            anonymize: false,
            ignored: vec![],
            stats_retention_secs: 3600,
        },
        onetdns_control::PersistOpts::default(),
    );
    let server = parity_server_with(authority, with_lane, Some(recorder.clone()));
    (server.with_recorder(Some(recorder)), stats)
}

#[cfg(unix)]
fn parity_server(authority: std::net::SocketAddr, with_lane: bool) -> NativeServer {
    parity_server_with(authority, with_lane, None)
}

#[cfg(unix)]
fn parity_server_with(
    authority: std::net::SocketAddr,
    with_lane: bool,
    recorder: Option<onetdns_control::Recorder>,
) -> NativeServer {
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let backend = Arc::new(NativeBackend::Recurse {
        recursor: recursor.clone(),
        ns_rpz: None,
        block_ttl: Arc::new(AtomicU32::new(60)),
        local_ttl: Arc::new(AtomicU32::new(60)),
    });
    let layer =
        crate::cache::CacheLayer::new(backend, 64, 1, 0, 86_400, 0, 86_400).with_recorder(recorder);
    let cache = layer.handle();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(layer),
        60,
    );
    if with_lane {
        server.with_reactor_lane(recursor, cache, 32)
    } else {
        server
    }
}

#[cfg(unix)]
fn lane_answer(server: &NativeServer, request: &Message) -> Message {
    use onetdns_runtime::ReactorDisposition;
    let packet = request.try_encode().expect("질의 인코딩");
    let mut w = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
        ReactorDisposition::Submitted,
        "레인이 받아야 대조가 의미 있다. Fallback이면 게이트가 막은 것"
    );
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while out.is_empty() && std::time::Instant::now() < deadline {
        let mut fds = Vec::new();
        let mut map = Vec::new();
        server.reactor_collect(&mut fds, &mut map);

        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        } else {
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
        }
        server.reactor_tick(std::time::Instant::now(), &mut out);
    }
    assert_eq!(out.len(), 1, "레인 응답이 정확히 하나 나와야 한다");
    Message::parse(&out[0].1).expect("레인 응답 파싱")
}

fn record_keys(records: &[ApRecord]) -> Vec<String> {
    let mut keys: Vec<String> = records
        .iter()
        .filter(|record| record.rtype != ApRt::OPT)
        .map(|record| {
            format!(
                "{}|{:?}|{:?}",
                record.name.to_ascii_lower(),
                record.rtype,
                record.rdata
            )
        })
        .collect();
    keys.sort();
    keys
}

#[cfg(unix)]
#[test]
/// Otherwise answers would depend on which path took the query.
fn reactor_lane_answers_match_the_sync_path() {
    let authority = spawn_parity_authority();
    for (name, qtype) in [
        ("ok.", ApRt::A),
        ("nodata.", ApRt::A),
        ("nx.", ApRt::A),
        ("alias.", ApRt::A),
        ("alias2.", ApRt::A),
        ("extra.", ApRt::A),
        ("forgedad.", ApRt::A),
        ("dead.", ApRt::A),
    ] {
        let mut request = Message::query(0x33, ApName::from_str(name).unwrap(), qtype);

        request
            .additionals
            .push(onetdns_proto::Edns::default().try_to_record().unwrap());
        let sync = parity_server(authority, false)
            .handle(&request, &ctx())
            .unwrap_or_else(|| panic!("{name}: 동기 응답이 없다"));
        let lane = lane_answer(&parity_server(authority, true), &request);

        assert_eq!(lane.header.rcode, sync.header.rcode, "{name}: rcode 불일치");
        assert_eq!(
            (
                lane.header.authentic_data,
                lane.header.authoritative,
                lane.header.truncated,
                lane.header.recursion_available,
            ),
            (
                sync.header.authentic_data,
                sync.header.authoritative,
                sync.header.truncated,
                sync.header.recursion_available,
            ),
            "{name}: 헤더 비트 불일치(AD/AA/TC/RA)"
        );
        assert_eq!(
            record_keys(&lane.answers),
            record_keys(&sync.answers),
            "{name}: 답변 구획 불일치"
        );
        if name == "alias2." {
            assert_eq!(lane.answers.len(), 3, "2홉 추적의 답 누적이 어긋났다");
        }
        assert_eq!(
            record_keys(&lane.authorities),
            record_keys(&sync.authorities),
            "{name}: 권한 구획 불일치"
        );
        assert_eq!(
            record_keys(&lane.additionals),
            record_keys(&sync.additionals),
            "{name}: 부가 구획 불일치"
        );

        let ede_of = |m: &Message| {
            m.opt()
                .and_then(onetdns_proto::Edns::from_record)
                .and_then(|e| e.ede())
                .map(|(code, _)| code)
        };
        assert_eq!(ede_of(&lane), ede_of(&sync), "{name}: EDE 불일치");
    }
}

#[cfg(unix)]
fn drain_recent(stats: &onetdns_control::Stats) -> Vec<onetdns_control::QueryEvent> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let recent = stats.recent(8);
        if !recent.is_empty() || std::time::Instant::now() >= deadline {
            return recent;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(unix)]
#[test]
fn reactor_lane_records_query_events_like_the_sync_path() {
    let authority = spawn_parity_authority();

    for qname in ["ok.", "dead."] {
        let request = Message::query(0x44, ApName::from_str(qname).unwrap(), ApRt::A);

        let (sync_server, sync_stats) = parity_server_recording(authority, false);
        sync_server.handle(&request, &ctx()).expect("동기 응답");
        let sync_events = drain_recent(&sync_stats);

        let (lane_server, lane_stats) = parity_server_recording(authority, true);
        lane_answer(&lane_server, &request);
        let lane_events = drain_recent(&lane_stats);

        assert_eq!(sync_events.len(), 1, "동기: 질의당 이벤트 하나");
        assert_eq!(
            lane_events.len(),
            1,
            "레인: 질의당 이벤트 하나여야 한다(0이면 대시보드가 비고, 2면 이중 계상)"
        );
        let (s, l) = (&sync_events[0], &lane_events[0]);
        assert_eq!(
            (
                l.action,
                l.name.as_ref().map(ApName::to_string),
                l.qtype.as_str(),
                l.rcode.as_str()
            ),
            (
                s.action,
                s.name.as_ref().map(ApName::to_string),
                s.qtype.as_str(),
                s.rcode.as_str()
            ),
            "레인 이벤트가 동기 경로와 다르다"
        );
        assert_eq!(l.answers, s.answers, "답변 요약 불일치");
        assert_eq!(
            (l.reason.as_str(), l.stage.as_str(), l.detail.as_str()),
            (s.reason.as_str(), s.stage.as_str(), s.detail.as_str()),
            "진단(사유·단계·상세) 불일치"
        );
        assert!(
            l.latency_us > 0,
            "레인 처리시간이 0이다. 떠맡은 시각이 아니라 완료 시각으로 쟀다"
        );

        assert!(
            sync_stats.metrics.snapshot().avg_latency_ms > 0.0,
            "동기 기준선이 지연을 안 남겼다면 대조가 공허하다"
        );
        assert!(
            lane_stats.metrics.snapshot().avg_latency_ms > 0.0,
            "레인이 지연 지표를 남기지 않았다"
        );

        assert_eq!(
            lane_stats.metrics.snapshot().cache_lookups,
            sync_stats.metrics.snapshot().cache_lookups,
            "캐시 조회 계상 불일치"
        );
        assert_eq!(
            lane_stats.metrics.snapshot().cache_hits,
            sync_stats.metrics.snapshot().cache_hits,
            "캐시 적중 계상 불일치"
        );
    }
}

#[cfg(unix)]
fn lane_backend_and_cache() -> (Arc<dyn Resolver>, crate::cache::CacheHandle) {
    let layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let handle = layer.handle();
    (Arc::new(layer), handle)
}

#[cfg(unix)]
fn spawn_truncating_authority() -> std::net::SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(req) = Message::parse(&buf[..n]) else {
                continue;
            };
            let Some(q) = req.questions.first().cloned() else {
                continue;
            };
            let mut resp = base_response(&req);
            resp.header.authoritative = true;
            resp.header.truncated = true;
            resp.questions = vec![q.clone()];
            resp.answers.push(ApRecord::new(
                q.name.clone(),
                60,
                ApRData::A(Ipv4Addr::new(192, 0, 2, 7)),
            ));
            let _ = sock.send_to(&resp.try_encode().unwrap(), from);
        }
    });
    addr
}

#[cfg(unix)]
fn spawn_mixed_truncating_authority() -> std::net::SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(req) = Message::parse(&buf[..n]) else {
                continue;
            };
            let Some(q) = req.questions.first().cloned() else {
                continue;
            };
            let mut resp = base_response(&req);
            resp.header.authoritative = true;
            resp.header.truncated = q.name.to_ascii_lower().starts_with("tc");
            resp.questions = vec![q.clone()];
            resp.answers.push(ApRecord::new(
                q.name.clone(),
                60,
                ApRData::A(Ipv4Addr::new(192, 0, 2, 7)),
            ));
            let _ = sock.send_to(&resp.try_encode().unwrap(), from);
        }
    });
    addr
}

#[cfg(unix)]
struct SlowAnswer(std::time::Duration);

#[cfg(unix)]
impl Resolver for SlowAnswer {
    fn resolve(&self, request: &Message) -> Option<Message> {
        std::thread::sleep(self.0);
        let mut response = base_response(request);
        let name = request.questions.first()?.name.clone();
        response.answers.push(ApRecord::new(
            name,
            60,
            ApRData::A(Ipv4Addr::new(9, 9, 9, 9)),
        ));
        Some(response)
    }
}

#[cfg(unix)]
#[test]
#[ignore = "꼬리 지연 프로브: cargo test -p onetdns --release -- --ignored --nocapture"]
/// One retried query must not delay those behind it.
fn probe_lane_retry_fallback_head_of_line_delay() {
    use onetdns_runtime::ReactorDisposition;

    const FALLBACK: std::time::Duration = std::time::Duration::from_millis(400);
    let authority = spawn_mixed_truncating_authority();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let layer =
        crate::cache::CacheLayer::new(Arc::new(SlowAnswer(FALLBACK)), 64, 1, 0, 86_400, 0, 0);
    let cache = layer.handle();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(layer),
        60,
    )
    .with_reactor_lane(recursor, cache, 32);

    let names = ["tc0.", "ok1.", "ok2.", "ok3.", "ok4."];
    let start = std::time::Instant::now();
    for name in names {
        let packet = Message::query(0x60, ApName::from_str(name).unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut w = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
            ReactorDisposition::Submitted,
            "{name}: 레인이 받아야 프로브가 성립한다"
        );
    }

    let mut done: Vec<(std::time::Duration, usize)> = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while done.len() < names.len() && std::time::Instant::now() < deadline {
        let mut fds = Vec::new();
        let mut map = Vec::new();
        server.reactor_collect(&mut fds, &mut map);
        let mut out = Vec::new();
        if !fds.is_empty() {
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 50) };
        }
        let now = std::time::Instant::now();
        server.reactor_pump(&fds, 0, &map, now, &mut out);
        server.reactor_tick(now, &mut out);
        for (_, wire) in &out {
            let parsed = Message::parse(wire).expect("응답 파싱");
            let is_fallback = parsed
                .answers
                .iter()
                .any(|record| matches!(record.rdata, ApRData::A(ip) if ip.octets()[0] == 9));
            done.push((start.elapsed(), usize::from(is_fallback)));
        }
    }

    assert_eq!(done.len(), names.len(), "전원 완료해야 한다");
    let lane_max = done
        .iter()
        .filter(|(_, fallback)| *fallback == 0)
        .map(|(at, _)| *at)
        .max()
        .expect("레인 응답이 있어야 한다");
    println!(
        "PROBE 동기 폴백 {:?} 동안 레인 질의 최대 지연 {:?} (완료 {}건)",
        FALLBACK,
        lane_max,
        done.len()
    );
    println!(
        "PROBE 인질 여부: 레인 최대 지연이 폴백 시간의 {:.0}%",
        lane_max.as_secs_f64() / FALLBACK.as_secs_f64() * 100.0
    );
}

#[cfg(unix)]
#[test]
/// Otherwise only that query would fail.
fn reactor_lane_retry_is_resolved_by_the_sync_chain_not_servfail() {
    use onetdns_runtime::ReactorDisposition;

    let authority = spawn_truncating_authority();
    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(500))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache, 32);

    let packet = Message::query(0x21, ApName::from_str("tcexample.").unwrap(), ApRt::A)
        .try_encode()
        .unwrap();
    let mut w = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
        ReactorDisposition::Submitted
    );

    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while out.is_empty() && std::time::Instant::now() < deadline {
        let mut fds = Vec::new();
        let mut map = Vec::new();
        server.reactor_collect(&mut fds, &mut map);

        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        } else {
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
        }
        server.reactor_tick(std::time::Instant::now(), &mut out);
    }

    assert_eq!(out.len(), 1, "레인이 응답을 냈다");
    let resp = Message::parse(&out[0].1).expect("응답 파싱");
    assert_eq!(
        resp.header.rcode,
        ResponseCode::NoError.0,
        "동기 체인이 풀어야 한다. SERVFAIL이면 레인이 절단 응답을 실패로 종결한 것"
    );
    assert!(
        resp.answers.iter().any(
            |record| matches!(record.rdata, ApRData::A(ip) if ip == Ipv4Addr::new(1, 2, 3, 4))
        ),
        "동기 체인의 답이 나와야 한다: {:?}",
        resp.answers
    );
}

#[cfg(unix)]
#[test]
/// Folding the fallback result into None would make a permanent failure look like a transport
/// failure, and the client would get a false network error reason.
fn reactor_lane_fallback_failure_keeps_its_reason() {
    use onetdns_runtime::ReactorDisposition;

    struct PermanentFailure;
    impl Resolver for PermanentFailure {
        fn resolve(&self, _req: &Message) -> Option<Message> {
            None
        }
        fn resolve_outcome(&self, _req: &Message) -> ResolveOutcome {
            ResolveOutcome::Failure(ResolveFailure::Permanent(Some(
                onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY,
            )))
        }
    }

    let authority = spawn_truncating_authority();
    let layer =
        crate::cache::CacheLayer::new(Arc::new(PermanentFailure), 64, 1, 0, 86_400, 0, 86_400);
    let cache = layer.handle();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(500))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(layer),
        60,
    )
    .with_reactor_lane(recursor, cache, 32);

    let mut request = Message::query(0x22, ApName::from_str("tcfail.").unwrap(), ApRt::A);
    request
        .additionals
        .push(onetdns_proto::Edns::default().try_to_record().unwrap());
    let packet = request.try_encode().unwrap();
    let mut w = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
        ReactorDisposition::Submitted
    );

    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while out.is_empty() && std::time::Instant::now() < deadline {
        let mut fds = Vec::new();
        let mut map = Vec::new();
        server.reactor_collect(&mut fds, &mut map);

        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        } else {
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
        }
        server.reactor_tick(std::time::Instant::now(), &mut out);
    }

    assert_eq!(out.len(), 1, "레인이 응답을 냈다");
    let resp = Message::parse(&out[0].1).expect("응답 파싱");
    assert_eq!(resp.header.rcode, ResponseCode::ServFail.0);
    let ede = resp
        .opt()
        .and_then(onetdns_proto::Edns::from_record)
        .and_then(|edns| edns.ede())
        .map(|(code, _)| code);
    assert_eq!(
        ede,
        Some(onetdns_proto::ede_code::NO_REACHABLE_AUTHORITY),
        "동기 체인이 알린 사유가 나가야 한다. 23이면 실패를 전송 실패로 뭉갠 것"
    );
}

#[cfg(unix)]
#[test]
/// The lane builds the answer under the config at submit and stores it separately afterward;
/// storing into a cache cleared in between would bring back an answer from the old config.
fn reactor_lane_answer_does_not_land_in_a_cache_cleared_after_submit() {
    use onetdns_runtime::ReactorDisposition;

    let authority = spawn_mixed_truncating_authority();
    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(500))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache.clone(), 32);

    let resolve = |name: &str, clear_after_submit: bool| {
        let request = Message::query(0x31, ApName::from_str(name).unwrap(), ApRt::A);
        let packet = request.try_encode().unwrap();
        let mut w = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
            ReactorDisposition::Submitted,
            "{name}: 레인이 받아야 확인할 수 있습니다"
        );
        if clear_after_submit {
            cache.clear();
        }
        assert_eq!(
            pump_lane_until_answered(&server).len(),
            1,
            "{name}: 레인이 답해야 합니다"
        );
        request
    };

    let kept = resolve("okkept.", false);
    assert!(
        cache.lane_response(&kept).is_some(),
        "비우지 않았으면 레인의 답이 담겨야 합니다"
    );
    let dropped = resolve("okdropped.", true);
    assert!(
        cache.lane_response(&dropped).is_none(),
        "맡긴 뒤에 비운 캐시에 레인의 답이 담겼습니다"
    );
}

#[cfg(unix)]
/// Empty after 5 seconds without one.
fn pump_lane_until_answered(server: &NativeServer) -> Vec<(std::net::SocketAddr, Vec<u8>)> {
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while out.is_empty() && std::time::Instant::now() < deadline {
        let mut fds = Vec::new();
        let mut map = Vec::new();
        server.reactor_collect(&mut fds, &mut map);
        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        } else {
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
        }
        server.reactor_tick(std::time::Instant::now(), &mut out);
    }
    out
}

#[cfg(unix)]
#[test]
/// The lane picks the answer with the feature set at submit; tagging it with the set at completion
/// would serve an answer chosen under old conditions as a cache hit under the new config.
fn reactor_lane_answer_carries_the_generation_it_was_submitted_under() {
    use onetdns_runtime::{ReactorDisposition, WireDisposition};

    let authority = spawn_mixed_truncating_authority();
    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(500))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::BlockEngine::empty(
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        cache.clone(),
    )))
    .with_reactor_lane(recursor, cache, 32);

    let resolve = |name: &str, reload_after_submit: bool| {
        let packet = Message::query(0x32, ApName::from_str(name).unwrap(), ApRt::A)
            .try_encode()
            .unwrap();
        let mut w = onetdns_proto::Writer::with_limit(1232);
        assert_eq!(
            server.reactor_submit(&packet, &ctx(), &mut w, Instant::now()),
            ReactorDisposition::Submitted,
            "{name}: 레인이 받아야 확인할 수 있습니다"
        );
        if reload_after_submit {
            update_features(&server, |features| features.wire_epoch += 1);
        }
        assert_eq!(
            pump_lane_until_answered(&server).len(),
            1,
            "{name}: 레인이 답해야 합니다"
        );
        let mut hit = onetdns_proto::Writer::with_limit(1232);
        server.handle_udp_wire_hit(&packet, &ctx(), &mut hit, Instant::now())
    };

    assert_eq!(
        resolve("okfresh.", false),
        WireDisposition::Respond,
        "같은 세대 안에서 끝난 레인의 답은 wire 항목으로 나가야 합니다"
    );
    assert_eq!(
        resolve("okstale.", true),
        WireDisposition::Fallback,
        "맡긴 뒤 세대가 바뀌었는데 레인의 답이 새 세대의 wire 항목으로 나갔습니다"
    );
}

#[cfg(unix)]
fn spawn_cloaking_authority() -> std::net::SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("mock bind");
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let tracker = ApName::from_str("tracker.evil.example").unwrap();
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(req) = Message::parse(&buf[..n]) else {
                continue;
            };
            let Some(q) = req.questions.first().cloned() else {
                continue;
            };
            let mut resp = base_response(&req);
            resp.header.authoritative = true;
            resp.questions = vec![q.clone()];
            if q.name.eq_ignore_case(&tracker) {
                resp.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::A(Ipv4Addr::new(203, 0, 113, 9)),
                ));
            } else {
                resp.answers.push(ApRecord::new(
                    q.name.clone(),
                    60,
                    ApRData::Cname(tracker.clone()),
                ));
            }
            let _ = sock.send_to(&resp.try_encode().unwrap(), from);
        }
    });
    addr
}

#[cfg(unix)]
#[test]
fn reactor_lane_applies_cname_uncloaking_to_resolved_answers() {
    use onetdns_runtime::ReactorDisposition;

    let authority = spawn_cloaking_authority();
    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "||tracker.evil.example^",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache, 32);

    let packet = Message::query(
        0x11,
        ApName::from_str("cdn.publisher.example").unwrap(),
        ApRt::A,
    )
    .try_encode()
    .unwrap();
    let mut w = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
        ReactorDisposition::Submitted,
        "질의 이름 자체는 Allow라 레인에 제출된다"
    );

    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while out.is_empty() && std::time::Instant::now() < deadline {
        let mut fds = Vec::new();
        let mut map = Vec::new();
        server.reactor_collect(&mut fds, &mut map);

        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        } else {
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
        }
        server.reactor_tick(std::time::Instant::now(), &mut out);
    }

    assert_eq!(out.len(), 1, "레인이 응답을 냈다");
    let resp = Message::parse(&out[0].1).expect("응답 파싱");
    assert_eq!(
        resp.header.rcode,
        ResponseCode::NXDomain.0,
        "클로킹 CNAME 대상이 차단이면 답이 아니라 차단 응답이 나가야 한다"
    );
}

#[cfg(unix)]
#[test]
/// The lane accepts by the query name alone, so the hidden name shows only in the answer. No
/// response alone cannot be told from one still in progress, so completion is checked through the
/// log.
fn reactor_lane_answers_nothing_when_a_cname_target_has_noresponse() {
    use onetdns_runtime::ReactorDisposition;

    let authority = spawn_cloaking_authority();
    let (backend, cache) = lane_backend_and_cache();
    let recursor = Arc::new(
        onetdns_recurse::Recursor::new(vec![authority], std::time::Duration::from_millis(800))
            .with_server_acl(vec![], vec!["127.0.0.0/8".parse().unwrap()]),
    );
    let (recorder, stats) = querylog_recorder();
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(onetdns_filter::build_from_str(
            "||tracker.evil.example^$dnsrewrite=NORESPONSE",
            "",
            BlockResponse::NxDomain,
        ))),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_reactor_lane(recursor, cache, 32)
    .with_recorder(Some(recorder));

    let packet = Message::query(
        0x12,
        ApName::from_str("cdn.publisher.example").unwrap(),
        ApRt::A,
    )
    .try_encode()
    .unwrap();
    let mut w = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.reactor_submit(&packet, &ctx(), &mut w, std::time::Instant::now()),
        ReactorDisposition::Submitted,
        "대조군이 무효입니다: 질의 이름 자체는 허용이라 레인에 제출돼야 합니다"
    );

    let dropped = || {
        stats
            .recent(8)
            .iter()
            .any(|event| event.action == "blocked" && event.rcode == "DROPPED")
    };
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while out.is_empty() && !dropped() && std::time::Instant::now() < deadline {
        let mut fds = Vec::new();
        let mut map = Vec::new();
        server.reactor_collect(&mut fds, &mut map);

        if fds.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(2));
        } else {
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
            server.reactor_pump(&fds, 0, &map, std::time::Instant::now(), &mut out);
        }
        server.reactor_tick(std::time::Instant::now(), &mut out);
    }

    assert!(
        out.is_empty(),
        "별칭 뒤에 숨은 무응답 이름에 레인이 답했습니다"
    );
    assert!(dropped(), "레인이 무응답 처리를 마치지 않았습니다");
}

fn dns64_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut m = base_response(&req);
                m.header.rcode = ResponseCode::NoError.0;
                if let Some(q) = req.questions.first() {
                    if q.qtype == RecordType::A {
                        m.answers.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                        ));
                    } else {
                        m.authorities.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::soa(onetdns_proto::Soa {
                                mname: ApName::from_str("ns.v4only.test").unwrap(),
                                rname: ApName::from_str("hostmaster.v4only.test").unwrap(),
                                serial: 1,
                                refresh: 3600,
                                retry: 600,
                                expire: 86400,
                                minimum: 60,
                            }),
                        ));
                    }
                }
                let _ = sock.send_to(&m.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

#[test]
fn dns64_synthesizes_aaaa() {
    let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
    let s = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![dns64_upstream()],
            Duration::from_secs(2),
        ))),
        60,
    );

    let mut prefix = [0u8; 16];
    prefix[0] = 0x00;
    prefix[1] = 0x64;
    prefix[2] = 0xff;
    prefix[3] = 0x9b;
    update_features(&s, |features| features.dns64_prefix = Some(prefix));
    let mut query = q("v4only.test");
    query.questions[0].qtype = RecordType::AAAA;
    let resp = s.handle(&query, &ctx()).unwrap();

    assert_eq!(resp.answers.len(), 1);
    match &resp.answers[0].rdata {
        ApRData::Aaaa(ip) => {
            let o = ip.octets();
            assert_eq!(&o[0..4], &[0x00, 0x64, 0xff, 0x9b]);
            assert_eq!(&o[12..16], &[7, 7, 7, 7]);
        }
        _ => panic!("합성 AAAA 기대"),
    }
}

fn dns64_servfail_aaaa_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            if let Ok(req) = Message::parse(&buf[..n]) {
                let mut m = base_response(&req);
                if let Some(q) = req.questions.first() {
                    if q.qtype == RecordType::A {
                        m.header.rcode = ResponseCode::NoError.0;
                        m.answers.push(ApRecord::new(
                            q.name.clone(),
                            60,
                            ApRData::A(Ipv4Addr::new(7, 7, 7, 7)),
                        ));
                    } else {
                        m.header.rcode = ResponseCode::ServFail.0;
                    }
                }
                let _ = sock.send_to(&m.try_encode().unwrap(), from);
            }
        }
    });
    addr
}

#[test]
fn dns64_does_not_mask_servfail() {
    let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
    let s = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(NativeBackend::Forward(Forwarder::new(
            vec![dns64_servfail_aaaa_upstream()],
            Duration::from_secs(2),
        ))),
        60,
    );

    let mut prefix = [0u8; 16];
    prefix[0] = 0x00;
    prefix[1] = 0x64;
    prefix[2] = 0xff;
    prefix[3] = 0x9b;
    update_features(&s, |features| features.dns64_prefix = Some(prefix));
    let mut query = q("v4only.test");
    query.questions[0].qtype = RecordType::AAAA;
    let resp = s.handle(&query, &ctx()).unwrap();

    assert_eq!(
        resp.header.rcode,
        ResponseCode::ServFail.0,
        "상류 SERVFAIL 은 보존돼야 한다"
    );
    assert!(
        resp.answers.is_empty(),
        "SERVFAIL 에 AAAA 를 합성하면 안 된다"
    );
}

#[test]
fn nsid_attached_to_response() {
    let s = server("");
    update_features(&s, |features| features.nsid = Some(b"onetdns".to_vec()));

    let mut req = q("allowed.test");
    let mut edns = Edns::default();
    edns.options.push((OPT_NSID, Vec::new()));
    req.additionals.push(edns.try_to_record().unwrap());
    let resp = s.handle(&req, &ctx()).unwrap();
    let opt = resp.opt().expect("OPT 부착");
    let edns = Edns::from_record(opt).unwrap();
    assert!(edns
        .options
        .iter()
        .any(|(c, v)| *c == OPT_NSID && v == b"onetdns"));
}

#[test]
fn domain_needed_and_bogus_priv_predicates() {
    assert!(is_single_label(&ApName::from_str("wpad").unwrap()));
    assert!(!is_single_label(&ApName::from_str("foo.bar").unwrap()));

    assert!(is_private_reverse(
        &ApName::from_str("1.0.168.192.in-addr.arpa").unwrap()
    ));
    assert!(is_private_reverse(
        &ApName::from_str("5.10.in-addr.arpa").unwrap()
    ));
    assert!(is_private_reverse(
        &ApName::from_str("20.172.in-addr.arpa").unwrap()
    ));
    assert!(!is_private_reverse(
        &ApName::from_str("8.8.8.8.in-addr.arpa").unwrap()
    ));
    assert!(!is_private_reverse(
        &ApName::from_str("40.172.in-addr.arpa").unwrap()
    ));
    assert!(is_private_reverse(
        &ApName::from_str("d.f.ip6.arpa").unwrap()
    ));
    assert!(!is_private_reverse(
        &ApName::from_str("1.0.0.2.ip6.arpa").unwrap()
    ));
}

#[test]
fn empty_zone_predicate_and_block() {
    assert!(is_empty_zone(&ApName::from_str("home.arpa").unwrap()));
    assert!(is_empty_zone(&ApName::from_str("foo.home.arpa").unwrap()));
    assert!(is_empty_zone(
        &ApName::from_str("1.2.0.192.in-addr.arpa").unwrap()
    ));
    assert!(is_empty_zone(
        &ApName::from_str("5.10.in-addr.arpa").unwrap()
    ));
    assert!(!is_empty_zone(&ApName::from_str("example.com").unwrap()));
    assert!(!is_empty_zone(
        &ApName::from_str("8.8.8.8.in-addr.arpa").unwrap()
    ));

    let s = server_local_only(false, false, true);
    let resp = s.handle(&q("nas.home.arpa"), &ctx()).unwrap();
    assert_eq!(
        resp.header.rcode,
        ResponseCode::NXDomain.0,
        "home.arpa는 업스트림 미전달 NXDOMAIN"
    );
    assert_eq!(negative_soa_ttl(&resp), 60);
}

#[test]
/// 100.64.0.0/10 is 64 zones; catching only one would let reverse lookups for the rest go out.
/// DNS-SD queries with non-octet labels below a zone are inside it too. The test upstream answers
/// NOERROR to everything, so NXDOMAIN means the local cut answered.
fn cgnat_reverse_never_reaches_upstream() {
    let s = server_local_only(false, false, true);
    let ptr = |name: &str| Message::query(0x1234, ApName::from_str(name).unwrap(), RecordType::PTR);
    for name in [
        "1.0.64.100.in-addr.arpa",
        "9.8.100.100.in-addr.arpa",
        "255.255.127.100.in-addr.arpa",
        "127.100.in-addr.arpa",
        "b._dns-sd._udp.0.0.65.100.in-addr.arpa",
        "lb._dns-sd._udp.0.1.168.192.in-addr.arpa",
        "db._dns-sd._udp.0.0.20.172.in-addr.arpa",
    ] {
        let resp = s.handle(&ptr(name), &ctx()).unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NXDomain.0,
            "{name} 의 질의가 업스트림으로 나갔습니다"
        );
    }
    for name in [
        "1.0.63.100.in-addr.arpa",
        "1.0.128.100.in-addr.arpa",
        "100.in-addr.arpa",
        "lb._dns-sd._udp.0.0.8.8.in-addr.arpa",
    ] {
        let resp = s.handle(&ptr(name), &ctx()).unwrap();
        assert_eq!(
            resp.header.rcode,
            ResponseCode::NoError.0,
            "대조군이 무효입니다: 영역 밖인 {name} 은 업스트림이 답해야 합니다"
        );
    }
}

#[test]
/// The zone names' nibbles are written by hand, so they are checked against names built from
/// addresses.
fn rfc6303_ipv6_reverse_zones_are_empty_zones() {
    fn reverse(address: &str) -> ApName {
        let address: std::net::Ipv6Addr = address.parse().unwrap();
        let mut name = String::new();
        for byte in address.octets().iter().rev() {
            name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
        }
        name.push_str("ip6.arpa");
        ApName::from_str(&name).unwrap()
    }
    for address in ["::", "::1", "2001:db8::1", "2001:db8:ffff:ffff::"] {
        assert!(
            is_empty_zone(&reverse(address)),
            "{address} 의 역방향 이름을 빈 영역으로 보지 않습니다"
        );
    }
    for address in ["::2", "2001:db9::1", "2001:4860::8888"] {
        assert!(
            !is_empty_zone(&reverse(address)),
            "{address} 는 빈 영역이 아닙니다"
        );
    }
}

#[test]
/// This server's own home.arpa zone must not be overridden by its own `empty_zones` setting.
fn local_answers_win_over_the_local_only_cut() {
    let local: Arc<dyn Resolver> = Arc::new(StaticAnswer {
        name: ApName::from_str("nas.home.arpa").unwrap(),
    });
    let names = Arc::new(crate::layers::LocalOnlyNames::new(true, true, true));
    let ttl = Arc::new(std::sync::atomic::AtomicU32::new(60));
    let base: Arc<dyn Resolver> = Arc::new(NativeBackend::Forward(Forwarder::new(
        vec![mock_upstream()],
        Duration::from_secs(2),
    )));
    let cut: Arc<dyn Resolver> = Arc::new(crate::layers::LocalOnlyLayer::new(base, names, ttl));
    let engine = onetdns_filter::build_from_str("", "", BlockResponse::NxDomain);
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        Arc::new(StaticFirst { local, inner: cut }),
        60,
    );

    let answered = server.handle(&q("nas.home.arpa"), &ctx()).unwrap();
    assert_eq!(
        answered.header.rcode,
        ResponseCode::NoError.0,
        "로컬 권한 영역이 있는 이름은 로컬 답이 나가야 합니다"
    );
    assert_eq!(answered.answers.len(), 1);

    let cut_off = server.handle(&q("other.home.arpa"), &ctx()).unwrap();
    assert_eq!(
        cut_off.header.rcode,
        ResponseCode::NXDomain.0,
        "로컬이 답하지 못하면 업스트림으로 새지 않고 NXDOMAIN이어야 합니다"
    );
}

#[test]
/// Repairing would let a different name hit the rule.
fn text_policy_name_rejects_invalid_utf8_without_repair() {
    let configured = ApName::from_str("�.Example").unwrap();
    let raw = ApName::from_labels(vec![vec![0xff], b"Example".to_vec()]).unwrap();

    assert_eq!(
        normalized_text_name(&configured).as_deref(),
        Some("�.example")
    );
    assert_eq!(normalized_text_name(&raw), None);
}

#[test]
fn dnssec_bogus_counter_accumulates() {
    let name = onetdns_proto::Name::from_str("dnssec-failed.example").unwrap();
    let before = DNSSEC_BOGUS_TOTAL.load(Ordering::Relaxed);
    note_dnssec_bogus(&name);
    note_dnssec_bogus(&name);
    assert_eq!(
        DNSSEC_BOGUS_TOTAL.load(Ordering::Relaxed),
        before + 2,
        "bogus 발생마다 누적"
    );
}

#[test]
fn domain_needed_blocks_dotless_forward() {
    let s = server_local_only(true, false, false);
    let resp = s.handle(&q("wpad"), &ctx()).unwrap();
    assert_eq!(
        resp.header.rcode,
        ResponseCode::NXDomain.0,
        "점 없는 이름은 NXDOMAIN(업스트림 미전달)"
    );
    assert_eq!(negative_soa_ttl(&resp), 60);
}

#[test]
fn harden_large_queries_drops_oversized() {
    let s = server("");
    update_features(&s, |features| features.harden_large_queries = true);

    let oversized_wire = vec![0u8; MAX_LARGE_QUERY_BYTES + 1];
    let mut oversized = ctx();
    oversized.raw = Some(&oversized_wire);
    assert!(
        s.handle(&q("example.com"), &oversized).is_none(),
        "한도 초과 질의는 응답 없이 폐기"
    );

    let normal_wire = vec![0u8; MAX_LARGE_QUERY_BYTES];
    let mut normal = ctx();
    normal.raw = Some(&normal_wire);
    assert!(
        s.handle(&q("example.com"), &normal).is_some(),
        "한도 이하 질의는 정상 처리"
    );
}

#[test]
/// A fast path that hands a query on must not count its rule; the path that answers does. Counting
/// in both would show each blocked or allowlisted query twice.
fn each_answered_query_counts_its_rule_once() {
    use onetdns_runtime::WireDisposition;

    let (backend, cache) = fixed_answer_cache();
    let engine = onetdns_filter::build_from_str(
        "||blocked.example^\n@@||allowed.example^",
        "",
        BlockResponse::NxDomain,
    )
    .with_hit_tracking(true);
    let server = NativeServer::new(
        shared_filter(ArcSwap::from_pointee(engine)),
        Arc::new(IpAcl::allow_all()),
        vec![],
        backend,
        60,
    )
    .with_wire_fast_path(Some((
        crate::wirecache::WireEntryFactory::new(0, 86_400),
        cache,
    )));
    let hits = |rule: &str| {
        server
            .filter
            .load()
            .top_rule_hits(10)
            .into_iter()
            .find(|(name, _)| name == rule)
            .map_or(0, |(_, hits)| hits)
    };
    let wire = |name: &str| {
        let request = Message::query(0x0202, ApName::from_str(name).unwrap(), ApRt::A);
        let mut out = onetdns_proto::Writer::with_limit(1232);
        let disposition = server.handle_udp_wire(
            &request.try_encode().unwrap(),
            &ctx(),
            &mut out,
            Instant::now(),
        );
        (request, disposition)
    };

    let (blocked, disposition) = wire("blocked.example");
    assert_eq!(
        disposition,
        WireDisposition::Respond,
        "the fast path answers the block itself"
    );
    assert_eq!(hits("blocked.example"), 1);
    let response = server.handle(&blocked, &ctx()).unwrap();
    assert_eq!(response.header.rcode, ResponseCode::NXDomain.0);
    assert_eq!(hits("blocked.example"), 2);

    assert_eq!(
        wire("allowed.example").1,
        WireDisposition::Respond,
        "the miss is resolved through the full path"
    );
    assert_eq!(hits("allowed.example"), 1);
    assert_eq!(
        wire("allowed.example").1,
        WireDisposition::Respond,
        "the stored answer is sent from the fast path"
    );
    assert_eq!(hits("allowed.example"), 2);
}

#[test]
/// The fast path writes the block straight from the query bytes; the message, its EDNS, and the
/// query log entry must be what the normal path produces for the same query.
fn wire_lane_block_answers_match_the_normal_path() {
    use onetdns_runtime::WireDisposition;

    let blocks = [
        BlockResponse::NxDomain,
        BlockResponse::NoData,
        BlockResponse::Refused,
        BlockResponse::ZeroIp,
        BlockResponse::Custom {
            v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            v6: None,
        },
        BlockResponse::Custom {
            v4: None,
            v6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        },
    ];
    for block in blocks {
        let (recorder, stats) = onetdns_control::channel(
            64,
            64,
            3600,
            onetdns_control::RecorderOpts {
                querylog: true,
                anonymize: false,
                ignored: vec![],
                stats_retention_secs: 3600,
            },
            onetdns_control::PersistOpts::default(),
        );
        let (backend, cache) = fixed_answer_cache();
        let engine = onetdns_filter::build_from_str("||blocked.example^", "", block);
        let server = NativeServer::new(
            shared_filter(ArcSwap::from_pointee(engine)),
            Arc::new(IpAcl::allow_all()),
            vec![],
            backend,
            60,
        )
        .with_wire_fast_path(Some((
            crate::wirecache::WireEntryFactory::new(0, 86_400),
            cache,
        )))
        .with_recorder(Some(recorder));
        let mut logged = 0;
        for qtype in [ApRt::A, ApRt::AAAA, ApRt::TXT] {
            for (edns, rd, name) in [
                (None, true, "blocked.example"),
                (Some(false), true, "Ads.Blocked.EXAMPLE"),
                (Some(true), false, "blocked.example"),
            ] {
                let mut query = Message::query(0x4242, ApName::from_str(name).unwrap(), qtype);
                query.header.recursion_desired = rd;
                query.header.checking_disabled = !rd;
                if let Some(dnssec_ok) = edns {
                    let opt = Edns {
                        dnssec_ok,
                        ..Edns::default()
                    };
                    query.additionals.push(opt.try_to_record().unwrap());
                }
                let wire = query.try_encode().unwrap();
                let case = format!(
                    "{block:?} {qtype:?} {name} edns={edns:?} rd={rd} cd={}",
                    !rd
                );

                let mut fast = onetdns_proto::Writer::with_limit(1232);
                assert_eq!(
                    server.handle_udp_wire(&wire, &ctx(), &mut fast, Instant::now()),
                    WireDisposition::Respond,
                    "{case}"
                );
                let request = Message::parse(&wire).unwrap();
                let response = server.handle(&request, &ctx()).unwrap();
                let mut normal = onetdns_proto::Writer::with_limit(1232);
                onetdns_runtime::encode_limited(&request, &response, &mut normal);
                assert_eq!(
                    format!("{:?}", Message::parse(&fast.buf).unwrap()),
                    format!("{:?}", Message::parse(&normal.buf).unwrap()),
                    "{case}"
                );

                logged += 2;
                let deadline = Instant::now() + Duration::from_secs(3);
                let recent = loop {
                    if stats.recent(64).len() >= logged || Instant::now() >= deadline {
                        break stats.recent(2);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                let entry = |event: &onetdns_control::QueryEvent| {
                    (
                        event.name.clone(),
                        event.qtype.clone(),
                        event.action,
                        event.rcode.clone(),
                        event.reason.clone(),
                        event.stage.clone(),
                        event.rule.clone(),
                        event.list.clone(),
                    )
                };
                assert_eq!(recent.len(), 2, "{case}");
                assert_eq!(entry(&recent[1]), entry(&recent[0]), "{case}");
            }
        }
    }
}
