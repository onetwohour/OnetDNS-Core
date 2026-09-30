/*!
 * @brief 두 빠른 경로가 보통 경로와 같은 답을 내는지, 그리고 각 관문이 실제로 막는지.
 */

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
/** @brief 비었는지 판정이 값과 함께 교체되는지. */
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

/** @brief 언제나 실패하는 테스트용 체인. */
struct FailBackend;

impl Resolver for FailBackend {
    /** @brief 언제나 답하지 않는다. */
    fn resolve(&self, _req: &Message) -> Option<Message> {
        None
    }
}

#[test]
/** @brief 다른 서버로 가라는 응답이 그대로 클라이언트에 가는지. */
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

/** @brief 고정 응답을 내는 테스트용 업스트림. */
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

/** @brief 자기가 권한이라고 표시해 보내는 테스트용 업스트림. */
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

/** @brief 검증됐다고 표시해 보내는 테스트용 업스트림. */
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
/** @brief 업스트림이 설정한 검증 표시를 지우는지. 그대로 넘기면 검증하지 않은 것을 검증됐다고 하는 셈이다. */
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

/** @brief 차단 목록을 걸어 만든 테스트용 핸들러. */
pub(crate) fn server(block_list: &str) -> NativeServer {
    server_with_chain(block_list, |base| base)
}

/**
 * @brief 기본 백엔드를 계층으로 감싼 테스트용 서버.
 * @details 밖에 물어보면 안 되는 이름을 끊는 일은 업스트림 질의 바로 앞 계층이 한다.
 *          그 계층을 빼고 테스트하면 실제 조립과 다른 것을 재게 된다.
 */
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

/** @brief 밖에 물어보면 안 되는 이름을 끊는 계층을 씌운 테스트용 서버. */
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

/** @brief 한 이름에만 답하는 테스트용 로컬 소스. 권한 영역 슬롯을 대신한다. */
struct StaticAnswer {
    /** @brief 답할 이름. */
    name: ApName,
}

impl Resolver for StaticAnswer {
    /** @brief 이 이름이면 답하고, 아니면 없음. */
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

/** @brief 로컬 원천을 먼저 보고 없으면 안으로 넘기는 테스트용 계층. */
struct StaticFirst {
    /** @brief 로컬 원천. */
    local: Arc<dyn Resolver>,
    /** @brief 다음 계층. */
    inner: Arc<dyn Resolver>,
}

impl Resolver for StaticFirst {
    /** @brief 해석한다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        match self.resolve_outcome(request) {
            ResolveOutcome::Response(response) => Some(response),
            ResolveOutcome::Failure(_) => None,
        }
    }

    /** @brief 로컬이 답하면 그 답, 아니면 안쪽 결과. */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        match self.local.resolve(request) {
            Some(response) => ResolveOutcome::Response(response),
            None => self.inner.resolve_outcome(request),
        }
    }
}

/** @brief 테스트 중에 기능 세트를 바꾼다. */
pub(crate) fn update_features(server: &NativeServer, update: impl FnOnce(&mut NativeFeatures)) {
    let mut features = (*server.features.load()).clone();
    update(&mut features);
    server.features.store(Arc::new(features));
}

/** @brief 테스트용 차단 엔진 슬롯. */
pub(crate) fn shared_filter(filter: ArcSwap<BlockEngine>) -> Arc<SharedFilter> {
    Arc::new(SharedFilter::new(filter.load()))
}

#[test]
/** @brief 권한 영역 빠른 경로를 막는 기능이 켜지면 판정도 함께 바뀌는지. */
fn native_feature_swap_tracks_authority_wire_gates() {
    let features = NativeFeatures::default();
    let safe_search = features.safe_search.clone();
    let swap = NativeFeatureSwap::from_pointee(features);
    assert!(!swap.authority_wire_blocked());
    assert!(!swap.harden_large_queries());
    assert!(!swap.safe_search_enabled());

    let mut next = (*swap.load()).clone();
    next.block_aaaa = true;
    swap.store(Arc::new(next));
    assert!(swap.authority_wire_blocked());

    let mut next = (*swap.load()).clone();
    next.block_aaaa = false;
    next.harden_large_queries = true;
    swap.store(Arc::new(next));
    assert!(!swap.authority_wire_blocked());
    assert!(swap.harden_large_queries());

    let mut next = (*swap.load()).clone();
    next.cookies = CookiePolicy {
        keeper: Some(Arc::new(CookieKeeper::from_secret(&[1; 16]))),
        strict: false,
    };
    swap.store(Arc::new(next));
    assert!(
        !swap.authority_wire_blocked(),
        "lenient는 COOKIE 옵션이 붙은 질의만 구조적 경로로 보내야 합니다"
    );

    let mut next = (*swap.load()).clone();
    next.cookies.strict = true;
    swap.store(Arc::new(next));
    assert!(
        swap.authority_wire_blocked(),
        "strict는 쿠키 없는 질의도 BADCOOKIE로 보내야 합니다"
    );

    safe_search.store(true, Ordering::Release);
    assert!(swap.safe_search_enabled());

    let mut replacement = (*swap.load()).clone();
    replacement.harden_large_queries = false;
    replacement.safe_search = Arc::new(AtomicBool::new(false));
    swap.store(Arc::new(replacement));
    assert!(
        swap.authority_wire_blocked(),
        "추적되지 않는 safe-search 포인터 교체는 fail-closed"
    );
}

#[test]
#[ignore = "microbenchmark: run with --release -- --ignored --nocapture"]
/** @brief 같은 질의에서 기능 snapshot을 두 번 잡는 비용과 한 번 재사용하는 비용. */
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
            sink ^= black_box(features.events().is_some() as usize);
        }
        black_box(sink);
        started.elapsed().as_nanos() as f64 / iters as f64
    }

    fn twice(swap: &ArcSwap<NativeFeatures>, iters: u64) -> f64 {
        let mut sink = 0usize;
        let started = Instant::now();
        for _ in 0..iters {
            let identify = black_box(swap.load());
            sink ^= black_box(identify.edns_buffer as usize);
            let record = black_box(swap.load());
            sink ^= black_box(record.events().is_some() as usize);
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
/**
 * @brief 읽지 못한 질의를 버리지 않고 FORMERR로 답하는지, 그리고 그 답이 접근 제어와
 *        속도 제한을 지나는지.
 * @details 버리면 클라이언트에게는 무응답이라 데드라인을 다 기다린 뒤 재시도한다. 다만
 *          파싱 전이라 일반 경로의 두 관문을 지나오지 못했으므로 여기서 다시 봐야
 *          한다. 안 보면 거부한 클라이언트에게도 서버가 있다고 알리게 된다.
 */
fn an_unparsable_query_is_answered_with_formerr_behind_the_usual_gates() {
    // 질문 하나를 적어 놓고 둘이라고 말하는 헤더. 파서가 거부한다.
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
}

#[test]
/**
 * @brief 전달 백엔드가 업스트림의 권한 표시를 그대로 돌려주지 않는지.
 * @details 업스트림이 권한이지 이 서버가 아니다. 그대로 돌려주면 이 서버가 맡지 않은 이름에 권한이라고
 *          알리는 것이고, 캐시 히트에서는 그 표시가 사라져 같은 서버의 두 경로가 서로
 *          다른 답을 낸다. 이 서버의 영역의 답에 이 표시를 설정하는 것은 위쪽 권한 계층이 한다.
 */
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

/** @brief 테스트용 요청 맥락. */
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

/** @brief 테스트용 질의. */
pub(crate) fn q(name: &str) -> Message {
    Message::query(0x1234, ApName::from_str(name).unwrap(), RecordType::A)
}

/** @brief 응답에 담긴 부정 수명. */
pub(crate) fn negative_soa_ttl(message: &Message) -> u32 {
    message
        .authorities
        .iter()
        .find(|record| record.rtype == RecordType::SOA)
        .expect("합성 부정 응답 SOA")
        .ttl
}

/** @brief 정해진 응답 코드를 내는 테스트용 체인. */
struct FixedRcode(u16);

impl Resolver for FixedRcode {
    /** @brief 미리 정해 둔 응답을 돌려준다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        let mut response = base_response(request);
        response.header.rcode = self.0;
        Some(response)
    }
}

/** @brief 정해진 답을 내는 테스트용 체인. */
struct FixedAnswer;

impl Resolver for FixedAnswer {
    /** @brief 미리 정해 둔 응답을 돌려준다. */
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

/** @brief 정해진 답과 그것을 담을 캐시. */
fn fixed_answer_cache() -> (Arc<dyn Resolver>, crate::cache::CacheHandle) {
    let layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let handle = layer.handle();
    (Arc::new(layer), handle)
}

#[test]
/** @brief 빠른 경로가 질의 번호를 고쳐 내보내고, 세대가 다르면 쓰지 않는지. */
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
        WireDisposition::Fallback
    );

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

    update_features(&server, |features| features.block_aaaa = true);
    let mut out5 = onetdns_proto::Writer::with_limit(1232);
    assert_eq!(
        server.handle_udp_wire(&third_wire, &ctx(), &mut out5, std::time::Instant::now()),
        WireDisposition::Fallback
    );
}

#[test]
/** @brief 인라인 키보다 긴 정상 질의가 거부되지 않고 구조화 경로에서 답을 받는지. */
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

/** @brief 모양을 정해 둔 답을 내는 테스트용 체인. */
struct ShapedAnswer;

impl Resolver for ShapedAnswer {
    /** @brief 미리 정해 둔 응답을 돌려준다. */
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

/** @brief 빠른 경로를 켜거나 끈 테스트용 핸들러. */
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
/** @brief 고정해 둔 주소를 캐시 밖에서 답할 때와 담아 둔 바이트로 답할 때의 비용. */
fn bench_split_local_outside_cache_vs_cached_wire_hit() {
    /** @brief 테스트용 핸들러. */
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

    /** @brief 반복 횟수. */
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
/** @brief 설정을 다시 읽은 뒤 이전 수명으로 만든 항목이 들어오지 못하는지. */
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
    server.wire_epoch.fetch_add(1, Ordering::AcqRel);
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
    server.wire_epoch.fetch_add(1, Ordering::AcqRel);
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
/** @brief 바깥 계층의 답을 고정해 둔 주소의 답으로 오해하지 않는지. 오해하면 수명이 늙지 않는다. */
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
/** @brief 단순 질의는 조립 없이 나가고, 기능이 하나라도 켜지면 보통 경로로 전환하는지. */
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

    // 옵션 없는 OPT 하나만 붙은 질의는 빠른 경로가 맡되, 나가는 바이트는 구조적 경로와
    // 한 바이트도 다르면 안 된다. 실제 클라이언트는 거의 전부 이 모양으로 물어본다.
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

    // 응답에 담을 것이 생기거나 절단 사다리가 필요한 모양은 전부 물러선다.
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
}

#[test]
/** @brief DDR이 켜져도 권한 고속 경로는 특수 이름 하나만 양보하고 나머지는 유지하는지. */
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
/** @brief 밖을 가리키는 별칭을 오류로 바꾸지 않는지. */
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
/** @brief 권한 영역 빠른 경로와 보통 경로의 비용. */
fn bench_authoritative_exact_wire_vs_structured_path() {
    /** @brief 테스트용 권한 핸들러. */
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

    /** @brief 질의 하나를 처리해 바이트를 받는다. */
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
    /** @brief 반복 횟수. */
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
/** @brief 빠른 경로의 답이 보통 경로와 바이트까지 같은지. 다르면 캐시가 맞았는지에 따라 답이 갈린다. */
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
/** @brief 아무것도 막지 않는 설정에서 빠른 경로를 쓰는지. */
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
/** @brief 빠른 경로가 응답 캐시 하나만 쓰는지. 둘로 나누면 같은 답을 두 번 담는다. */
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
    let filter_tag =
        (Arc::as_ptr(&filter) as usize).rotate_left(17) ^ server.wire_epoch.load(Ordering::Acquire);
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
/** @brief 체인을 바꾸면 새 질의는 새 캐시를 보고, 진행 중 스냅숏은 이전 세대를 안전하게 유지하는지. */
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

    server.replace_lane_runtime(
        crate::wirecache::WireEntryFactory::new(0, 300),
        new_cache.clone(),
        None,
        true,
    );
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
/** @brief 체인 교체 뒤 wire 경로도 새 캐시와 새 TTL 상한을 즉시 쓰는지. */
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
    server.wire_epoch.fetch_add(1, Ordering::AcqRel);
    server.replace_lane_runtime(
        crate::wirecache::WireEntryFactory::new(0, 31),
        new_cache,
        None,
        false,
    );

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
/** @brief 빠른 경로에서 일반 경로로 넘어가도 제한을 두 번 세지 않는지. */
fn wire_lane_hit_charges_rate_limit_once_across_fallback() {
    use onetdns_runtime::WireDisposition;

    /** @brief 호출 수를 세는 테스트용 제한기. */
    struct CountingLimiter(AtomicUsize);
    impl RateLimiter for CountingLimiter {
        /** @brief 세고 통과시킨다. */
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
/** @brief 교체해도 이미 잡고 처리 중인 것이 깨지지 않는지. */
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

/** @brief 빈 응답을 내는 테스트용 업스트림. */
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

/**
 * @brief 별칭 하나만 담아 보내는 테스트용 업스트림. 부정 응답 SOA는 담지 않는다.
 *
 * @details 이름이 CNAME으로 이어지고 그 끝에 요청한 종류가 없을 때(IPv6 주소가 없는
 *          이름의 AAAA가 대표적이다) 실제 업스트림이 내는 모양이다. 공개 리졸버 여럿이
 *          이때 SOA를 담지 않는다.
 */
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

/** @brief 내부망 주소를 답하는 테스트용 업스트림. */
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

/** @brief 이 업스트림을 쓰는 테스트용 핸들러. */
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

/** @brief 사유 코드를 담아 보내는 테스트용 업스트림. */
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
/** @brief 답한 주소가 바이트로 오갔다 와도 그대로인지. */
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
/**
 * @brief 별칭만 실려 온 응답을 실패로 바꾸지 않는지.
 *
 * @details 이름이 CNAME으로 이어지고 그 끝에 요청한 종류가 없으면 업스트림은 CNAME 하나에
 *          NOERROR로 답한다. 부정 응답 SOA를 함께 담지 않는 업스트림이 흔하다. 그것을
 *          실패로 바꾸면 CNAME 뒤에 선 이름의 AAAA가 전부 실패한다. 실제로
 *          emergency.zeta-ai.io의 AAAA가 그렇게 막혔다.
 * @warning 별칭이 없는 빈 NOERROR는 그대로 막아야 한다. 그것은 근거도 답도 없는 응답이다.
 */
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
/**
 * @brief 근거 없이 비어 온 응답을 규격대로 그대로 전달하는지.
 *
 * @details RFC 2308이 모든 구간이 빈 것을 NODATA의 한 모양으로 열거해 두었다.
 *          SOA가 없을 때 규격이 정한 처분은 거절이 아니라 캐시 금지이고, 담지 않는 것은
 *          캐시 계층이 따로 한다(unproven_empty_noerror_is_not_cached).
 * @warning 한때 이것을 SERVFAIL로 바꿨다. RFC 4074가 바로 그 동작을 지목한다. IPv6
 *          주소가 없는 이름의 AAAA에 SERVFAIL을 주면 질의자가 A로 다시 묻지 못하고
 *          되풀이한다. 실제로 CNAME 뒤에 선 이름의 AAAA가 전부 막혔다.
 */
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
/** @brief 내부망 주소를 걷어 낸 뒤 빈 성공 응답이 남지 않는지. 남으면 없다는 뜻이 된다. */
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
/**
 * @brief ECS 옵션을 요청한 클라이언트에게만 그대로 돌려주는지.
 *
 * @details RFC 7871은 두 방향을 함께 규정한다. 대역 정보를 쓰는 서버는 질의에
 *          그 옵션이 없었으면 응답에 넣어서는 안 되고, 있었으면 반드시 넣어야 한다.
 *          하류가 전달 리졸버면 이 값으로 자기 캐시의 범위를 정하므로, 빠뜨리면 대역별
 *          답을 모두에게 주는 캐시가 된다.
 * @note SCOPE 는 0 이다. 이 서버는 설정된 고정 대역으로 업스트림에 물으므로 어느 클라이언트에게나
 *       같은 답이 나가고, 0 이 아닌 값을 적으면 하류가 그 대역 전용 답으로 잘못 담는다.
 */
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

    // 클라이언트가 SCOPE 를 잘못 적어 보내도 이 서버의 응답의 SCOPE 는 0 이다.
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

    // SOURCE 24 인데 주소가 두 옥텟뿐이라 형식이 깨졌다. 그대로 돌려주면 어긋난 옵션을
    // 하류로 퍼뜨리게 되므로 넣지 않는다.
    let short = vec![0, 1, 24, 0, 192, 0];
    let response = using(true).handle(&with_ecs(Some(short)), &ctx()).unwrap();
    assert_eq!(
        echoed(&response),
        None,
        "형식이 깨진 옵션은 그대로 돌려주지 않습니다"
    );
}

#[test]
/** @brief 업스트림이 보낸 사유가 그대로 전해지는지. */
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
/** @brief 실패에 사유가 담기는지. */
fn resolver_failure_carries_diagnostic_ede() {
    /** @brief 정해진 실패를 내는 테스트용 체인. */
    struct FailBackend(ResolveFailure);
    impl Resolver for FailBackend {
        /** @brief 언제나 답하지 않는다. */
        fn resolve(&self, _req: &Message) -> Option<Message> {
            None
        }
        /** @brief 정해진 실패를 알린다. */
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
/** @brief 접근 제어에 막혔음을 사유로 알리는지. */
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
/** @brief 차단됐음을 사유로 알리는지. */
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
/** @brief 답에 담긴 주소가 차단 대상이면 막는지. */
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

/** @brief 큰 테스트용 영역. */
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

/** @brief 언제나 통과시키는 테스트용 제한기. */
struct ActivePermitLimiter;

impl RateLimiter for ActivePermitLimiter {
    /** @brief 통과시킨다. */
    fn check(&self, _client: &ClientInfo) -> RateDecision {
        RateDecision::Permit
    }
}

/**
 * @brief 첫 판정 뒤에 켜지는 테스트용 제한기.
 * @details DynamicRateLimiter::replace가 질의 처리 도중에 제한기를 거는 것을 결정적으로
 *          흉내 낸다. 실제로는 컨트롤 플레인 스레드가 그 사이에 끼어든다.
 */
struct LateActivatingLimiter {
    /** @brief is_active를 몇 번 물었는지. */
    asked: std::sync::atomic::AtomicUsize,
}

impl RateLimiter for LateActivatingLimiter {
    /** @brief 통과시킨다. */
    fn check(&self, _client: &ClientInfo) -> RateDecision {
        RateDecision::Permit
    }

    /** @brief 처음 물을 때만 꺼져 있다고 답한다. */
    fn is_active(&self) -> bool {
        self.asked.fetch_add(1, Ordering::Relaxed) != 0
    }
}

#[test]
/** @brief 판정 사이에 제한기가 켜져도 고속 경로가 답으로 수렴하는지. */
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
    // 제한기가 꺼져 있다고 본 뒤 켜졌으므로 클라이언트를 만들지 않았다. 여기서 죽지 않고
    // 보통 경로로 전환해야 한다. 고속 경로는 언제 일반 경로로 넘겨도 정답이다.
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
/**
 * @brief EDNS 없는 UDP 질의에 512바이트를 넘는 답을 무할당 경로가 그대로 내보내지
 *        않는지. TCP 에는 그 상한이 없으므로 거기서는 그대로 답해야 한다.
 * @details 이 경로에는 절단 사다리가 없다. 물러서지 않으면 RFC 1035가 정한
 *          크기를 넘는 데이터그램이 나가고, 클라이언트는 TC 도 못 보므로 TCP 로 다시
 *          묻지도 않는다.
 */
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
/**
 * @brief 이 서버가 맡은 영역의 ANY가 표준 알고리즘을 먼저 따르는지.
 * @details RFC 8482는 최소 응답을 답 구간에만 허용하고 "Except as described below
 *          in this section, the DNS responder MUST follow the standard algorithms"
 *          라고 규정한다. 해석하기 전에 합성하면 없는 이름이 NOERROR가 되어 존재를
 *          알리고 부정 캐시도 서지 않으며, 권한 표시도 서지 않는다. 4.2는 QNAME에
 *          CNAME이 있으면 합성하지 말라고 하므로 그것도 함께 본다.
 */
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
/** @brief 큰 영역이 여러 청크로 나뉘어 가는지. */
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

    // 성공한 영역 전송은 어느 경로도 통계에 남기지 않는다. 기록기가 있다는 이유로 이
    // 경로가 포기하면 영역을 전부 다시 만들기만 하고 남는 기록은 그대로 없다.
    {
        let (recorder, _stats) = onetdns_control::channel(
            8,
            8,
            60,
            onetdns_control::RecorderOpts::default(),
            onetdns_control::PersistOpts::default(),
        );
        let mut features = (*srv.features.load()).clone();
        features.recorder = Some(recorder);
        srv.features.store(Arc::new(features));
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
/** @brief 원격 업데이트가 반영되고 시리얼이 오르는지. */
fn ddns_update_applies_and_bumps_serial() {
    let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 1 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\n";
    let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(zone);
    let store = Arc::new(ArcSwap::new(Arc::new(zs)));
    let srv = server("")
        .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
        .with_ddns(
            vec!["127.0.0.0/8".parse().unwrap()],
            false,
            vec![],
            vec![ApName::from_str("example.com").unwrap()],
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
/** @brief 선행 조건과 기록 모양을 확인하는지. 어긋난 것이 통과하면 영역이 깨진다. */
fn ddns_enforces_prerequisite_sets_and_update_record_shape() {
    let zone_text = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 10 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nmulti IN A 10.0.0.2\nmulti IN A 10.0.0.3\n";
    let zone = onetdns_authority::parse_zone(zone_text, "example.com").unwrap();
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(zone);
    let store = Arc::new(ArcSwap::new(Arc::new(zs)));
    let srv = server("")
        .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
        .with_ddns(
            vec!["127.0.0.0/8".parse().unwrap()],
            false,
            vec![],
            vec![ApName::from_str("example.com").unwrap()],
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
            vec![],
            vec![ApName::from_str("primary-only.test").unwrap()],
        );
    update.answers.clear();
    update.authorities.clear();
    assert_eq!(
        secondary.handle(&update, &tcp).unwrap().header.rcode,
        9,
        "secondary 복제 zone은 로컬 DDNS 수정 불가"
    );
}

/** @brief DDNS 갱신 판정에 쓸 영역과 서버를 새로 만든다. */
#[allow(clippy::type_complexity)]
fn ddns_fixture() -> (Arc<ArcSwap<onetdns_authority::ZoneStore>>, NativeServer) {
    let zone_text = "$ORIGIN skip.test.\n$TTL 300\n@ IN SOA ns admin 10 300 60 86400 60\n@ IN NS ns\nns IN A 10.0.0.1\nmulti IN A 10.0.0.2\nsub IN NS ns.sub\nns.sub IN A 10.0.0.5\n";
    let mut zs = onetdns_authority::ZoneStore::new();
    zs.add(onetdns_authority::parse_zone(zone_text, "skip.test").unwrap());
    let store = Arc::new(ArcSwap::new(Arc::new(zs)));
    let srv = server("")
        .with_xfr(store.clone(), vec!["127.0.0.0/8".parse().unwrap()])
        .with_ddns(
            vec!["127.0.0.0/8".parse().unwrap()],
            false,
            vec![],
            vec![ApName::from_str("skip.test").unwrap()],
        );
    (store, srv)
}

/** @brief 갱신부에 기록들을 담은 UPDATE 한 통. */
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

/** @brief 이 이름에 이 종류가 몇 개나 있는지. */
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
/**
 * @brief 어긋나는 갱신 RR 하나만 건너뛰고 나머지는 그대로 적용하는지.
 *
 * @details RFC 2136은 CNAME 이 다른 데이터와 공존하게 되는 추가와 정점의
 *          마지막 NS 삭제를 그 RR 만 건너뛰고 남은 것을 마저 처리한 뒤 NOERROR 로
 *          답하라고 정한다. 예전에는 일단 적용해 보고 영역 검증이 거부하면 SERVFAIL 을
 *          냈는데, 그러면 같은 메시지에 실려 온 멀쩡한 갱신까지 함께 사라진다.
 * @note 위임의 마지막 NS 는 지울 수 있어야 한다. 정점과 같은 규칙을 걸면 한번 만든
 *       위임을 영영 걷지 못한다.
 */
fn ddns_skips_only_the_conflicting_record() {
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };

    let (store, srv) = ddns_fixture();
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

    let (store, srv) = ddns_fixture();
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

    let (store, srv) = ddns_fixture();
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

    let (store, srv) = ddns_fixture();
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
/**
 * @brief 영역부 클래스가 다른 UPDATE 와 선행조건 검사 차례가 규격대로인지.
 *
 * @details RFC 2136은 영역부 개수와 ZTYPE 만 형식 오류로 보고, ZCLASS 가 이 서버가
 *          맡은 영역과 다르면 NOTAUTH 로 답하게 한다. 형식 오류로 답하면 요청자는 자기
 *          메시지가 깨진 줄 알고 고치려 들지만 실제로는 서버를 잘못 고른 것이다.
 *          선행조건은 3.2.5 의사코드가 TTL 을 영역 범위보다 먼저 보게 정한다.
 */
fn ddns_reports_a_foreign_zone_class_as_notauth() {
    let tcp = RequestCtx {
        src: "127.0.0.1:5555".parse().unwrap(),
        transport: RtTransport::Do53Tcp,
        raw: None,
        client_id: None,
        authenticated: false,
        auth_identity: None,
    };
    let (store, srv) = ddns_fixture();

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
/**
 * @brief 갱신이 담아 온 SOA 일련번호를 그대로 두는지.
 *
 * @details RFC 2136은 되돌리는 SOA 교체만 무시하고, 갱신이 일련번호를 직접 바꾸면
 *          서버가 또 올리지 말라고 정한다. 비교는 RFC 1982 모듈로 산술이다. 예전에는
 *          SOA 추가를 늘 버리고 언제나 하나를 올려, 요청자가 적어 준 값이 영역에 남지
 *          않았다.
 */
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

    let (store, srv) = ddns_fixture();
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

    let (store, srv) = ddns_fixture();
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

    let (store, srv) = ddns_fixture();
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
/**
 * @brief 무할당 경로로 답해도 지표에 남는지.
 *
 * @details 이 경로가 기록하지 못하던 시절의 조건(기록기가 있으면 막는다)이 그대로
 *          남아 있으면, 컨트롤 플레인을 만들어 두는 모든 배치에서 경로가 전부 죽는다. 반대로
 *          조건만 지우고 기록을 안 붙이면 대시보드에서 권한 응답이 조용히 사라진다.
 *          Personal 모드처럼 ACL이 클라이언트를 요구해도 식별과 기록은 같은 기능 세대
 *          snapshot 하나를 써야 한다. 셋 다 조용한 사고라 여기서 붙든다.
 */
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
    let mut features = NativeFeatures::default();
    features.recorder = Some(recorder);
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
    .with_features(features)
    .with_authority_wire_path(Some(store), true);

    let mut output = onetdns_proto::Writer::with_limit(1232);
    for (name, expected) in [
        ("www.rec.test", ResponseCode::NoError),
        ("nope.rec.test", ResponseCode::NXDomain),
    ] {
        let request = Message::query(0x1234, ApName::from_str(name).unwrap(), RecordType::A);
        output.clear();
        server.features.take_test_loads();
        assert_eq!(
            server.handle_udp_wire(
                &request.try_encode().unwrap(),
                &ctx(),
                &mut output,
                Instant::now()
            ),
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
            "ACL 식별과 기록이 질의 세대 snapshot 하나를 공유해야 합니다"
        );
    }

    for _ in 0..200 {
        if stats.metrics.snapshot().total >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let snapshot = stats.metrics.snapshot();
    assert_eq!(
        snapshot.total, 2,
        "무할당 경로로 답한 질의가 지표에 남지 않았습니다"
    );
}

#[test]
/**
 * @brief 묻지 않은 쪽에는 DNSSEC 레코드를 보내지 않는지.
 *
 * @details 재귀 리졸버는 검증 여부와 무관하게 업스트림에 DO=1로 묻는다. 그래야 DO=1로 묻는
 *          질의자에게 줄 서명을 가지고 있을 수 있다. 그 대신 묻지 않은 쪽에 담아 보내면
 *          응답만 커지고 절단으로 이어진다.
 * @warning DNSKEY와 DS는 질의자가 직접 물을 수 있는 종류라 걷어내면 안 된다.
 */
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

    // 대조군. DO를 설정한 쪽에는 그대로 나가야 한다. 걷어내기가 언제나 실행되는 것을 막는다.
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
/**
 * @brief 요청에 OPT가 있으면 응답에도 반드시 넣고, 없으면 넣지 않는지.
 * @details RFC 6891이 양쪽을 다 MUST로 정한다. 빼면 상대는 이 서버가 EDNS를 모르는 것으로
 *          보고 512바이트로 전환하고, 쿠키·NSID·패딩·EDE를 담을 슬롯도 사라진다.
 *          반대로 EDNS 없는 요청에 붙이면 이전 클라이언트가 응답을 거부한다.
 */
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
/**
 * @brief 질문이 둘인 질의에 FORMERR을 주되 그것을 그대로 돌려주지 않는지.
 *
 * @details RFC 9619는 opcode 0인 DNS 메시지가 QDCOUNT를 1보다 크게 담을 수 없다고
 *          정한다. 응답도 opcode 0이므로 질문부를 그대로 돌려주면 이 서버의 답이 같은
 *          규칙을 어긴다. BIND도 이 자리에서 질문부를 비운다.
 */
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

    // 질문이 없는 질의도 같은 분기를 지난다. 비우는 것이 무해해야 한다.
    let mut empty = Message::default();
    empty.header.id = 7;
    let response = srv.handle(&empty, &ctx).expect("응답이 없습니다");
    assert_eq!(response.header.rcode, ResponseCode::FormErr.0);
    assert!(response.questions.is_empty());
}

#[test]
/**
 * @brief 구현하지 않은 opcode에 NOTIMP로 답하는지.
 * @details FORMERR은 요청이 깨졌다는 뜻이라 보낸 쪽이 질의를 고쳐 다시 보낸다. 모르는
 *          opcode는 요청이 멀쩡한데 이 서버가 못 하는 것이므로 뜻이 다르고, 진단하는
 *          쪽에서 둘을 갈라 봐야 한다.
 */
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
/** @brief 특수 요청이 올바른 질문 하나만 담았는지 확인하는지. */
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
/** @brief 하위 서버마다 정해 둔 키로 알리는지. */
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
/** @brief 고친 뒤 바뀐 부분만 보내는지. */
fn ixfr_returns_incremental_after_ddns() {
    let zone_text = "$ORIGIN ix.test.\n$TTL 300\n@ IN SOA ns1 admin 10 300 60 86400 60\n@ IN NS ns1\nns1 IN A 10.0.0.1\nold IN A 10.0.0.5\nkeep1 IN A 10.0.0.11\nkeep2 IN A 10.0.0.12\nkeep3 IN A 10.0.0.13\nkeep4 IN A 10.0.0.14\nkeep5 IN A 10.0.0.15\nkeep6 IN A 10.0.0.16\nkeep7 IN A 10.0.0.17\nkeep8 IN A 10.0.0.18\n";
    let zone = onetdns_authority::parse_zone(zone_text, "ix.test").unwrap();
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
            vec![],
            vec![ApName::from_str("ix.test").unwrap()],
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
/** @brief 감추기로 했으면 서버 이름과 버전을 답하지 않는지. */
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
/** @brief 클라이언트에 맞는 업스트림이 먼저 쓰이는지. */
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
/** @brief 허용된 이름이 업스트림으로 가는지. */
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
/** @brief 차단된 이름이 없다고 답하는지. */
fn blocked_returns_nxdomain() {
    let s = server("||blocked.test^\n");
    let resp = s.handle(&q("blocked.test"), &ctx()).unwrap();
    assert_eq!(resp.header.rcode, ResponseCode::NXDomain.0);
    assert!(resp.answers.is_empty());
}

#[test]
/**
 * @brief 목록 규칙에 막힌 질의가 그 목록을 기록에 남기는지.
 * @details 질의 기록 화면은 이 값으로 어느 구독이 막았는지 보여 주고 허용 버튼을 고른다.
 *          목록 밖에서 직접 넣은 규칙은 목록을 남기지 않아야 한다.
 */
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
    );
    let mut features = (*server.features.load()).clone();
    features.recorder = Some(recorder);
    let server = server.with_features(features);

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
/** @brief 재작성 답이 고정해 둔 주소의 수명을 쓰는지. */
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
/** @brief 안전 검색으로 바꾼 답이 고정해 둔 수명을 쓰는지. */
fn safe_search_cname_uses_local_ttl() {
    let s = server("");
    s.local_ttl.store(41, Ordering::Release);
    s.features.load().safe_search.store(true, Ordering::Release);

    let response = s.handle(&q("google.com"), &ctx()).unwrap();
    let cname = response
        .answers
        .iter()
        .find(|record| record.rtype == RecordType::CNAME)
        .expect("safe-search CNAME");
    assert_eq!(cname.ttl, 41);
}

#[test]
/** @brief 정책이 막은 답이 차단 수명을 쓰는지. */
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
/**
 * @brief 모든 것을 묻는 질의에 RFC 8482의 합성 HINFO로 답하는지.
 *
 * @details 온전한 ANY는 큰 답을 끌어내 증폭에 쓰인다. 다만 RFC 8482는 답하지 않는
 *          방법을 셋만 열거하고 그 밖에는 표준 알고리즘을 따르라고 하므로, 거절이
 *          아니라 합성 HINFO가 규격이 정한 모양이다.
 * @note DO를 설정한 질의자에게는 관례대로 답한다. 4.2가 서명된 영역이면 RRSIG를 함께
 *       요구하는데 합성한 레코드에는 붙일 서명이 없다.
 */
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

    // DO를 설정하면 합성하지 않는다. 이 서버에는 any.test 영역이 없으므로 관례 경로로 간다.
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
/** @brief 뷰에 드는 클라이언트면 다르게 답하는지. */
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
/** @brief 뷰 이름의 원래 바이트가 바뀌지 않는지. */
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
/** @brief 접근 제어가 막은 질의를 거절하는지. */
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

#[test]
/** @brief IPv6 답을 끄면 없다가 아니라 비어 있다고 답하는지. */
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
/** @brief 응답 쪽 정책이 최종 답을 막을 수 있는지. */
fn response_hook_verdict_blocks_final_answer() {
    /** @brief 테스트용 정책 플러그인. */
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
/** @brief 내부망 주소가 답에서 빠지는지. */
fn rebind_protection_strips_private() {
    let s = server("");
    update_features(&s, |features| features.rebind_protection = true);
    let resp = s.handle(&q("pub.test"), &ctx()).unwrap();
    assert_eq!(resp.answers.len(), 1, "공인 IP는 보존");
}

#[test]
/** @brief 주소 때문에 막은 답이 차단 수명을 쓰는지. */
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
/** @brief 레인이 처리하지 않는 검사는 보통 경로로 넘기는지. 안 넘기면 그 검사가 없는 것처럼 답이 나간다. */
fn reactor_lane_defers_answer_address_filters_and_ns_rpz_to_sync_path() {
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

    let rebind = lane_server(plain());
    update_features(&rebind, |features| features.rebind_protection = true);
    assert_eq!(submit(&rebind), ReactorDisposition::Fallback);

    let bogus = lane_server(plain());
    update_features(&bogus, |features| {
        features.bogus_nxdomain = vec!["7.7.7.7/32".parse().unwrap()]
    });
    assert_eq!(submit(&bogus), ReactorDisposition::Fallback);

    let denied = lane_server(plain());
    update_features(&denied, |features| {
        features.recurse_deny_answers = vec!["7.7.7.7/32".parse().unwrap()]
    });
    assert_eq!(submit(&denied), ReactorDisposition::Fallback);

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
/** @brief DDR을 켠 재귀 레인이 특수 이름만 체인에 양보하고 일반 콜드미스는 계속 맡는지. */
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
/** @brief lenient 쿠키의 무쿠키 콜드미스만 리액터가 맡고 COOKIE 질의는 발급 경로로 넘기는지. */
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

    update_features(&server, |features| features.cookies.strict = true);
    assert_eq!(
        submit(&q("strict-reactor.example")),
        ReactorDisposition::Fallback,
        "strict는 무쿠키 질의를 BADCOOKIE 경로로 넘깁니다"
    );
}

#[cfg(unix)]
#[test]
/** @brief 레인에서 일반 경로로 넘어가도 제한을 두 번 세지 않는지. */
fn reactor_submit_charges_rate_limit_once_across_fallback() {
    use onetdns_runtime::ReactorDisposition;

    /** @brief 호출 수를 세는 테스트용 제한기. */
    struct CountingLimiter(AtomicUsize);
    impl RateLimiter for CountingLimiter {
        /** @brief 세고 통과시킨다. */
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
/** @brief 두 경로 비교에 쓸 테스트용 권한 서버. */
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
/** @brief 기록을 남기는 테스트용 핸들러. */
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
    let features = server.features.load();
    let mut features = (*features).clone();
    features.recorder = Some(recorder);
    (server.with_features(features), stats)
}

#[cfg(unix)]
/** @brief 레인을 켜거나 끈 테스트용 핸들러. */
fn parity_server(authority: std::net::SocketAddr, with_lane: bool) -> NativeServer {
    parity_server_with(authority, with_lane, None)
}

#[cfg(unix)]
/** @brief 설정을 지정한 테스트용 핸들러. */
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
/** @brief 레인으로 답 하나를 받는다. */
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

/** @brief 기록들을 비교할 문자열 목록으로. */
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
/** @brief 레인의 답이 보통 경로와 같은지. 다르면 어느 경로로 갔느냐에 따라 답이 갈린다. */
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
/** @brief 최근 기록을 가져간다. */
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
/** @brief 레인도 보통 경로와 같은 기록을 남기는지. */
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
/** @brief 레인 테스트에 쓸 체인과 캐시. */
fn lane_backend_and_cache() -> (Arc<dyn Resolver>, crate::cache::CacheHandle) {
    let layer = crate::cache::CacheLayer::new(Arc::new(FixedAnswer), 64, 1, 0, 86_400, 0, 86_400);
    let handle = layer.handle();
    (Arc::new(layer), handle)
}

#[cfg(unix)]
/** @brief 언제나 잘린 응답을 내는 테스트용 권한 서버. */
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
/** @brief 일부만 잘린 응답을 내는 테스트용 권한 서버. */
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
/** @brief 느리게 답하는 테스트용 체인. */
struct SlowAnswer(std::time::Duration);

#[cfg(unix)]
impl Resolver for SlowAnswer {
    /** @brief 미리 정해 둔 응답을 돌려준다. */
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
/** @brief 다시 묻는 하나가 뒤의 질의를 막지 않는지. */
fn probe_lane_retry_fallback_head_of_line_delay() {
    use onetdns_runtime::ReactorDisposition;

    /** @brief 대체 경로로 넘어가기까지 기다릴 시간. */
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
/** @brief 레인이 다시 물어야 할 것을 보통 체인이 마저 푸는지. 안 풀면 그 질의만 오류가 된다. */
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
/**
 * @brief 레인이 넘긴 질의를 동기 체인도 풀지 못하면 그 실패 사유가 그대로 나가는지.
 * @details 대체 처리 결과를 없음으로 접으면 영구 실패도 전송 실패로 보여, 클라이언트가
 *          사실과 다른 network error 사유를 받는다.
 */
fn reactor_lane_fallback_failure_keeps_its_reason() {
    use onetdns_runtime::ReactorDisposition;

    /** @brief 언제나 영구 실패를 내는 테스트용 체인. */
    struct PermanentFailure;
    impl Resolver for PermanentFailure {
        /** @brief 언제나 답하지 않는다. */
        fn resolve(&self, _req: &Message) -> Option<Message> {
            None
        }
        /** @brief 닿을 권한 서버가 없다고 알린다. */
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
/** @brief 별칭 뒤에 숨긴 답을 내는 테스트용 권한 서버. */
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
/** @brief 레인의 답에도 별칭 뒤를 들추는 검사가 걸리는지. */
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

/** @brief IPv4 답만 내는 테스트용 업스트림. */
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
/** @brief IPv4 답으로 IPv6 답을 지어내는지. */
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

#[test]
/** @brief 서버 식별이 응답에 담기는지. */
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
/** @brief 점 없는 이름과 내부망 역조회 판정. */
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
/** @brief 밖에 새 나가면 안 되는 이름을 막는지. */
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
/**
 * @brief 밖에 못 묻게 한 이름이라도 로컬이 답할 수 있으면 그 답이 먼저 나가는지.
 * @details 자기 설정으로 만든 home.arpa 영역을 자기 empty_zones 설정이 덮으면 안 된다.
 */
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
/** @brief 올바르지 않은 문자를 고쳐서 통과시키지 않는지. 고치면 다른 이름이 규칙에 걸린다. */
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
/** @brief 검증 실패가 세어지는지. */
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
/** @brief 점 없는 이름을 밖에 묻지 않는지. */
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
/** @brief 지나치게 큰 질의를 버리는지. */
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
