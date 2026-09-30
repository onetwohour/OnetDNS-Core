/*!
 * @brief DNSCrypt UDP 리스너.
 */

use std::net::{SocketAddr, UdpSocket};

use crate::{
    decrypt_query, encrypt_response, Provider, CLIENT_MAGIC_LEN, CLIENT_NONCE_LEN, PUBKEY_LEN,
    RESOLVER_MAGIC,
};

/** @brief 암호화 질의의 고정 헤더 길이: 매직 + 클라이언트 공개키 + 논스. */
const HEADER_LEN: usize = CLIENT_MAGIC_LEN + PUBKEY_LEN + CLIENT_NONCE_LEN;

/** @brief Poly1305 인증 태그 길이. 이보다 짧은 본문은 복호화할 것이 없다. */
const AEAD_TAG_LEN: usize = 16;

/** @brief 응답 패킷의 고정 부분: 리졸버 매직 + 논스 + 인증 태그. */
const RESPONSE_OVERHEAD: usize = RESOLVER_MAGIC.len() + 24 + AEAD_TAG_LEN;

/** @brief 응답 평문을 맞추는 블록 크기. */
const PAD_BLOCK: usize = 64;

/**
 * @brief 이 질의에 담아 보낼 수 있는 DNS 응답 크기.
 *
 * @details UDP 응답 패킷은 그것을 부른 질의 패킷보다 길면 안 된다. 출처를 속인 작은
 *          질의 하나가 큰 응답을 끌어내는 증폭이 되기 때문이다. 평문은 64의 배수로
 *          채워지고 패딩은 최소 한 바이트라, 남는 곳에서 그만큼을 뺀 값이 예산이다.
 * @return 넘지 않아야 할 DNS 메시지 바이트 수. 0이면 답을 담을 슬롯이 없다.
 */
fn response_budget(query_len: usize) -> usize {
    let room = query_len.saturating_sub(RESPONSE_OVERHEAD);
    (room / PAD_BLOCK * PAD_BLOCK).saturating_sub(1)
}

/**
 * @brief TCP 로 담아 보낼 수 있는 DNS 응답 크기.
 * @details TCP 는 핸드셰이크로 출처가 확인되므로 증폭이 성립하지 않는다. 규격도 응답을 그대로
 *          보내라고 한다. 길이 접두사가 16비트인 것만이 상한이다.
 */
const TCP_RESPONSE_BUDGET: usize = u16::MAX as usize - RESPONSE_OVERHEAD - PAD_BLOCK;

/**
 * @brief 받아들일 TCP 질의 길이 상한.
 * @details 질의를 답 크기에 맞춰 부풀릴 까닭이 TCP 에는 없다. 길이 접두사만 믿고 곳을
 *          잡아 주면 아무 숫자나 적어 보낸 쪽이 메모리를 정하게 된다.
 */
pub const MAX_TCP_QUERY: usize = 8192;

/**
 * @brief 패킷 하나에 대한 응답을 만든다. UDP 와 TCP 가 함께 쓴다.
 *
 * @details 앞 8바이트로 두 경우로 나눈다. 클라이언트 매직이면 암호화 질의, 아니면
 *          인증서 조회일 수 있다. 어느 쪽도 아니면 답하지 않는다.
 * @param over_udp UDP 이면 응답을 질의 길이 안으로 줄인다. TCP 는 핸드셰이크로 출처가 확인되어
 *                 증폭이 성립하지 않으므로 그대로 보낸다.
 * @return 보낼 페이로드. TCP 라도 길이 접두사는 붙이지 않는다.
 */
pub fn respond<H, A>(
    provider: &Provider,
    packet: &[u8],
    src: SocketAddr,
    over_udp: bool,
    handler: &H,
    allowed: &A,
) -> Option<Vec<u8>>
where
    H: Fn(Vec<u8>, SocketAddr, usize) -> Option<Vec<u8>>,
    A: Fn(SocketAddr) -> bool,
{
    if packet.len() >= CLIENT_MAGIC_LEN && packet[..CLIENT_MAGIC_LEN] == provider.client_magic {
        if packet.len() < HEADER_LEN + AEAD_TAG_LEN {
            return None;
        }
        let mut client_pk = [0u8; 32];
        client_pk.copy_from_slice(&packet[CLIENT_MAGIC_LEN..CLIENT_MAGIC_LEN + PUBKEY_LEN]);
        let mut client_nonce = [0u8; 12];
        client_nonce.copy_from_slice(&packet[CLIENT_MAGIC_LEN + PUBKEY_LEN..HEADER_LEN]);

        let key = provider.shared_key(&client_pk);
        let dns_query = match decrypt_query(&key, &client_nonce, &packet[HEADER_LEN..]) {
            Some(query) => query,
            None => {
                onetdns_core::trace!(%src, "Could not decrypt DNSCrypt request");
                return None;
            }
        };

        let budget = if over_udp {
            response_budget(packet.len())
        } else {
            TCP_RESPONSE_BUDGET
        };
        if budget == 0 {
            return None;
        }
        let dns_response = handler(dns_query, src, budget)?;
        if dns_response.len() > budget {
            onetdns_core::debug!(event = "dnscrypt.response_over_budget", client = %src, len = dns_response.len(), budget = budget, "Response exceeds the size budget; not sent");
            return None;
        }
        let (nonce, ct) = encrypt_response(&key, &client_nonce, &dns_response);
        let mut out = Vec::with_capacity(RESOLVER_MAGIC.len() + nonce.len() + ct.len());
        out.extend_from_slice(&RESOLVER_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Some(out)
    } else if allowed(src) {
        provider.cert_txt_response(packet)
    } else {
        None
    }
}

/**
 * @brief 응답 전송 실패를 기록한다.
 * @details 닿지 않는 클라이언트가 대량으로 질의하면 실패마다 기록하는 것 자체가 부하가
 *          된다. 2의 거듭제곱 번째만 남긴다.
 */
fn record_send_error(src: SocketAddr, error: &std::io::Error) {
    use std::sync::atomic::{AtomicU64, Ordering};
    /** @brief 누적 실패 수. */
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let count = COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        onetdns_core::warn!(event = "dnscrypt.send_failed", client = %src, count = count, %error, "Could not send DNSCrypt response");
    }
}

/**
 * @brief DNSCrypt 질의를 받아 처리한다.
 *
 * @details 패킷 앞 8바이트로 두 경우로 나눈다. 클라이언트 매직이면 암호화 질의,
 *          아니면 인증서 TXT 질의일 수 있다. 어느 쪽도 아니면 조용히 버린다.
 * @param handler 복호화된 DNS 질의와 응답 크기 예산을 받아 응답을 돌려주는 콜백.
 * @param allowed 이 주소에 답해도 되는지 묻는 콜백. 인증서 조회는 암호도 인증도 없이
 *                누구나 부를 수 있어, 여기서 막지 않으면 접근 제어와 속도 제한을 전혀
 *                거치지 않는 증폭 경로가 된다.
 * @note 패킷 하나마다 장애 격리 경계를 친다. 조작된 패킷이 유발한 패닉이 리스너 전체를
 *       죽이지 않게 하려는 것이다.
 * @note 읽기에 타임아웃을 걸어야 종료 신호를 주기적으로 확인할 수 있다. 무한 대기면
 *       재로드 때 이 스레드가 합류하지 않아 소켓이 계속 묶인다.
 */
pub fn serve<H, A>(
    provider: Provider,
    socket: UdpSocket,
    handler: H,
    allowed: A,
    shutdown: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()>
where
    H: Fn(Vec<u8>, SocketAddr, usize) -> Option<Vec<u8>>,
    A: Fn(SocketAddr) -> bool,
{
    let wait = onetdns_core::udp::RecvWait::new(std::time::Duration::from_millis(500));
    if let Err(error) = wait.install(&socket) {
        onetdns_core::error!(event = "dnscrypt.read_timeout_failed", %error, "Could not set a receive timeout; this thread will not exit on reload and will keep the port bound");
    }
    let mut buf = vec![0u8; 4096];
    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        let (n, src) = match wait.recv_from(&socket, &mut buf) {
            Ok(x) => x,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                onetdns_core::debug!(event = "dnscrypt.recv_failed", error = %e, "Failed to receive DNSCrypt packet");
                continue;
            }
        };
        let packet = &buf[..n];

        let _ = onetdns_core::isolation::catch_request(|| {
            if let Some(out) = respond(&provider, packet, src, true, &handler, &allowed) {
                if let Err(error) = socket.send_to(&out, src) {
                    record_send_error(src, &error);
                }
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /**
     * @brief 응답 패킷이 질의 패킷보다 길어지지 않는지.
     *
     * @details 출처를 속인 작은 질의 하나로 큰 응답을 끌어낼 수 있으면 리졸버가 증폭기가
     *          된다. 규격이 응답을 질의 길이 안으로 줄이고 TC 비트를 설정하라고 하는 까닭이다.
     * @note 예산은 DNS 메시지 길이 기준이다. 여기에 매직과 논스, 인증 태그, 그리고 64의
     *       배수로 맞추는 패딩이 붙은 것이 실제 패킷이다.
     */
    fn a_response_never_outgrows_the_query_that_asked_for_it() {
        for query_len in [132usize, 256, 324, 512, 1024, 1500, 4096] {
            let budget = response_budget(query_len);
            let padded = crate::pad(&vec![0u8; budget], PAD_BLOCK).len();
            let packet = RESPONSE_OVERHEAD + padded;
            assert!(
                packet <= query_len,
                "질의 {query_len}B 에 응답 {packet}B 는 증폭입니다 (예산 {budget})"
            );
        }
    }

    #[test]
    /** @brief 답을 담을 슬롯이 없는 짧은 질의는 예산이 0이 되는지. */
    fn a_query_too_short_to_carry_an_answer_gets_no_budget() {
        for query_len in [0usize, 48, 100, 111] {
            assert_eq!(response_budget(query_len), 0, "{query_len}B");
        }
    }

    /** @brief 인증서 조회 하나를 보내고 답이 오는지 본다. */
    fn ask_for_cert(allow: bool) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};

        let provider = Provider::generate("2.dnscrypt-cert.test", 86_400);
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            let _ = serve(
                provider,
                server,
                |_query, _src, _budget| None,
                move |_src| allow,
                &worker_stop,
            );
        });

        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in "2.dnscrypt-cert.test".split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 16, 0, 1]);

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(700)))
            .unwrap();
        client.send_to(&query, addr).unwrap();
        let mut buf = [0u8; 4096];
        let answered = client.recv_from(&mut buf).is_ok();
        stop.store(true, Ordering::Release);
        let _ = thread.join();
        answered
    }

    /** @brief 이 공급자에게 보낼 암호화 질의 하나를 만든다. */
    fn build_query(provider: &Provider, dns: &[u8], pad_to: usize) -> Vec<u8> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut csk = [0u8; 32];
        onetdns_core::fill_random(&mut csk);
        let client_sk = StaticSecret::from(csk);
        let client_pk = PublicKey::from(&client_sk).to_bytes();
        let raw = client_sk
            .diffie_hellman(&PublicKey::from(provider.resolver_pk))
            .to_bytes();
        let shared = crate::box_beforenm(&raw);

        let mut client_nonce = [0u8; 12];
        onetdns_core::fill_random(&mut client_nonce);
        let mut nonce = [0u8; 24];
        nonce[..12].copy_from_slice(&client_nonce);

        let mut padded = dns.to_vec();
        padded.push(0x80);
        while padded.len() < pad_to {
            padded.push(0);
        }
        let mut packet = Vec::new();
        packet.extend_from_slice(&provider.client_magic);
        packet.extend_from_slice(&client_pk);
        packet.extend_from_slice(&client_nonce);
        packet.extend_from_slice(&crate::secretbox_seal(&shared, &nonce, &padded));
        packet
    }

    #[test]
    /**
     * @brief TCP 는 응답을 질의 길이에 맞춰 줄이지 않는지.
     *
     * @details UDP 는 출처를 속일 수 있어 응답을 질의 안으로 줄여야 하지만, TCP 는 핸드셰이크로
     *          출처가 확인되므로 증폭이 성립하지 않는다. 규격도 TCP 응답은 질의보다 길어도
     *          그대로 보내라고 한다. 여기서 줄이면 큰 답이 갈 길이 아예 없어진다.
     */
    fn tcp_does_not_shrink_the_answer_to_the_query() {
        let provider = Provider::generate("2.dnscrypt-cert.test", 86_400);
        let dns: &[u8] =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x04test\x00\x00\x01\x00\x01";
        let packet = build_query(&provider, dns, 256);

        let seen = std::sync::Mutex::new(Vec::new());
        let handler = |_q: Vec<u8>, _src: SocketAddr, budget: usize| -> Option<Vec<u8>> {
            seen.lock().unwrap().push(budget);
            None
        };
        let allow = |_src: SocketAddr| true;
        let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        respond(&provider, &packet, src, true, &handler, &allow);
        respond(&provider, &packet, src, false, &handler, &allow);
        let budgets = seen.lock().unwrap().clone();
        assert_eq!(budgets.len(), 2, "두 번 다 핸들러에 닿아야 합니다");
        assert!(
            budgets[0] < packet.len(),
            "UDP 예산 {}은 질의 {}보다 작아야 합니다",
            budgets[0],
            packet.len()
        );
        assert!(
            budgets[1] > 4096,
            "TCP 예산 {}이 질의 길이에 묶여 있습니다",
            budgets[1]
        );
    }

    #[test]
    /**
     * @brief 인증서 조회도 접근 제어와 속도 제한 뒤에 있는지.
     *
     * @details 이 경로는 암호도 인증도 없이 누구나 부를 수 있고 질의보다 네 배 큰 답을
     *          돌려준다. 파이프라인을 타지 않으므로 여기서 막지 않으면 그 경로만 아무
     *          제한 없이 열린 증폭기가 된다.
     */
    fn the_certificate_lookup_answers_only_allowed_clients() {
        assert!(ask_for_cert(true), "허용된 클라이언트는 답을 받아야 합니다");
        assert!(
            !ask_for_cert(false),
            "막힌 클라이언트에게 인증서를 내주면 안 됩니다"
        );
    }
}
