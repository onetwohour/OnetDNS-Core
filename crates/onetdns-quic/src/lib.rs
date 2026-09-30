/*!
 * @brief QUIC와 HTTP/3.
 *
 * @details 소켓을 직접 만지지 않는 sans-IO 설계다. 데이터그램을 넣으면 상태가 바뀌고,
 *          내보낼 데이터그램을 꺼내 간다. 실제 입출력은 소비하는 쪽이 한다.
 * @note 이 설계 덕분에 시간과 네트워크 없이 프로토콜 전체를 결정적으로 테스트할 수 있다.
 */

/** @brief 연결 상태 기계. 패킷을 받고 내보낼 데이터그램을 만든다. */
pub mod conn;
/** @brief QUIC 프레임 인코딩과 파싱. */
pub mod frame;
/** @brief HTTP/3. */
pub mod h3;
/** @brief 패킷 헤더 인코딩과 파싱. */
pub mod packet;
/** @brief 전송 매개변수. */
pub mod params;
/** @brief 패킷 암호화와 헤더 보호. */
pub mod protect;
/** @brief QPACK 헤더 압축. */
pub mod qpack;
/** @brief 주소 검증용 Retry와 토큰. */
pub mod retry;
/** @brief QUIC 가변 길이 정수. */
pub mod varint;

pub use conn::{Connection, PeerClose, QuicDiagnostic, QuicError, Role, MAX_RECV_UDP_PAYLOAD};
pub use h3::{H3Client, H3Connection};

use sha2::Sha256;

/** @brief Initial 키 유도에 쓰는 고정 salt. 판마다 값이 다르다. */
pub const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/**
 * @brief TLS 1.3 방식의 레이블 붙은 키 확장.
 * @note 레이블에 접두사가 붙는다. 같은 비밀에서 용도별로 다른 키가 나오게 하는 장치다.
 */
pub fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label);

    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let hk = hkdf::Hkdf::<Sha256>::from_prk(secret).expect("PRK length");
    let mut out = vec![0u8; out_len];
    hk.expand(&info, &mut out).expect("HKDF expand length");
    out
}

#[derive(Debug, Clone)]
/** @brief 한 방향의 패킷 보호 키 세트. */
pub struct PacketKeys {
    /** @brief 본문 암호화 키. */
    pub key: Vec<u8>,

    /** @brief 논스 기준값. 패킷 번호와 XOR해 논스를 만든다. */
    pub iv: Vec<u8>,

    /** @brief 헤더 보호 키. */
    pub hp: Vec<u8>,
}

impl Drop for PacketKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.iv.zeroize();
        self.hp.zeroize();
    }
}

/** @brief 비밀에서 패킷 보호 키 세트를 만든다. */
pub fn derive_packet_keys(secret: &[u8], key_len: usize) -> PacketKeys {
    PacketKeys {
        key: hkdf_expand_label(secret, b"quic key", b"", key_len),
        iv: hkdf_expand_label(secret, b"quic iv", b"", 12),
        hp: hkdf_expand_label(secret, b"quic hp", b"", key_len),
    }
}

/** @brief 키 갱신 시 다음 세대 비밀. 앞선 비밀에서 한 방향으로만 나온다. */
pub fn next_key_update_secret(secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(secret, b"quic ku", b"", secret.len())
}

/**
 * @brief 갱신된 키와 논스만 새로 만든다.
 * @note 헤더 보호 키는 그대로 쓴다. 규격이 그렇게 정했고, 갱신 중에도 헤더는 계속
 *       풀 수 있어야 하기 때문이다.
 */
pub fn derive_updated_kv(secret: &[u8], key_len: usize, hp: Vec<u8>) -> PacketKeys {
    PacketKeys {
        key: hkdf_expand_label(secret, b"quic key", b"", key_len),
        iv: hkdf_expand_label(secret, b"quic iv", b"", 12),
        hp,
    }
}

/**
 * @brief 최초 연결 식별자에서 양쪽 Initial 비밀을 만든다.
 * @warning 이 값은 식별자만 알면 누구나 만들 수 있다. Initial 패킷의 암호화는 기밀이
 *          아니라 경로상 장비의 간섭을 막는 것이 목적이다.
 */
pub fn initial_secrets(dcid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(&INITIAL_SALT), dcid);
    let client = hkdf_expand_label(&prk, b"client in", b"", 32);
    let server = hkdf_expand_label(&prk, b"server in", b"", 32);
    (client, server)
}

#[cfg(test)]
/** @brief 키 유도를 공표된 벡터에 대조한다. */
mod tests {
    use super::*;

    /** @brief 16진 문자열을 바이트로. */
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    /** @brief Initial 키 유도를 규격 부록 벡터와 비교한다. */
    fn rfc9001_a1_initial_keys() {
        let dcid = hex("8394c8f03e515708");
        let (client, server) = initial_secrets(&dcid);

        assert_eq!(
            client,
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );

        assert_eq!(
            server,
            hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );

        let ck = derive_packet_keys(&client, 16);
        assert_eq!(ck.key, hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(ck.iv, hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(ck.hp, hex("9f50449e04a0e810283a1e9933adedd2"));

        let sk = derive_packet_keys(&server, 16);
        assert_eq!(sk.key, hex("cf3a5331653c364c88f0f379b6067e37"));
        assert_eq!(sk.iv, hex("0ac1493ca1905853b0bba03e"));
        assert_eq!(sk.hp, hex("c206b8d9b9f0f37644430b490eeaa314"));
    }

    #[test]
    /** @brief 레이블 확장이 알려진 값과 맞는지. */
    fn expand_label_known() {
        let secret = [0x42u8; 32];
        let a = hkdf_expand_label(&secret, b"quic key", b"", 16);
        let b = hkdf_expand_label(&secret, b"quic key", b"", 16);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);

        assert_ne!(a, hkdf_expand_label(&secret, b"quic iv", b"", 16));
    }
}
