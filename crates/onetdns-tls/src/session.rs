/*!
 * @brief 세션 재개.
 *
 * @details 티켓에 재개 상태를 담아 클라이언트에게 준다. 서버는 상태를 기억하지 않고
 *          티켓을 열어 복원한다.
 * @warning 티켓은 암호화되고 인증된다. 그러지 않으면 클라이언트가 재개 상태를 지어내
 *          이쪽이 그것을 믿게 된다.
 */

use crate::sys::fill_random;

/** @brief TLS 1.3이 허용하는 세션 티켓 최대 수명, 7일. */
pub const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

#[derive(Clone, Debug, PartialEq, Eq)]
/** @brief 클라이언트가 가지고 있는 재개 정보. */
pub struct TlsSession {
    /** @brief 이 세션을 발급한 서버 이름. 다른 SNI에 재사용하지 않는다. */
    pub server_name: String,

    /** @brief 이 세션의 암호 스위트. */
    pub suite: u16,

    /** @brief 다시 붙을 때 쓸 비밀. */
    pub psk: Vec<u8>,

    /** @brief 서버에 되돌려줄 티켓. */
    pub ticket: Vec<u8>,
    /** @brief 이 티켓이 유효한 기간. */
    pub lifetime_secs: u32,
    /** @brief 나이를 가리는 데 더할 값. */
    pub age_add: u32,

    /** @brief 왕복 없이 보낼 수 있는 자료 크기. */
    pub max_early_data: u32,

    /** @brief 이 세션에서 협상했던 ALPN. */
    pub alpn: Option<Vec<u8>>,

    /** @brief 이 세션에서 상대가 알렸던 전송 설정. */
    pub server_transport_params: Vec<u8>,

    /** @brief 이 티켓을 받은 시각. 나이를 측정하는 기준이다. */
    pub obtained_at_ms: u64,
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.psk.zeroize();
    }
}

impl TlsSession {
    /** @brief 티켓 나이를 가린 값. 그대로 보내면 연결을 추적당한다. */
    pub fn obfuscated_age(&self, now_ms: u64) -> u32 {
        let age = now_ms
            .saturating_sub(self.obtained_at_ms)
            .min(u32::MAX as u64) as u32;
        age.wrapping_add(self.age_add)
    }

    /** @brief 아직 쓸 수 있는지. */
    pub fn is_fresh(&self, now_ms: u64) -> bool {
        let age_secs = now_ms.saturating_sub(self.obtained_at_ms) / 1000;
        age_secs < self.lifetime_secs.min(MAX_TICKET_LIFETIME_SECS) as u64
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/** @brief 티켓 안에 담기는 재개 상태. */
pub struct ResumptionState {
    /** @brief 티켓을 발급한 SNI. */
    pub server_name: Option<String>,

    /** @brief 이 세션의 암호 스위트. */
    pub suite: u16,
    /** @brief 다시 붙을 때 쓸 비밀. */
    pub psk: Vec<u8>,
    /** @brief 이 세션에서 협상했던 ALPN. */
    pub alpn: Option<Vec<u8>>,

    /** @brief 이 티켓을 낸 시각. */
    pub issued_ms: u64,
    /** @brief 나이를 가리는 데 더할 값. */
    pub age_add: u32,
    /** @brief 이 티켓이 유효한 기간. */
    pub lifetime_secs: u32,
    /** @brief 왕복 없이 받아들일 자료 크기. */
    pub max_early_data: u32,
}

impl Drop for ResumptionState {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.psk.zeroize();
    }
}

impl ResumptionState {
    /** @brief 상태를 바이트로. */
    fn serialize(&self) -> Option<Vec<u8>> {
        if self.psk.is_empty() || self.psk.len() > u8::MAX as usize {
            return None;
        }
        if self
            .alpn
            .as_ref()
            .is_some_and(|alpn| alpn.is_empty() || alpn.len() > u8::MAX as usize)
        {
            return None;
        }
        if self.server_name.as_ref().is_some_and(|server_name| {
            server_name.is_empty() || server_name.len() > 253 || !server_name.is_ascii()
        }) {
            return None;
        }
        let mut v = Vec::new();
        v.extend_from_slice(&self.suite.to_be_bytes());
        v.push(self.psk.len() as u8);
        v.extend_from_slice(&self.psk);
        match &self.alpn {
            Some(a) => {
                v.push(a.len() as u8);
                v.extend_from_slice(a);
            }
            None => v.push(0),
        }
        match &self.server_name {
            Some(server_name) => {
                v.push(server_name.len() as u8);
                v.extend_from_slice(server_name.as_bytes());
            }
            None => v.push(0),
        }
        v.extend_from_slice(&self.issued_ms.to_be_bytes());
        v.extend_from_slice(&self.age_add.to_be_bytes());
        v.extend_from_slice(&self.lifetime_secs.to_be_bytes());
        v.extend_from_slice(&self.max_early_data.to_be_bytes());
        Some(v)
    }

    /** @brief 바이트에서 상태를 읽는다. 길이가 어긋나면 없다. */
    fn deserialize(b: &[u8]) -> Option<ResumptionState> {
        let suite = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
        let mut i = 2usize;
        let psk_len = *b.get(i)? as usize;
        i += 1;
        let psk = b.get(i..i + psk_len)?.to_vec();
        i += psk_len;
        let alpn_len = *b.get(i)? as usize;
        i += 1;
        let alpn = if alpn_len == 0 {
            None
        } else {
            let a = b.get(i..i + alpn_len)?.to_vec();
            i += alpn_len;
            Some(a)
        };
        let server_name_len = *b.get(i)? as usize;
        i += 1;
        let server_name = if server_name_len == 0 {
            None
        } else {
            let name = b.get(i..i + server_name_len)?;
            i += server_name_len;
            let name = std::str::from_utf8(name).ok()?;
            if !name.is_ascii() {
                return None;
            }
            Some(name.to_string())
        };
        let issued_ms = u64::from_be_bytes(b.get(i..i + 8)?.try_into().ok()?);
        i += 8;
        let age_add = u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?);
        i += 4;
        let lifetime_secs = u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?);
        i += 4;
        let max_early_data = u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?);
        if b.len() != i + 4 {
            return None;
        }
        Some(ResumptionState {
            server_name,
            suite,
            psk,
            alpn,
            issued_ms,
            age_add,
            lifetime_secs,
            max_early_data,
        })
    }
}

/** @brief 티켓을 암호화하고 복호화하는 것. 비밀 하나를 가지고 있다. */
pub struct Ticketer {
    /** @brief 티켓을 암호화하고 복호화하는 키. */
    key: [u8; 32],
}

impl Ticketer {
    /** @brief 새 비밀로 만든다. */
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        fill_random(&mut key);
        let ticketer = Ticketer { key };
        use zeroize::Zeroize;
        key.zeroize();
        ticketer
    }

    /** @brief 주어진 비밀로 만든다. */
    pub fn from_key(mut key: [u8; 32]) -> Self {
        let ticketer = Ticketer { key };
        use zeroize::Zeroize;
        key.zeroize();
        ticketer
    }

    /** @brief 상태를 티켓으로 봉한다. */
    pub fn seal(&self, state: &ResumptionState) -> Option<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&self.key)
            .expect("Session encryption key must be 32 bytes");
        let mut nonce = [0u8; 12];
        fill_random(&mut nonce);
        let mut plaintext = state.serialize()?;
        let encrypted = cipher.encrypt(
            (&nonce).into(),
            Payload {
                msg: &plaintext,
                aad: b"onetdns-ticket-v1",
            },
        );
        use zeroize::Zeroize;
        plaintext.zeroize();
        let ct = encrypted.ok()?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Some(out)
    }

    /**
     * @brief 티켓을 열어 상태를 되찾는다.
     * @warning 인증이 맞지 않으면 없다. 다른 서버가 만든 티켓이나 조작된 티켓이 여기서 걸린다.
     */
    pub fn open(&self, ticket: &[u8]) -> Option<ResumptionState> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        if ticket.len() < 12 + 16 {
            return None;
        }
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&self.key).ok()?;
        let nonce: [u8; 12] = ticket[..12].try_into().ok()?;
        let mut pt = cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ticket[12..],
                    aad: b"onetdns-ticket-v1",
                },
            )
            .ok()?;
        let state = ResumptionState::deserialize(&pt);
        use zeroize::Zeroize;
        pt.zeroize();
        state
    }
}

impl Drop for Ticketer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

impl Default for Ticketer {
    /** @brief 새 비밀로 만든다. */
    fn default() -> Self {
        Self::new()
    }
}

/** @brief 현재 Unix 밀리초. */
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
/** @brief 티켓 왕복과, 조작되거나 남의 티켓 거부. */
mod tests {
    use super::*;

    /** @brief 테스트용 재개 상태. */
    fn sample_state() -> ResumptionState {
        ResumptionState {
            server_name: Some("dns.example".to_string()),
            suite: 0x1301,
            psk: vec![7u8; 32],
            alpn: Some(b"doq".to_vec()),
            issued_ms: 1_700_000_000_000,
            age_add: 0xDEADBEEF,
            lifetime_secs: 7200,
            max_early_data: 0xffff_ffff,
        }
    }

    #[test]
    /** @brief 암호화하고 복호화하는 왕복. */
    fn ticket_seal_open_roundtrip() {
        let t = Ticketer::new();
        let st = sample_state();
        let ticket = t.seal(&st).unwrap();
        assert_eq!(t.open(&ticket), Some(st));
    }

    #[test]
    /** @brief 조작된 티켓과 남의 티켓을 거부하는지. */
    fn tampered_or_foreign_ticket_rejected() {
        let t = Ticketer::new();
        let mut ticket = t.seal(&sample_state()).unwrap();
        let n = ticket.len();
        ticket[n - 1] ^= 0xFF;
        assert_eq!(t.open(&ticket), None, "변조 티켓은 열리지 않아야");

        let other = Ticketer::new();
        let foreign = other.seal(&sample_state()).unwrap();
        assert_eq!(t.open(&foreign), None, "다른 STEK 티켓은 열리지 않아야");
        assert_eq!(t.open(&[0u8; 8]), None, "짧은 티켓 거부");
    }

    #[test]
    /** @brief 프로토콜이 없는 상태도 왕복하는지. */
    fn state_alpn_none_roundtrip() {
        let t = Ticketer::from_key([9u8; 32]);
        let mut st = sample_state();
        st.alpn = None;
        let ticket = t.seal(&st).unwrap();
        assert_eq!(t.open(&ticket), Some(st));
    }

    #[test]
    /** @brief 길이가 어긋난 상태를 거부하는지. */
    fn oversized_or_empty_length_prefixed_state_is_rejected() {
        let t = Ticketer::from_key([9u8; 32]);
        let mut st = sample_state();
        st.psk.clear();
        assert!(t.seal(&st).is_none());

        st.psk = vec![7; u8::MAX as usize + 1];
        assert!(t.seal(&st).is_none());

        st.psk = vec![7; 32];
        st.alpn = Some(Vec::new());
        assert!(t.seal(&st).is_none());

        st.alpn = Some(vec![b'a'; u8::MAX as usize + 1]);
        assert!(t.seal(&st).is_none());

        st.alpn = None;
        st.server_name = Some(String::new());
        assert!(t.seal(&st).is_none());
        st.server_name = Some("a".repeat(254));
        assert!(t.seal(&st).is_none());
        st.server_name = Some("한글.example".to_string());
        assert!(t.seal(&st).is_none());
    }

    #[test]
    /** @brief 가린 나이가 되감겨도 계산이 맞는지. */
    fn obfuscated_age_wraps() {
        let s = TlsSession {
            server_name: "dns.example".to_string(),
            suite: 0x1301,
            psk: vec![],
            ticket: vec![],
            lifetime_secs: 10,
            age_add: u32::MAX,
            max_early_data: 0,
            alpn: None,
            server_transport_params: vec![],
            obtained_at_ms: 1000,
        };

        assert_eq!(s.obfuscated_age(3000), 2000u32.wrapping_add(u32::MAX));
        assert!(s.is_fresh(1000 + 9_999));
        assert!(!s.is_fresh(1000 + 10_000));
    }

    #[test]
    /** @brief 서버가 더 긴 수명을 적어도 클라이언트가 7일 뒤 재사용하지 않는지. */
    fn ticket_freshness_never_exceeds_seven_days() {
        let mut session = TlsSession {
            server_name: "dns.example".to_string(),
            suite: 0x1301,
            psk: vec![1; 32],
            ticket: vec![2],
            lifetime_secs: u32::MAX,
            age_add: 0,
            max_early_data: 0,
            alpn: None,
            server_transport_params: Vec::new(),
            obtained_at_ms: 1_000,
        };
        assert!(session.is_fresh(1_000 + 604_799_000));
        assert!(!session.is_fresh(1_000 + 604_800_000));
        session.lifetime_secs = 60;
        assert!(!session.is_fresh(1_000 + 60_000));
    }
}
