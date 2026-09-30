/*!
 * @brief TLS 1.3 키 유도 일정.
 *
 * @details 하나의 비밀이 단계를 거치며 자란다. 초기, 핸드셰이크, 응용 순으로 나아가고 각
 *          단계에서 방향별 키가 갈라져 나온다.
 * @note 각 유도에 레이블과 핸드셰이크 기록 해시가 들어간다. 그래서 같은 키 교환이라도 핸드셰이크
 *       내용이 다르면 다른 키가 나온다.
 */

use hmac::Mac;

use crate::msg::consts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 이 스위트가 쓰는 해시. */
pub enum Hash {
    /** @brief SHA-256. */
    Sha256,
    /** @brief SHA-384. */
    Sha384,
}

impl Hash {
    /** @brief 해시 출력 길이. */
    pub fn len(&self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }

    /** @brief 해시를 계산한다. */
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Hash::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(data).to_vec(),
        }
    }
}

/** @brief 스위트에 맞는 해시와 키 길이. */
pub fn suite_params(suite: u16) -> Option<(Hash, usize)> {
    match suite {
        consts::TLS_AES_128_GCM_SHA256 => Some((Hash::Sha256, 16)),
        consts::TLS_AES_256_GCM_SHA384 => Some((Hash::Sha384, 32)),
        consts::TLS_CHACHA20_POLY1305_SHA256 => Some((Hash::Sha256, 32)),
        _ => None,
    }
}

/** @brief 입력 재료에서 의사난수 키를 추출한다. */
pub fn hkdf_extract(hash: Hash, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm)
            .0
            .to_vec(),
        Hash::Sha384 => hkdf::Hkdf::<sha2::Sha384>::extract(Some(salt), ikm)
            .0
            .to_vec(),
    }
}

/** @brief 의사난수 키를 필요한 길이로 늘린다. */
pub fn hkdf_expand(hash: Hash, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    match hash {
        Hash::Sha256 => {
            hkdf::Hkdf::<sha2::Sha256>::from_prk(prk)
                .expect("PRK length")
                .expand(info, &mut okm)
                .expect("OKM length");
        }
        Hash::Sha384 => {
            hkdf::Hkdf::<sha2::Sha384>::from_prk(prk)
                .expect("PRK length")
                .expand(info, &mut okm)
                .expect("OKM length");
        }
    }
    okm
}

/**
 * @brief 레이블을 붙여 확장한다.
 * @note 레이블에 고정 접두사가 붙는다. 같은 비밀에서 용도별로 다른 키가 나오게 하는 장치다.
 */
pub fn hkdf_expand_label(
    hash: Hash,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    let full = format!("tls13 {label}");
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(hash, secret, &info, len)
}

/** @brief 레이블과 핸드셰이크 기록 해시로 다음 비밀을 만든다. */
pub fn derive_secret(hash: Hash, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, secret, label, transcript_hash, hash.len())
}

/** @brief 비밀에서 레코드 보호용 키와 논스 기준값을 만든다. */
pub fn traffic_keys(hash: Hash, secret: &[u8], key_len: usize) -> (Vec<u8>, Vec<u8>) {
    let key = hkdf_expand_label(hash, secret, "key", &[], key_len);
    let iv = hkdf_expand_label(hash, secret, "iv", &[], 12);
    (key, iv)
}

/** @brief 다음 세대 응용 traffic secret을 만든다. */
pub fn traffic_update(hash: Hash, secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, secret, "traffic upd", &[], hash.len())
}

/** @brief 핸드셰이크 확인 값 계산에 쓸 키. */
pub fn finished_key(hash: Hash, base_key: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, base_key, "finished", &[], hash.len())
}

/** @brief 재개에 쓸 미리 공유된 키. */
pub fn resumption_psk(hash: Hash, res_master: &[u8], nonce: &[u8]) -> Vec<u8> {
    hkdf_expand_label(hash, res_master, "resumption", nonce, hash.len())
}

/**
 * @brief 상수 시간 비교.
 * @warning 핸드셰이크 확인 값 비교에 쓴다. 걸린 시간이 새면 올바른 값을 한 바이트씩 맞힐 수 있다.
 */
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/**
 * @brief 핸드셰이크 기록 전체를 확인하는 값.
 * @warning 이 값이 핸드셰이크 위조를 막는 마지막 검사다. 중간자가 메시지를 바꿨다면 여기서 어긋난다.
 */
pub fn finished_verify_data(hash: Hash, finished_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => {
            let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(finished_key).expect("key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
        Hash::Sha384 => {
            let mut m = hmac::Hmac::<sha2::Sha384>::new_from_slice(finished_key).expect("key");
            m.update(transcript_hash);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/** @brief 핸드셰이크 기록. 오간 메시지를 순서대로 해시한다. */
pub struct Transcript {
    /** @brief 쓰는 요약 방식. */
    hash: Hash,
    /** @brief 지금까지 오간 핸드셰이크 바이트. */
    data: Vec<u8>,
}

impl Transcript {
    /** @brief 빈 기록. */
    pub fn new(hash: Hash) -> Self {
        Self {
            hash,
            data: Vec::new(),
        }
    }

    /** @brief 핸드셰이크 기록 버퍼가 allocator에서 보유한 바이트. */
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.data.capacity()
    }

    /** @brief 메시지를 기록에 더한다. 와이어 바이트 그대로다. */
    pub fn update(&mut self, msg_wire: &[u8]) {
        self.data.extend_from_slice(msg_wire);
    }

    /** @brief 지금까지의 기록 해시. */
    pub fn hash(&self) -> Vec<u8> {
        self.hash.digest(&self.data)
    }

    /** @brief 기록 원본. */
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /**
     * @brief 기록을 그 해시로 바꾼다.
     * @details 서버가 다시 시도를 요청할 때 규격이 정한 절차다. 원본을 그대로 두면
     *          양쪽 기록이 갈린다.
     */
    pub fn replace_with_message_hash(&mut self) {
        let ch_hash = self.hash.digest(&self.data);
        let mut synthetic = vec![254u8, 0x00, 0x00, ch_hash.len() as u8];
        synthetic.extend_from_slice(&ch_hash);
        self.data = synthetic;
    }
}

/** @brief 지금 단계의 비밀을 가지고 있는 것. */
pub struct KeySchedule {
    /** @brief 쓰는 요약 방식. */
    hash: Hash,
    /** @brief 여기서 다음 비밀을 이끌어 낸다. */
    secret: Vec<u8>,
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

impl KeySchedule {
    /** @brief 미리 공유된 키 없이 시작한다. */
    pub fn new(hash: Hash) -> Self {
        let zeros = vec![0u8; hash.len()];
        let early = hkdf_extract(hash, &zeros, &zeros);
        Self {
            hash,
            secret: early,
        }
    }

    /** @brief 현재 key schedule 비밀 버퍼가 보유한 바이트. */
    pub(crate) fn retained_payload_bytes(&self) -> usize {
        self.secret.capacity()
    }

    /** @brief 미리 공유된 키로 시작한다. 재개에 쓴다. */
    pub fn new_with_psk(hash: Hash, psk: &[u8]) -> Self {
        let zeros = vec![0u8; hash.len()];
        let early = hkdf_extract(hash, &zeros, psk);
        Self {
            hash,
            secret: early,
        }
    }

    /** @brief 재개 제안을 핸드셰이크 기록에 묶고 중간 비밀은 반환 전에 지운다. */
    pub fn psk_binder(&self, truncated_ch_hash: &[u8]) -> Vec<u8> {
        use zeroize::Zeroizing;
        let binder_key = Zeroizing::new(derive_secret(
            self.hash,
            &self.secret,
            "res binder",
            &self.empty_hash(),
        ));
        let finished = Zeroizing::new(finished_key(self.hash, &binder_key));
        finished_verify_data(self.hash, &finished, truncated_ch_hash)
    }

    /** @brief 조기 데이터 보호에 쓸 비밀. */
    pub fn client_early_traffic_secret(&self, ch_transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "c e traffic", ch_transcript_hash)
    }

    /** @brief 다음 재개에 쓸 비밀. */
    pub fn resumption_master_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "res master", transcript_hash)
    }

    /** @brief 이 일정이 쓰는 해시. */
    pub fn hash(&self) -> Hash {
        self.hash
    }

    /** @brief 지금 단계의 비밀. */
    pub fn current_secret(&self) -> &[u8] {
        &self.secret
    }

    /** @brief 키 교환 결과를 넣어 핸드셰이크 단계로 나아간다. */
    pub fn enter_handshake(&mut self, ecdhe: &[u8]) {
        use zeroize::Zeroize;
        let mut derived = derive_secret(self.hash, &self.secret, "derived", &self.empty_hash());
        let next = hkdf_extract(self.hash, &derived, ecdhe);
        derived.zeroize();
        self.secret.zeroize();
        self.secret = next;
    }

    /** @brief 응용 단계로 나아간다. */
    pub fn enter_master(&mut self) {
        use zeroize::Zeroize;
        let mut derived = derive_secret(self.hash, &self.secret, "derived", &self.empty_hash());
        let zeros = vec![0u8; self.hash.len()];
        let next = hkdf_extract(self.hash, &derived, &zeros);
        derived.zeroize();
        self.secret.zeroize();
        self.secret = next;
    }

    /** @brief 클라이언트 방향 핸드셰이크 비밀. */
    pub fn client_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "c hs traffic", transcript_hash)
    }
    /** @brief 서버 방향 핸드셰이크 비밀. */
    pub fn server_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "s hs traffic", transcript_hash)
    }
    /** @brief 클라이언트 방향 응용 비밀. */
    pub fn client_application_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "c ap traffic", transcript_hash)
    }
    /** @brief 서버 방향 응용 비밀. */
    pub fn server_application_traffic_secret(&self, transcript_hash: &[u8]) -> Vec<u8> {
        derive_secret(self.hash, &self.secret, "s ap traffic", transcript_hash)
    }

    /** @brief 빈 입력의 해시. 단계 사이 유도에 쓰인다. */
    fn empty_hash(&self) -> Vec<u8> {
        self.hash.digest(&[])
    }
}

#[cfg(test)]
/** @brief 유도 결과를 공표된 벡터에 대조하고, 단계 진행이 결정적인지 본다. */
mod tests {
    use super::*;

    /** @brief 16진 문자열을 바이트로. */
    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    /** @brief HKDF 구현을 규격 벡터와 비교한다. */
    fn rfc5869_hkdf_sha256_vector() {
        let ikm = vec![0x0b; 22];
        let salt = hx("000102030405060708090a0b0c");
        let info = hx("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(Hash::Sha256, &salt, &ikm);
        assert_eq!(
            prk,
            hx("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = hkdf_expand(Hash::Sha256, &prk, &info, 42);
        assert_eq!(
            okm,
            hx("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    #[test]
    /** @brief 레이블 확장의 입력 배치가 규격과 맞는지. */
    fn expand_label_info_layout() {
        let secret = vec![0xABu8; 32];
        let got = hkdf_expand_label(Hash::Sha256, &secret, "key", &[], 4);
        let mut info = Vec::new();
        info.extend_from_slice(&4u16.to_be_bytes());
        let full = b"tls13 key";
        info.push(full.len() as u8);
        info.extend_from_slice(full);
        info.push(0);
        let expect = hkdf_expand(Hash::Sha256, &secret, &info, 4);
        assert_eq!(got, expect);
        assert_eq!(got.len(), 4);
    }

    #[test]
    /** @brief 같은 입력에서 같은 비밀이 나오는지. */
    fn key_schedule_progression_deterministic() {
        let hash = Hash::Sha256;
        let mut ks = KeySchedule::new(hash);
        let early = ks.current_secret().to_vec();
        assert_eq!(early.len(), 32);

        ks.enter_handshake(&[0x07; 32]);
        let hs_secret = ks.current_secret().to_vec();
        assert_ne!(hs_secret, early);

        let th = hash.digest(b"transcript-up-to-serverhello");
        let chs = ks.client_handshake_traffic_secret(&th);
        let shs = ks.server_handshake_traffic_secret(&th);
        assert_eq!(chs.len(), 32);
        assert_ne!(chs, shs);

        let (key, iv) = traffic_keys(hash, &chs, 16);
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);

        let fk = finished_key(hash, &shs);
        let vd1 = finished_verify_data(hash, &fk, &th);
        let vd2 = finished_verify_data(hash, &fk, &th);
        assert_eq!(vd1, vd2);
        assert_eq!(vd1.len(), 32);

        let vd3 = finished_verify_data(hash, &fk, &hash.digest(b"other"));
        assert_ne!(vd1, vd3);

        ks.enter_master();
        let cap = ks.client_application_traffic_secret(&th);
        assert_eq!(cap.len(), 32);
        assert_ne!(cap, chs);
    }

    #[test]
    /** @brief 스위트에서 해시와 키 길이가 제대로 골라지는지. */
    fn suite_params_lookup() {
        assert_eq!(
            suite_params(consts::TLS_AES_128_GCM_SHA256),
            Some((Hash::Sha256, 16))
        );
        assert_eq!(
            suite_params(consts::TLS_AES_256_GCM_SHA384),
            Some((Hash::Sha384, 32))
        );
        assert_eq!(
            suite_params(consts::TLS_CHACHA20_POLY1305_SHA256),
            Some((Hash::Sha256, 32))
        );
        assert_eq!(suite_params(0x0000), None);
    }
}
