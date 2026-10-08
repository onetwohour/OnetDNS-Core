/*!
 * @brief 권한 zone 온라인 서명.
 *
 * @details 이 서버가 서빙하는 zone에 RRSIG와 부재 증명 체인을 붙인다. 기본 알고리즘은 13이고,
 *          존별로 15(Ed25519)를 고를 수 있다. 서명이 3배 싸지만 알고리즘 15를 모르는
 *          검증기는 그 zone을 insecure로 떨어뜨리므로 기본값은 바꾸지 않는다.
 * @note 검증기와 같은 signed_data를 써서 서명 대상을 만든다. 서명자와 검증자가 따로
 *       정규형을 구현하면 어긋나는 순간을 알아차릴 수 없다.
 */

use onetdns_proto::{DnsClass, Name, RData, Record, RecordType};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{signed_data, Dnskey, Ds, Rrsig};

/** @brief 유효 개시를 현재보다 이만큼 앞당긴다. 검증기와 이 서버의 시계가 어긋나도 견디게 한다. */
const INCEPTION_SKEW: u64 = 3_600;
/** @brief 서명 유효 기간. 짧으면 재서명이 잦고, 길면 폐기가 늦게 반영된다. */
const VALIDITY: u64 = 14 * 86_400;

/**
 * @brief zone 서명에 쓸 알고리즘.
 *
 * @details 기본값은 13이다. 서명 비용은 알고리즘 15가 더 싸므로 zone마다 15를 고를 수
 *          있게 열어 두었다. 검증기 조합을 늘리지 않으려고 기본값은 옮기지 않는다.
 * @note 알고리즘 15를 모르는 검증기는 그 zone을 bogus가 아니라 insecure로 떨어뜨린다.
 *       상호운용 판단이 필요한 선택이므로 기본값을 바꾸지 않는다.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignAlgorithm {
    /** @brief 알고리즘 13. ECDSA P-256 + SHA-256. */
    #[default]
    EcdsaP256,
    /** @brief 알고리즘 15. Ed25519(RFC 8080). */
    Ed25519,
}

impl SignAlgorithm {
    /** @brief DNSKEY와 RRSIG에 담을 번호. */
    pub fn number(self) -> u8 {
        match self {
            SignAlgorithm::EcdsaP256 => 13,
            SignAlgorithm::Ed25519 => 15,
        }
    }

    /** @brief 설정 문자열에서. 모르는 이름은 None. */
    pub fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "ecdsap256" => Some(SignAlgorithm::EcdsaP256),
            "ed25519" => Some(SignAlgorithm::Ed25519),
            _ => None,
        }
    }
}

/**
 * @brief 실제 서명 키. 알고리즘마다 다른 곡선을 쓴다.
 * @invariant 이 열거형이 곧 알고리즘 번호의 단일 출처다. 서명·DNSKEY·PEM이 모두 여기서
 *            갈라지므로 한쪽만 바꾸면 공표한 키와 실제 서명이 어긋난다.
 */
enum SignKey {
    /** @brief 알고리즘 13. */
    EcdsaP256(SigningKey),
    /** @brief 알고리즘 15. 서명이 훨씬 싸다. */
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

impl SignKey {
    /** @brief 이 키의 알고리즘. */
    fn algorithm(&self) -> SignAlgorithm {
        match self {
            SignKey::EcdsaP256(_) => SignAlgorithm::EcdsaP256,
            SignKey::Ed25519(_) => SignAlgorithm::Ed25519,
        }
    }

    /** @brief 시드에서 키를 만든다. 시드가 쓸 수 없으면 다시 해시해 고른다. */
    fn from_seed(algorithm: SignAlgorithm, seed: [u8; 32]) -> Self {
        match algorithm {
            SignAlgorithm::EcdsaP256 => SignKey::EcdsaP256(key_from_seed(seed)),
            SignAlgorithm::Ed25519 => {
                let mut seed = Zeroizing::new(seed);
                let key = ed25519_dalek::SigningKey::from_bytes(&seed);
                seed.zeroize();
                SignKey::Ed25519(Box::new(key))
            }
        }
    }

    /** @brief 서명 대상 바이트에 서명한다. */
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            SignKey::EcdsaP256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(data);
                signature.to_bytes().to_vec()
            }
            SignKey::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(data).to_bytes().to_vec()
            }
        }
    }

    /** @brief DNSKEY RDATA에 담을 공개 키 바이트. */
    fn public_key(&self) -> Vec<u8> {
        match self {
            SignKey::EcdsaP256(key) => {
                let point = key.verifying_key().to_encoded_point(false);
                let mut pk = Vec::with_capacity(64);
                pk.extend_from_slice(
                    point
                        .x()
                        .expect("P-256 public key must have an x coordinate"),
                );
                pk.extend_from_slice(
                    point
                        .y()
                        .expect("P-256 public key must have a y coordinate"),
                );
                pk
            }
            SignKey::Ed25519(key) => key.verifying_key().to_bytes().to_vec(),
        }
    }

    /** @brief PKCS#8 PEM으로 내보낸다. 재시작 사이 키를 보존하는 용도다. */
    fn to_pkcs8_pem(&self) -> Option<Zeroizing<String>> {
        match self {
            SignKey::EcdsaP256(key) => key.to_pkcs8_pem(Default::default()).ok(),
            SignKey::Ed25519(key) => key.to_pkcs8_pem(Default::default()).ok(),
        }
    }

    /**
     * @brief PKCS#8 PEM에서 읽는다.
     * @details 알고리즘을 지정하지 않는다. 저장된 키 자체가 무엇인지 말한다. P-256으로
     *          읽히지 않으면 Ed25519로 시도한다.
     */
    fn from_pkcs8_pem(pem: &str) -> Option<Self> {
        if let Ok(key) = SigningKey::from_pkcs8_pem(pem) {
            return Some(SignKey::EcdsaP256(key));
        }
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .ok()
            .map(|key| SignKey::Ed25519(Box::new(key)))
    }
}

/**
 * @brief 한 zone의 서명자.
 * @details KSK를 따로 두지 않으면 키 하나가 SEP까지 겸한다. 나눠 두면 DNSKEY RRset은
 *          KSK로, 나머지는 ZSK로 서명한다.
 */
pub struct ZoneSigner {
    /** @brief ZSK. KSK가 없으면 이 키가 전부를 서명한다. */
    key: SignKey,
    /** @brief KSK. 있으면 DNSKEY RRset 전용 서명 키다. */
    ksk: Option<SignKey>,

    /** @brief zone apex. 서명자 이름이자 DNSKEY의 소유자다. */
    pub owner: Name,

    /** @brief 서명에는 쓰지 않고 DNSKEY RRset에만 담을 키들. 롤오버 사전 공표용이다. */
    published_extra: Vec<Dnskey>,
}

impl ZoneSigner {
    /** @brief 시드에서 ZSK 하나를 만든다. 그 키가 SEP까지 겸한다. */
    pub fn generate(owner: Name, seed: [u8; 32]) -> ZoneSigner {
        Self::generate_with(owner, seed, SignAlgorithm::default())
    }

    /** @brief 알고리즘을 골라 ZSK 하나를 만든다. */
    pub fn generate_with(owner: Name, seed: [u8; 32], algorithm: SignAlgorithm) -> ZoneSigner {
        ZoneSigner {
            key: SignKey::from_seed(algorithm, seed),
            ksk: None,
            owner,
            published_extra: Vec::new(),
        }
    }

    /** @brief 이 서명자가 쓰는 알고리즘. */
    pub fn algorithm(&self) -> SignAlgorithm {
        self.key.algorithm()
    }

    /** @brief ZSK와 KSK를 각각 만든다. KSK만 부모에 DS로 올리면 ZSK는 자유롭게 굴릴 수 있다. */
    pub fn generate_split(owner: Name, zsk_seed: [u8; 32], ksk_seed: [u8; 32]) -> ZoneSigner {
        Self::generate_split_with(owner, zsk_seed, ksk_seed, SignAlgorithm::default())
    }

    /** @brief 알고리즘을 골라 ZSK와 KSK를 만든다. */
    pub fn generate_split_with(
        owner: Name,
        zsk_seed: [u8; 32],
        ksk_seed: [u8; 32],
        algorithm: SignAlgorithm,
    ) -> ZoneSigner {
        ZoneSigner {
            key: SignKey::from_seed(algorithm, zsk_seed),
            ksk: Some(SignKey::from_seed(algorithm, ksk_seed)),
            owner,
            published_extra: Vec::new(),
        }
    }

    /** @brief 저장된 ZSK를 PEM에서 읽는다. 재시작해도 같은 키로 서명해야 캐시가 깨지지 않는다. */
    pub fn from_pkcs8_pem(pem: &str, owner: Name) -> Option<ZoneSigner> {
        let key = SignKey::from_pkcs8_pem(pem)?;
        Some(ZoneSigner {
            key,
            ksk: None,
            owner,
            published_extra: Vec::new(),
        })
    }

    /**
     * @brief 저장된 ZSK와 선택적 KSK를 읽는다.
     * @return 어느 한쪽이라도 해석되지 않으면 None. 절반만 읽고 나머지를 새로 만들면
     *         공표된 DNSKEY와 실제 서명 키가 어긋난다.
     */
    pub fn from_pkcs8_pems(
        zsk_pem: &str,
        ksk_pem: Option<&str>,
        owner: Name,
    ) -> Option<ZoneSigner> {
        let key = SignKey::from_pkcs8_pem(zsk_pem)?;
        let ksk = match ksk_pem {
            Some(p) => Some(SignKey::from_pkcs8_pem(p)?),
            None => None,
        };
        Some(ZoneSigner {
            key,
            ksk,
            owner,
            published_extra: Vec::new(),
        })
    }

    /**
     * @brief 서명에는 쓰지 않되 DNSKEY RRset에 함께 담을 키를 등록한다.
     * @details 롤오버는 새 키를 먼저 공표하고, 검증기들이 그것을 본 뒤에야 서명을 옮겨야
     *          한다. 공표 없이 바로 바꾸면 그 사이 응답이 전부 검증 실패한다.
     */
    pub fn with_published_keys(mut self, extra: Vec<Dnskey>) -> Self {
        self.published_extra = extra;
        self
    }

    /** @brief ZSK를 PEM으로 내보낸다. 재시작 사이 키를 보존하는 용도다. */
    pub fn to_pkcs8_pem(&self) -> Option<Zeroizing<String>> {
        self.key.to_pkcs8_pem()
    }

    /** @brief KSK를 PEM으로 내보낸다. 나눠 두지 않았으면 None. */
    pub fn ksk_pem(&self) -> Option<Zeroizing<String>> {
        self.ksk.as_ref()?.to_pkcs8_pem()
    }

    /** @brief KSK와 ZSK가 나뉘어 있는지. */
    pub fn is_split(&self) -> bool {
        self.ksk.is_some()
    }

    /** @brief DNSKEY RRset에 담길 키 전부: ZSK, 있으면 KSK, 그리고 사전 공표 키들. */
    pub fn dnskeys(&self) -> Vec<Dnskey> {
        let mut v = vec![self.dnskey()];
        if let Some(k) = self.ksk_dnskey() {
            v.push(k);
        }
        v.extend(self.published_extra.iter().cloned());
        v
    }

    /**
     * @brief ZSK의 DNSKEY.
     * @note KSK가 없으면 이 키가 SEP도 겸하므로 플래그가 257이 된다. 나뉘어 있으면 256이다.
     */
    pub fn dnskey(&self) -> Dnskey {
        let flags = if self.ksk.is_some() { 256 } else { 257 };
        dnskey_of(&self.key, flags)
    }

    /** @brief KSK의 DNSKEY. 항상 SEP 플래그가 붙는다. */
    pub fn ksk_dnskey(&self) -> Option<Dnskey> {
        self.ksk.as_ref().map(|k| dnskey_of(k, 257))
    }

    /** @brief 공표할 DNSKEY 레코드 전부. apex 소유자로 만든다. */
    pub fn dnskey_records(&self, ttl: u32) -> Vec<Record> {
        let mut v = vec![Record {
            name: self.owner.clone(),
            rtype: RecordType(48),
            class: DnsClass::IN,
            ttl,
            rdata: RData::Unknown(48, self.dnskey().rdata_bytes()),
        }];
        if let Some(ksk) = self.ksk_dnskey() {
            v.push(Record {
                name: self.owner.clone(),
                rtype: RecordType(48),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(48, ksk.rdata_bytes()),
            });
        }

        for k in &self.published_extra {
            v.push(Record {
                name: self.owner.clone(),
                rtype: RecordType(48),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(48, k.rdata_bytes()),
            });
        }
        v
    }

    /**
     * @brief 부모에 올릴 DS. KSK가 있으면 그것으로, 없으면 ZSK로 만든다.
     * @note 부모가 지목하는 키가 곧 신뢰 진입점이므로, ZSK를 굴려도 이 DS는 그대로여야 한다.
     */
    pub fn ds(&self) -> Option<Ds> {
        let key = self.ksk_dnskey().unwrap_or_else(|| self.dnskey());
        Ds::from_dnskey(&key, &self.owner, 2)
    }

    /**
     * @brief CDS와 CDNSKEY 레코드: 부모에게 DS를 이렇게 바꿔 달라는 자식 쪽 신호다.
     * @details 부모가 이 값을 그대로 반영하므로 실제 SEP 키와 어긋나면 위임이 끊긴다.
     */
    pub fn cds_cdnskey_records(&self, ttl: u32) -> Vec<Record> {
        let key = self.ksk_dnskey().unwrap_or_else(|| self.dnskey());
        let Some(ds) = self.ds() else {
            return Vec::new();
        };
        vec![
            Record {
                name: self.owner.clone(),
                rtype: RecordType(59),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(59, ds.rdata_bytes()),
            },
            Record {
                name: self.owner.clone(),
                rtype: RecordType(60),
                class: DnsClass::IN,
                ttl,
                rdata: RData::Unknown(60, key.rdata_bytes()),
            },
        ]
    }

    /**
     * @brief RRset 하나를 서명해 RRSIG 레코드를 만든다.
     *
     * @details DNSKEY RRset은 KSK로, 나머지는 ZSK로 서명한다. labels 필드는 빈 라벨과
     *          와일드카드를 뺀 개수다. 검증기가 이 값으로 와일드카드 확장을 되돌리므로
     *          별표를 세면 소유자 이름이 어긋난다.
     * @param rrset 같은 소유자·타입의 레코드들. 첫 레코드에서 메타데이터를 가져온다.
     * @param now   현재 시각(Unix 초).
     * @return RRSIG 레코드. 빈 RRset이면 None.
     */
    /**
     * @brief 고정 digest에 곡선 연산만 되풀이해 1회 비용을 낸다.
     *
     * @details 서명 한 건의 비용에서 곡선 연산이 차지하는 몫을 갈라 보려는 계측용이다.
     *          대조 엔진보다 느릴 때 고칠 수 있는 곳이 앞단인지 암호 라이브러리인지를
     *          이 값으로 정한다.
     * @param iterations 되풀이 횟수. 0이면 0을 돌려준다.
     * @return 1회당 마이크로초.
     */
    /**
     * @brief 알고리즘 15(Ed25519)로 같은 일을 할 때의 1회 비용.
     *
     * @details 알고리즘 13의 곡선 연산이 대조 엔진보다 비싼 것이 확인되어, 이미 트리에 있는
     *          검증된 크레이트로 닫을 수 있는지 재려는 계측용이다. 서명 경로를 바꾸지는
     *          않는다. 알고리즘 선택은 검증기 상호운용에 걸리는 결정이다.
     * @param iterations 되풀이 횟수. 0이면 0을 돌려준다.
     * @return 1회당 마이크로초.
     */
    pub fn bench_ed25519_sign_us(iterations: usize) -> f64 {
        if iterations == 0 {
            return 0.0;
        }
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let message = [0x5au8; 32];
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            let signature = key.sign(std::hint::black_box(&message));
            std::hint::black_box(&signature);
        }
        started.elapsed().as_secs_f64() * 1e6 / iterations as f64
    }

    pub fn bench_raw_sign_us(&self, iterations: usize) -> f64 {
        if iterations == 0 {
            return 0.0;
        }
        let digest = [0x5au8; 32];
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(self.key.sign(std::hint::black_box(&digest)));
        }
        started.elapsed().as_secs_f64() * 1e6 / iterations as f64
    }

    pub fn sign_rrset(&self, rrset: &[Record], now: u64) -> Option<Record> {
        let first = rrset.first()?;
        let (signing_key, key_tag) = if first.rtype.0 == 48 {
            match (self.ksk.as_ref(), self.ksk_dnskey()) {
                (Some(key), Some(dnskey)) => (key, dnskey.key_tag()),
                _ => (&self.key, self.dnskey().key_tag()),
            }
        } else {
            (&self.key, self.dnskey().key_tag())
        };

        let labels = first
            .name
            .labels()
            .iter()
            .filter(|l| !l.is_empty() && *l != b"*")
            .count() as u8;
        let mut meta = Rrsig {
            type_covered: first.rtype.0,
            algorithm: signing_key.algorithm().number(),
            labels,
            original_ttl: first.ttl,
            expiration: (now + VALIDITY) as u32,
            inception: now.saturating_sub(INCEPTION_SKEW) as u32,
            key_tag,
            signer: self.owner.clone(),
            signature: Vec::new(),
        };
        let data = signed_data(&meta, rrset);
        meta.signature = signing_key.sign(&data);
        Some(Record {
            name: first.name.clone(),
            rtype: RecordType(46),
            class: DnsClass::IN,
            ttl: first.ttl,
            rdata: RData::Unknown(46, meta.rdata_bytes()),
        })
    }
}

/**
 * @brief 시드에서 서명 키를 만든다.
 * @details 시드가 위수 범위를 벗어나면 해시해서 다시 시도한다. 확률은 무시할 만큼 낮지만,
 *          실패를 그냥 넘기면 키 생성이 패닉으로 끝난다.
 */
fn key_from_seed(seed: [u8; 32]) -> SigningKey {
    let mut seed = Zeroizing::new(seed);
    loop {
        if let Ok(k) = SigningKey::from_bytes((&*seed).into()) {
            return k;
        }
        use sha2::Digest as _;
        let next = sha2::Sha256::digest(seed.as_slice()).into();
        seed.zeroize();
        *seed = next;
    }
}

/** @brief PEM에서 ZSK의 공개 부분만 추출한다. 사전 공표 목록을 만들 때 쓴다. */
pub fn zsk_dnskey_from_pkcs8_pem(pem: &str) -> Option<Dnskey> {
    let key = SignKey::from_pkcs8_pem(pem)?;
    Some(dnskey_of(&key, 256))
}

/**
 * @brief 서명 키에서 DNSKEY를 만든다.
 * @note 공개키는 비압축 점에서 접두사를 뗀 x와 y를 잇는다. 알고리즘 13의 형식이다.
 */
fn dnskey_of(key: &SignKey, flags: u16) -> Dnskey {
    Dnskey {
        flags,
        protocol: 3,
        algorithm: key.algorithm().number(),
        public_key: key.public_key(),
    }
}

/** @brief NSEC3 해시 매개변수. */
#[derive(Debug, Clone, Default)]
pub struct Nsec3Params {
    /** @brief 추가 해시 반복. 검증기 CPU를 그대로 늘리므로 크게 잡지 않는다. */
    pub iterations: u16,
    /** @brief 사전 계산 공격을 늦추는 salt. */
    pub salt: Vec<u8>,
}

/** @brief 부재 증명 방식. */
#[derive(Debug, Clone, Default)]
pub enum DenialMode {
    /** @brief NSEC. 단순하지만 zone의 이름 목록이 그대로 드러난다. */
    #[default]
    Nsec,
    /** @brief NSEC3. 이름을 해시로 가리는 대신 검증 비용이 는다. */
    Nsec3(Nsec3Params),
}

/** @brief NSEC 방식으로 zone에 서명한다. */
pub fn sign_zone(records: &[Record], signer: &ZoneSigner, now: u64) -> Vec<Record> {
    sign_zone_with(records, signer, now, &DenialMode::Nsec)
}

/**
 * @brief zone 전체에 서명하고 부재 증명 체인을 붙인다.
 *
 * @details 기존 DNSSEC 레코드를 먼저 걷어내고 새로 만든다. 남겨 두면 이전 서명과 새 서명이
 *          섞여 검증기가 어느 쪽을 볼지 알 수 없다.
 * @note 위임 지점 아래는 서명하지 않는다. 그 데이터는 자식 zone 소유라 이 서버의 권한 밖이고,
 *       부모가 서명하면 자식이 바꾼 내용과 어긋난다. 위임에서 이 서버가 서명하는 것은
 *       DS와 부재 증명 레코드뿐이다.
 * @param mode 부재 증명 방식.
 * @return 서명과 부재 증명이 붙은 zone 레코드 전부.
 */
pub fn sign_zone_with(
    records: &[Record],
    signer: &ZoneSigner,
    now: u64,
    mode: &DenialMode,
) -> Vec<Record> {
    sign_zone_reusing(records, signer, now, mode, &[])
}

/**
 * @brief 지난 서명을 물려받아 zone에 서명한다.
 *
 * @details 영역을 고칠 때마다 전부 다시 서명하면 레코드 하나를 바꾸는 값이 영역 크기에
 *          비례한다. 내용이 그대로이고 서명이 넉넉히 살아 있는 RRset은 지난 서명을 그대로
 *          쓰고, 바뀐 것과 새 부재 증명만 새로 서명한다.
 * @param previous 지난 서명된 레코드들. 이 서버가 직접 만들어 이 서버의 저장소에 가지고 있던 것만
 *                 넘겨야 한다. 바깥에서 받은 RRSIG를 넣으면 검증하지 않고 내보내게 된다.
 *                 빈 배열이면 전부 새로 서명한다.
 * @return 서명과 부재 증명이 붙은 zone 레코드 전부. 물려받든 새로 만들든 결과 구성은 같다.
 */
pub fn sign_zone_reusing(
    records: &[Record],
    signer: &ZoneSigner,
    now: u64,
    mode: &DenialMode,
    previous: &[Record],
) -> Vec<Record> {
    use std::collections::{BTreeMap, HashSet};
    let soa_min = records
        .iter()
        .find_map(|r| match &r.rdata {
            RData::Soa(s) => Some(s.minimum),
            _ => None,
        })
        .unwrap_or(300);

    let mut out: Vec<Record> = records
        .iter()
        .filter(|r| !matches!(r.rtype.0, 46 | 47 | 48 | 50 | 51 | 59 | 60))
        .cloned()
        .collect();
    out.extend(signer.dnskey_records(3_600));
    out.extend(signer.cds_cdnskey_records(3_600));

    let origin_labels = signer.owner.num_labels();
    let mut delegation_names: Vec<Name> = out
        .iter()
        .filter(|record| {
            record.rtype == RecordType::NS && !record.name.eq_ignore_case(&signer.owner)
        })
        .map(|record| record.name.clone())
        .collect();
    delegation_names.sort_by_key(Name::num_labels);
    let mut delegation_keys = HashSet::<Vec<Vec<u8>>>::new();
    for name in delegation_names {
        let below_existing_cut = ((origin_labels + 1)..name.num_labels())
            .any(|labels| delegation_keys.contains(&canonical_key(&name.suffix(labels))));
        if !below_existing_cut {
            delegation_keys.insert(canonical_key(&name));
        }
    }
    let delegation_scope = |name: &Name| -> u8 {
        if delegation_keys.contains(&canonical_key(name)) {
            return 1;
        }
        for labels in (origin_labels + 1)..name.num_labels() {
            if delegation_keys.contains(&canonical_key(&name.suffix(labels))) {
                return 2;
            }
        }
        0
    };

    let mut owners: BTreeMap<Vec<Vec<u8>>, (Name, Vec<u16>)> = BTreeMap::new();
    for r in &out {
        let scope = delegation_scope(&r.name);
        if scope == 2 || scope == 1 && !matches!(r.rtype, RecordType::NS | RecordType::DS) {
            continue;
        }
        let key = canonical_key(&r.name);
        let e = owners
            .entry(key)
            .or_insert_with(|| (r.name.clone(), Vec::new()));
        if !e.1.contains(&r.rtype.0) {
            e.1.push(r.rtype.0);
        }
    }
    let owner_names: Vec<Name> = owners.values().map(|(name, _)| name.clone()).collect();
    for name in owner_names {
        if name.num_labels() < origin_labels
            || !name.suffix(origin_labels).eq_ignore_case(&signer.owner)
        {
            continue;
        }
        for labels in origin_labels..name.num_labels() {
            let ancestor = name.suffix(labels);
            owners
                .entry(canonical_key(&ancestor))
                .or_insert_with(|| (ancestor, Vec::new()));
        }
    }
    let ordered: Vec<(Name, Vec<u16>)> = owners.into_values().collect();

    match mode {
        DenialMode::Nsec => out.extend(build_nsec_chain(&ordered, soa_min)),
        DenialMode::Nsec3(params) => {
            out.push(nsec3param_record(&signer.owner, params, soa_min));
            out.extend(build_nsec3_chain(&signer.owner, &ordered, params, soa_min));
        }
    }

    let mut sets: BTreeMap<(Vec<Vec<u8>>, u16), Vec<Record>> = BTreeMap::new();
    for r in &out {
        sets.entry((canonical_key(&r.name), r.rtype.0))
            .or_default()
            .push(r.clone());
    }
    let mut signable: Vec<&Vec<Record>> = Vec::new();
    let reusable = ReusableSignatures::new(previous, signer, now);
    for rrset in sets.values() {
        let first = &rrset[0];
        let scope = delegation_scope(&first.name);
        if scope == 2 || scope == 1 && !matches!(first.rtype, RecordType::DS | RecordType::NSEC) {
            continue;
        }
        match reusable.take(rrset) {
            Some(sig) => out.push(sig),
            None => signable.push(rrset),
        }
    }
    sign_rrsets_into(&mut out, &signable, signer, now);
    out
}

/**
 * @brief 아직 쓸 수 있는 지난 서명을 찾아 주는 것.
 *
 * @details 영역을 고칠 때마다 전부 다시 서명하면 레코드 하나를 바꾸는 값이 영역 크기에
 *          비례한다. 내용이 그대로이고 서명이 넉넉히 살아 있으면 그 서명을 그대로 쓴다.
 * @warning 지난 서명은 이 서버가 직접 만들어 이 서버의 저장소에 가지고 있던 것만 넘겨야 한다.
 *          바깥에서 받은 RRSIG를 여기 넣으면 검증하지 않고 내보내게 된다.
 * @invariant 재사용 조건은 서명자 이름·알고리즘·키 tag·남은 수명·원본 TTL·RRset 내용이
 *            모두 같을 때뿐이다. 하나라도 어긋나면 새로 서명한다.
 */
struct ReusableSignatures<'a> {
    /**
     * @brief (정규 소유자, 덮는 타입) → 지난 서명과 그때의 RRset. 모두 빌려 쓴다.
     * @note 키는 Name::canonical_key의 평평한 바이트열이다. 라벨마다 Vec을 만드는
     *       형태를 쓰면 이 테이블을 만드는 값이 서명보다 커진다. 실제로 그랬다.
     */
    entries: std::collections::HashMap<(Vec<u8>, u16), (&'a Record, Vec<&'a Record>)>,
}

/** @brief 남은 수명이 이보다 짧으면 다시 서명한다. 만료가 임박한 서명을 물려주지 않으려는 것이다. */
const REUSE_MIN_REMAINING: u64 = VALIDITY / 4;

/**
 * @brief RRSIG RDATA에서 물려받기 판정에 쓰는 값만 읽는다.
 *
 * @details 서명 바이트와 서명자 이름을 복사하지 않으려는 것이다. 지난 영역의 RRSIG를
 *          전부 완전 해석하면 그 할당이 재사용 이득을 먹는다.
 * @param apex_wire 이 서버의 apex의 압축 없는 와이어. 서명자 이름을 여기에 대조한다.
 * @return (덮는 타입, 알고리즘, 개시, 만료, key tag). 형식이 어긋나거나 서명자가 다르면 None.
 */
fn rrsig_reuse_header(record: &Record, apex_wire: &[u8]) -> Option<(u16, u8, u32, u32, u16)> {
    let RData::Unknown(46, raw) = &record.rdata else {
        return None;
    };
    if raw.len() < 18 {
        return None;
    }
    let type_covered = u16::from_be_bytes([raw[0], raw[1]]);
    let algorithm = raw[2];
    let expiration = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let inception = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let key_tag = u16::from_be_bytes([raw[16], raw[17]]);
    let signer = raw.get(18..)?;
    if signer.len() < apex_wire.len()
        || !signer[..apex_wire.len()]
            .iter()
            .zip(apex_wire)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return None;
    }
    Some((type_covered, algorithm, inception, expiration, key_tag))
}

impl<'a> ReusableSignatures<'a> {
    /** @brief 지난 서명 목록에서 쓸 수 있는 것만 골라 담는다. 레코드는 복제하지 않는다. */
    fn new(previous: &'a [Record], signer: &ZoneSigner, now: u64) -> Self {
        let mut entries = std::collections::HashMap::new();
        if previous.is_empty() {
            return Self { entries };
        }
        let zsk_tag = signer.dnskey().key_tag();
        let ksk_tag = signer.ksk_dnskey().map(|key| key.key_tag());
        let expected_algorithm = signer.algorithm().number();
        let apex_wire = signer.owner.canonical_key();

        /* 지난 RRset들을 먼저 모은다. 서명은 내용이 그대로일 때만 물려줄 수 있다. */
        let mut rrsets: std::collections::HashMap<(Vec<u8>, u16), Vec<&'a Record>> =
            std::collections::HashMap::new();
        for record in previous.iter().filter(|record| record.rtype.0 != 46) {
            rrsets
                .entry((record.name.canonical_key(), record.rtype.0))
                .or_default()
                .push(record);
        }

        for record in previous.iter().filter(|record| record.rtype.0 == 46) {
            let Some((type_covered, algorithm, inception, expiration, key_tag)) =
                rrsig_reuse_header(record, &apex_wire)
            else {
                continue;
            };
            let expected_tag = if type_covered == 48 {
                ksk_tag.unwrap_or(zsk_tag)
            } else {
                zsk_tag
            };
            let alive = u64::from(expiration) > now.saturating_add(REUSE_MIN_REMAINING)
                && u64::from(inception) <= now;
            if algorithm != expected_algorithm || key_tag != expected_tag || !alive {
                continue;
            }
            let key = (record.name.canonical_key(), type_covered);
            let Some(rrset) = rrsets.remove(&key) else {
                continue;
            };
            entries.insert(key, (record, rrset));
        }
        Self { entries }
    }

    /** @brief 이 RRset에 그대로 쓸 수 있는 지난 서명. 내용이 다르면 없다. */
    fn take(&self, rrset: &[Record]) -> Option<Record> {
        let first = rrset.first()?;
        let mut buffer = [0u8; 255];
        let key = first.name.canonical_key_into(&mut buffer)?;
        let (sig, previous) = self.entries.get(&(key.to_vec(), first.rtype.0))?;
        rrsets_identical(rrset, previous).then(|| (*sig).clone())
    }
}

/**
 * @brief 두 RRset이 서명 대상으로서 같은지.
 * @details TTL은 서명 대상에 들어가므로 함께 본다. 순서는 정규형에서 정렬되므로 무시한다.
 */
fn rrsets_identical(left: &[Record], right: &[&Record]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    /* 순서만 다른 같은 집합도 같은 것으로 본다. 한쪽이 작으므로 이차 비교로 충분하다. */
    let same = |a: &Record, b: &Record| {
        a.ttl == b.ttl && a.class == b.class && a.rtype == b.rtype && a.rdata == b.rdata
    };
    let mut used = [false; 8];
    if left.len() > used.len() {
        /* 큰 RRset은 드물다. 그때만 정렬 가능한 형태로 비교한다. */
        let key = |record: &Record| {
            (
                record.ttl,
                record.class.0,
                crate::canonical_rdata(&record.rdata),
            )
        };
        let mut a: Vec<_> = left.iter().map(key).collect();
        let mut b: Vec<_> = right.iter().map(|record| key(record)).collect();
        a.sort();
        b.sort();
        return a == b;
    }
    for candidate in left {
        let mut matched = false;
        for (index, other) in right.iter().enumerate() {
            if !used[index] && same(candidate, other) {
                used[index] = true;
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    true
}

/** @brief 병렬 서명으로 넘어가는 RRset 수. 이보다 작으면 스레드를 시작하는 값이 더 크다. */
const PARALLEL_SIGN_MIN_RRSETS: usize = 256;

/**
 * @brief RRset들에 서명한다. 충분히 많으면 코어를 나눠 쓴다.
 *
 * @details 서명은 RRset마다 독립이고 서명자는 안에서 아무것도 바꾸지 않는다. 큰 영역은
 *          로드 시간의 대부분을 여기서 쓰는데 그 동안 코어 하나만 돌고 나머지는 논다.
 * @param out    서명을 이어 붙일 곳. 조각을 순서대로 넣으므로 결과는 코어 수와 무관하게
 *               정렬된 입력 순서 그대로다.
 * @param rrsets 서명 대상. 호출자가 위임 범위를 이미 걸러 둔다.
 * @note 조각 하나가 패닉하면 그대로 다시 던진다. 절반만 서명된 영역을 내보내면 검증기가
 *       그 영역을 전부 Bogus로 본다.
 */
fn sign_rrsets_into(out: &mut Vec<Record>, rrsets: &[&Vec<Record>], signer: &ZoneSigner, now: u64) {
    let sign_part = |part: &[&Vec<Record>]| -> Vec<Record> {
        part.iter()
            .filter_map(|rrset| signer.sign_rrset(rrset, now))
            .collect()
    };

    let threads = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .min(rrsets.len().max(1));
    if threads < 2 || rrsets.len() < PARALLEL_SIGN_MIN_RRSETS {
        out.extend(sign_part(rrsets));
        return;
    }

    /* 슬롯을 미리 잡아 이어 붙이는 동안 다시 늘리지 않는다. */
    out.reserve(rrsets.len());
    let chunk = rrsets.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let handles: Vec<_> = rrsets
            .chunks(chunk)
            .map(|part| scope.spawn(move || sign_part(part)))
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(part) => out.extend(part),
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
    });
}

/**
 * @brief 정규 순서로 늘어놓은 이름들을 순환 구조의 NSEC 체인으로 엮는다.
 * @details 마지막 이름의 next는 처음으로 되돌아간다. 이 되감김이 있어야 zone 끝 뒤의
 *          이름들도 부재가 증명된다.
 * @note 각 NSEC은 자기 자신(47)과 RRSIG(46)를 타입 목록에 넣는다. 실제로 존재하는
 *       타입이므로 빠뜨리면 그 타입 질의가 NODATA로 잘못 증명된다.
 */
fn build_nsec_chain(ordered: &[(Name, Vec<u16>)], ttl: u32) -> Vec<Record> {
    let n = ordered.len();
    let mut nsecs = Vec::with_capacity(n);
    for i in 0..n {
        let (owner, types) = &ordered[i];
        let (next, _) = &ordered[(i + 1) % n];
        let mut all_types: Vec<u16> = types.clone();
        all_types.push(46);
        all_types.push(47);
        let mut rdata = Vec::new();
        crate::canonical_name_into(next, &mut rdata);
        rdata.extend_from_slice(&type_bitmap(&all_types));
        nsecs.push(Record {
            name: owner.clone(),
            rtype: RecordType(47),
            class: DnsClass::IN,
            ttl,
            rdata: RData::Unknown(47, rdata),
        });
    }
    nsecs
}

/** @brief apex의 NSEC3PARAM: 이 zone이 어떤 해시 매개변수를 쓰는지 알린다. */
fn nsec3param_record(apex: &Name, p: &Nsec3Params, ttl: u32) -> Record {
    let mut rdata = vec![1u8, 0u8];
    rdata.extend_from_slice(&p.iterations.to_be_bytes());
    rdata.push(p.salt.len() as u8);
    rdata.extend_from_slice(&p.salt);
    Record {
        name: apex.clone(),
        rtype: RecordType(51),
        class: DnsClass::IN,
        ttl,
        rdata: RData::Unknown(51, rdata),
    }
}

/**
 * @brief 이름들을 해시해 정렬한 뒤 순환 구조의 NSEC3 체인으로 엮는다.
 * @details 정렬 기준은 원래 이름이 아니라 해시다. 해시가 겹치면 하나로 합친다. 같은
 *          소유자에 NSEC3이 둘이면 검증기가 어느 쪽을 볼지 정해지지 않는다.
 * @note apex의 타입 목록에는 NSEC3PARAM(51)을 넣는다. 실제로 apex에 존재하기 때문이다.
 */
fn build_nsec3_chain(
    apex: &Name,
    ordered: &[(Name, Vec<u16>)],
    p: &Nsec3Params,
    ttl: u32,
) -> Vec<Record> {
    let mut nodes: Vec<(Vec<u8>, Vec<u16>)> = ordered
        .iter()
        .map(|(name, types)| {
            let mut t = types.clone();
            t.push(46);
            if name.eq_ignore_case(apex) {
                t.push(51);
            }
            (crate::nsec3_hash(name, &p.salt, p.iterations), t)
        })
        .collect();
    nodes.sort_by(|a, b| a.0.cmp(&b.0));
    nodes.dedup_by(|a, b| a.0 == b.0);

    let n = nodes.len();
    let mut out = Vec::with_capacity(n);
    let mut skipped = 0usize;
    for i in 0..n {
        let (hash, types) = &nodes[i];
        let (next_hash, _) = &nodes[(i + 1) % n];
        let owner_label = crate::base32hex_encode(hash).to_ascii_lowercase();
        let mut owner_labels = Vec::with_capacity(apex.labels().len() + 1);
        owner_labels.push(owner_label.into_bytes());
        owner_labels.extend(apex.labels().map(<[u8]>::to_vec));

        let owner = match Name::from_labels(owner_labels) {
            Ok(owner) => owner,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let mut rdata = vec![1u8, 0u8];
        rdata.extend_from_slice(&p.iterations.to_be_bytes());
        rdata.push(p.salt.len() as u8);
        rdata.extend_from_slice(&p.salt);
        rdata.push(next_hash.len() as u8);
        rdata.extend_from_slice(next_hash);
        rdata.extend_from_slice(&type_bitmap(types));
        out.push(Record {
            name: owner,
            rtype: RecordType(50),
            class: DnsClass::IN,
            ttl,
            rdata: RData::Unknown(50, rdata),
        });
    }
    if skipped > 0 {
        onetdns_core::error!(event = "dnssec.nsec3_owner_invalid", zone = %apex.to_ascii_lower(), skipped = skipped, nodes = n, "Could not build an NSEC3 owner name, leaving a gap in the chain; denial proofs for this zone will fail validation");
    }
    out
}

/** @brief 정규 순서로 정렬하기 위한 키: 라벨을 뒤집고 소문자로 내린다. */
fn canonical_key(name: &Name) -> Vec<Vec<u8>> {
    name.labels()
        .iter()
        .rev()
        .map(|l| l.to_ascii_lowercase())
        .collect()
}

/**
 * @brief 타입 목록을 NSEC/NSEC3 비트맵으로 인코딩한다.
 * @details 정규형을 지킨다. 윈도우를 번호 순으로 내고, 뒤쪽 0 옥텟은 잘라 내며, 비어 있는
 *          윈도우는 아예 넣지 않는다. 파서 쪽이 이 형식만 받으므로 어기면 이 서버가 만든
 *          zone을 이 서버가 못 읽는다.
 */
fn type_bitmap(types: &[u16]) -> Vec<u8> {
    use std::collections::BTreeMap;
    let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
    for &t in types {
        let w = (t >> 8) as u8;
        let lo = (t & 0xff) as usize;
        let bm = windows.entry(w).or_insert([0u8; 32]);
        bm[lo / 8] |= 0x80 >> (lo % 8);
    }
    let mut out = Vec::new();
    for (w, bm) in windows {
        let len = bm.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
        if len == 0 {
            continue;
        }
        out.push(w);
        out.push(len as u8);
        out.extend_from_slice(&bm[..len]);
    }
    out
}

/**
 * @brief 이 질의의 부재를 증명하는 데 필요한 NSEC만 고른다.
 *
 * @details NODATA면 그 이름과 정확히 일치하는 NSEC 하나로 끝난다. NXDOMAIN이면 이름
 *          자체와 가능한 와일드카드 후보들까지 덮는 NSEC을 모아야 한다. 와일드카드를
 *          빼면 검증기가 증명을 받아들이지 않는다.
 * @return 소유자 이름 기준으로 중복을 없앤 최소 집합. 체인 전체를 붙이면 zone의 이름이
 *         그만큼 노출된다.
 */
pub fn pick_denial_nsecs(nsecs: &[Record], qname: &Name, nxdomain: bool) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    let mut push = |r: &Record| {
        if !out.iter().any(|x| x.name.eq_ignore_case(&r.name)) {
            out.push(r.clone());
        }
    };
    if !nxdomain {
        for r in nsecs {
            if r.name.eq_ignore_case(qname) {
                push(r);
            }
        }
        return out;
    }

    let mut targets = vec![qname.clone()];
    let labels = qname.labels();
    for i in 1..labels.len() {
        let mut wildcard_labels = vec![b"*".to_vec()];
        wildcard_labels.extend(qname.labels().skip(i).map(<[u8]>::to_vec));
        if let Ok(w) = Name::from_labels(wildcard_labels) {
            targets.push(w);
        }
    }
    for t in &targets {
        for r in nsecs {
            if r.rtype != RecordType(47) {
                continue;
            }
            if let Some(n) = crate::Nsec::from_record(r) {
                if crate::nsec_covers(&r.name, &n.next, t) {
                    push(r);
                }
            }
        }
    }
    out
}

/**
 * @brief 이 질의의 부재를 증명하는 데 필요한 NSEC3만 고른다.
 *
 * @details NXDOMAIN이면 세 조각을 모은다. closest encloser에 일치하는 것, next closer를
 *          덮는 것, 그리고 와일드카드를 덮는 것. 하나라도 빠지면 검증기가 증명을
 *          받아들이지 않는다.
 * @note 해시 매개변수는 체인의 첫 NSEC3에서 가져와 전부에 같은 값을 쓴다. zone 안에서
 *       매개변수가 섞이면 검증기의 일관성 검사에 걸린다.
 */
pub fn pick_denial_nsec3(nsec3s: &[Record], qname: &Name, nxdomain: bool) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    let mut push = |r: &Record| {
        if !out.iter().any(|x| x.name.eq_ignore_case(&r.name)) {
            out.push(r.clone());
        }
    };

    let Some(first) = nsec3s.iter().find_map(crate::Nsec3::from_record) else {
        return out;
    };
    let (salt, iters) = (first.salt.clone(), first.iterations);
    let hash_owner = |r: &Record| -> Option<Vec<u8>> {
        r.name
            .labels()
            .first()
            .and_then(crate::base32hex_decode_pub)
    };
    let covers = |name: &Name| -> Option<Record> {
        let q = crate::nsec3_hash(name, &salt, iters);
        for r in nsec3s {
            if r.rtype != RecordType(50) {
                continue;
            }
            let (Some(owner), Some(n3)) = (hash_owner(r), crate::Nsec3::from_record(r)) else {
                continue;
            };
            if crate::hash_covers_pub(&owner, &n3.next_hashed, &q) {
                return Some(r.clone());
            }
        }
        None
    };
    let matches = |name: &Name| -> Option<Record> {
        let q = crate::nsec3_hash(name, &salt, iters);
        nsec3s
            .iter()
            .find(|r| hash_owner(r).as_deref() == Some(q.as_slice()))
            .cloned()
    };

    if !nxdomain {
        if let Some(r) = matches(qname) {
            push(&r);
        }
        return out;
    }

    let labels = qname.labels();
    let mut ce: Option<Name> = None;
    for count in (0..=labels.len()).rev() {
        let cand = qname.suffix(count);
        if matches(&cand).is_some() {
            ce = Some(cand);
            break;
        }
    }

    if let Some(ce) = &ce {
        if let Some(r) = matches(ce) {
            push(&r);
        }

        let ce_n = ce.num_labels();
        if qname.num_labels() > ce_n {
            let nc = qname.suffix(ce_n + 1);
            if let Some(r) = covers(&nc) {
                push(&r);
            }
        }

        let mut wildcard_labels = vec![b"*".to_vec()];
        wildcard_labels.extend(ce.labels().map(<[u8]>::to_vec));
        if let Ok(w) = Name::from_labels(wildcard_labels) {
            if let Some(r) = covers(&w) {
                push(&r);
            }
        }
    }
    out
}

/** @brief 서명 결과를 이 서버의 검증기로 되돌려 확인한다. 서명자와 검증자의 정규형 일치. */
#[cfg(test)]
mod tests {
    use super::*;
    use onetdns_proto::Soa;
    use std::net::Ipv4Addr;

    /** @brief 이름 문자열을 Name으로. */
    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    /** @brief apex, NS, glue, 일반 A를 갖춘 최소 zone. */
    fn zone_records() -> Vec<Record> {
        vec![
            Record {
                name: n("example.com"),
                rtype: RecordType::SOA,
                class: DnsClass::IN,
                ttl: 300,
                rdata: RData::soa(Soa {
                    mname: n("ns1.example.com"),
                    rname: n("admin.example.com"),
                    serial: 1,
                    refresh: 300,
                    retry: 60,
                    expire: 86_400,
                    minimum: 60,
                }),
            },
            Record::new(n("example.com"), 300, RData::Ns(n("ns1.example.com"))),
            Record::new(
                n("ns1.example.com"),
                300,
                RData::A(Ipv4Addr::new(10, 0, 0, 1)),
            ),
            Record::new(
                n("www.example.com"),
                300,
                RData::A(Ipv4Addr::new(10, 0, 0, 2)),
            ),
        ]
    }

    /** @brief 부모에 보낼 CDS/CDNSKEY가 실제 SEP 키와 일치하고 서명까지 붙는지. */
    #[test]
    fn cds_cdnskey_published_and_signed() {
        let signer = ZoneSigner::generate_split(n("example.com"), [3u8; 32], [9u8; 32]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);
        let apex = n("example.com");

        let cds: Vec<&Record> = signed
            .iter()
            .filter(|r| r.rtype.0 == 59 && r.name.eq_ignore_case(&apex))
            .collect();
        let cdnskey: Vec<&Record> = signed
            .iter()
            .filter(|r| r.rtype.0 == 60 && r.name.eq_ignore_case(&apex))
            .collect();
        assert_eq!(cds.len(), 1, "CDS 1건");
        assert_eq!(cdnskey.len(), 1, "CDNSKEY 1건");

        let ds = signer.ds().unwrap();
        let ksk = signer.ksk_dnskey().unwrap();
        assert_eq!(cds[0].rdata, RData::Unknown(59, ds.rdata_bytes()));
        assert_eq!(cdnskey[0].rdata, RData::Unknown(60, ksk.rdata_bytes()));

        let covers = |tc: u16| {
            signed.iter().any(|r| {
                r.rtype.0 == 46
                    && r.name.eq_ignore_case(&apex)
                    && Rrsig::from_record(r)
                        .map(|s| s.type_covered == tc)
                        .unwrap_or(false)
            })
        };
        assert!(covers(59), "CDS RRSIG");
        assert!(covers(60), "CDNSKEY RRSIG");

        let resigned = sign_zone(&signed, &signer, now);
        assert_eq!(
            resigned.iter().filter(|r| r.rtype.0 == 59).count(),
            1,
            "재서명 CDS 1건"
        );
        assert_eq!(
            resigned.iter().filter(|r| r.rtype.0 == 60).count(),
            1,
            "재서명 CDNSKEY 1건"
        );
    }

    /** @brief 사전 공표 키가 DNSKEY RRset에 담기고 그 RRset이 여전히 검증되는지. */
    #[test]
    fn pre_published_zsk_in_signed_dnskey_rrset() {
        let next_key = ZoneSigner::generate(n("example.com"), [88u8; 32]).dnskey();
        let signer = ZoneSigner::generate_split(n("example.com"), [3u8; 32], [9u8; 32])
            .with_published_keys(vec![next_key.clone()]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);
        let apex = n("example.com");

        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&apex) && r.rtype.0 == 48)
            .cloned()
            .collect();
        assert_eq!(keyset.len(), 3, "ZSK+KSK+차기ZSK");
        assert!(
            keyset
                .iter()
                .any(|r| r.rdata == RData::Unknown(48, next_key.rdata_bytes())),
            "차기 ZSK 게시"
        );

        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&apex) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        let ksk = signer.ksk_dnskey().unwrap();
        crate::validate_rrset(&keyset, &keysigs, &[ksk], now as u32)
            .expect("DNSKEY 검증(차기 키 포함)");

        let next_tag = next_key.key_tag();
        assert!(
            !signed
                .iter()
                .filter(|r| r.rtype.0 == 46)
                .filter_map(Rrsig::from_record)
                .any(|s| s.key_tag == next_tag),
            "차기 ZSK는 서명에 미사용"
        );
    }

    /** @brief 이 서버가 서명한 zone을 이 서버의 검증기가 통과시키는지. 정규형이 어긋나면 여기서 걸린다. */
    #[test]
    fn ed25519_signed_zone_validates_and_persists() {
        let signer =
            ZoneSigner::generate_with(n("example.com"), [31u8; 32], SignAlgorithm::Ed25519);
        let now = 1_700_000_000u64;
        assert_eq!(signer.algorithm(), SignAlgorithm::Ed25519);
        assert_eq!(signer.dnskey().algorithm, 15);
        assert_eq!(
            signer.dnskey().public_key.len(),
            32,
            "Ed25519 공개 키는 32옥텟입니다"
        );

        let signed = sign_zone(&zone_records(), &signer, now);
        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        assert!(sigs.iter().all(|s| s.algorithm == 15));
        crate::validate_rrset(&rrset, &sigs, &[signer.dnskey()], now as u32)
            .expect("알고리즘 15 서명이 이 서버의 검증기를 통과해야 합니다");

        /* DNSKEY RRset도 스스로 검증되어야 한다. 여기가 깨지면 신뢰 진입점이 끊긴다. */
        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 48)
            .cloned()
            .collect();
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        crate::validate_rrset(&keyset, &keysigs, &[signer.dnskey()], now as u32)
            .expect("DNSKEY RRset 자기 서명도 검증되어야 합니다");
        assert!(signer.ds().is_some(), "부모에 올릴 DS가 나와야 합니다");

        /* 재시작 사이 키가 보존되어야 한다. PEM 왕복이 깨지면 영역이 전부 바뀐다. */
        let pem = signer.to_pkcs8_pem().expect("Ed25519 PEM 내보내기");
        let restored =
            ZoneSigner::from_pkcs8_pem(&pem, n("example.com")).expect("Ed25519 PEM 읽기");
        assert_eq!(restored.algorithm(), SignAlgorithm::Ed25519);
        assert_eq!(restored.dnskey().public_key, signer.dnskey().public_key);
        assert_eq!(restored.dnskey().key_tag(), signer.dnskey().key_tag());

        /* 저장된 키의 종류는 파일이 스스로 말한다. 알고리즘을 따로 안 적어도 된다. */
        let p256_pem = ZoneSigner::generate(n("example.com"), [7u8; 32])
            .to_pkcs8_pem()
            .expect("P-256 PEM");
        let back = ZoneSigner::from_pkcs8_pem(&p256_pem, n("example.com")).expect("P-256 PEM 읽기");
        assert_eq!(back.algorithm(), SignAlgorithm::EcdsaP256);
        assert_eq!(back.dnskey().algorithm, 13);
    }

    #[test]
    fn resigning_reuses_only_what_is_still_valid_and_unchanged() {
        use std::net::Ipv4Addr;

        let signer = ZoneSigner::generate(n("example.com"), [11u8; 32]);
        let now = 1_700_000_000u64;
        let mut records = zone_records();
        for index in 0..64 {
            records.push(Record::new(
                n(&format!("h{index:03}.example.com")),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, (index % 250 + 1) as u8)),
            ));
        }
        let first = sign_zone(&records, &signer, now);

        /* 아무것도 안 바꾸면 서명이 전부 물려받아져 바이트까지 같아야 한다. */
        let again = sign_zone_reusing(&records, &signer, now + 60, &DenialMode::Nsec, &first);
        let sigs = |zone: &[Record]| -> Vec<Vec<u8>> {
            let mut v: Vec<Vec<u8>> = zone
                .iter()
                .filter(|r| r.rtype.0 == 46)
                .filter_map(|r| Rrsig::from_record(r).map(|s| s.signature))
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            sigs(&first),
            sigs(&again),
            "내용이 그대로면 지난 서명을 그대로 써야 합니다"
        );

        /* 한 이름의 주소를 바꾸면 그 RRset만 새 서명을 받아야 한다. */
        let mut changed = records.clone();
        for record in &mut changed {
            if record.name.eq_ignore_case(&n("h007.example.com")) {
                record.rdata = RData::A(Ipv4Addr::new(203, 0, 113, 9));
            }
        }
        let after = sign_zone_reusing(&changed, &signer, now + 60, &DenialMode::Nsec, &first);
        let target_sig = |zone: &[Record]| -> Option<Vec<u8>> {
            zone.iter()
                .filter(|r| r.name.eq_ignore_case(&n("h007.example.com")) && r.rtype.0 == 46)
                .filter_map(Rrsig::from_record)
                .find(|s| s.type_covered == RecordType::A.0)
                .map(|s| s.signature)
        };
        assert_ne!(
            target_sig(&first),
            target_sig(&after),
            "바뀐 RRset은 새로 서명해야 합니다"
        );
        let untouched = |zone: &[Record]| -> Option<Vec<u8>> {
            zone.iter()
                .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype.0 == 46)
                .filter_map(Rrsig::from_record)
                .find(|s| s.type_covered == RecordType::A.0)
                .map(|s| s.signature)
        };
        assert_eq!(
            untouched(&first),
            untouched(&after),
            "안 바뀐 이웃은 지난 서명을 유지해야 합니다"
        );
        /* 물려받은 것이 실제로 검증되는지. 물려받기가 어긋나면 검증기가 Bogus로 본다. */
        let rrset: Vec<Record> = after
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let rrsigs: Vec<Rrsig> = after
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        crate::validate_rrset(&rrset, &rrsigs, &[signer.dnskey()], (now + 60) as u32)
            .expect("물려받은 서명도 검증되어야 합니다");

        /* 만료가 임박하면 물려받지 않는다. */
        let late = now + VALIDITY - REUSE_MIN_REMAINING / 2;
        let refreshed = sign_zone_reusing(&records, &signer, late, &DenialMode::Nsec, &first);
        assert_ne!(
            sigs(&first),
            sigs(&refreshed),
            "만료가 가까운 서명은 새로 만들어야 합니다"
        );

        /* 다른 키의 서명은 물려받지 않는다. */
        let other = ZoneSigner::generate(n("example.com"), [22u8; 32]);
        let foreign = sign_zone_reusing(&records, &other, now + 60, &DenialMode::Nsec, &first);
        assert_ne!(
            sigs(&first),
            sigs(&foreign),
            "다른 키가 만든 서명을 물려받으면 안 됩니다"
        );
        let foreign_rrset: Vec<Record> = foreign
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let foreign_sigs: Vec<Rrsig> = foreign
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("h008.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        crate::validate_rrset(
            &foreign_rrset,
            &foreign_sigs,
            &[other.dnskey()],
            (now + 60) as u32,
        )
        .expect("새 키로 다시 서명한 결과가 그 키로 검증되어야 합니다");
    }

    #[test]
    fn parallel_signing_matches_the_sequential_order_and_signs_everything() {
        use std::net::Ipv4Addr;

        /* 병렬 문턱을 넘기는 크기여야 조각 이어 붙이기가 실제로 걸린다. */
        let owners = PARALLEL_SIGN_MIN_RRSETS * 4;
        let signer = ZoneSigner::generate(n("example.com"), [9u8; 32]);
        let now = 1_700_000_000u64;
        let mut records = zone_records();
        for index in 0..owners {
            records.push(Record::new(
                n(&format!("h{index:05}.example.com")),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, (index % 250 + 1) as u8)),
            ));
        }

        let signed = sign_zone(&records, &signer, now);
        assert!(
            signed.iter().filter(|r| r.rtype.0 == 46).count() > PARALLEL_SIGN_MIN_RRSETS,
            "병렬 경로를 실제로 태우는 크기여야 합니다"
        );

        /*
         * 서명은 정렬된 RRset 순서 그대로 붙는다. 조각을 순서대로 이어 붙이지 않으면
         * 코어 수에 따라 결과가 달라진다.
         */
        let sig_keys: Vec<(Vec<Vec<u8>>, u16)> = signed
            .iter()
            .filter(|r| r.rtype.0 == 46)
            .filter_map(|r| Rrsig::from_record(r).map(|s| (canonical_key(&r.name), s.type_covered)))
            .collect();
        let mut sorted = sig_keys.clone();
        sorted.sort();
        assert_eq!(sig_keys, sorted, "서명이 정규 순서를 벗어났습니다");

        /* 서명해야 할 RRset이 하나도 빠지지 않았는지. 조각 하나를 잃으면 여기서 걸린다. */
        let mut unsigned: Vec<String> = Vec::new();
        let signed_set: std::collections::HashSet<(Vec<Vec<u8>>, u16)> =
            sig_keys.into_iter().collect();
        for record in signed.iter().filter(|r| r.rtype.0 != 46) {
            if !signed_set.contains(&(canonical_key(&record.name), record.rtype.0)) {
                unsigned.push(format!("{} {}", record.name, record.rtype.0));
            }
        }
        assert!(unsigned.is_empty(), "서명이 빠진 RRset: {unsigned:?}");

        /* 값 자체도 유효해야 한다. 순서만 맞고 내용이 틀리면 소용이 없다. */
        let target = n("h00000.example.com");
        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&target) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&target) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        crate::validate_rrset(&rrset, &sigs, &[signer.dnskey()], now as u32)
            .expect("병렬로 만든 서명도 검증되어야 합니다");
    }

    #[test]
    fn signed_zone_validates_with_own_verifier() {
        let signer = ZoneSigner::generate(n("example.com"), [7u8; 32]);
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);

        let dnskey = signer.dnskey();

        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        assert!(!sigs.is_empty(), "www A RRSIG 존재");
        crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], now as u32).expect("양성 검증");

        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 48)
            .cloned()
            .collect();
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        crate::validate_rrset(&keyset, &keysigs, &[dnskey.clone()], now as u32)
            .expect("DNSKEY 검증");
        let ds = signer.ds().expect("DS");
        crate::verify_ds(&ds, &dnskey, &n("example.com")).expect("DS 일치");

        let nsecs: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 47).cloned().collect();
        assert!(!nsecs.is_empty(), "NSEC 체인 존재");
        assert!(
            crate::prove_name_nonexistent(&nsecs, &n("nope.example.com")),
            "NXDOMAIN 부재증명"
        );

        assert!(!crate::prove_name_nonexistent(
            &nsecs,
            &n("www.example.com")
        ));

        assert!(
            crate::prove_nodata(&nsecs, &n("www.example.com"), 28),
            "NODATA 증명"
        );
        assert!(
            !crate::prove_nodata(&nsecs, &n("www.example.com"), 1),
            "A는 있음"
        );
    }

    /** @brief NSEC3 방식으로 서명한 zone도 같은 검증기를 통과하는지. */
    #[test]
    fn nsec3_signed_zone_validates() {
        let signer = ZoneSigner::generate(n("example.com"), [21u8; 32]);
        let now = 1_700_000_000u64;
        let salt = vec![0xab, 0xcd];
        let mode = DenialMode::Nsec3(Nsec3Params {
            iterations: 0,
            salt: salt.clone(),
        });
        let mut source = zone_records();
        source.push(Record::new(
            n("deep.example.com"),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 3)),
        ));
        let signed = sign_zone_with(&source, &signer, now, &mode);

        let nsec3s: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 50).cloned().collect();
        assert!(nsec3s.len() >= 3, "owner마다 NSEC3");
        assert!(signed.iter().any(|r| r.rtype.0 == 51), "NSEC3PARAM 부착");

        let denial = pick_denial_nsec3(&nsec3s, &n("nope.example.com"), true);
        assert!(!denial.is_empty(), "부재증명 NSEC3 선택");
        assert!(
            crate::prove_name_nonexistent_nsec3(&denial, &n("nope.example.com")),
            "NSEC3 NXDOMAIN 증명"
        );

        let nd = pick_denial_nsec3(&nsec3s, &n("www.example.com"), false);
        assert!(
            crate::prove_nodata_nsec3(&nd, &n("www.example.com"), 28),
            "NSEC3 NODATA"
        );
        assert!(
            !crate::prove_nodata_nsec3(&nd, &n("www.example.com"), 1),
            "A는 있음"
        );

        let deep_query = n("missing.deep.example.com");
        let deep_denial = pick_denial_nsec3(&nsec3s, &deep_query, true);
        let deep_hash = crate::nsec3_hash(&n("deep.example.com"), &salt, 0);
        assert!(deep_denial.iter().any(|record| {
            record
                .name
                .labels()
                .first()
                .and_then(crate::base32hex_decode_pub)
                .is_some_and(|hash| hash == deep_hash)
        }));

        let owner = &nsec3s[0].name;
        let set: Vec<Record> = nsec3s
            .iter()
            .filter(|r| r.name.eq_ignore_case(owner))
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(owner) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 50)
            .collect();
        assert!(!sigs.is_empty(), "RRSIG(NSEC3)");
        crate::validate_rrset(&set, &sigs, &[signer.dnskey()], now as u32)
            .expect("NSEC3 RRSIG 검증");
    }

    /**
     * @brief 빈 비단말도 체인에 들어가야 한다.
     * @details 레코드가 없어도 트리 상 존재하는 이름이다. 빠뜨리면 그 이름이 없다고
     *          증명돼 아래쪽 이름의 부재 증명이 어긋난다.
     */
    #[test]
    fn denial_chains_include_empty_nonterminals() {
        let signer = ZoneSigner::generate(n("example.com"), [31u8; 32]);
        let now = 1_700_000_000u64;
        let mut source = zone_records();
        source.push(Record::new(
            n("leaf.empty.example.com"),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 4)),
        ));
        let empty = n("empty.example.com");

        let nsec_signed = sign_zone_with(&source, &signer, now, &DenialMode::Nsec);
        let nsecs: Vec<Record> = nsec_signed
            .into_iter()
            .filter(|record| record.rtype == RecordType::NSEC)
            .collect();
        assert!(nsecs
            .iter()
            .any(|record| record.name.eq_ignore_case(&empty)));
        assert!(crate::prove_nodata(&nsecs, &empty, RecordType::AAAA.0));

        let params = Nsec3Params {
            iterations: 0,
            salt: vec![0xab, 0xcd],
        };
        let nsec3_signed =
            sign_zone_with(&source, &signer, now, &DenialMode::Nsec3(params.clone()));
        let nsec3s: Vec<Record> = nsec3_signed
            .into_iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .collect();
        let empty_hash = crate::nsec3_hash(&empty, &params.salt, params.iterations);
        assert!(
            nsec3s
                .iter()
                .any(|record| crate::nsec3_owner_hash(record)
                    .is_some_and(|owner| owner == empty_hash))
        );
        assert!(crate::prove_nodata_nsec3(
            &nsec3s,
            &empty,
            RecordType::AAAA.0
        ));
    }

    /** @brief 위임 아래 데이터는 자식 소유라 부모가 서명하지 않는다. DS와 NSEC만 예외다. */
    #[test]
    fn delegation_ns_and_glue_are_not_zone_signed() {
        let signer = ZoneSigner::generate(n("example.com"), [32u8; 32]);
        let now = 1_700_000_000u64;
        let child = n("child.example.com");
        let glue = n("ns.child.example.com");
        let nested = n("deep.child.example.com");
        let mut source = zone_records();
        source.push(Record::new(child.clone(), 300, RData::Ns(glue.clone())));
        source.push(Record::new(
            child.clone(),
            300,
            RData::Unknown(43, vec![0, 1, 13, 2]),
        ));
        source.push(Record::new(
            glue.clone(),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 53)),
        ));
        source.push(Record::new(
            n("host.child.example.com"),
            300,
            RData::A(Ipv4Addr::new(10, 0, 0, 54)),
        ));
        source.push(Record::new(
            nested.clone(),
            300,
            RData::Ns(n("ns.deep.child.example.com")),
        ));
        source.push(Record::new(
            nested.clone(),
            300,
            RData::Unknown(43, vec![0, 2, 13, 2]),
        ));

        let signed = sign_zone_with(&source, &signer, now, &DenialMode::Nsec);
        let signatures = |owner: &Name, covered: RecordType| {
            signed
                .iter()
                .filter(|record| record.name.eq_ignore_case(owner))
                .filter_map(Rrsig::from_record)
                .filter(|signature| signature.type_covered == covered.0)
                .count()
        };
        assert_eq!(signatures(&child, RecordType::NS), 0);
        assert_eq!(signatures(&child, RecordType::DS), 1);
        assert_eq!(signatures(&glue, RecordType::A), 0);
        assert_eq!(signatures(&nested, RecordType::DS), 0);
        let child_nsec = signed
            .iter()
            .find(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&child))
            .and_then(crate::Nsec::from_record)
            .expect("delegation NSEC");
        assert!(child_nsec.has_type(RecordType::NS.0));
        assert!(child_nsec.has_type(RecordType::DS.0));
        assert!(!child_nsec.has_type(RecordType::A.0));
        assert!(!signed
            .iter()
            .any(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&glue)));
        assert!(!signed
            .iter()
            .any(|record| record.rtype == RecordType::NSEC && record.name.eq_ignore_case(&nested)));

        let params = Nsec3Params {
            iterations: 0,
            salt: vec![0xab, 0xcd],
        };
        let nsec3_signed =
            sign_zone_with(&source, &signer, now, &DenialMode::Nsec3(params.clone()));
        let child_hash = crate::nsec3_hash(&child, &params.salt, params.iterations);
        let glue_hash = crate::nsec3_hash(&glue, &params.salt, params.iterations);
        let nested_hash = crate::nsec3_hash(&nested, &params.salt, params.iterations);
        let hashes: Vec<Vec<u8>> = nsec3_signed
            .iter()
            .filter(|record| record.rtype == RecordType::NSEC3)
            .filter_map(crate::nsec3_owner_hash)
            .collect();
        assert!(hashes.contains(&child_hash));
        assert!(!hashes.contains(&glue_hash));
        assert!(!hashes.contains(&nested_hash));
    }

    /** @brief 여러 부재 상황을 한데 모아, 고른 증명이 실제로 검증기를 통과하는지 확인한다. */
    #[test]
    fn dnssec_negative_proof_corpus() {
        let signer = ZoneSigner::generate(n("example.com"), [42u8; 32]);
        let now = 1_700_000_000u64;
        let nowu = now as u32;
        let signed = sign_zone_with(&zone_records(), &signer, now, &DenialMode::Nsec);
        let dnskey = signer.dnskey();

        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype == RecordType::A)
            .cloned()
            .collect();
        let sigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == RecordType::A.0)
            .collect();
        assert!(!rrset.is_empty() && !sigs.is_empty());

        crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], nowu).expect("기준 양성");

        let expired_at = (now + VALIDITY + 100) as u32;
        assert!(
            crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], expired_at).is_err(),
            "만료 서명 거부"
        );

        let before = (now - INCEPTION_SKEW - 100) as u32;
        assert!(
            crate::validate_rrset(&rrset, &sigs, &[dnskey.clone()], before).is_err(),
            "미도래 서명 거부"
        );

        let mut tampered = rrset.clone();
        if let RData::A(ip) = &mut tampered[0].rdata {
            *ip = Ipv4Addr::new(6, 6, 6, 6);
        }
        assert!(
            crate::validate_rrset(&tampered, &sigs, &[dnskey.clone()], nowu).is_err(),
            "변조 rrset 거부"
        );

        let mut badsig = sigs.clone();
        badsig[0].signature[0] ^= 0xff;
        assert!(
            crate::validate_rrset(&rrset, &badsig, &[dnskey.clone()], nowu).is_err(),
            "변조 서명 거부"
        );

        let other = ZoneSigner::generate(n("example.com"), [7u8; 32]);
        assert!(
            crate::validate_rrset(&rrset, &sigs, &[other.dnskey()], nowu).is_err(),
            "타 키 거부"
        );

        let mut ds = signer.ds().expect("DS");
        ds.digest[0] ^= 0xff;
        assert!(
            crate::verify_ds(&ds, &dnskey, &n("example.com")).is_err(),
            "변조 DS 거부"
        );

        let keyset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 48)
            .cloned()
            .collect();
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        assert!(
            crate::validate_dnskey_set(
                &keyset,
                &keysigs,
                &[other.ds().unwrap()],
                &n("example.com"),
                nowu
            )
            .is_err(),
            "비매칭 DS → 매칭 KSK 없음으로 거부"
        );
        crate::validate_dnskey_set(
            &keyset,
            &keysigs,
            &[signer.ds().unwrap()],
            &n("example.com"),
            nowu,
        )
        .expect("정상 DNSKEY 검증");

        let nsecs: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 47).cloned().collect();
        assert!(
            crate::prove_name_nonexistent(&nsecs, &n("nope.example.com")),
            "NXDOMAIN 부재증명"
        );
        let owner = nsecs[0].name.clone();
        let nset: Vec<Record> = nsecs
            .iter()
            .filter(|r| r.name.eq_ignore_case(&owner))
            .cloned()
            .collect();
        let nsigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&owner) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 47)
            .collect();
        crate::validate_rrset(&nset, &nsigs, &[dnskey.clone()], nowu).expect("NSEC RRSIG 검증");
        assert!(
            crate::validate_rrset(&nset, &nsigs, &[dnskey.clone()], expired_at).is_err(),
            "만료 NSEC 거부(denial도 시간유효 필요)"
        );
    }

    /** @brief PEM 왕복에서 같은 키가 나오는지. 재시작 때 서명 키가 바뀌면 안 된다. */
    #[test]
    fn signer_key_persists_via_pem() {
        let s1 = ZoneSigner::generate(n("example.com"), [7u8; 32]);
        let pem = s1.to_pkcs8_pem().expect("pem");
        let s2 = ZoneSigner::from_pkcs8_pem(&pem, n("example.com")).expect("load");
        assert_eq!(
            s1.dnskey().key_tag(),
            s2.dnskey().key_tag(),
            "키 영속화 → 같은 key_tag/DS"
        );
        assert_eq!(s1.ds().unwrap().digest, s2.ds().unwrap().digest);
    }

    /** @brief 키를 나눠 두면 DNSKEY는 KSK로, 나머지는 ZSK로 서명되고 체인이 성립하는지. */
    #[test]
    fn ksk_zsk_split_signs_and_validates() {
        let signer = ZoneSigner::generate_split(n("example.com"), [31u8; 32], [32u8; 32]);
        assert!(signer.is_split());
        let now = 1_700_000_000u64;
        let signed = sign_zone(&zone_records(), &signer, now);
        let keys = signer.dnskeys();
        assert_eq!(keys.len(), 2, "ZSK+KSK 게시");
        assert_eq!(signer.dnskey().flags, 256, "ZSK flags 256");
        assert_eq!(signer.ksk_dnskey().unwrap().flags, 257, "KSK flags 257 SEP");

        let ds = signer.ds().unwrap();
        assert_eq!(
            ds.key_tag,
            signer.ksk_dnskey().unwrap().key_tag(),
            "DS는 KSK"
        );

        let keyset: Vec<Record> = signed.iter().filter(|r| r.rtype.0 == 48).cloned().collect();
        assert_eq!(keyset.len(), 2);
        let keysigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 48)
            .collect();
        crate::validate_rrset(&keyset, &keysigs, &keys, now as u32).expect("DNSKEY(KSK) 검증");

        let rrset: Vec<Record> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 1)
            .cloned()
            .collect();
        let asigs: Vec<Rrsig> = signed
            .iter()
            .filter(|r| r.name.eq_ignore_case(&n("www.example.com")) && r.rtype.0 == 46)
            .filter_map(Rrsig::from_record)
            .filter(|s| s.type_covered == 1)
            .collect();
        assert_eq!(asigs[0].key_tag, signer.dnskey().key_tag(), "A는 ZSK 서명");
        crate::validate_rrset(&rrset, &asigs, &keys, now as u32).expect("A(ZSK) 검증");
    }
}
