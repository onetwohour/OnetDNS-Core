/**
 * @file
 * @brief 전달 방식에서 받은 응답을 이 서버가 직접 검증한다.
 *
 * @details 재귀 방식은 위임을 직접 걸으므로 내려오는 길에 DNSKEY와 DS를 함께 모은다.
 *          전달 방식에는 그 길이 없으므로 업스트림 서버에 DNSKEY와 DS를 따로 물어 신뢰 체인을
 *          구성한다. 업스트림이 이미 검증한 결과(AD 비트)는 믿지 않는다. 업스트림이 무엇을 했는지
 *          이 서버가 확인할 수 없기 때문이다.
 * @warning 업스트림에는 언제나 CD=1로 묻는다. 그러지 않으면 서명이 깨진 이름에 업스트림이 먼저
 *          SERVFAIL로 답해 버려 이 서버가 무엇이 잘못됐는지 볼 수 없다.
 */
use crate::native::{ResolveFailure, ResolveOutcome, Resolver};
use onetdns_core::MutexExt;
use onetdns_proto::{Edns, Message, Name, Record, RecordType, ResponseCode};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

/**
 * @brief 체인 하나를 구성하는 동안 업스트림에 물을 수 있는 횟수 상한.
 *
 * @details 이름 하나가 업스트림에 무한정 질의를 일으키지 못하게 한다. 루트부터 리프까지 라벨마다
 *          DS 한 번과 DNSKEY 한 번이면 족하므로, 흔한 깊이에서는 절반도 쓰지 않는다.
 * @warning 초과하면 검증 실패로 본다. 모르는 것을 안전하다고 답하지 않는다.
 */
const MAX_CHAIN_QUERIES: u32 = 24;

/** @brief 체인을 구성할 때 따라 내려갈 라벨 수 상한. */
const MAX_CHAIN_DEPTH: usize = 16;

/** @brief 확정한 체인을 담아 둘 곳 수. */
const CHAIN_CACHE_ENTRIES: usize = 4096;

/** @brief 확정한 체인을 이보다 오래 가지고 있지 않는다. */
const CHAIN_CACHE_MAX_TTL: u32 = 3600;

/** @brief 확정한 체인을 최소한 이만큼은 가지고 있는다. 라벨마다 다시 묻지 않으려는 것이다. */
const CHAIN_CACHE_MIN_TTL: u32 = 60;

/**
 * @brief 한 영역까지 구성한 신뢰 체인의 결과.
 *
 * @details 서명이 없는 위임을 만나면 그 아래는 검증할 것이 없다. 그것과 "검증에 실패했다"를
 *          구분해야 서명 없는 영역을 SERVFAIL로 막지 않는다.
 */
#[derive(Clone)]
enum ChainVerdict {
    /** @brief 이름을 담는 서명된 영역과 그 확정된 키. */
    Secure {
        /** @brief 영역의 확정된 키. */
        keys: Arc<[onetdns_dnssec::Dnskey]>,
        /** @brief 이름을 담는 가장 깊은 영역 apex. */
        apex: Name,
    },
    /** @brief 위임이 서명되지 않아 검증할 것이 없다. */
    Insecure,
}

/** @brief 담아 둔 체인 하나. */
struct CachedChain {
    /** @brief 판정. */
    verdict: ChainVerdict,
    /** @brief 이 시각이 지나면 체인을 다시 구성한다. Unix 초. */
    expires: u32,
    /** @brief 이 판정을 낼 때 쓴 앵커의 지문. 앵커가 바뀌면 버린다. */
    anchor_tag: u64,
}

/**
 * @brief 전달받은 응답을 검증하는 계층.
 *
 * @invariant 이 계층 위쪽(캐시 계열)은 이미 검증된 응답만 본다. 아래쪽(예비 업스트림 포함)은
 *            전부 이 계층을 거친다.
 */
pub struct ForwardValidateLayer {
    /** @brief 실제로 물어볼 곳. */
    inner: Arc<dyn Resolver>,
    /** @brief 루트 신뢰 기준. 무중단 갱신으로 바뀔 수 있다. */
    anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
    /** @brief 확정한 체인. */
    chains: Mutex<onetdns_core::LruMap<Vec<u8>, CachedChain>>,
    /** @brief 부수 질의에 붙일 번호. */
    next_id: AtomicU16,
    /** @brief 판정 방침. */
    policy: ForwardValidationPolicy,
}

/**
 * @brief 전달 검증기의 판정 방침. 재귀 리졸버와 같은 설정 키에서 온다.
 * @details 전달 방식이 기본값이므로, 이 키들이 재귀 리졸버에만 닿으면 대부분의 설치에서 아무 효과가
 *          없다.
 */
pub struct ForwardValidationPolicy {
    /** @brief DS 부재에 서명된 증명을 요구할지. */
    pub strict: bool,
    /** @brief 검증에 실패한 답을 SERVFAIL 대신 AD 없이 내보낼지. */
    pub permissive: bool,
    /** @brief 클라이언트가 CD=1로 물어도 검증할지. */
    pub ignore_cd: bool,
    /** @brief 검증하지 않을 도메인. 그 아래 이름도 포함한다. */
    pub insecure_domains: Vec<Name>,
    /** @brief RFC 8509 루트 키 센티널 질의에 앵커 상태로 답할지. */
    pub root_key_sentinel: bool,
}

impl ForwardValidateLayer {
    /**
     * @brief 계층을 만든다.
     * @param inner 실제로 물어볼 곳. 예비 업스트림까지 포함한 것이어야 한다.
     * @param anchors 루트 신뢰 기준 핸들.
     * @param policy 판정 방침.
     */
    pub fn new(
        inner: Arc<dyn Resolver>,
        anchors: Arc<onetdns_core::ArcSwap<Vec<onetdns_dnssec::Ds>>>,
        policy: ForwardValidationPolicy,
    ) -> Self {
        ForwardValidateLayer {
            inner,
            anchors,
            chains: Mutex::new(onetdns_core::LruMap::new(CHAIN_CACHE_ENTRIES)),
            next_id: AtomicU16::new(1),
            policy,
        }
    }

    /**
     * @brief 검증된 답이 센티널 질의라면 SERVFAIL 로 답해야 하는지.
     * @details 질의자는 is-ta 와 not-ta 두 이름의 응답 차이로 이 서버가 어느 루트 키를 믿는지
     *          알아낸다. 검증된 A, AAAA 답에만 적용한다.
     */
    fn sentinel_fails(&self, request: &Message) -> bool {
        let Some(question) = request.questions.first() else {
            return false;
        };
        if question.qtype != RecordType::A && question.qtype != RecordType::AAAA {
            return false;
        }
        question
            .name
            .labels()
            .first()
            .and_then(onetdns_dnssec::RootKeySentinel::parse)
            .is_some_and(|sentinel| sentinel.fails(&self.anchors.load()))
    }

    /** @brief 부수 질의에 쓸 번호. */
    fn query_id(&self) -> u16 {
        self.next_id.fetch_add(1, Ordering::Relaxed) | 1
    }

    /**
     * @brief 업스트림에 한 건 묻는다. 서명을 받아야 하므로 DO=1, 업스트림 판정을 막으려 CD=1이다.
     * @return 응답. 닿지 못하면 없다.
     */
    fn ask(&self, name: &Name, qtype: RecordType, budget: &mut u32) -> Option<Message> {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let mut query = Message::query(self.query_id(), name.clone(), qtype);
        query.header.checking_disabled = true;
        let edns = Edns {
            dnssec_ok: true,
            ..Edns::default()
        };
        query.additionals.push(edns.try_to_record().ok()?);
        let response = self.inner.resolve(&query)?;
        if response.header.rcode != ResponseCode::NoError.0
            && response.header.rcode != ResponseCode::NXDomain.0
        {
            return None;
        }
        Some(response)
    }

    /** @brief 앵커 목록의 지문. 앵커가 바뀌면 담아 둔 판정을 못 쓰게 하려는 것이다. */
    fn anchor_tag(anchors: &[onetdns_dnssec::Ds]) -> u64 {
        let mut tag: u64 = 0xcbf2_9ce4_8422_2325;
        for ds in anchors {
            for byte in ds
                .key_tag
                .to_be_bytes()
                .iter()
                .chain(std::slice::from_ref(&ds.algorithm))
                .chain(std::slice::from_ref(&ds.digest_type))
                .chain(ds.digest.iter())
            {
                tag ^= u64::from(*byte);
                tag = tag.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        tag
    }

    /** @brief 담아 둔 판정을 꺼낸다. 앵커가 바뀌었거나 수명이 지났으면 없다. */
    fn cached(&self, zone: &Name, now: u32, anchor_tag: u64) -> Option<ChainVerdict> {
        let key = zone.canonical_key();
        let mut chains = self.chains.lock_recover();
        let entry = chains.get(&key)?;
        if entry.anchor_tag != anchor_tag || entry.expires <= now {
            chains.pop(&key);
            return None;
        }
        Some(entry.verdict.clone())
    }

    /** @brief 판정을 담아 둔다. */
    fn remember(&self, zone: &Name, verdict: &ChainVerdict, now: u32, ttl: u32, anchor_tag: u64) {
        let ttl = ttl.clamp(CHAIN_CACHE_MIN_TTL, CHAIN_CACHE_MAX_TTL);
        self.chains.lock_recover().put(
            zone.canonical_key(),
            CachedChain {
                verdict: verdict.clone(),
                expires: now.saturating_add(ttl),
                anchor_tag,
            },
        );
    }

    /**
     * @brief 루트부터 이 이름을 담는 영역까지 신뢰 체인을 구성한다.
     *
     * @details 루트의 DNSKEY를 앵커로 확정한 뒤, 라벨을 하나씩 내려가며 DS를 묻는다. DS가
     *          있으면 그 이름이 서명된 위임이므로 DNSKEY까지 확정하고 내려간다. DS가 없으면
     *          부모 키로 서명된 증명을 보고 서명되지 않은 위임인지, 위임이 아닌 보통 이름인지
     *          가린다. 위임이 아니면 같은 영역 키를 가지고 다음 라벨로 간다.
     * @warning 라벨마다 위임이라고 가정하면 서명된 영역의 보통 이름에 대한 DS 부재 증명이
     *          서명되지 않은 위임의 증명으로 읽힌다. 그러면 서명을 떼어 낸 답이 검증 없이
     *          나가고, 이름 자신을 서명자로 적은 위조 서명도 통과한다.
     * @param name 체인 끝. 응답 서명의 signer 이름이거나, 서명이 없을 때는 질의 이름이다.
     * @return 확정된 판정. 구성하지 못하면 없다. 그때는 검증 실패로 다룬다.
     */
    fn chain_to(&self, name: &Name, now: u32, budget: &mut u32) -> Option<ChainVerdict> {
        let anchors = self.anchors.load();
        if anchors.is_empty() {
            return None;
        }
        let anchor_tag = Self::anchor_tag(&anchors);
        if let Some(verdict) = self.cached(name, now, anchor_tag) {
            return Some(verdict);
        }

        let labels = name.num_labels();
        if labels > MAX_CHAIN_DEPTH {
            return None;
        }

        let mut trusted_ds: Vec<onetdns_dnssec::Ds> = anchors.to_vec();
        let mut apex = Name::root();
        let mut examined = 0usize;
        let mut ttl = u32::MAX;
        let verdict = 'zones: loop {
            let Some((dnskeys, dnskey_rrsigs)) = self.dnskey_rrset(&apex, budget) else {
                onetdns_core::debug!(
                    event = "dnssec.forward_no_dnskey",
                    zone = %apex.to_ascii_lower(),
                    "Could not get this zone's DNSKEY and its signatures; cannot build the chain"
                );
                return None;
            };
            ttl = dnskeys.iter().map(|record| record.ttl).fold(ttl, u32::min);
            let keys = match onetdns_dnssec::validate_dnskey_set(
                &dnskeys,
                &dnskey_rrsigs,
                &trusted_ds,
                &apex,
                now,
            ) {
                Ok(keys) => keys,
                Err(error) => {
                    onetdns_core::debug!(
                        event = "dnssec.forward_chain_bogus",
                        zone = %apex.to_ascii_lower(),
                        error = ?error,
                        "Zone key does not match the DS established above"
                    );
                    return None;
                }
            };
            while examined < labels {
                examined += 1;
                let child = name.suffix(examined);
                let Some((ds_records, ds_rrsigs, nsec, nsec_rrsigs, nsec3, nsec3_rrsigs)) =
                    self.delegation_evidence(&child, budget)
                else {
                    onetdns_core::debug!(
                        event = "dnssec.forward_no_ds",
                        zone = %child.to_ascii_lower(),
                        "Could not get a DS response; cannot build the chain"
                    );
                    return None;
                };
                if !ds_records.is_empty() {
                    if onetdns_dnssec::validate_rrset_in_zone(
                        &ds_records,
                        &ds_rrsigs,
                        &keys,
                        &apex,
                        now,
                    )
                    .is_err()
                    {
                        onetdns_core::debug!(
                            event = "dnssec.forward_ds_bogus",
                            zone = %child.to_ascii_lower(),
                            "Delegation's DS signature does not verify with the parent key"
                        );
                        return None;
                    }
                    let supported: Vec<onetdns_dnssec::Ds> = ds_records
                        .iter()
                        .filter_map(onetdns_dnssec::Ds::from_record)
                        .filter(onetdns_dnssec::ds_is_supported)
                        .collect();
                    if supported.is_empty() {
                        break 'zones ChainVerdict::Insecure;
                    }
                    trusted_ds = supported;
                    apex = child;
                    continue 'zones;
                }
                let evidence = onetdns_dnssec::DenialEvidence {
                    nsec: &nsec,
                    nsec_rrsigs: &nsec_rrsigs,
                    nsec3: &nsec3,
                    nsec3_rrsigs: &nsec3_rrsigs,
                };
                match onetdns_dnssec::classify_ds_absence(&apex, &keys, &evidence, &child, now) {
                    onetdns_dnssec::DsAbsence::InsecureDelegation => {
                        break 'zones ChainVerdict::Insecure;
                    }
                    onetdns_dnssec::DsAbsence::NotACut => {}
                    onetdns_dnssec::DsAbsence::Unproven if self.policy.strict => {
                        onetdns_core::debug!(
                            event = "dnssec.forward_ds_unproven",
                            zone = %child.to_ascii_lower(),
                            "No signed proof that the DS is absent"
                        );
                        return None;
                    }
                    onetdns_dnssec::DsAbsence::Unproven => break 'zones ChainVerdict::Insecure,
                }
            }
            break ChainVerdict::Secure {
                keys: keys.into(),
                apex,
            };
        };
        let ttl = if ttl == u32::MAX {
            CHAIN_CACHE_MIN_TTL
        } else {
            ttl
        };
        self.remember(name, &verdict, now, ttl, anchor_tag);
        Some(verdict)
    }

    /** @brief 이 영역의 DNSKEY와 그 서명. 어느 하나라도 없으면 없다. */
    fn dnskey_rrset(
        &self,
        zone: &Name,
        budget: &mut u32,
    ) -> Option<(Vec<Record>, Vec<onetdns_dnssec::Rrsig>)> {
        let response = self.ask(zone, RecordType::DNSKEY, budget)?;
        let (dnskeys, dnskey_rrsigs) =
            onetdns_dnssec::anchor::extract_dnskey_rrset(&response.answers, zone);
        if dnskeys.is_empty() || dnskey_rrsigs.is_empty() {
            return None;
        }
        Some((dnskeys, dnskey_rrsigs))
    }

    /**
     * @brief 이 이름의 DS와, DS가 없다면 그 부재 증명을 모은다.
     * @return (DS, DS 서명, NSEC, NSEC 서명, NSEC3, NSEC3 서명).
     */
    #[allow(clippy::type_complexity)]
    fn delegation_evidence(
        &self,
        child: &Name,
        budget: &mut u32,
    ) -> Option<(
        Vec<Record>,
        Vec<onetdns_dnssec::Rrsig>,
        Vec<Record>,
        Vec<onetdns_dnssec::Rrsig>,
        Vec<Record>,
        Vec<onetdns_dnssec::Rrsig>,
    )> {
        let response = self.ask(child, RecordType::DS, budget)?;
        let ds_records = section_records(&response.answers, child, RecordType::DS);
        let ds_rrsigs = covering_rrsigs(&response.answers, child, RecordType::DS);
        if !ds_records.is_empty() {
            return Some((
                ds_records,
                ds_rrsigs,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ));
        }
        onetdns_core::debug!(
            event = "dnssec.forward_ds_empty",
            zone = %child.to_ascii_lower(),
            rcode = response.header.rcode,
            answers = response.answers.len(),
            authorities = response.authorities.len(),
            "Delegation has no DS; treating it as proven absent"
        );
        let nsec = records_of_type(&response.authorities, RecordType::NSEC);
        let nsec3 = records_of_type(&response.authorities, RecordType::NSEC3);
        let nsec_rrsigs = rrsigs_covering_type(&response.authorities, RecordType::NSEC);
        let nsec3_rrsigs = rrsigs_covering_type(&response.authorities, RecordType::NSEC3);
        Some((
            Vec::new(),
            Vec::new(),
            nsec,
            nsec_rrsigs,
            nsec3,
            nsec3_rrsigs,
        ))
    }

    /**
     * @brief 응답 하나를 판정한다.
     * @return 참이면 서명이 확인됐다(AD를 설정한다), 거짓이면 검증할 것이 없다(그대로 낸다).
     *         실패는 없음으로 답하고 호출자가 SERVFAIL로 바꾼다.
     */
    fn verdict_for(&self, response: &Message, now: u32, budget: &mut u32) -> Option<bool> {
        let question = response.questions.first()?;
        if response.answers.is_empty() {
            /*
             * 답이 없는 응답이다. 증명은 권한 구간에 있고 이 계층은 부재 증명까지 확인하지
             * 않으므로 AD를 설정하지 않고 그대로 낸다. 답 구간에 서명이 없다는 것만으로
             * 떼어 낸 것으로 보면, 서명된 영역의 NODATA가 전부 SERVFAIL이 된다.
             * 다만 서명된 영역인데 권한 구간에도 서명이 하나도 없으면 누가 걷어 낸
             * 것이므로 막는다. 그러지 않으면 답을 지워 부정 응답으로 바꾸는 강등이 통한다.
             */
            let stripped = matches!(
                self.chain_to(&question.name, now, budget),
                Some(ChainVerdict::Secure { .. })
            ) && !response
                .authorities
                .iter()
                .any(|record| record.rtype == RecordType::RRSIG);
            if stripped {
                onetdns_core::debug!(
                    event = "dnssec.forward_denial_unsigned",
                    qname = %question.name.to_ascii_lower(),
                    "Negative answer from a signed zone carries no signatures"
                );
                return None;
            }
            return Some(false);
        }
        let signer = match answer_signer(response) {
            Some(signer) => signer,
            None => {
                /*
                 * 서명이 하나도 없다. 서명돼야 할 곳인지 체인으로 확인한다. 서명되지 않은
                 * 영역이면 그대로 두고, 서명된 영역인데 서명이 없으면 떼어 낸 것이다.
                 */
                return match self.chain_to(&question.name, now, budget) {
                    Some(ChainVerdict::Insecure) => Some(false),
                    Some(ChainVerdict::Secure { .. }) => None,
                    None => None,
                };
            }
        };
        let keys = match self.chain_to(&signer, now, budget)? {
            ChainVerdict::Secure { keys, apex } if apex.eq_ignore_case(&signer) => keys,
            ChainVerdict::Secure { apex, .. } => {
                onetdns_core::debug!(
                    event = "dnssec.forward_signer_not_apex",
                    signer = %signer.to_ascii_lower(),
                    apex = %apex.to_ascii_lower(),
                    "Signer name is not the zone apex"
                );
                return None;
            }
            ChainVerdict::Insecure => return Some(false),
        };
        let rrset = section_records(&response.answers, &question.name, question.qtype);
        if rrset.is_empty() {
            /*
             * 답이 없는 응답이다. 부정 응답의 증명까지 여기서 세우지는 않으므로 서명을
             * 확인했다고 말하지 않는다. 틀린 AD를 설정하는 것보다 설정하지 않는 편이 낫다.
             */
            return Some(false);
        }
        let rrsigs = covering_rrsigs(&response.answers, &question.name, question.qtype);
        if rrsigs.is_empty() {
            onetdns_core::debug!(
                event = "dnssec.forward_answer_unsigned",
                qname = %question.name.to_ascii_lower(),
                "Answer from a signed zone has no covering signature"
            );
            return None;
        }
        match onetdns_dnssec::validate_rrset_in_zone(&rrset, &rrsigs, &keys, &signer, now) {
            Ok(()) => Some(true),
            Err(error) => {
                onetdns_core::debug!(
                    event = "dnssec.forward_answer_bogus",
                    signer = %signer.to_ascii_lower(),
                    records = rrset.len(),
                    signatures = rrsigs.len(),
                    keys = keys.len(),
                    error = ?error,
                    "Covering signature on the answer did not verify"
                );
                None
            }
        }
    }
}

impl Resolver for ForwardValidateLayer {
    /** @brief 해석한다. 실패는 없음으로 바꾼다. */
    fn resolve(&self, request: &Message) -> Option<Message> {
        crate::layers::outcome_to_option(self.resolve_outcome(request))
    }

    /**
     * @brief 업스트림 응답을 받아 이 서버가 검증한 뒤 AD를 설정한다.
     *
     * @details 클라이언트가 CD=1로 물으면 검증을 건너뛴다. 그것이 CD의 뜻이다.
     * @warning 검증에 실패하면 답을 내보내지 않는다. 사유는 되돌릴 수 없는 실패로 알린다.
     *          다른 업스트림에 다시 물어도 같은 서명이 온다.
     * @warning 내보내기 전에 원래 질의 기준으로 DNSSEC 전용 레코드를 걷어낸다. 안쪽 계층은
     *          이 서버가 DO=1로 바꿔 물은 질의를 보므로 걷어내지 않는다. 여기서 빠뜨리면 DO 없이
     *          물은 질의자, EDNS 를 모르는 질의자에게도 RRSIG 가 나간다.
     */
    fn resolve_outcome(&self, request: &Message) -> ResolveOutcome {
        let honor_cd = request.header.checking_disabled && !self.policy.ignore_cd;
        if honor_cd || request.questions.len() != 1 {
            return self.inner.resolve_outcome(request);
        }
        let mut upstream = request.clone();
        upstream.header.checking_disabled = true;
        set_dnssec_ok(&mut upstream);

        let mut response = match self.inner.resolve_outcome(&upstream) {
            ResolveOutcome::Response(response) => response,
            failure => return failure,
        };
        if response.header.rcode != ResponseCode::NoError.0
            && response.header.rcode != ResponseCode::NXDomain.0
        {
            response.header.authentic_data = false;
            crate::native::strip_dnssec_unless_requested(request, &mut response);
            return ResolveOutcome::Response(response);
        }

        let insecure = request.questions[0].name.clone();
        if self
            .policy
            .insecure_domains
            .iter()
            .any(|domain| insecure.ends_with_ignore_case(domain))
        {
            response.header.authentic_data = false;
            crate::native::strip_dnssec_unless_requested(request, &mut response);
            return ResolveOutcome::Response(response);
        }

        let now = now_secs();
        let mut budget = MAX_CHAIN_QUERIES;
        match self.verdict_for(&response, now, &mut budget) {
            Some(true) if self.policy.root_key_sentinel && self.sentinel_fails(request) => {
                response.answers.clear();
                response.authorities.clear();
                response
                    .additionals
                    .retain(|record| record.rtype == RecordType::OPT);
                response.header.rcode = ResponseCode::ServFail.0;
                response.header.authentic_data = false;
                ResolveOutcome::Response(response)
            }
            Some(authentic) => {
                response.header.authentic_data = authentic && asks_for_ad(request);
                crate::native::strip_dnssec_unless_requested(request, &mut response);
                ResolveOutcome::Response(response)
            }
            None if self.policy.permissive => {
                onetdns_core::warn!(
                    event = "dnssec.forward_bogus_permissive",
                    qname = %insecure.to_ascii_lower(),
                    "Could not verify signatures; answering without AD because permissive mode is on"
                );
                response.header.authentic_data = false;
                crate::native::strip_dnssec_unless_requested(request, &mut response);
                ResolveOutcome::Response(response)
            }
            None => {
                let question = response
                    .questions
                    .first()
                    .map(|q| q.name.to_ascii_lower())
                    .unwrap_or_default();
                onetdns_core::warn!(
                    event = "dnssec.forward_bogus",
                    qname = %question,
                    "Could not verify signatures on the forwarded answer; not answering"
                );
                ResolveOutcome::Failure(ResolveFailure::Permanent(Some(
                    onetdns_proto::ede_code::DNSSEC_BOGUS,
                )))
            }
        }
    }
}

/**
 * @brief 클라이언트가 AD 비트를 받겠다고 했는지.
 * @details RFC 6840 은 DO 나 AD 를 설정해 물은 질의자에게만 AD 를 설정하라고 한다. 둘 다 없는
 *          질의자는 AD 를 해석하지 못할 수 있다.
 */
fn asks_for_ad(request: &Message) -> bool {
    request.header.authentic_data
        || request
            .additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT)
            .filter_map(Edns::from_record)
            .any(|edns| edns.dnssec_ok)
}

/** @brief 요청에 DO 비트를 설정한다. OPT가 없으면 만든다. */
pub(crate) fn set_dnssec_ok(request: &mut Message) {
    if let Some(existing) = request
        .additionals
        .iter()
        .position(|record| record.rtype == RecordType::OPT)
    {
        if let Some(mut edns) = Edns::from_record(&request.additionals[existing]) {
            if edns.dnssec_ok {
                return;
            }
            edns.dnssec_ok = true;
            if let Ok(record) = edns.try_to_record() {
                request.additionals[existing] = record;
            }
            return;
        }
        request.additionals.remove(existing);
    }
    let edns = Edns {
        dnssec_ok: true,
        ..Edns::default()
    };
    if let Ok(record) = edns.try_to_record() {
        request.additionals.push(record);
    }
}

/** @brief 이 이름과 종류의 레코드만 모은다. */
fn section_records(section: &[Record], name: &Name, qtype: RecordType) -> Vec<Record> {
    section
        .iter()
        .filter(|record| record.rtype == qtype && record.name.eq_ignore_case(name))
        .cloned()
        .collect()
}

/** @brief 이 종류의 레코드만 모은다. 이름은 보지 않는다. */
fn records_of_type(section: &[Record], qtype: RecordType) -> Vec<Record> {
    section
        .iter()
        .filter(|record| record.rtype == qtype)
        .cloned()
        .collect()
}

/** @brief 이 이름과 종류를 덮는 서명들. */
fn covering_rrsigs(
    section: &[Record],
    name: &Name,
    qtype: RecordType,
) -> Vec<onetdns_dnssec::Rrsig> {
    section
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG && record.name.eq_ignore_case(name))
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .filter(|rrsig| rrsig.type_covered == qtype.0)
        .collect()
}

/** @brief 이 종류를 덮는 서명들. 이름은 보지 않는다. */
fn rrsigs_covering_type(section: &[Record], qtype: RecordType) -> Vec<onetdns_dnssec::Rrsig> {
    section
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG)
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .filter(|rrsig| rrsig.type_covered == qtype.0)
        .collect()
}

/**
 * @brief 답을 서명한 영역 이름.
 *
 * @details signer 이름을 서명에서 가져온다. 전달 방식에는 위임을 걸은 기록이 없으므로,
 *          어느 영역의 키로 확인해야 하는지는 서명 자신만 알려 줄 수 있다.
 * @return 답 구간에 질문 종류를 덮는 서명이 있으면 그 signer.
 */
fn answer_signer(response: &Message) -> Option<Name> {
    let qtype = response.questions.first()?.qtype;
    response
        .answers
        .iter()
        .filter(|record| record.rtype == RecordType::RRSIG)
        .filter_map(onetdns_dnssec::Rrsig::from_record)
        .find(|rrsig| rrsig.type_covered == qtype.0 || rrsig.type_covered == RecordType::CNAME.0)
        .map(|rrsig| rrsig.signer)
}

/** @brief 지금 Unix 초. */
fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::ResolveOutcome;
    use onetdns_proto::{DnsClass, Question, RData};

    /** @brief 미리 정해 둔 답만 내주는 리졸버. 업스트림에 실제로 묻지 않으려는 것이다. */
    struct Canned {
        /** @brief (이름 소문자, 종류) 별 답. */
        answers: std::collections::HashMap<(String, u16), Message>,
        /** @brief 받은 질의 수. */
        asked: std::sync::atomic::AtomicUsize,
    }

    impl Resolver for Canned {
        fn resolve(&self, request: &Message) -> Option<Message> {
            self.asked.fetch_add(1, Ordering::Relaxed);
            let question = request.questions.first()?;
            let key = (question.name.to_ascii_lower(), question.qtype.0);
            let mut response = self.answers.get(&key)?.clone();
            response.header.id = request.header.id;
            response.questions = request.questions.clone();
            Some(response)
        }
    }

    /** @brief 서명 없는 답 하나. */
    fn unsigned_answer(name: &str) -> Message {
        let owner = Name::from_str(name).unwrap();
        let mut message = Message::query(1, owner.clone(), RecordType::A);
        message.header.response = true;
        message.header.recursion_available = true;
        message.answers.push(Record {
            name: owner,
            rtype: RecordType::A,
            class: DnsClass::IN,
            ttl: 60,
            rdata: RData::A([192, 0, 2, 1].into()),
        });
        message
    }

    /** @brief 루트 신뢰 기준이 비어 있는 검증기. 체인을 구성할 수 없다. */
    fn layer_without_anchors(inner: Arc<dyn Resolver>) -> ForwardValidateLayer {
        ForwardValidateLayer::new(
            inner,
            Arc::new(onetdns_core::ArcSwap::new(Arc::new(Vec::new()))),
            ForwardValidationPolicy {
                strict: true,
                permissive: false,
                ignore_cd: false,
                insecure_domains: Vec::new(),
                root_key_sentinel: true,
            },
        )
    }

    #[test]
    /**
     * @brief 클라이언트가 CD=1로 물으면 검증을 건너뛰는지.
     *
     * @details CD의 뜻이 그것이다. 건너뛰지 않으면 검증을 끄고 원본을 보려는 진단이
     *          이 서버의 판정에 막혀 아무것도 볼 수 없게 된다.
     */
    fn checking_disabled_passes_through_untouched() {
        let mut answers = std::collections::HashMap::new();
        answers.insert(
            ("unsigned.test".to_string(), 1),
            unsigned_answer("unsigned.test"),
        );
        let canned = Arc::new(Canned {
            answers,
            asked: std::sync::atomic::AtomicUsize::new(0),
        });
        let layer = layer_without_anchors(canned.clone());

        let mut request =
            Message::query(7, Name::from_str("unsigned.test").unwrap(), RecordType::A);
        request.header.checking_disabled = true;
        let outcome = layer.resolve_outcome(&request);
        assert!(
            matches!(outcome, ResolveOutcome::Response(ref r) if r.answers.len() == 1),
            "CD=1인데 답을 막았습니다"
        );
        assert_eq!(
            canned.asked.load(Ordering::Relaxed),
            1,
            "CD=1인데 체인을 세우려 했습니다"
        );
    }

    #[test]
    /**
     * @brief DO 없이 물은 질의자에게 DNSSEC 전용 레코드가 나가지 않는지.
     *
     * @details 업스트림에는 DO=1로 묻기 때문에 서명이 붙은 답이 돌아온다. 오류 응답을
     *          그대로 넘기는 분기와 검증을 마친 분기가 같은 걷어내기를 거친다.
     */
    fn dnssec_records_do_not_reach_a_client_that_did_not_ask() {
        let owner = Name::from_str("refused.test").unwrap();
        let mut refused = Message::query(1, owner.clone(), RecordType::A);
        refused.header.response = true;
        refused.header.rcode = ResponseCode::Refused.0;
        refused.authorities.push(Record {
            name: owner.clone(),
            rtype: RecordType::RRSIG,
            class: DnsClass::IN,
            ttl: 60,
            rdata: RData::Unknown(RecordType::RRSIG.0, vec![0; 18]),
        });
        let mut answers = std::collections::HashMap::new();
        answers.insert(("refused.test".to_string(), 1), refused);
        let layer = layer_without_anchors(Arc::new(Canned {
            answers,
            asked: std::sync::atomic::AtomicUsize::new(0),
        }));

        let plain = Message::query(7, owner.clone(), RecordType::A);
        let ResolveOutcome::Response(response) = layer.resolve_outcome(&plain) else {
            panic!("오류 응답을 그대로 넘기지 않았습니다");
        };
        assert!(
            response.authorities.is_empty(),
            "DO 없이 물었는데 RRSIG 가 나갔습니다"
        );

        let mut asked = Message::query(8, owner, RecordType::A);
        set_dnssec_ok(&mut asked);
        let ResolveOutcome::Response(response) = layer.resolve_outcome(&asked) else {
            panic!("오류 응답을 그대로 넘기지 않았습니다");
        };
        assert_eq!(
            response.authorities.len(),
            1,
            "DO=1로 물었는데 RRSIG 를 걷어냈습니다"
        );
    }

    #[test]
    /**
     * @brief 체인을 구성하지 못하면 답하지 않는지.
     *
     * @details 루트 신뢰 기준이 없으면 서명이 있는지조차 판정할 수 없다. 그때 그대로
     *          내보내면 검증한다고 말해 놓고 검증하지 않은 답을 주는 것이 된다.
     */
    fn an_unbuildable_chain_is_not_answered() {
        let mut answers = std::collections::HashMap::new();
        answers.insert(
            ("unsigned.test".to_string(), 1),
            unsigned_answer("unsigned.test"),
        );
        let canned = Arc::new(Canned {
            answers,
            asked: std::sync::atomic::AtomicUsize::new(0),
        });
        let layer = layer_without_anchors(canned);

        let request = Message::query(7, Name::from_str("unsigned.test").unwrap(), RecordType::A);
        assert!(
            matches!(
                layer.resolve_outcome(&request),
                ResolveOutcome::Failure(ResolveFailure::Permanent(Some(code)))
                    if code == onetdns_proto::ede_code::DNSSEC_BOGUS
            ),
            "체인을 구성하지 못했는데 답했습니다"
        );
    }

    /** @brief 답이 없는 응답. 부정 증명을 권한 구간에 담을지 고를 수 있다. */
    fn nodata_answer(name: &str, signed_denial: bool) -> Message {
        let owner = Name::from_str(name).unwrap();
        let mut message = Message::query(1, owner.clone(), RecordType::A);
        message.header.response = true;
        message.header.recursion_available = true;
        message.authorities.push(Record {
            name: owner.clone(),
            rtype: RecordType::SOA,
            class: DnsClass::IN,
            ttl: 60,
            rdata: RData::Unknown(RecordType::SOA.0, vec![0u8; 4]),
        });
        if signed_denial {
            message.authorities.push(Record {
                name: owner,
                rtype: RecordType::RRSIG,
                class: DnsClass::IN,
                ttl: 60,
                rdata: RData::Unknown(RecordType::RRSIG.0, vec![0u8; 20]),
            });
        }
        message
    }

    #[test]
    /**
     * @brief 답이 없는 응답을 서명이 떼인 것으로 오해하지 않는지.
     *
     * @details 부정 응답의 증명은 권한 구간에 있으므로 답 구간에는 서명이 없는 것이
     *          정상이다. 답 구간만 보고 판정하면 서명된 영역의 NODATA가 전부 SERVFAIL이
     *          된다. AAAA가 없는 이름, HTTPS 기록이 없는 이름이 모두 여기 걸린다.
     * @note 그 대신 권한 구간에도 서명이 하나도 없으면 막는다. 답을 지워 부정 응답으로
     *       바꾸는 강등을 그대로 통과시키지 않기 위해서다.
     */
    fn a_negative_answer_is_not_treated_as_a_stripped_signature() {
        let build = |signed_denial: bool| {
            let mut answers = std::collections::HashMap::new();
            answers.insert(
                ("nodata.test".to_string(), 1),
                nodata_answer("nodata.test", signed_denial),
            );
            Arc::new(Canned {
                answers,
                asked: std::sync::atomic::AtomicUsize::new(0),
            })
        };
        let request = Message::query(9, Name::from_str("nodata.test").unwrap(), RecordType::A);

        /* 루트 신뢰 기준이 없으면 체인이 Secure가 아니므로 부정 응답은 그대로 나간다. */
        let layer = layer_without_anchors(build(true));
        let outcome = layer.resolve_outcome(&request);
        let ResolveOutcome::Response(response) = outcome else {
            panic!("부정 응답을 막았습니다");
        };
        assert_eq!(
            response.header.rcode,
            onetdns_proto::ResponseCode::NoError.0
        );
        assert!(response.answers.is_empty());
        assert!(
            !response.header.authentic_data,
            "부재 증명을 확인하지 않았으므로 AD를 설정하면 안 됩니다"
        );

        /* 권한 구간에 서명이 없어도, 체인이 Secure가 아니면 막을 근거가 없다. */
        let layer = layer_without_anchors(build(false));
        assert!(
            matches!(layer.resolve_outcome(&request), ResolveOutcome::Response(_)),
            "서명 여부를 판정할 수 없으면 그대로 내보내야 합니다"
        );
    }

    #[test]
    /** @brief 업스트림에 보내는 질의에 DO와 CD가 서는지. */
    fn upstream_queries_carry_do_and_cd() {
        struct Spy(Mutex<Vec<(bool, bool)>>);
        impl Resolver for Spy {
            fn resolve(&self, request: &Message) -> Option<Message> {
                let dnssec_ok = request
                    .additionals
                    .iter()
                    .filter(|record| record.rtype == RecordType::OPT)
                    .filter_map(Edns::from_record)
                    .any(|edns| edns.dnssec_ok);
                self.0
                    .lock_recover()
                    .push((dnssec_ok, request.header.checking_disabled));
                None
            }
        }
        let spy = Arc::new(Spy(Mutex::new(Vec::new())));
        let layer = layer_without_anchors(spy.clone());
        let request = Message::query(7, Name::from_str("a.test").unwrap(), RecordType::A);
        let _ = layer.resolve_outcome(&request);
        let seen = spy.0.lock_recover().clone();
        assert_eq!(
            seen,
            vec![(true, true)],
            "업스트림 질의에 DO 또는 CD가 없습니다"
        );
    }

    #[test]
    /** @brief 요청에 이미 OPT가 있어도 DO만 설정하고 나머지는 그대로 두는지. */
    fn existing_opt_keeps_its_payload_size() {
        let mut request = Message::query(7, Name::from_str("a.test").unwrap(), RecordType::A);
        let edns = Edns {
            udp_payload: 4096,
            ..Edns::default()
        };
        request.additionals.push(edns.try_to_record().unwrap());
        set_dnssec_ok(&mut request);

        let found: Vec<Edns> = request
            .additionals
            .iter()
            .filter(|record| record.rtype == RecordType::OPT)
            .filter_map(Edns::from_record)
            .collect();
        assert_eq!(found.len(), 1, "OPT가 하나여야 합니다");
        assert!(found[0].dnssec_ok, "DO를 설정하지 않았습니다");
        assert_eq!(found[0].udp_payload, 4096, "요청이 알린 크기를 바꿨습니다");
    }

    #[test]
    /** @brief 답을 서명한 영역을 서명 자신에게서 읽는지. */
    fn the_signer_comes_from_the_signature() {
        let owner = Name::from_str("deep.sub.example.test").unwrap();
        let mut response = unsigned_answer("deep.sub.example.test");
        response.questions = vec![Question {
            name: owner.clone(),
            qtype: RecordType::A,
            qclass: DnsClass::IN,
        }];
        assert!(
            answer_signer(&response).is_none(),
            "서명이 없는데 서명자를 찾았습니다"
        );
    }
}
