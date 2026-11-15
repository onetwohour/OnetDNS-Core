//! Automated trust anchor updates (RFC 5011). An anchor is the starting point of validation and
//! must not change without evidence: a new key has to be seen in a DNSKEY RRset signed by an
//! already trusted key and stay through the hold-down period before it is trusted. A revocation
//! counts only when signed by the revoked key itself.
//!
//! Loosening these checks lets an attacker plant their own key as an anchor. Refusing a valid
//! update stops service; accepting a wrong one breaks everything.

use onetdns_proto::{Name, Record, RecordType};

use crate::{validate_rrset_in_zone, Dnskey, Ds, Rrsig};

/// RFC 5011 recommends 30 days.
pub const DEFAULT_HOLD_DOWN_SECS: u64 = 30 * 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    /// Trusted; only these keys go into `active_ds`.
    Valid,

    /// Seen but still in hold-down; `since` restarts when observation breaks.
    AddPend { since: u64 },

    /// Revoked by its own signature; never returns to `Valid`.
    Revoked,
}

#[derive(Debug, Clone)]
pub struct ManagedKey {
    pub key: Dnskey,
    pub state: KeyState,
    /// Detects gaps in observation.
    pub last_seen: u64,
}

#[derive(Debug, Clone)]
pub struct AnchorManager {
    /// Usually the root.
    pub zone: Name,
    /// Keys that are not `Valid` stay for state tracking.
    pub keys: Vec<ManagedKey>,
    /// Shortened only in tests.
    pub hold_down_secs: u64,
}

impl AnchorManager {
    /// Initial keys skip hold-down because the operator verified them out of band. Only keys added
    /// later go through observation and waiting.
    pub fn bootstrap(zone: Name, initial: Vec<Dnskey>, now: u64) -> AnchorManager {
        let keys = initial
            .into_iter()
            .map(|key| ManagedKey {
                key,
                state: KeyState::Valid,
                last_seen: now,
            })
            .collect();
        AnchorManager {
            zone,
            keys,
            hold_down_secs: DEFAULT_HOLD_DOWN_SECS,
        }
    }

    /// The only basis for verifying updates.
    fn valid_keys(&self) -> Vec<Dnskey> {
        self.keys
            .iter()
            .filter(|k| k.state == KeyState::Valid)
            .map(|k| k.key.clone())
            .collect()
    }

    /// Only `Valid` keys: `AddPend` is not trusted yet and `Revoked` is gone.
    pub fn active_ds(&self) -> Vec<Ds> {
        self.keys
            .iter()
            .filter(|k| k.state == KeyState::Valid)
            .filter_map(|k| Ds::from_dnskey(&k.key, &self.zone, 2))
            .collect()
    }

    /// The order is the safety. First the RRset signature is verified with the current `Valid`
    /// keys; on failure nothing changes. Then revoked keys are processed, accepting only a
    /// revocation signed by that key itself: allowing another key's signature would let one
    /// compromised key remove all the others. Last, new keys enter `AddPend` and those that
    /// completed hold-down become `Valid`.
    ///
    /// A gap longer than twice the RRset's minimum TTL restarts hold-down: observation was not
    /// continuous, so a key an attacker showed briefly cannot be promoted by time alone. With no
    /// `Valid` key nothing can be verified, so the update is refused. Returns true when the state
    /// changed and needs saving.
    pub fn update(&mut self, dnskeys: &[Record], rrsigs: &[Rrsig], now: u64) -> bool {
        let valid = self.valid_keys();
        if valid.is_empty() {
            return false;
        }

        if validate_rrset_in_zone(dnskeys, rrsigs, &valid, &self.zone, now as u32).is_err() {
            return false;
        }
        let observed: Vec<Dnskey> = dnskeys.iter().filter_map(Dnskey::from_record).collect();
        let observation_gap = dnskeys
            .iter()
            .map(|record| u64::from(record.ttl.max(1)))
            .min()
            .unwrap_or(3600)
            .saturating_mul(2)
            .max(60);
        let mut changed = false;

        for obs in &observed {
            let tag = obs.key_tag();
            if obs.is_revoked() {
                let self_signed = rrsigs.iter().any(|sig| {
                    sig.signer.eq_ignore_case(&self.zone)
                        && crate::rrsig_time_valid_accepting(sig, now as u32, false)
                        && crate::verify_rrsig(dnskeys, sig, obs).is_ok()
                });
                if !self_signed {
                    continue;
                }
                let mut base = obs.clone();
                base.flags &= !0x0080;
                let base_tag = base.key_tag();
                if let Some(k) = self
                    .keys
                    .iter_mut()
                    .find(|k| k.key.key_tag() == base_tag && k.key.public_key == obs.public_key)
                {
                    if k.state != KeyState::Revoked {
                        k.state = KeyState::Revoked;
                        k.last_seen = now;
                        changed = true;
                    }
                }
                continue;
            }
            match self
                .keys
                .iter_mut()
                .find(|k| k.key.key_tag() == tag && k.key.public_key == obs.public_key)
            {
                Some(k) => {
                    if let KeyState::AddPend { since } = k.state {
                        if now < k.last_seen || now.saturating_sub(k.last_seen) > observation_gap {
                            k.state = KeyState::AddPend { since: now };
                            changed = true;
                        } else {
                            k.state = KeyState::AddPend { since };
                        }
                    }
                    k.last_seen = now;
                }
                None => {
                    self.keys.push(ManagedKey {
                        key: obs.clone(),
                        state: KeyState::AddPend { since: now },
                        last_seen: now,
                    });
                    changed = true;
                }
            }
        }

        for k in &mut self.keys {
            if let KeyState::AddPend { since } = k.state {
                if k.last_seen == now && now.saturating_sub(since) >= self.hold_down_secs {
                    k.state = KeyState::Valid;
                    changed = true;
                }
            }
        }

        let present: Vec<u16> = observed.iter().map(|k| k.key_tag()).collect();
        let before = self.keys.len();
        self.keys.retain(|k| {
            let seen = present.contains(&k.key.key_tag()) || k.last_seen == now;
            match k.state {
                KeyState::Valid => true,
                _ => seen,
            }
        });
        if self.keys.len() != before {
            changed = true;
        }
        changed
    }

    /// Hold-down progress must survive restarts; losing it restarts the wait and misses the
    /// rollover. The root zone is written as a single dot rather than an empty string, because
    /// deserialization checks the field count.
    pub fn serialize(&self) -> String {
        let zone = if self.zone.is_root() {
            ".".to_string()
        } else {
            self.zone.to_ascii_lower()
        };
        let mut out = format!(
            "ONETDNS-ANCHOR\nzone {zone}\nhold_down {}\n",
            self.hold_down_secs
        );
        for k in &self.keys {
            let st = match k.state {
                KeyState::Valid => "valid 0".to_string(),
                KeyState::AddPend { since } => format!("addpend {since}"),
                KeyState::Revoked => "revoked 0".to_string(),
            };
            out.push_str(&format!(
                "key {} {} {} {} {}\n",
                st,
                k.key.flags,
                k.key.algorithm,
                k.last_seen,
                crate::tsig::b64_encode(&k.key.public_key)
            ));
        }
        out
    }

    /// Strict: any mismatch in header, line order, field count, state name or `since` rejects the
    /// whole file, as does a duplicate key, since there would be no telling which state is real.
    /// The file sits on disk and is not trusted input: reading half and defaulting the rest would
    /// let a tampered file make any key `Valid`. On `None` the caller falls back to the configured
    /// initial anchors.
    pub fn deserialize(text: &str) -> Option<AnchorManager> {
        let mut lines = text.lines();
        if lines.next()? != "ONETDNS-ANCHOR" {
            return None;
        }
        let zone_line: Vec<_> = lines.next()?.split_whitespace().collect();
        if zone_line.len() != 2 || zone_line[0] != "zone" {
            return None;
        }
        let zone = Name::from_str(zone_line[1]).ok()?;
        let hold_line: Vec<_> = lines.next()?.split_whitespace().collect();
        if hold_line.len() != 2 || hold_line[0] != "hold_down" {
            return None;
        }
        let hold_down_secs = hold_line[1].parse::<u64>().ok()?;
        let mut keys = Vec::new();
        for line in lines {
            let t: Vec<&str> = line.split_whitespace().collect();
            if t.len() != 7 || t[0] != "key" {
                return None;
            }
            let since = t[2].parse::<u64>().ok()?;
            let state = match t[1] {
                "valid" if since == 0 => KeyState::Valid,
                "revoked" if since == 0 => KeyState::Revoked,
                "addpend" => KeyState::AddPend { since },
                _ => return None,
            };
            let flags: u16 = t[3].parse().ok()?;
            let algorithm: u8 = t[4].parse().ok()?;
            let last_seen: u64 = t[5].parse().ok()?;
            let public_key = crate::tsig::b64_decode(t[6])?;
            if public_key.is_empty() {
                return None;
            }
            let key = Dnskey {
                flags,
                protocol: 3,
                algorithm,
                public_key,
            };
            if keys.iter().any(|existing: &ManagedKey| {
                existing.key.key_tag() == key.key_tag() && existing.key.public_key == key.public_key
            }) {
                return None;
            }
            keys.push(ManagedKey {
                key,
                state,
                last_seen,
            });
        }
        if keys.is_empty() {
            return None;
        }
        Some(AnchorManager {
            zone,
            keys,
            hold_down_secs,
        })
    }
}

/// Checks both the owner name and `type_covered`: signatures over another name or type would make
/// the update decide on the wrong data.
pub fn extract_dnskey_rrset(records: &[Record], zone: &Name) -> (Vec<Record>, Vec<Rrsig>) {
    let keys: Vec<Record> = records
        .iter()
        .filter(|r| r.rtype == RecordType::DNSKEY && r.name.eq_ignore_case(zone))
        .cloned()
        .collect();
    let sigs: Vec<Rrsig> = records
        .iter()
        .filter(|r| r.rtype == RecordType(46) && r.name.eq_ignore_case(zone))
        .filter_map(Rrsig::from_record)
        .filter(|s| s.type_covered == RecordType::DNSKEY.0)
        .collect();
    (keys, sigs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::ZoneSigner;
    use onetdns_proto::{DnsClass, RData};

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    fn dnskey_rrset(keys: &[Dnskey], signer: &ZoneSigner, zone: &Name, now: u64) -> Vec<Record> {
        let mut recs: Vec<Record> = keys
            .iter()
            .map(|k| Record {
                name: zone.clone(),
                rtype: RecordType::DNSKEY,
                class: DnsClass::IN,
                ttl: 3600,
                rdata: RData::Unknown(48, k.rdata_bytes()),
            })
            .collect();
        let sig = signer.sign_rrset(&recs, now).unwrap();
        recs.push(sig);
        recs
    }

    #[test]
    fn new_key_held_down_then_promoted() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [1u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [2u8; 32]);

        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);
        mgr.hold_down_secs = 1000;
        assert_eq!(mgr.active_ds().len(), 1);

        let rr = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        assert!(mgr.update(&keys, &sigs, now), "k2 새로 관찰 → 변경");
        assert_eq!(mgr.active_ds().len(), 1, "hold-down 전 k2 미신뢰");

        let later = now + 1001;
        let rr2 = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, later);
        let (keys2, sigs2) = extract_dnskey_rrset(&rr2, &zone);
        mgr.update(&keys2, &sigs2, later);
        assert_eq!(mgr.active_ds().len(), 2, "hold-down 후 k2 신뢰");

        let rr3 = dnskey_rrset(&[k2.dnskey()], &k2, &zone, later);
        let (keys3, sigs3) = extract_dnskey_rrset(&rr3, &zone);
        assert!(
            validate_rrset_in_zone(&keys3, &sigs3, &mgr.valid_keys(), &mgr.zone, later as u32)
                .is_ok()
        );
    }

    #[test]
    fn revoked_key_removed() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [3u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [4u8; 32]);

        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey(), k2.dnskey()], now);
        assert_eq!(mgr.active_ds().len(), 2);

        let mut revoked = k1.dnskey();
        revoked.flags |= 0x0080;
        let rr = dnskey_rrset(&[revoked, k2.dnskey()], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        assert!(mgr.update(&keys, &sigs, now), "k1 revoke → 변경");
        let ds = mgr.active_ds();
        assert_eq!(ds.len(), 1, "k1 제거, k2만 신뢰");
        assert_eq!(ds[0].key_tag, k2.dnskey().key_tag());
    }

    #[test]
    fn revoke_requires_self_signature_not_other_key() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [11u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [12u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey(), k2.dnskey()], now);
        assert_eq!(mgr.active_ds().len(), 2);

        let mut revoked_k2 = k2.dnskey();
        revoked_k2.flags |= 0x0080;
        let rr = dnskey_rrset(&[k1.dnskey(), revoked_k2], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        mgr.update(&keys, &sigs, now);
        assert_eq!(mgr.active_ds().len(), 2, "타 키 서명으로는 폐기 불가");
    }

    #[test]
    fn unsigned_update_ignored() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [5u8; 32]);
        let attacker = ZoneSigner::generate(zone.clone(), [6u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);

        let rr = dnskey_rrset(&[k1.dnskey(), attacker.dnskey()], &attacker, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        assert!(
            !mgr.update(&keys, &sigs, now),
            "검증에 실패했습니다 → 변경 없음"
        );
        assert_eq!(mgr.active_ds().len(), 1, "공격자 키 미추가");
    }

    #[test]
    fn pending_key_gap_restarts_hold_down() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [9u8; 32]);
        let k2 = ZoneSigner::generate(zone.clone(), [10u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);
        mgr.hold_down_secs = 1000;

        let rr = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, now);
        let (keys, sigs) = extract_dnskey_rrset(&rr, &zone);
        mgr.update(&keys, &sigs, now);

        let later = now + 10_000;
        let rr2 = dnskey_rrset(&[k1.dnskey(), k2.dnskey()], &k1, &zone, later);
        let (keys2, sigs2) = extract_dnskey_rrset(&rr2, &zone);
        mgr.update(&keys2, &sigs2, later);
        assert_eq!(mgr.active_ds().len(), 1, "관찰 공백 뒤 즉시 승격 금지");
    }

    #[test]
    fn serialize_roundtrip() {
        let zone = n("example.com");
        let now = 1_700_000_000u64;
        let k1 = ZoneSigner::generate(zone.clone(), [7u8; 32]);
        let mut mgr = AnchorManager::bootstrap(zone.clone(), vec![k1.dnskey()], now);
        mgr.keys.push(ManagedKey {
            key: ZoneSigner::generate(zone.clone(), [8u8; 32]).dnskey(),
            state: KeyState::AddPend { since: now },
            last_seen: now,
        });
        let text = mgr.serialize();
        let restored = AnchorManager::deserialize(&text).expect("역직렬화");
        assert_eq!(restored.keys.len(), 2);
        assert_eq!(restored.active_ds().len(), 1, "Valid만 활성");
        assert_eq!(restored.hold_down_secs, mgr.hold_down_secs);
        assert!(AnchorManager::deserialize(text.trim_start_matches("ONETDNS-ANCHOR\n")).is_none());
        assert!(AnchorManager::deserialize(&text.replacen("hold_down", "removed", 1)).is_none());
        assert!(AnchorManager::deserialize(&(text.clone() + "extra value\n")).is_none());
    }

    #[test]
    fn root_zone_state_survives_serialize_roundtrip() {
        let root = Name::root();
        let key = ZoneSigner::generate(root.clone(), [9u8; 32]);
        let mgr = AnchorManager::bootstrap(root.clone(), vec![key.dnskey()], 1_700_000_000);
        let text = mgr.serialize();
        assert!(text.contains("zone ."), "루트는 '.'로 직렬화");
        let restored = AnchorManager::deserialize(&text).expect("루트 상태 역직렬화");
        assert!(restored.zone.is_root());
        assert_eq!(restored.active_ds().len(), 1);
    }
}
