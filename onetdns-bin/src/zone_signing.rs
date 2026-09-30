/*!
 * @brief 권한 영역 서명 키를 읽거나 만들고 ZSK를 교체한다.
 */

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::atomic_file::{atomic_write_secret, replace_file, FileBackup};
use crate::{
    read_text_limited, rollover, sleep_or_shutdown, unix_now, LOCAL_KEY_MAX_BYTES,
    LOCAL_STATE_MAX_BYTES,
};

/** @brief 이 영역의 서명 키 경로. */
pub(crate) fn zsk_path_for(zc: &onetdns_config::ZoneConfig) -> std::path::PathBuf {
    zc.dnssec_key.clone().unwrap_or_else(|| {
        let base = zc.file.clone().unwrap_or_default();
        std::path::PathBuf::from(format!("{}.key", base.display()))
    })
}

/** @brief 이 영역이 키를 둘로 나눠 쓰는지. */
pub(crate) fn zone_is_split_key(zc: &onetdns_config::ZoneConfig) -> bool {
    if zc.dnssec_ksk.is_some() {
        return true;
    }
    let base = zc.file.clone().unwrap_or_default();
    std::path::PathBuf::from(format!("{}.ksk", base.display())).exists()
}

/** @brief 서명 키를 주기적으로 교체하는 스레드를 시작한다. */
pub(crate) fn spawn_zsk_rollover(
    zones: Vec<(onetdns_proto::Name, std::path::PathBuf)>,
    interval: u64,
    reload_keys: ZoneKeyReload,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<Option<std::thread::JoinHandle<()>>> {
    if interval == 0 || zones.is_empty() {
        return Ok(None);
    }
    let timing = rollover::RollTiming::from_interval(interval);
    let check = (interval / 100).clamp(1, 3600);
    std::thread::Builder::new()
        .name("zsk-rollover".into())
        .spawn(move || loop {
            if sleep_or_shutdown(check, &shutdown) {
                break;
            }
            let now = unix_now();
            let mut rolled = Vec::new();
            for (origin, zsk) in &zones {
                let sp = rollover::state_path(zsk);
                let stored = match read_text_limited(&sp, LOCAL_STATE_MAX_BYTES) {
                    Ok(text) => match rollover::RollState::parse(&text) {
                        Some(state) => Some(state),
                        None => {
                            onetdns_core::warn!(event = "dnssec.zsk_state_corrupt", zone = %origin.to_ascii_lower(), path = %sp.display(), "ZSK 교체 상태 파일의 형식이 깨져 있어 첫 단계부터 다시 시작합니다");
                            None
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => {
                        onetdns_core::warn!(event = "dnssec.zsk_state_read_failed", zone = %origin.to_ascii_lower(), path = %sp.display(), error = %e, "ZSK 교체 상태 파일을 읽지 못해 첫 단계부터 다시 시작합니다");
                        None
                    }
                };
                let state = match stored {
                    Some(state) => state,
                    None => {
                        let state = rollover::RollState::stable(now);
                        if let Err(e) = atomic_write_secret(&sp, state.serialize().as_bytes()) {
                            onetdns_core::error!(event = "dnssec.zsk_init_save_failed", zone = %origin.to_ascii_lower(), error = %e, "ZSK 교체 초기 상태를 저장하지 못해 키 교체를 시작하지 않습니다");
                            continue;
                        }
                        state
                    }
                };
                let Some(next_state) = rollover::advance(state, now, timing) else {
                    continue;
                };
                let key_backup = match RollKeyBackup::capture(zsk) {
                    Ok(backup) => backup,
                    Err(e) => {
                        onetdns_core::error!(event = "dnssec.zsk_backup_failed", zone = %origin.to_ascii_lower(), error = %e, "ZSK 파일을 백업하지 못해 키 교체를 보류합니다");
                        continue;
                    }
                };
                if !apply_roll_transition(origin, zsk, state.phase, next_state.phase) {

                    if let Err(rollback_err) = key_backup.restore(zsk) {
                        onetdns_core::error!(event = "dnssec.zsk_restore_failed", zone = %origin.to_ascii_lower(), error = %rollback_err, "ZSK 교체 실패 후 키 파일을 이전 상태로 되돌리지 못했습니다");
                    }
                    continue;
                }

                if let Err(e) = atomic_write_secret(&sp, next_state.serialize().as_bytes()) {
                    if let Err(rollback_err) = key_backup.restore(zsk) {
                        onetdns_core::error!(event = "dnssec.zsk_save_and_restore_failed", zone = %origin.to_ascii_lower(), error = %e, rollback_error = %rollback_err, "ZSK 상태 저장과 키 복구가 모두 실패했습니다");
                    } else {
                        onetdns_core::error!(event = "dnssec.zsk_rolled_back", zone = %origin.to_ascii_lower(), error = %e, "ZSK 교체 상태를 저장하지 못해 키 변경을 되돌렸습니다");
                    }
                    continue;
                }
                rolled.push(origin.clone());
            }
            if !rolled.is_empty() {
                match reload_keys(&rolled) {
                    Ok(()) => onetdns_core::info!(event = "dnssec.zsk_step_applied", zones = rolled.len(), "ZSK 교체 단계를 갱신하고 서명 키와 DNS 영역만 다시 불러왔습니다"),
                    Err(error) => onetdns_core::error!(event = "dnssec.zsk_reload_failed", %error, "ZSK 교체 단계는 저장했지만 새 키로 DNS 영역을 다시 만들지 못했습니다. 다음 확인 주기에 다시 시도합니다"),
                }
            }
        })
        .map(Some)
}

/** @brief 서명 영역과 그 키. 키 교체와 설정 변경이 이 핸들 하나를 교체한다. */
pub(crate) type SharedZoneSigners =
    Arc<onetdns_core::ArcSwap<Vec<(onetdns_proto::Name, ZoneSigningCtx)>>>;

/** @brief 키를 교체한 영역들을 새 키로 다시 만든다. */
pub(crate) type ZoneKeyReload =
    Arc<dyn Fn(&[onetdns_proto::Name]) -> Result<(), String> + Send + Sync>;

/** @brief 교체 전 키. 실패하면 되돌린다. */
struct RollKeyBackup {
    /** @brief 지금 쓰는 키. */
    active: FileBackup,
    /** @brief 다음에 쓸 키. */
    next: FileBackup,
    /** @brief 직전에 쓰던 키. */
    prev: FileBackup,
}

impl RollKeyBackup {
    /** @brief 지금 키를 담아 둔다. */
    fn capture(zsk: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            active: FileBackup::capture(zsk, true)?,
            next: FileBackup::capture(&rollover::next_path(zsk), true)?,
            prev: FileBackup::capture(&rollover::prev_path(zsk), true)?,
        })
    }

    /** @brief 담아 둔 키로 되돌린다. */
    fn restore(&self, zsk: &std::path::Path) -> std::io::Result<()> {
        let next_path = rollover::next_path(zsk);
        let prev_path = rollover::prev_path(zsk);
        let paths = [
            (zsk, &self.active),
            (next_path.as_path(), &self.next),
            (prev_path.as_path(), &self.prev),
        ];
        let mut errors = Vec::new();
        for (path, backup) in paths {
            if let Err(e) = backup.restore(path) {
                errors.push(format!("{}: {e}", path.display()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(errors.join("; ")))
        }
    }
}

/** @brief 키 교체를 한 단계 진행한다. 새 키를 미리 알리고 충분히 기다린 뒤에 바꿔야 검증이 끊기지 않는다. */
fn apply_roll_transition(
    origin: &onetdns_proto::Name,
    zsk: &std::path::Path,
    from: rollover::Phase,
    to: rollover::Phase,
) -> bool {
    use rollover::Phase;
    let next = rollover::next_path(zsk);
    let prev = rollover::prev_path(zsk);
    match (from, to) {
        (Phase::Stable, Phase::Publish) => {
            match onetdns_dnssec::sign::ZoneSigner::generate(origin.clone(), random_seed())
                .to_pkcs8_pem()
            {
                Some(pem) => match atomic_write_secret(&next, pem.as_bytes()) {
                    Ok(()) => {
                        onetdns_core::info!(event = "dnssec.zsk_next_published", zone = %origin.to_ascii_lower(), "다음 ZSK를 미리 게시했습니다");
                        true
                    }
                    Err(e) => {
                        onetdns_core::error!(event = "dnssec.zsk_next_save_failed", zone = %origin.to_ascii_lower(), error = %e, "다음 ZSK를 저장하지 못해 키 교체를 보류합니다");
                        false
                    }
                },
                None => {
                    onetdns_core::error!(event = "dnssec.zsk_next_encode_failed", zone = %origin.to_ascii_lower(), "새로 만든 ZSK를 PKCS#8로 옮기지 못해 키 교체를 보류합니다");
                    false
                }
            }
        }
        (Phase::Publish, Phase::Activate) => {
            if !next.exists() {
                onetdns_core::warn!(event = "dnssec.zsk_promote_no_next", zone = %origin.to_ascii_lower(), ".next 키가 없어 ZSK 승격을 보류합니다");
                return false;
            }
            if let Err(e) = replace_file(zsk, &prev) {
                onetdns_core::error!(event = "dnssec.zsk_prev_move_failed", error = %e, "현재 ZSK를 .prev 파일로 옮기지 못했습니다");
                return false;
            }
            if let Err(e) = replace_file(&next, zsk) {
                onetdns_core::error!(event = "dnssec.zsk_promote_failed", error = %e, ".next 키를 활성 ZSK로 바꾸지 못해 이전 키를 유지합니다");
                if let Err(rollback_err) = replace_file(&prev, zsk) {
                    onetdns_core::error!(event = "dnssec.zsk_revert_failed", error = %rollback_err, "현재 ZSK를 즉시 이전 상태로 되돌리지 못했습니다");
                }
                return false;
            }
            onetdns_core::info!(event = "dnssec.zsk_activated", zone = %origin.to_ascii_lower(), "새 ZSK를 활성화했습니다");
            true
        }
        (Phase::Activate, Phase::Stable) => {
            if let Err(e) = std::fs::remove_file(&prev) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    onetdns_core::error!(event = "dnssec.zsk_retire_failed", error = %e, "이전 ZSK를 폐기하지 못해 안정 상태 전환을 보류합니다");
                    return false;
                }
            }
            onetdns_core::info!(event = "dnssec.zsk_retired", zone = %origin.to_ascii_lower(), "이전 ZSK를 폐기해 안정 상태로 전환했습니다");
            true
        }
        _ => {
            onetdns_core::error!(event = "dnssec.zsk_phase_unexpected", zone = %origin.to_ascii_lower(), from = ?from, to = ?to, "ZSK 교체 단계가 순서를 벗어나 이번 전환을 건너뜁니다");
            false
        }
    }
}

#[derive(Clone)]
/** @brief 영역 하나를 서명할 키들. */
pub(crate) struct ZoneSigningCtx {
    /** @brief 실제로 서명하는 것. */
    pub(crate) signer: Arc<onetdns_dnssec::sign::ZoneSigner>,
    /** @brief 부재 증명 방식. */
    mode: onetdns_dnssec::sign::DenialMode,
}

impl ZoneSigningCtx {
    /** @brief 이 기록들에 서명한다. */
    pub(crate) fn sign(&self, records: &[onetdns_proto::Record]) -> Vec<onetdns_proto::Record> {
        self.sign_reusing(records, &[])
    }

    /**
     * @brief 지난 서명을 물려받아 서명한다.
     * @param previous 이 서버가 직접 서명해 저장소에 가지고 있던 레코드들. 바깥에서 받은 것을
     *                 넘기면 검증하지 않은 서명을 내보내게 된다.
     */
    pub(crate) fn sign_reusing(
        &self,
        records: &[onetdns_proto::Record],
        previous: &[onetdns_proto::Record],
    ) -> Vec<onetdns_proto::Record> {
        onetdns_dnssec::sign::sign_zone_reusing(
            records,
            &self.signer,
            unix_now(),
            &self.mode,
            previous,
        )
    }
}

/** @brief 무작위 시드. */
fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    onetdns_tls::sys::fill_random(&mut s);
    s
}

/**
 * @brief 키를 읽거나 만든다.
 * @param algorithm 새로 만들 때 쓸 알고리즘. 이미 있는 키는 파일이 스스로 무엇인지 말한다.
 */
fn load_or_create_key_pem(
    path: &std::path::Path,
    label: &str,
    algorithm: onetdns_dnssec::sign::SignAlgorithm,
) -> Result<Zeroizing<String>, String> {
    match read_text_limited(path, LOCAL_KEY_MAX_BYTES) {
        Ok(pem) => return Ok(Zeroizing::new(pem)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "{label} DNSSEC 키 '{}'를 읽지 못했습니다: {error}",
                path.display()
            ));
        }
    }
    let s = onetdns_dnssec::sign::ZoneSigner::generate_with(
        onetdns_proto::Name::root(),
        random_seed(),
        algorithm,
    );
    let pem = s
        .to_pkcs8_pem()
        .ok_or_else(|| format!("{label} DNSSEC 키를 PKCS#8 형식으로 만들지 못했습니다"))?;
    if let Err(e) = atomic_write_secret(path, pem.as_bytes()) {
        return Err(format!(
            "{label} DNSSEC 키 '{}'를 저장하지 못했습니다: {e}",
            path.display()
        ));
    }
    onetdns_core::info!(event = "dnssec.key_created", key_role = label, path = %path.display(), key_algorithm = algorithm.number(), "DNSSEC 서명 키를 생성해 저장했습니다");
    Ok(pem)
}

/** @brief 이 영역의 서명기를 올린다. */
pub(crate) fn load_zone_signer(zc: &onetdns_config::ZoneConfig) -> Result<ZoneSigningCtx, String> {
    use onetdns_dnssec::sign::{DenialMode, Nsec3Params, ZoneSigner};
    let origin = onetdns_proto::Name::from_str(&zc.origin)
        .map_err(|_| format!("DNS 영역 이름이 올바르지 않습니다: {}", zc.origin))?;
    let base = zc.file.clone().unwrap_or_default();
    let zsk_path = zc
        .dnssec_key
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.key", base.display())));
    let algorithm = if zc.dnssec_algorithm.is_empty() {
        onetdns_dnssec::sign::SignAlgorithm::default()
    } else {
        onetdns_dnssec::sign::SignAlgorithm::from_str(&zc.dnssec_algorithm).ok_or_else(|| {
            format!(
                "DNS 영역 '{}'의 `dnssec_algorithm` 값을 알 수 없습니다: {}",
                zc.origin, zc.dnssec_algorithm
            )
        })?
    };
    let zsk_pem = load_or_create_key_pem(&zsk_path, "ZSK", algorithm)?;

    let ksk_path = zc
        .dnssec_ksk
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(format!("{}.ksk", base.display())));
    let split = zc.dnssec_ksk.is_some() || ksk_path.exists();
    let signer = if split {
        let ksk_pem = load_or_create_key_pem(&ksk_path, "KSK", algorithm)?;
        ZoneSigner::from_pkcs8_pems(zsk_pem.as_str(), Some(ksk_pem.as_str()), origin.clone())
            .ok_or_else(|| {
                format!(
                    "DNS 영역 '{}'의 ZSK 또는 KSK 형식이 잘못되었습니다",
                    zc.origin
                )
            })?
    } else {
        ZoneSigner::from_pkcs8_pem(zsk_pem.as_str(), origin.clone())
            .ok_or_else(|| format!("DNS 영역 '{}'의 ZSK 형식이 잘못되었습니다", zc.origin))?
    };

    if signer.algorithm() != algorithm {
        return Err(format!(
            "DNS 영역 '{}'의 저장된 키는 알고리즘 {}인데 `dnssec_algorithm`은 {}입니다. 키 파일을 옮기거나 설정을 맞추십시오",
            zc.origin,
            signer.algorithm().number(),
            algorithm.number()
        ));
    }

    let mut published: Vec<onetdns_dnssec::Dnskey> = Vec::new();
    let mut seen_tags: Vec<u16> = vec![signer.dnskey().key_tag()];
    let mut add = |pem: &str, label: &str| -> Result<(), String> {
        if let Some(dk) = onetdns_dnssec::sign::zsk_dnskey_from_pkcs8_pem(pem) {
            let tag = dk.key_tag();
            if !seen_tags.contains(&tag) {
                seen_tags.push(tag);
                published.push(dk);
                onetdns_core::info!(event = "dnssec.additional_zsk_published", zone = %zc.origin, key_tag = tag, key_source = label, "추가 ZSK를 DNSKEY 응답에 게시했습니다");
            }
            Ok(())
        } else {
            Err(format!(
                "DNS 영역 '{}'의 추가 ZSK 형식이 잘못되었습니다: {label}",
                zc.origin
            ))
        }
    };
    if let Some(next_path) = &zc.dnssec_key_next {
        let pem = Zeroizing::new(read_text_limited(next_path, LOCAL_KEY_MAX_BYTES).map_err(
            |error| {
                format!(
                    "차기 ZSK '{}'를 읽지 못했습니다: {error}",
                    next_path.display()
                )
            },
        )?);
        add(pem.as_str(), "차기 ZSK 사전발행(dnssec_key_next)")?;
    }
    for slot in [
        rollover::next_path(&zsk_path),
        rollover::prev_path(&zsk_path),
    ] {
        match read_text_limited(&slot, LOCAL_KEY_MAX_BYTES) {
            Ok(pem) => {
                let pem = Zeroizing::new(pem);
                add(pem.as_str(), "롤오버 슬롯 키 게시(DNSKEY)")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "롤오버 ZSK '{}'를 읽지 못했습니다: {error}",
                    slot.display()
                ));
            }
        }
    }
    let signer = if published.is_empty() {
        signer
    } else {
        signer.with_published_keys(published)
    };
    let mode = if zc.dnssec_nsec3 {
        DenialMode::Nsec3(Nsec3Params {
            iterations: zc.dnssec_nsec3_iterations,
            salt: Vec::new(),
        })
    } else {
        DenialMode::Nsec
    };
    Ok(ZoneSigningCtx {
        signer: Arc::new(signer),
        mode,
    })
}

/** @brief 영역에 서명을 붙인다. */
pub(crate) fn sign_authority_zone(
    zone: onetdns_authority::Zone,
    ctx: &ZoneSigningCtx,
) -> Option<onetdns_authority::Zone> {
    let origin = zone.origin().clone();
    let mut records = zone.axfr_records();
    records.pop();
    let signed = ctx.sign(&records);
    let out = onetdns_authority::Zone::from_records(signed).ok()?;
    if let Some(ds) = ctx.signer.ds() {
        let digest: String = ds.digest.iter().map(|b| format!("{b:02X}")).collect();
        let kind = if ctx.signer.is_split() {
            "KSK/ZSK 분리"
        } else {
            "CSK"
        };
        onetdns_core::info!(
            event = "dnssec.zone_signed",
            zone = %origin.to_ascii_lower(),
            ds = %format!("{} IN DS {} 13 2 {}", origin.to_ascii_lower(), ds.key_tag, digest),
            mode = kind,
            "DNSSEC 서명을 마쳤습니다. 표시된 DS 레코드를 부모 영역에 등록해야 합니다"
        );
    }
    Some(out)
}

#[cfg(test)]
/** @brief 영역 서명. */
mod tests {
    use super::*;
    use crate::{unix_now, LOCAL_KEY_MAX_BYTES};

    #[test]
    /** @brief 키를 못 읽었을 때 조용히 새로 만들지 않는지. 만들면 서명이 전부 바뀐다. */
    fn unreadable_dnssec_key_is_not_silently_replaced() {
        let path = std::env::temp_dir().join(format!(
            "onetdns-oversized-key-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let original = vec![b'x'; LOCAL_KEY_MAX_BYTES as usize + 1];
        std::fs::write(&path, &original).unwrap();

        assert!(load_or_create_key_pem(&path, "test key", Default::default()).is_err());
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            original.len() as u64
        );

        let _ = std::fs::remove_file(path);
    }
}
