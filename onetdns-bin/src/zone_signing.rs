//! Loads or creates signing keys for authoritative zones and rolls ZSKs.

use std::sync::Arc;

use onetdns_config::Config;
use zeroize::Zeroizing;

use crate::atomic_file::{atomic_write_secret, replace_file, FileBackup};
use crate::config_apply::SecondaryRestart;
use crate::edge::EdgeServices;
use crate::{
    read_text_limited, rollover, sleep_or_shutdown, unix_now, LOCAL_KEY_MAX_BYTES,
    LOCAL_STATE_MAX_BYTES,
};

pub(crate) fn zsk_path_for(zc: &onetdns_config::ZoneConfig) -> std::path::PathBuf {
    zc.dnssec_key.clone().unwrap_or_else(|| {
        let base = zc.file.clone().unwrap_or_default();
        std::path::PathBuf::from(format!("{}.key", base.display()))
    })
}

/// KSK and ZSK as separate keys.
pub(crate) fn zone_is_split_key(zc: &onetdns_config::ZoneConfig) -> bool {
    if zc.dnssec_ksk.is_some() {
        return true;
    }
    let base = zc.file.clone().unwrap_or_default();
    std::path::PathBuf::from(format!("{}.ksk", base.display())).exists()
}

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
                            onetdns_core::warn!(event = "dnssec.zsk_state_corrupt", zone = %origin.to_ascii_lower(), path = %sp.display(), "ZSK rollover state file is malformed; starting over from the first step");
                            None
                        }
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => {
                        onetdns_core::warn!(event = "dnssec.zsk_state_read_failed", zone = %origin.to_ascii_lower(), path = %sp.display(), error = %e, "Could not read the ZSK rollover state file; starting over from the first step");
                        None
                    }
                };
                let state = match stored {
                    Some(state) => state,
                    None => {
                        let state = rollover::RollState::stable(now);
                        if let Err(e) = atomic_write_secret(&sp, state.serialize().as_bytes()) {
                            onetdns_core::error!(event = "dnssec.zsk_init_save_failed", zone = %origin.to_ascii_lower(), error = %e, "Could not save the initial ZSK rollover state; not starting the rollover");
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
                        onetdns_core::error!(event = "dnssec.zsk_backup_failed", zone = %origin.to_ascii_lower(), error = %e, "Could not back up the ZSK file; postponing the rollover");
                        continue;
                    }
                };
                if !apply_roll_transition(origin, zsk, state.phase, next_state.phase) {

                    if let Err(rollback_err) = key_backup.restore(zsk) {
                        onetdns_core::error!(event = "dnssec.zsk_restore_failed", zone = %origin.to_ascii_lower(), error = %rollback_err, "Could not restore the key files after a failed ZSK rollover");
                    }
                    continue;
                }

                if let Err(e) = atomic_write_secret(&sp, next_state.serialize().as_bytes()) {
                    if let Err(rollback_err) = key_backup.restore(zsk) {
                        onetdns_core::error!(event = "dnssec.zsk_save_and_restore_failed", zone = %origin.to_ascii_lower(), error = %e, rollback_error = %rollback_err, "Saving ZSK state and restoring the keys both failed");
                    } else {
                        onetdns_core::error!(event = "dnssec.zsk_rolled_back", zone = %origin.to_ascii_lower(), error = %e, "Could not save ZSK rollover state; reverted the key change");
                    }
                    continue;
                }
                rolled.push(origin.clone());
            }
            if !rolled.is_empty() {
                match reload_keys(&rolled) {
                    Ok(()) => onetdns_core::info!(event = "dnssec.zsk_step_applied", zones = rolled.len(), "Advanced the ZSK rollover step and reloaded only the signing keys and DNS zones"),
                    Err(error) => onetdns_core::error!(event = "dnssec.zsk_reload_failed", %error, "Saved the ZSK rollover step but could not rebuild the DNS zones with the new key; retrying next check"),
                }
            }
        })
        .map(Some)
}

/// Only split-key signed zones roll. A changed zone list or period stops and joins the old job, then
/// starts a new one.
pub(crate) fn rollover_restart(
    jobs: Arc<EdgeServices>,
    reload_keys: ZoneKeyReload,
) -> SecondaryRestart {
    Arc::new(move |next: &Config| -> Result<(), String> {
        jobs.retire_all();
        let stop = jobs.restart_all();
        let zones = next
            .zones
            .iter()
            .filter(|zone| zone.dnssec_sign && zone_is_split_key(zone))
            .map(|zone| {
                onetdns_proto::Name::from_str(&zone.origin)
                    .map(|origin| (origin, zsk_path_for(zone)))
                    .map_err(|_| format!("Invalid DNS zone name: {}", zone.origin))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let thread = spawn_zsk_rollover(
            zones,
            next.dnssec_roll_interval_secs,
            reload_keys.clone(),
            stop,
        )
        .map_err(|error| format!("Could not start the DNSSEC ZSK rollover thread: {error}"))?;
        if let Some(thread) = thread {
            jobs.keep("zsk-rollover", thread);
        }
        Ok(())
    })
}

/// Signed zones and their keys. Key rolls and config changes swap this one handle.
pub(crate) type SharedZoneSigners =
    Arc<onetdns_core::ArcSwap<Vec<(onetdns_proto::Name, ZoneSigningCtx)>>>;

/// Rebuilds the zones whose keys rolled.
pub(crate) type ZoneKeyReload =
    Arc<dyn Fn(&[onetdns_proto::Name]) -> Result<(), String> + Send + Sync>;

/// Keys before the roll, restored on failure.
struct RollKeyBackup {
    active: FileBackup,
    next: FileBackup,
    prev: FileBackup,
}

impl RollKeyBackup {
    fn capture(zsk: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            active: FileBackup::capture(zsk, true)?,
            next: FileBackup::capture(&rollover::next_path(zsk), true)?,
            prev: FileBackup::capture(&rollover::prev_path(zsk), true)?,
        })
    }

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

/// Advances a key roll one step. The new key must be published and waited on long enough before the
/// switch, or validation breaks.
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
                        onetdns_core::info!(event = "dnssec.zsk_next_published", zone = %origin.to_ascii_lower(), "Pre-published the next ZSK");
                        true
                    }
                    Err(e) => {
                        onetdns_core::error!(event = "dnssec.zsk_next_save_failed", zone = %origin.to_ascii_lower(), error = %e, "Could not save the next ZSK; postponing the rollover");
                        false
                    }
                },
                None => {
                    onetdns_core::error!(event = "dnssec.zsk_next_encode_failed", zone = %origin.to_ascii_lower(), "Could not convert the new ZSK to PKCS#8; postponing the rollover");
                    false
                }
            }
        }
        (Phase::Publish, Phase::Activate) => {
            if !next.exists() {
                onetdns_core::warn!(event = "dnssec.zsk_promote_no_next", zone = %origin.to_ascii_lower(), "No .next key; postponing ZSK promotion");
                return false;
            }
            if let Err(e) = replace_file(zsk, &prev) {
                onetdns_core::error!(event = "dnssec.zsk_prev_move_failed", error = %e, "Could not move the current ZSK to the .prev file");
                return false;
            }
            if let Err(e) = replace_file(&next, zsk) {
                onetdns_core::error!(event = "dnssec.zsk_promote_failed", error = %e, "Could not promote the .next key to the active ZSK; keeping the previous key");
                if let Err(rollback_err) = replace_file(&prev, zsk) {
                    onetdns_core::error!(event = "dnssec.zsk_revert_failed", error = %rollback_err, "Could not immediately restore the current ZSK");
                }
                return false;
            }
            onetdns_core::info!(event = "dnssec.zsk_activated", zone = %origin.to_ascii_lower(), "Activated the new ZSK");
            true
        }
        (Phase::Activate, Phase::Stable) => {
            if let Err(e) = std::fs::remove_file(&prev) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    onetdns_core::error!(event = "dnssec.zsk_retire_failed", error = %e, "Could not retire the previous ZSK; postponing the move to steady state");
                    return false;
                }
            }
            onetdns_core::info!(event = "dnssec.zsk_retired", zone = %origin.to_ascii_lower(), "Retired the previous ZSK; rollover reached steady state");
            true
        }
        _ => {
            onetdns_core::error!(event = "dnssec.zsk_phase_unexpected", zone = %origin.to_ascii_lower(), from = ?from, to = ?to, "ZSK rollover step is out of order; skipping this transition");
            false
        }
    }
}

#[derive(Clone)]
pub(crate) struct ZoneSigningCtx {
    pub(crate) signer: Arc<onetdns_dnssec::sign::ZoneSigner>,
    mode: onetdns_dnssec::sign::DenialMode,
}

impl ZoneSigningCtx {
    pub(crate) fn sign(&self, records: &[onetdns_proto::Record]) -> Vec<onetdns_proto::Record> {
        self.sign_reusing(records, &[])
    }

    /// Reuses signatures from `previous`, which must be records this server signed; signatures from
    /// elsewhere would go out unverified.
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

fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    onetdns_tls::sys::fill_random(&mut s);
    s
}

/// `algorithm` applies only to a new key; an existing file carries its own.
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
                "Could not read {label} DNSSEC key '{}': {error}",
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
        .ok_or_else(|| format!("Could not convert the {label} DNSSEC key to PKCS#8"))?;
    if let Err(e) = atomic_write_secret(path, pem.as_bytes()) {
        return Err(format!(
            "Could not save {label} DNSSEC key '{}': {e}",
            path.display()
        ));
    }
    onetdns_core::info!(event = "dnssec.key_created", key_role = label, path = %path.display(), key_algorithm = algorithm.number(), "Generated and saved DNSSEC signing keys");
    Ok(pem)
}

pub(crate) fn load_zone_signer(zc: &onetdns_config::ZoneConfig) -> Result<ZoneSigningCtx, String> {
    use onetdns_dnssec::sign::{DenialMode, Nsec3Params, ZoneSigner};
    let origin = onetdns_proto::Name::from_str(&zc.origin)
        .map_err(|_| format!("Invalid DNS zone name: {}", zc.origin))?;
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
                "DNS zone '{}' has an unknown `dnssec_algorithm`: {}",
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
            .ok_or_else(|| format!("DNS zone '{}' has a malformed ZSK or KSK", zc.origin))?
    } else {
        ZoneSigner::from_pkcs8_pem(zsk_pem.as_str(), origin.clone())
            .ok_or_else(|| format!("DNS zone '{}' has a malformed ZSK", zc.origin))?
    };

    if signer.algorithm() != algorithm {
        return Err(format!(
            "The stored key for DNS zone '{}' uses algorithm {}, but `dnssec_algorithm` is {}. Move the key files or change the setting to match",
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
                onetdns_core::info!(event = "dnssec.additional_zsk_published", zone = %zc.origin, key_tag = tag, key_source = label, "Published an additional ZSK in DNSKEY responses");
            }
            Ok(())
        } else {
            Err(format!(
                "DNS zone '{}' has a malformed additional ZSK: {label}",
                zc.origin
            ))
        }
    };
    if let Some(next_path) = &zc.dnssec_key_next {
        let pem = Zeroizing::new(read_text_limited(next_path, LOCAL_KEY_MAX_BYTES).map_err(
            |error| {
                format!(
                    "Could not read the next ZSK '{}': {error}",
                    next_path.display()
                )
            },
        )?);
        add(pem.as_str(), "pre-published next ZSK (dnssec_key_next)")?;
    }
    for slot in [
        rollover::next_path(&zsk_path),
        rollover::prev_path(&zsk_path),
    ] {
        match read_text_limited(&slot, LOCAL_KEY_MAX_BYTES) {
            Ok(pem) => {
                let pem = Zeroizing::new(pem);
                add(pem.as_str(), "rollover slot key published in DNSKEY")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Could not read the rollover ZSK '{}': {error}",
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
            "separate KSK/ZSK"
        } else {
            "CSK"
        };
        onetdns_core::info!(
            event = "dnssec.zone_signed",
            zone = %origin.to_ascii_lower(),
            ds = %format!("{} IN DS {} 13 2 {}", origin.to_ascii_lower(), ds.key_tag, digest),
            mode = kind,
            "DNSSEC signing finished; register the DS record shown here with the parent zone"
        );
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{unix_now, LOCAL_KEY_MAX_BYTES};

    #[test]
    /// A new key would change every signature.
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
