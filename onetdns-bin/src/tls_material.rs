/*!
 * @brief TLS 인증서와 키를 읽고 검사해 서버 설정으로 만들고, 관리 API의 인증서 교체를 처리한다.
 */

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use onetdns_config::Config;
use zeroize::Zeroizing;

use crate::atomic_file::{atomic_write_secret, commit_cert_key, rollback_cert_key};
use crate::config_apply::apply_config_edit;
use crate::config_edit::{rewrite_config_kv, toml_quote};
use crate::error::{BoxResult, Context};
use crate::listeners::TlsSlots;
use crate::{
    acme, http, read_bytes_limited, read_text_limited, unix_now, ConfigTextSlot,
    LOCAL_CA_MAX_BYTES, LOCAL_KEY_MAX_BYTES,
};

/**
 * @brief 암호화 전송이 함께 쓸 인증서와 개인키를 한 번만 마련한다.
 *
 * @details 전송마다 따로 만들면 자체 서명일 때 DoT·DoH·DoQ·DoH3 이 서로 다른 인증서를
 *          내놓는다. 자체 서명은 고정해 쓰는 것이므로, 한 곳에서 받은 인증서로 다른
 *          전송에 붙지 못한다. DDR 로 여러 암호화 주소를 알리는 배포에서 특히 드러난다.
 */
pub(crate) fn native_tls_material(cfg: &Config) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    if let Some(host) = &cfg.tls_self_signed_host {
        onetdns_core::warn!(event = "tls.self_signed_in_use", host = %host, "Serving encrypted DNS with a self-signed certificate; clients will not connect unless they disable certificate verification");
        return onetdns_transport::self_signed_material(host)
            .map_err(|error| format!("Could not create a self-signed TLS certificate: {error}"));
    }
    if let (Some(c), Some(k)) = (&cfg.tls_cert, &cfg.tls_key) {
        return onetdns_transport::load_pem(c, k).map_err(|error| {
            format!("Could not read the TLS certificate or private key: {error}")
        });
    }
    Err("There is no TLS certificate for the encrypted DNS listening addresses".to_string())
}

/** @brief 암호화 전송에 쓸 TLS 설정을 만든다. */
pub(crate) fn native_tls_config(
    cfg: &Config,
    alpn: Vec<Vec<u8>>,
    material: &(Vec<Vec<u8>>, Vec<u8>),
) -> Result<Arc<onetdns_tls::ServerConfig>, String> {
    let (certs, key) = (material.0.clone(), material.1.clone());
    if certs.is_empty() {
        return Err("The TLS certificate chain is empty".to_string());
    }
    let mut sc = onetdns_tls::ServerConfig::from_chain_pkcs8(certs, &key)
        .ok_or_else(|| {
            "The TLS certificate and private key do not match, or the format is not supported"
                .to_string()
        })?
        .with_alpn(alpn);
    if let Some(ca_path) = &cfg.tls_client_ca {
        sc = sc.with_client_ca(load_client_ca(ca_path)?);
    }

    if cfg.tls_client_ca.is_none() {
        sc = sc.with_resumption(onetdns_tls::conn::ServerResumption::secure_default());
    }
    Ok(Arc::new(sc))
}

/** @brief 클라이언트 인증서를 확인할 CA 번들을 읽는다. */
pub(crate) fn load_client_ca(path: &std::path::Path) -> Result<onetdns_tls::TrustStore, String> {
    let pem = read_bytes_limited(path, LOCAL_CA_MAX_BYTES).map_err(|error| {
        format!(
            "Could not read the mTLS CA file ({}): {error}",
            path.display()
        )
    })?;
    onetdns_tls::TrustStore::try_from_pem(&pem).map_err(|error| {
        format!("The mTLS CA file contains a corrupted or unsupported certificate: {error}")
    })
}

/** @brief 공유 캐시의 TLS 인증서를 검증할 신뢰 저장소. CA 파일이 없으면 시스템 신뢰 저장소를 쓴다. */
pub(crate) fn cachedb_redis_roots(
    ca: Option<&std::path::Path>,
) -> Result<onetdns_tls::TrustStore, String> {
    let Some(path) = ca else {
        return Ok(onetdns_tls::TrustStore::system());
    };
    let pem = read_bytes_limited(path, LOCAL_CA_MAX_BYTES).map_err(|error| {
        format!(
            "Could not read the shared cache TLS CA file ({}): {error}",
            path.display()
        )
    })?;
    onetdns_tls::TrustStore::try_from_pem(&pem).map_err(|error| {
        format!(
            "The shared cache TLS CA file contains a corrupted or unsupported certificate: {error}"
        )
    })
}

/** @brief 자체 서명 인증서를 만든다. */
pub(crate) fn gen_cert(host: String, cert_out: PathBuf, key_out: PathBuf) -> BoxResult<()> {
    let (cert_pem, key_pem) = onetdns_transport::generate_self_signed_pem(&host)?;
    commit_cert_key(&cert_out, cert_pem.as_bytes(), &key_out, key_pem.as_bytes()).with_context(
        || {
            format!(
                "Could not save the certificate or private key file: {} / {}",
                cert_out.display(),
                key_out.display()
            )
        },
    )?;
    println!(
        "Created a self-signed certificate: {} / {} (host={host})",
        cert_out.display(),
        key_out.display()
    );
    Ok(())
}

/** @brief 인증서와 키에서 읽어 낸 정보. */
pub(crate) struct TlsMaterialInfo {
    /** @brief 읽어 낸 인증서들. */
    pub(crate) parsed: Vec<onetdns_tls::X509>,
    /** @brief 모든 인증서가 유효 기간 안인지. */
    pub(crate) all_times_valid: bool,
    /** @brief 체인의 연결이 맞는지. */
    pub(crate) chain_links_valid: bool,
    /** @brief 체인의 제약이 지켜지는지. */
    pub(crate) chain_constraints_valid: bool,
    /** @brief 스스로 서명한 인증서인지. */
    pub(crate) self_signed: bool,
}

/** @brief 인증서와 키를 살펴본다. */
pub(crate) fn inspect_tls_material(
    certs: &[Vec<u8>],
    key: &[u8],
) -> Result<TlsMaterialInfo, String> {
    let cert0 = certs
        .first()
        .ok_or("The certificate chain is empty".to_string())?;
    if onetdns_tls::ServerConfig::from_chain_pkcs8(certs.to_vec(), key).is_none() {
        return Err(
            "Could not parse the certificate and private key; ECDSA P-256 in PKCS#8 is required"
                .to_string(),
        );
    }
    onetdns_transport::verify_key_matches_cert(cert0, key).map_err(|e| e.to_string())?;
    let parsed: Vec<onetdns_tls::X509> = certs
        .iter()
        .map(|der| onetdns_tls::X509::parse(der).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let leaf = parsed
        .first()
        .ok_or("The certificate chain is empty".to_string())?;
    let self_signed = leaf.issuer_raw == leaf.subject_raw;
    let now = unix_now() as i64;
    let all_times_valid = parsed.iter().all(|cert| cert.valid_at(now));

    let chain_links_valid = if parsed.len() == 1 {
        self_signed && leaf.verify_signed_by(leaf).is_ok()
    } else {
        parsed.windows(2).all(|pair| {
            pair[0].issuer_raw == pair[1].subject_raw && pair[0].verify_signed_by(&pair[1]).is_ok()
        })
    };
    let leaf_usage_valid = leaf.allows_tls_leaf_usage() && leaf.allows_server_auth();
    let issuer_constraints_valid = parsed.iter().enumerate().skip(1).all(|(index, cert)| {
        let below_ca_count = index.saturating_sub(1) as u32;
        cert.is_ca
            && cert.allows_cert_sign()
            && cert.path_len.is_none_or(|limit| below_ca_count <= limit)
    });
    let chain_constraints_valid = leaf_usage_valid && issuer_constraints_valid;
    Ok(TlsMaterialInfo {
        parsed,
        all_times_valid,
        chain_links_valid,
        chain_constraints_valid,
        self_signed,
    })
}

/** @brief 이 인증서와 키로 실제로 서빙할 수 있는지 확인한다. 확인 없이 바꾸면 다음 연결부터 전부 실패한다. */
fn require_servable_tls_material(certs: &[Vec<u8>], key: &[u8]) -> Result<(), String> {
    let info = inspect_tls_material(certs, key)?;
    if !info.all_times_valid {
        return Err(
            "The certificate chain contains a certificate that is not yet valid or has expired"
                .to_string(),
        );
    }
    if !info.chain_links_valid {
        return Err("The certificate chain is incomplete or its signatures and issuers do not link correctly".to_string());
    }
    if !info.chain_constraints_valid {
        return Err(
            "A certificate's basicConstraints, keyUsage, EKU, or pathLen does not fit a server chain"
                .to_string(),
        );
    }
    Ok(())
}

/** @brief 인증서와 키를 바꾼다. */
pub(crate) fn tls_configure(
    body: &str,
    cfg_cert: &Option<std::path::PathBuf>,
    cfg_key: &Option<std::path::PathBuf>,
    path: &Option<std::path::PathBuf>,
    prev: &ConfigTextSlot,
    reload: &Arc<std::sync::atomic::AtomicBool>,
) -> Result<String, String> {
    use std::path::PathBuf;
    let j = onetdns_core::json::parse(body)
        .map_err(|e| format!("Could not parse the JSON request body: {e}"))?;
    let onetdns_core::json::Json::Obj(fields) = &j else {
        return Err("The TLS settings request must be a JSON object".into());
    };
    /** @brief 인증서 설정 항목들. */
    const TLS_FIELDS: [&str; 4] = ["certificate_chain", "private_key", "cert_path", "key_path"];
    if fields
        .iter()
        .any(|(key, _)| !TLS_FIELDS.contains(&key.as_str()))
        || TLS_FIELDS.iter().any(|key| {
            fields
                .iter()
                .filter(|(candidate, _)| candidate == key)
                .count()
                > 1
        })
    {
        return Err("The TLS settings request has an unsupported or duplicate field".into());
    }
    let getstr = |k: &str| {
        j.get(k)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let inline_cert = getstr("certificate_chain");
    let inline_key = getstr("private_key");
    let requested_cert_path = getstr("cert_path");
    let requested_key_path = getstr("key_path");
    if inline_cert.is_some() != inline_key.is_some()
        || requested_cert_path.is_some() != requested_key_path.is_some()
    {
        return Err(
            "The certificate and private key, or the certificate path and private key path, must be given together".into(),
        );
    }

    let (cert_path, key_path, chain_len, material_backup) = if let (Some(cpem), Some(kpem)) =
        (inline_cert, inline_key)
    {
        let (certs, key) = onetdns_transport::parse_pem(cpem, kpem)
            .map_err(|e| format!("PEM certificate and private key validation failed: {e}"))?;
        let chain_len = certs.len();
        require_servable_tls_material(&certs, &key)?;
        let cert_p = requested_cert_path
            .map(PathBuf::from)
            .or_else(|| cfg_cert.clone())
            .ok_or("A cert_path or an existing tls_cert path is needed to save the certificate")?;
        let key_p = requested_key_path
            .map(PathBuf::from)
            .or_else(|| cfg_key.clone())
            .ok_or("A key_path or an existing tls_key path is needed to save the private key")?;
        let backup = commit_cert_key(&cert_p, cpem.as_bytes(), &key_p, kpem.as_bytes())
            .map_err(|e| format!("Could not save the certificate and private key: {e}"))?;
        (cert_p, key_p, chain_len, Some(backup))
    } else {
        let cert_p = requested_cert_path
            .map(PathBuf::from)
            .ok_or("Enter a cert_path file path or a certificate_chain value")?;
        let key_p = requested_key_path
            .map(PathBuf::from)
            .ok_or("Enter a key_path file path or a private_key value")?;
        let (certs, key) = onetdns_transport::load_pem(&cert_p, &key_p)
            .map_err(|e| format!("Could not load the PEM data: {e}"))?;
        let chain_len = certs.len();
        require_servable_tls_material(&certs, &key)?;
        (cert_p, key_p, chain_len, None)
    };

    let cert_s = cert_path.display().to_string();
    let key_s = key_path.display().to_string();
    let config_result = apply_config_edit(path, prev, reload, |text| {
        let out = rewrite_config_kv(text, "tls_cert", &toml_quote(&cert_s))?;
        rewrite_config_kv(&out, "tls_key", &toml_quote(&key_s))
    });
    if let Err(config_err) = config_result {
        if let Some(backup) = &material_backup {
            if let Err(rollback_err) = rollback_cert_key(&cert_path, &key_path, backup) {
                return Err(format!(
                    "Saving the configuration failed, and the certificate and private key could not be restored either: configuration error={config_err}; restore error={rollback_err}"
                ));
            }
        }
        return Err(config_err);
    }
    onetdns_core::info!(event = "tls.cert_installed", cert = %cert_s, key = %key_s, "Verified and saved the TLS certificate, then restarted the listeners");
    Ok(format!(
        "{{\"configured\":true,\"chain_len\":{chain_len},\"reloading\":true,\"cert\":{},\"key\":{}}}",
        onetdns_core::json::escape(&cert_s),
        onetdns_core::json::escape(&key_s)
    ))
}

/** @brief 인증서 발급을 돌린다. */
pub(crate) fn acme_issue_run(
    cfg: &Config,
    body: &str,
    resolver: http::HostResolver,
    tls_slots: Option<Arc<TlsSlots>>,
) -> Result<String, String> {
    let j = onetdns_core::json::parse(body)
        .map_err(|e| format!("Could not parse the JSON request body: {e}"))?;
    let bstr = |k: &str| j.get(k).and_then(|v| v.as_str()).map(String::from);
    let directory_url = bstr("directory")
        .or_else(|| cfg.acme_directory_url.clone())
        .ok_or("Enter the ACME directory URL in directory or acme_directory_url")?;
    let domains: Vec<String> = j
        .get("domains")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| cfg.acme_domains.clone());
    let contact = bstr("contact").or_else(|| cfg.acme_contact_email.clone());
    let challenge = bstr("challenge").unwrap_or_else(|| cfg.acme_challenge.clone());
    let account_only = j
        .get("account_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    onetdns_config::validate_acme_request(
        Some(&directory_url),
        &domains,
        contact.as_deref(),
        &challenge,
    )?;

    let account_key_pem = match cfg.acme_account_key_file.as_ref() {
        Some(path) => match read_text_limited(std::path::Path::new(path), LOCAL_KEY_MAX_BYTES) {
            Ok(pem) => Some(Zeroizing::new(pem)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "Could not read the ACME account key ({path}): {error}"
                ));
            }
        },
        None => None,
    };

    let params_domains = domains.clone();
    let params = acme::IssueParams {
        directory_url,
        domains,
        contact,
        challenge,
        account_key_pem,
        account_only,
    };
    let res = acme::run_issue(params, Duration::from_secs(20), resolver)?;

    if let Some(p) = &cfg.acme_account_key_file {
        if !std::path::Path::new(p).exists() {
            atomic_write_secret(std::path::Path::new(p), res.account_key_pem.as_bytes())
                .map_err(|e| format!("Could not save the ACME account key: {e}"))?;
        }
    }

    let mut issued = false;
    if let (Some(cert), Some(key)) = (&res.cert_pem, &res.cert_key_pem) {
        match (&cfg.acme_cert_file, &cfg.acme_key_file) {
            (Some(cf), Some(kf)) => {
                commit_cert_key(
                    std::path::Path::new(cf),
                    cert.as_bytes(),
                    std::path::Path::new(kf),
                    key.as_bytes(),
                )
                .map_err(|e| format!("Could not save the certificate and private key: {e}"))?;
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err("Set both acme_cert_file and acme_key_file, or neither".to_string());
            }
            (None, None) => {}
        }
        /*
         * 발급은 인증서 파일만 바꾼다. 실행 중인 수신 주소가 쥐고 있는 인증서까지 여기서
         * 갈지 않으면, 발급에 성공하고도 다시 시작할 때까지 이전 인증서를 계속 내민다.
         */
        if let Some(slots) = &tls_slots {
            match slots.refresh_certificate_files(cfg) {
                Ok(swapped) if !swapped.is_empty() => onetdns_core::info!(
                    event = "tls.certificate_reloaded",
                    changed = %swapped.join(","),
                    "Replaced the TLS certificate without closing listening addresses"
                ),
                Ok(_) => {}
                Err(error) => onetdns_core::warn!(
                    event = "tls.certificate_reload_failed",
                    %error,
                    "Could not load the issued certificate on the running listeners; keeping the previous certificate"
                ),
            }
        }
        issued = true;
        onetdns_core::info!(event = "acme.certificate_issued", account = %res.account_url, domains = %params_domains.join(","), stored = cfg.acme_cert_file.is_some(), "Issued a new certificate through ACME");
    }

    Ok(format!(
        "{{\"account\":{},\"issued\":{issued},\"cert_file\":{},\"key_file\":{}}}",
        onetdns_core::json::escape(&res.account_url),
        cfg.acme_cert_file
            .as_deref()
            .map(onetdns_core::json::escape)
            .unwrap_or_else(|| "null".to_string()),
        cfg.acme_key_file
            .as_deref()
            .map(onetdns_core::json::escape)
            .unwrap_or_else(|| "null".to_string()),
    ))
}
