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
        onetdns_core::warn!(event = "tls.self_signed_in_use", host = %host, "자체 서명 인증서로 암호화 DNS를 제공합니다. 클라이언트는 이 인증서를 신뢰하지 않으므로 검증을 끄지 않으면 연결하지 못합니다");
        return onetdns_transport::self_signed_material(host)
            .map_err(|error| format!("자체 서명 TLS 인증서를 만들지 못했습니다: {error}"));
    }
    if let (Some(c), Some(k)) = (&cfg.tls_cert, &cfg.tls_key) {
        return onetdns_transport::load_pem(c, k)
            .map_err(|error| format!("TLS 인증서 또는 개인키를 읽지 못했습니다: {error}"));
    }
    Err("암호화 DNS 수신 주소에 사용할 TLS 인증서가 없습니다".to_string())
}

/** @brief 암호화 전송에 쓸 TLS 설정을 만든다. */
pub(crate) fn native_tls_config(
    cfg: &Config,
    alpn: Vec<Vec<u8>>,
    material: &(Vec<Vec<u8>>, Vec<u8>),
) -> Result<Arc<onetdns_tls::ServerConfig>, String> {
    let (certs, key) = (material.0.clone(), material.1.clone());
    if certs.is_empty() {
        return Err("TLS 인증서 체인이 비어 있습니다".to_string());
    }
    let mut sc = onetdns_tls::ServerConfig::from_chain_pkcs8(certs, &key)
        .ok_or_else(|| {
            "TLS 인증서와 개인키가 일치하지 않거나 지원하지 않는 형식입니다".to_string()
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
            "mTLS CA 파일을 읽지 못했습니다({}): {error}",
            path.display()
        )
    })?;
    onetdns_tls::TrustStore::try_from_pem(&pem).map_err(|error| {
        format!("mTLS CA 파일에 손상됐거나 지원하지 않는 형식의 인증서가 있습니다: {error}")
    })
}

/** @brief 자체 서명 인증서를 만든다. */
pub(crate) fn gen_cert(host: String, cert_out: PathBuf, key_out: PathBuf) -> BoxResult<()> {
    let (cert_pem, key_pem) = onetdns_transport::generate_self_signed_pem(&host)?;
    commit_cert_key(&cert_out, cert_pem.as_bytes(), &key_out, key_pem.as_bytes()).with_context(
        || {
            format!(
                "인증서 또는 개인키 파일을 저장하지 못했습니다: {} / {}",
                cert_out.display(),
                key_out.display()
            )
        },
    )?;
    println!(
        "자체 서명 인증서 생성: {} / {} (host={host})",
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
    let cert0 = certs.first().ok_or("빈 인증서 체인".to_string())?;
    if onetdns_tls::ServerConfig::from_chain_pkcs8(certs.to_vec(), key).is_none() {
        return Err(
            "인증서와 개인 키를 해석하지 못했습니다. ECDSA P-256 PKCS#8 형식이 필요합니다"
                .to_string(),
        );
    }
    onetdns_transport::verify_key_matches_cert(cert0, key).map_err(|e| e.to_string())?;
    let parsed: Vec<onetdns_tls::X509> = certs
        .iter()
        .map(|der| onetdns_tls::X509::parse(der).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let leaf = parsed.first().ok_or("빈 인증서 체인".to_string())?;
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
        return Err("인증서 체인에 아직 유효하지 않거나 만료된 인증서가 있습니다".to_string());
    }
    if !info.chain_links_valid {
        return Err("인증서 체인이 불완전하거나 서명/issuer 연결이 올바르지 않습니다".to_string());
    }
    if !info.chain_constraints_valid {
        return Err(
            "인증서의 basicConstraints/keyUsage/EKU/pathLen 제약이 서버 체인에 맞지 않습니다"
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
        .map_err(|e| format!("JSON 요청 본문을 해석할 수 없습니다: {e}"))?;
    let onetdns_core::json::Json::Obj(fields) = &j else {
        return Err("TLS 설정 요청은 JSON 객체여야 합니다".into());
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
        return Err("TLS 설정 요청에 지원하지 않는 항목이나 중복 항목이 있습니다".into());
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
            "인증서와 개인 키, 인증서 경로와 개인 키 경로는 각각 함께 입력해야 합니다".into(),
        );
    }

    let (cert_path, key_path, chain_len, material_backup) =
        if let (Some(cpem), Some(kpem)) = (inline_cert, inline_key) {
            let (certs, key) = onetdns_transport::parse_pem(cpem, kpem)
                .map_err(|e| format!("PEM 인증서와 개인 키 검증에 실패했습니다: {e}"))?;
            let chain_len = certs.len();
            require_servable_tls_material(&certs, &key)?;
            let cert_p = requested_cert_path
                .map(PathBuf::from)
                .or_else(|| cfg_cert.clone())
                .ok_or("인증서를 저장할 cert_path 또는 기존 tls_cert 경로가 필요합니다")?;
            let key_p = requested_key_path
                .map(PathBuf::from)
                .or_else(|| cfg_key.clone())
                .ok_or("개인키를 저장할 key_path 또는 기존 tls_key 경로가 필요합니다")?;
            let backup = commit_cert_key(&cert_p, cpem.as_bytes(), &key_p, kpem.as_bytes())
                .map_err(|e| format!("인증서와 개인 키를 저장하지 못했습니다: {e}"))?;
            (cert_p, key_p, chain_len, Some(backup))
        } else {
            let cert_p = requested_cert_path
                .map(PathBuf::from)
                .ok_or("cert_path 파일 경로나 certificate_chain 값을 입력해야 합니다")?;
            let key_p = requested_key_path
                .map(PathBuf::from)
                .ok_or("key_path 파일 경로나 private_key 값을 입력해야 합니다")?;
            let (certs, key) = onetdns_transport::load_pem(&cert_p, &key_p)
                .map_err(|e| format!("PEM 데이터를 불러오지 못했습니다: {e}"))?;
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
                    "설정 저장에 실패했고 인증서와 개인 키도 이전 상태로 되돌리지 못했습니다: 설정 오류={config_err}; 복구 오류={rollback_err}"
                ));
            }
        }
        return Err(config_err);
    }
    onetdns_core::info!(event = "tls.cert_installed", cert = %cert_s, key = %key_s, "TLS 인증서를 검증하고 저장한 뒤 수신 서비스를 다시 시작했습니다");
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
        .map_err(|e| format!("JSON 요청 본문을 해석할 수 없습니다: {e}"))?;
    let bstr = |k: &str| j.get(k).and_then(|v| v.as_str()).map(String::from);
    let directory_url = bstr("directory")
        .or_else(|| cfg.acme_directory_url.clone())
        .ok_or("ACME 디렉터리 주소를 directory 또는 acme_directory_url에 입력해야 합니다")?;
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
                return Err(format!("ACME 계정 키를 읽지 못했습니다({path}): {error}"));
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
                .map_err(|e| format!("ACME 계정 키를 저장하지 못했습니다: {e}"))?;
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
                .map_err(|e| format!("인증서와 개인 키를 저장하지 못했습니다: {e}"))?;
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "acme_cert_file과 acme_key_file은 둘 다 설정하거나 둘 다 생략해야 합니다"
                        .to_string(),
                );
            }
            (None, None) => {}
        }
        // 발급은 인증서 파일만 바꾼다. 실행 중인 수신 주소가 쥐고 있는 인증서까지 여기서
        // 갈지 않으면, 발급에 성공하고도 다시 시작할 때까지 이전 인증서를 계속 내민다.
        if let Some(slots) = &tls_slots {
            match slots.refresh_certificate_files(cfg) {
                Ok(swapped) if !swapped.is_empty() => onetdns_core::info!(
                    event = "tls.certificate_reloaded",
                    changed = %swapped.join(","),
                    "수신 주소를 닫지 않고 TLS 인증서를 교체했습니다"
                ),
                Ok(_) => {}
                Err(error) => onetdns_core::warn!(
                    event = "tls.certificate_reload_failed",
                    %error,
                    "발급받은 인증서를 실행 중인 수신 주소에 올리지 못했습니다. 이전 인증서를 그대로 씁니다"
                ),
            }
        }
        issued = true;
        onetdns_core::info!(event = "acme.certificate_issued", account = %res.account_url, domains = %params_domains.join(","), stored = cfg.acme_cert_file.is_some(), "ACME로 인증서를 새로 발급받았습니다");
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
