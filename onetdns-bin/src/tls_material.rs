//! TLS certificates and keys: loading, checks, server config, and replacement through the
//! management API.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use onetdns_config::Config;
use onetdns_core::MutexExt;
use zeroize::Zeroizing;

use crate::atomic_file::{atomic_write_secret, commit_cert_key, rollback_cert_key};
use crate::config_apply::apply_config_edit;
use crate::config_edit::{
    remove_config_key, rewrite_config_kv, rewrite_config_string_array, toml_quote,
};
use crate::error::{BoxResult, Context};
use crate::listeners::TlsSlots;
use crate::{
    acme, http, read_bytes_limited, read_text_limited, unix_now, ConfigTextSlot,
    LOCAL_CA_MAX_BYTES, LOCAL_KEY_MAX_BYTES,
};

/// One certificate and key for every encrypted transport. Per-transport self-signed certificates
/// would differ, and a client that pinned one could not connect over another; DDR announcing
/// several encrypted endpoints makes this visible.
///
/// `self_signed_file` is where the `tls_self_signed_host` certificate is kept; `None` without a
/// config file, and then the certificate changes at every start.
pub(crate) fn native_tls_material(
    cfg: &Config,
    self_signed_file: Option<&Path>,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    if let Some(host) = &cfg.tls_self_signed_host {
        onetdns_core::warn!(event = "tls.self_signed_in_use", host = %host, "Serving TLS with a self-signed certificate; clients connect only if they trust it or skip certificate verification");
        return self_signed_material(host, self_signed_file);
    }
    if let (Some(c), Some(k)) = (&cfg.tls_cert, &cfg.tls_key) {
        return onetdns_transport::load_pem(c, k).map_err(|error| {
            format!("Could not read the TLS certificate or private key: {error}")
        });
    }
    Err("There is no TLS certificate for the encrypted DNS listening addresses".to_string())
}

/// Next to the config file. Stamps and Apple profiles pin this certificate, so it must outlive a
/// restart.
pub(crate) fn self_signed_file(config_path: Option<&Path>) -> Option<PathBuf> {
    Some(config_path?.parent()?.join("tls-self-signed.pem"))
}

/// A new certificate is made only when the kept one is missing, does not load, is for another
/// host, or has less than this left.
const SELF_SIGNED_RENEW_SECS: i64 = 30 * 86400;

fn self_signed_material(
    host: &str,
    file: Option<&Path>,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    // Listener setup and a hot apply can both get here; one must not overwrite what the other
    // just started serving.
    static CREATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = CREATE.lock_recover();
    if let Some(material) = file.and_then(|file| kept_self_signed(file, host)) {
        return Ok(material);
    }
    let (cert, key) = onetdns_transport::generate_self_signed_pem(host)
        .map_err(|error| format!("Could not create a self-signed TLS certificate: {error}"))?;
    let key = Zeroizing::new(key);
    let material = onetdns_transport::parse_pem(&cert, &key)
        .map_err(|error| format!("Could not create a self-signed TLS certificate: {error}"))?;
    let Some(file) = file else {
        return Ok(material);
    };
    let text = Zeroizing::new(format!("{cert}{}", key.as_str()));
    match atomic_write_secret(file, text.as_bytes()) {
        Ok(()) => {
            onetdns_core::info!(event = "tls.self_signed_created", host = %host, path = %file.display(), "Created a self-signed certificate and saved it for later starts")
        }
        Err(error) => {
            onetdns_core::warn!(event = "tls.self_signed_save_failed", path = %file.display(), %error, "Could not save the self-signed certificate; a new one will be made at the next start, and clients that pinned this one will stop connecting")
        }
    }
    Ok(material)
}

fn kept_self_signed(file: &Path, host: &str) -> Option<(Vec<Vec<u8>>, Vec<u8>)> {
    if !file.exists() {
        return None;
    }
    let (certs, key) = match onetdns_transport::load_pem(file, file) {
        Ok(material) => material,
        Err(error) => {
            onetdns_core::warn!(event = "tls.self_signed_unreadable", path = %file.display(), %error, "Could not use the saved self-signed certificate; making a new one");
            return None;
        }
    };
    let leaf = onetdns_tls::X509::parse(certs.first()?).ok()?;
    let usable = leaf.matches_hostname(host)
        && leaf.not_after - unix_now() as i64 > SELF_SIGNED_RENEW_SECS
        && onetdns_transport::verify_key_matches_cert(&certs[0], &key).is_ok();
    usable.then_some((certs, key))
}

/// Whether `leaf` is the certificate kept in `file`, so it is served again after a restart.
pub(crate) fn self_signed_is_kept(file: Option<&Path>, leaf: &[u8]) -> bool {
    let Some(text) = file.and_then(|file| read_text_limited(file, LOCAL_KEY_MAX_BYTES).ok()) else {
        return false;
    };
    let text = Zeroizing::new(text);
    crate::revoke::pem_chain_to_ders(&text)
        .first()
        .is_some_and(|kept| kept.as_slice() == leaf)
}

/// Seals session tickets with `ticket_key` when given, so tickets sealed with it elsewhere resume.
pub(crate) fn native_tls_config(
    cfg: &Config,
    alpn: Vec<Vec<u8>>,
    material: &(Vec<Vec<u8>>, Vec<u8>),
    ticket_key: Option<Zeroizing<[u8; 32]>>,
) -> Result<Arc<onetdns_tls::ServerConfig>, String> {
    let mut sc = server_config(material)?.with_alpn(alpn);
    if let Some(ca_path) = &cfg.tls_client_ca {
        sc = sc.with_client_ca(load_client_ca(ca_path)?);
    }

    if cfg.tls_client_ca.is_none() {
        let mut resumption = onetdns_tls::conn::ServerResumption::secure_default();
        if let Some(key) = ticket_key {
            resumption.ticketer = Arc::new(onetdns_tls::Ticketer::from_key(*key));
        }
        sc = sc.with_resumption(resumption);
    }
    Ok(Arc::new(sc))
}

/// For the HTTPS management listener. `tls_client_ca` does not apply: browsers present no client
/// certificate, and sign-in authenticates the user.
pub(crate) fn control_tls_config(
    material: &(Vec<Vec<u8>>, Vec<u8>),
) -> Result<Arc<onetdns_tls::ServerConfig>, String> {
    Ok(Arc::new(
        server_config(material)?
            .with_alpn(vec![b"http/1.1".to_vec()])
            .with_resumption(onetdns_tls::conn::ServerResumption::secure_default()),
    ))
}

fn server_config(
    (certs, key): &(Vec<Vec<u8>>, Vec<u8>),
) -> Result<onetdns_tls::ServerConfig, String> {
    if certs.is_empty() {
        return Err("The TLS certificate chain is empty".to_string());
    }
    onetdns_tls::ServerConfig::from_chain_pkcs8(certs.clone(), key).ok_or_else(|| {
        "The TLS certificate and private key do not match, or the format is not supported"
            .to_string()
    })
}

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

/// Trust store for the Redis TLS connection; the system store when no CA file is given.
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

pub(crate) struct TlsMaterialInfo {
    pub(crate) parsed: Vec<onetdns_tls::X509>,
    pub(crate) all_times_valid: bool,
    pub(crate) chain_links_valid: bool,
    pub(crate) chain_constraints_valid: bool,
    pub(crate) self_signed: bool,
}

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

/// Replacing with material that cannot be served would fail every new connection.
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
        let beside = |name: &str| {
            path.as_deref()
                .and_then(Path::parent)
                .map(|dir| dir.join(name))
        };
        let cert_p = requested_cert_path
            .map(PathBuf::from)
            .or_else(|| cfg_cert.clone())
            .or_else(|| beside("tls-cert.pem"));
        let key_p = requested_key_path
            .map(PathBuf::from)
            .or_else(|| cfg_key.clone())
            .or_else(|| beside("tls-key.pem"));
        let (Some(cert_p), Some(key_p)) = (cert_p, key_p) else {
            return Err("There is no configuration file to save the certificate next to".into());
        };
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
        serve_tls_files(text, &cert_path, &key_path)
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

/// Sets `tls_cert` and `tls_key` and drops `tls_self_signed_host`, which takes precedence.
fn serve_tls_files(text: &str, cert: &Path, key: &Path) -> Result<String, String> {
    let out = rewrite_config_kv(text, "tls_cert", &toml_quote(&cert.display().to_string()))?;
    let out = rewrite_config_kv(&out, "tls_key", &toml_quote(&key.display().to_string()))?;
    remove_config_key(&out, "tls_self_signed_host")
}

/// Let's Encrypt, used when neither the request nor the config names an ACME directory.
pub(crate) const DEFAULT_ACME_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// One ACME issuance.
pub(crate) struct AcmeRequest {
    directory: String,
    domains: Vec<String>,
    contact: Option<String>,
    challenge: String,
    account_only: bool,
}

impl AcmeRequest {
    /// Fields the body leaves out come from the config.
    pub(crate) fn parse(body: &str, cfg: &Config) -> Result<Self, String> {
        let j = onetdns_core::json::parse(body)
            .map_err(|e| format!("Could not parse the JSON request body: {e}"))?;
        let bstr = |k: &str| j.get(k).and_then(|v| v.as_str()).map(String::from);
        let request = Self {
            directory: bstr("directory")
                .or_else(|| cfg.acme_directory_url.clone())
                .unwrap_or_else(|| DEFAULT_ACME_DIRECTORY.to_string()),
            domains: j
                .get("domains")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_else(|| cfg.acme_domains.clone()),
            contact: bstr("contact").or_else(|| cfg.acme_contact_email.clone()),
            challenge: bstr("challenge").unwrap_or_else(|| cfg.acme_challenge.clone()),
            account_only: j
                .get("account_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };
        onetdns_config::validate_acme_request(
            Some(&request.directory),
            &request.domains,
            request.contact.as_deref(),
            &request.challenge,
        )?;
        Ok(request)
    }

    /// `None` until a certificate was requested.
    fn renewal(cfg: &Config) -> Option<Self> {
        if cfg.acme_domains.is_empty() {
            return None;
        }
        Some(Self {
            directory: cfg.acme_directory_url.clone()?,
            domains: cfg.acme_domains.clone(),
            contact: cfg.acme_contact_email.clone(),
            challenge: cfg.acme_challenge.clone(),
            account_only: false,
        })
    }

    pub(crate) fn recorded_in(&self, cfg: &Config) -> bool {
        cfg.acme_directory_url.as_deref() == Some(self.directory.as_str())
            && (self.domains.is_empty() || cfg.acme_domains == self.domains)
            && cfg.acme_challenge == self.challenge
            && (self.contact.is_none() || cfg.acme_contact_email == self.contact)
    }

    /// Recorded before issuing: renewal reads the config, and DNS-01 is answered only while
    /// `acme_directory_url` is set.
    pub(crate) fn record(&self, text: &str) -> Result<String, String> {
        let mut out = rewrite_config_kv(text, "acme_directory_url", &toml_quote(&self.directory))?;
        out = rewrite_config_kv(&out, "acme_challenge", &toml_quote(&self.challenge))?;
        if !self.domains.is_empty() {
            out = rewrite_config_string_array(&out, "acme_domains", &self.domains)?;
        }
        if let Some(contact) = &self.contact {
            out = rewrite_config_kv(&out, "acme_contact_email", &toml_quote(contact))?;
        }
        Ok(out)
    }
}

/// Where issuance keeps the account key, the certificate, and its key.
pub(crate) struct AcmeFiles {
    account_key: Option<PathBuf>,
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
}

impl AcmeFiles {
    /// `acme_*_file`, else `tls_cert`/`tls_key`, else next to the config file.
    pub(crate) fn of(cfg: &Config, config_path: Option<&Path>) -> Option<Self> {
        let beside = |name: &str| config_path.and_then(Path::parent).map(|dir| dir.join(name));
        let (cert, key) = match (
            &cfg.acme_cert_file,
            &cfg.acme_key_file,
            &cfg.tls_cert,
            &cfg.tls_key,
        ) {
            (Some(cert), Some(key), _, _) => (PathBuf::from(cert), PathBuf::from(key)),
            (None, None, Some(cert), Some(key)) => (cert.clone(), key.clone()),
            _ => (beside("acme-cert.pem")?, beside("acme-key.pem")?),
        };
        let account_key = cfg
            .acme_account_key_file
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| beside("acme-account-key.pem"));
        Some(Self {
            account_key,
            cert,
            key,
        })
    }

    /// False when the listeners already serve these files or `tls_cert` names other files.
    pub(crate) fn needs_serving(&self, cfg: &Config) -> bool {
        match (&cfg.tls_cert, &cfg.tls_key) {
            (Some(cert), Some(key)) if *cert == self.cert && *key == self.key => {
                cfg.tls_self_signed_host.is_some()
            }
            (Some(_), Some(_)) => false,
            _ => true,
        }
    }

    pub(crate) fn serve(&self, text: &str) -> Result<String, String> {
        serve_tls_files(text, &self.cert, &self.key)
    }
}

/// Returns the account URL and whether a certificate was issued.
pub(crate) fn acme_issue(
    request: &AcmeRequest,
    files: &AcmeFiles,
    cfg: &Config,
    resolver: http::HostResolver,
    tls_slots: Option<Arc<TlsSlots>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> Result<(String, bool), String> {
    let account_key_pem = match &files.account_key {
        Some(path) => match read_text_limited(path, LOCAL_KEY_MAX_BYTES) {
            Ok(pem) => Some(Zeroizing::new(pem)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "Could not read the ACME account key ({}): {error}",
                    path.display()
                ));
            }
        },
        None => None,
    };

    let params = acme::IssueParams {
        directory_url: request.directory.clone(),
        domains: request.domains.clone(),
        contact: request.contact.clone(),
        challenge: request.challenge.clone(),
        account_key_pem,
        account_only: request.account_only,
    };
    let res = acme::run_issue(params, Duration::from_secs(20), resolver, stop)?;

    if let Some(path) = &files.account_key {
        if !path.exists() {
            atomic_write_secret(path, res.account_key_pem.as_bytes())
                .map_err(|e| format!("Could not save the ACME account key: {e}"))?;
        }
    }

    let (Some(cert), Some(key)) = (&res.cert_pem, &res.cert_key_pem) else {
        return Ok((res.account_url, false));
    };
    commit_cert_key(&files.cert, cert.as_bytes(), &files.key, key.as_bytes())
        .map_err(|e| format!("Could not save the certificate and private key: {e}"))?;
    onetdns_core::info!(event = "acme.certificate_issued", account = %res.account_url, domains = %request.domains.join(","), cert = %files.cert.display(), "Issued a new certificate through ACME");
    // Issuance only writes the files; without this, listeners keep presenting the old
    // certificate until restart.
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
    Ok((res.account_url, true))
}

const ACME_RENEWAL_CHECK: Duration = Duration::from_secs(6 * 60 * 60);

/// Keeps a crash-looping server from asking the CA at every start.
const ACME_RENEWAL_FIRST_CHECK: Duration = Duration::from_secs(10 * 60);

/// With a third of the lifetime left, as Let's Encrypt advises.
fn renewal_due(not_before: i64, not_after: i64, now: i64) -> bool {
    now >= not_after - (not_after - not_before).max(0) / 3
}

#[derive(Clone)]
pub(crate) struct AcmeRenewal {
    pub(crate) runtime_cfg: Arc<onetdns_core::ArcSwap<Config>>,
    pub(crate) tls_slots: Arc<std::sync::Mutex<Option<Arc<TlsSlots>>>>,
    pub(crate) resolver: http::HostResolver,
    pub(crate) config_path: Option<PathBuf>,
}

impl AcmeRenewal {
    /// Generations share one schedule.
    pub(crate) fn spawn(
        self,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        static NEXT_CHECK: std::sync::Mutex<Option<std::time::Instant>> =
            std::sync::Mutex::new(None);
        std::thread::Builder::new()
            .name("acme-renew".into())
            .spawn(move || loop {
                if crate::sleep_or_shutdown(60, &stop) {
                    break;
                }
                let now = std::time::Instant::now();
                {
                    let mut next = NEXT_CHECK.lock_recover();
                    if now < *next.get_or_insert(now + ACME_RENEWAL_FIRST_CHECK) {
                        continue;
                    }
                    *next = Some(now + ACME_RENEWAL_CHECK);
                }
                self.renew_if_due(&stop);
            })
    }

    fn renew_if_due(&self, stop: &Arc<std::sync::atomic::AtomicBool>) {
        let cfg = self.runtime_cfg.load();
        let Some(request) = AcmeRequest::renewal(&cfg) else {
            return;
        };
        let Some(files) = AcmeFiles::of(&cfg, self.config_path.as_deref()) else {
            return;
        };
        // The first certificate is requested by hand.
        let Ok((certs, _)) = onetdns_transport::load_pem(&files.cert, &files.key) else {
            return;
        };
        let Some(leaf) = certs
            .first()
            .and_then(|der| onetdns_tls::X509::parse(der).ok())
        else {
            return;
        };
        let now = unix_now() as i64;
        if !renewal_due(leaf.not_before, leaf.not_after, now) {
            return;
        }
        let days_left = (leaf.not_after - now).div_euclid(86_400);
        let slots = self.tls_slots.lock_recover().clone();
        match acme_issue(
            &request,
            &files,
            &cfg,
            self.resolver.clone(),
            slots,
            stop.clone(),
        ) {
            Ok(_) => onetdns_core::info!(
                event = "acme.certificate_renewed",
                domains = %request.domains.join(","),
                "Renewed the ACME certificate"
            ),
            Err(error) => onetdns_core::warn!(
                event = "acme.renewal_failed",
                %error,
                days_left,
                "Could not renew the ACME certificate"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_self_signed_certificate_is_kept_while_its_host_stays() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-self-signed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("시험용 디렉터리");
        let file = self_signed_file(Some(&dir.join("OnetDNS.toml"))).unwrap();

        let (first, _) = self_signed_material("dns.example", Some(&file)).unwrap();
        assert!(self_signed_is_kept(Some(&file), &first[0]));
        let (again, _) = self_signed_material("dns.example", Some(&file)).unwrap();
        assert_eq!(first, again, "다시 시작하면 인증서가 바뀝니다");

        let (other, _) = self_signed_material("other.example", Some(&file)).unwrap();
        assert_ne!(first, other, "다른 호스트에 이전 인증서를 썼습니다");
        assert!(!self_signed_is_kept(Some(&file), &first[0]));
        assert!(self_signed_is_kept(Some(&file), &other[0]));

        let (unkept, _) = self_signed_material("dns.example", None).unwrap();
        assert!(!self_signed_is_kept(None, &unkept[0]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn config(text: &str) -> Config {
        Config::from_toml_str(text).unwrap()
    }

    #[test]
    fn an_issued_certificate_goes_where_the_listeners_read_it() {
        let config_path = Path::new("/etc/OnetDNS/OnetDNS.toml");
        let beside = AcmeFiles::of(&config(""), Some(config_path)).unwrap();
        assert_eq!(beside.cert, Path::new("/etc/OnetDNS/acme-cert.pem"));
        assert_eq!(beside.key, Path::new("/etc/OnetDNS/acme-key.pem"));
        assert_eq!(
            beside.account_key.as_deref(),
            Some(Path::new("/etc/OnetDNS/acme-account-key.pem"))
        );
        assert!(AcmeFiles::of(&config(""), None).is_none());

        let served = config("tls_cert = \"/srv/cert.pem\"\ntls_key = \"/srv/key.pem\"\n");
        let files = AcmeFiles::of(&served, Some(config_path)).unwrap();
        assert_eq!(files.cert, Path::new("/srv/cert.pem"));
        assert!(!files.needs_serving(&served));

        let separate = config(
            "tls_cert = \"/srv/cert.pem\"\ntls_key = \"/srv/key.pem\"\nacme_cert_file = \"/acme/cert.pem\"\nacme_key_file = \"/acme/key.pem\"\n",
        );
        let files = AcmeFiles::of(&separate, Some(config_path)).unwrap();
        assert_eq!(files.cert, Path::new("/acme/cert.pem"));
        assert!(
            !files.needs_serving(&separate),
            "tls_cert 가 가리키는 다른 파일을 바꿨습니다"
        );

        let self_signed = config("tls_self_signed_host = \"dns.example\"\n");
        let files = AcmeFiles::of(&self_signed, Some(config_path)).unwrap();
        assert!(files.needs_serving(&self_signed));
        let after = config(
            &files
                .serve("tls_self_signed_host = \"dns.example\"\n")
                .unwrap(),
        );
        assert_eq!(after.tls_cert.as_deref(), Some(files.cert.as_path()));
        assert_eq!(after.tls_key.as_deref(), Some(files.key.as_path()));
        assert_eq!(after.tls_self_signed_host, None);
        assert!(!files.needs_serving(&after));
    }

    #[test]
    fn a_request_without_a_directory_uses_lets_encrypt_and_is_recorded() {
        let before = config("");
        let request = AcmeRequest::parse(
            "{\"domains\":[\"dns.example.com\"],\"challenge\":\"dns01\"}",
            &before,
        )
        .unwrap();
        assert!(!request.recorded_in(&before));
        let after = config(&request.record("").unwrap());
        assert_eq!(
            after.acme_directory_url.as_deref(),
            Some(DEFAULT_ACME_DIRECTORY)
        );
        assert_eq!(after.acme_domains, ["dns.example.com"]);
        assert_eq!(after.acme_challenge, "dns01");
        assert!(request.recorded_in(&after));

        let again = AcmeRequest::parse("{}", &after).unwrap();
        assert!(
            again.recorded_in(&after),
            "설정에 있는 값으로 다시 발급하지 않습니다"
        );
        assert!(AcmeRequest::renewal(&before).is_none());
        assert!(AcmeRequest::renewal(&after).is_some());
    }

    #[test]
    fn renewal_starts_with_a_third_of_the_lifetime_left() {
        let day = 86_400;
        assert!(!renewal_due(0, 90 * day, 59 * day));
        assert!(renewal_due(0, 90 * day, 60 * day));
        assert!(!renewal_due(0, 6 * day, 3 * day));
        assert!(renewal_due(0, 6 * day, 4 * day));
    }

    #[test]
    fn an_uploaded_certificate_without_tls_cert_goes_next_to_the_config() {
        let dir = std::env::temp_dir().join(format!(
            "onetdns-upload-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("시험용 디렉터리");
        let config_path = dir.join("OnetDNS.toml");
        std::fs::write(&config_path, "tls_self_signed_host = \"dns.example\"\n").unwrap();
        let (cert, key) = onetdns_transport::generate_self_signed_pem("dns.example").unwrap();
        let body = format!(
            "{{\"certificate_chain\":{},\"private_key\":{}}}",
            onetdns_core::json::escape(&cert),
            onetdns_core::json::escape(&key)
        );
        let reload = Arc::new(std::sync::atomic::AtomicBool::new(false));

        tls_configure(
            &body,
            &None,
            &None,
            &Some(config_path.clone()),
            &ConfigTextSlot::default(),
            &reload,
        )
        .unwrap();

        let after = config(&std::fs::read_to_string(&config_path).unwrap());
        assert_eq!(after.tls_cert, Some(dir.join("tls-cert.pem")));
        assert_eq!(after.tls_key, Some(dir.join("tls-key.pem")));
        assert_eq!(
            after.tls_self_signed_host, None,
            "자체 서명 인증서가 앞섭니다"
        );
        let saved = std::fs::read_to_string(dir.join("tls-cert.pem")).unwrap();
        assert_eq!(saved.trim(), cert.trim());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
