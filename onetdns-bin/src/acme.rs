//! ACME certificate issuance. The protocol is only JSON and signatures, so it is handled here
//! without a separate client. This server answers the challenges itself: dns-01 through its own
//! DNS answers, http-01 through the control plane.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use onetdns_core::json::{self, Json};
use onetdns_core::MutexExt;

use crate::http;

/// Pending dns-01 answers, by name.
static DNS01: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn dns01_store() -> &'static Mutex<HashMap<String, String>> {
    DNS01.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn set_dns01(name: &str, txt: &str) {
    dns01_store().lock_recover().insert(
        name.trim_end_matches('.').to_ascii_lowercase(),
        txt.to_string(),
    );
}

/// `None` when no challenge is pending for the name.
pub fn dns01_txt(name: &str) -> Option<String> {
    dns01_store()
        .lock_recover()
        .get(&name.trim_end_matches('.').to_ascii_lowercase())
        .cloned()
}

/// Must run once the challenge ends, or the name keeps answering the value.
fn clear_dns01(name: &str) {
    dns01_store()
        .lock_recover()
        .remove(&name.trim_end_matches('.').to_ascii_lowercase());
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64url(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64URL[(n >> 18) as usize & 0x3f] as char);
        out.push(B64URL[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 0x3f] as char);
        }
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut b = Vec::new();
        let mut l = len;
        while l > 0 {
            b.push((l & 0xff) as u8);
            l >>= 8;
        }
        b.reverse();
        out.push(0x80 | b.len() as u8);
        out.extend_from_slice(&b);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    der_len(content.len(), &mut v);
    v.extend_from_slice(content);
    v
}

fn seq(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

/// SubjectPublicKeyInfo header for an uncompressed P-256 key.
const SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];

/// A P-256 key for the account or the certificate.
pub struct AccountKey {
    signing: SigningKey,
}

impl AccountKey {
    pub fn generate() -> AccountKey {
        let secret = loop {
            let mut b = Zeroizing::new([0u8; 32]);
            onetdns_tls::sys::fill_random(&mut b[..]);
            if let Ok(sk) = p256::SecretKey::from_slice(&b[..]) {
                break sk;
            }
        };
        AccountKey {
            signing: SigningKey::from(secret),
        }
    }

    /// Accepts PKCS#8 and SEC1 (`EC PRIVATE KEY`).
    pub fn from_pkcs8_pem(pem: &str) -> Option<AccountKey> {
        let der = pem_block(pem, "PRIVATE KEY").or_else(|| pem_block(pem, "EC PRIVATE KEY"))?;
        use p256::pkcs8::DecodePrivateKey;
        let secret = p256::SecretKey::from_pkcs8_der(&der)
            .ok()
            .or_else(|| p256::SecretKey::from_sec1_der(&der).ok())?;
        Some(AccountKey {
            signing: SigningKey::from(secret),
        })
    }

    pub fn to_pkcs8_pem(&self) -> Zeroizing<String> {
        use p256::pkcs8::EncodePrivateKey;
        let der = p256::SecretKey::from(self.signing.clone())
            .to_pkcs8_der()
            .expect("Could not convert the P-256 private key to PKCS#8");
        der_to_pem(der.as_bytes(), "PRIVATE KEY")
    }

    fn coords(&self) -> ([u8; 32], [u8; 32]) {
        let vk = self.signing.verifying_key();
        let point = vk.to_sec1_point(false);
        let x: [u8; 32] = point
            .x()
            .expect("P-256 public key is missing its x coordinate")
            .as_slice()
            .try_into()
            .unwrap();
        let y: [u8; 32] = point
            .y()
            .expect("P-256 public key is missing its y coordinate")
            .as_slice()
            .try_into()
            .unwrap();
        (x, y)
    }

    /// Members in lexicographic order with no whitespace: the thumbprint hashes this exact string,
    /// so another order would name another account.
    pub fn jwk_json(&self) -> String {
        let (x, y) = self.coords();
        format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            b64url(&x),
            b64url(&y)
        )
    }

    /// The JWK thumbprint, which identifies the account.
    pub fn thumbprint(&self) -> String {
        b64url(&sha256(self.jwk_json().as_bytes()))
    }

    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }

    pub fn dns01_value(&self, token: &str) -> String {
        b64url(&sha256(self.key_authorization(token).as_bytes()))
    }

    /// r||s, as JWS ES256 expects.
    fn sign_raw(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing.sign(msg);
        sig.to_bytes().to_vec()
    }

    fn sign_der(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }

    /// The protected header carries the JWK before the account exists and the account URL after.
    pub fn jws(&self, url: &str, payload: &str, nonce: &str, kid: Option<&str>) -> String {
        let protected = match kid {
            Some(k) => format!(
                "{{\"alg\":\"ES256\",\"kid\":{},\"nonce\":{},\"url\":{}}}",
                json::escape(k),
                json::escape(nonce),
                json::escape(url)
            ),
            None => format!(
                "{{\"alg\":\"ES256\",\"jwk\":{},\"nonce\":{},\"url\":{}}}",
                self.jwk_json(),
                json::escape(nonce),
                json::escape(url)
            ),
        };
        let p_b64 = b64url(protected.as_bytes());
        let payload_b64 = if payload.is_empty() {
            String::new()
        } else {
            b64url(payload.as_bytes())
        };
        let signing_input = format!("{p_b64}.{payload_b64}");
        let sig = b64url(&self.sign_raw(signing_input.as_bytes()));
        format!(
            "{{\"protected\":\"{p_b64}\",\"payload\":\"{payload_b64}\",\"signature\":\"{sig}\"}}"
        )
    }
}

/// The first domain is the subject CN and every domain goes into subjectAltName, which modern
/// clients read.
pub fn build_csr(domains: &[String], cert_key: &AccountKey) -> Vec<u8> {
    let (x, y) = cert_key.coords();
    let mut point = vec![0x04];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(&point);

    let cn = domains.first().cloned().unwrap_or_default();
    let mut attr = tlv(0x06, OID_CN);
    attr.extend(tlv(0x0c, cn.as_bytes()));
    let subject = seq(&tlv(0x31, &seq(&attr)));

    let mut san_names = Vec::new();
    for d in domains {
        san_names.extend(tlv(0x82, d.as_bytes()));
    }
    let san_value = seq(&san_names);
    let mut san_ext = tlv(0x06, OID_SAN);
    san_ext.extend(tlv(0x04, &san_value));
    let extensions = seq(&seq(&san_ext));

    let mut ext_req = tlv(0x06, OID_EXTENSION_REQUEST);
    ext_req.extend(tlv(0x31, &extensions));
    let attributes = tlv(0xa0, &seq(&ext_req));

    let mut cri = tlv(0x02, &[0x00]);
    cri.extend(subject);
    cri.extend(spki);
    cri.extend(attributes);
    let cri = seq(&cri);

    let sig = cert_key.sign_der(&cri);
    let mut sig_bits = vec![0x00];
    sig_bits.extend_from_slice(&sig);

    let mut csr = cri;
    csr.extend(seq(&tlv(0x06, OID_ECDSA_SHA256)));
    csr.extend(tlv(0x03, &sig_bits));
    seq(&csr)
}

fn pem_block(pem: &str, label: &str) -> Option<Zeroizing<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let s = pem.find(&begin)? + begin.len();
    let e = pem[s..].find(&end)? + s;
    b64_decode(&pem[s..e])
}

fn der_to_pem(der: &[u8], label: &str) -> Zeroizing<String> {
    let b64 = b64_std(der);
    let mut body = Zeroizing::new(String::new());
    for line in b64.as_bytes().chunks(64) {
        body.push_str(&String::from_utf8_lossy(line));
        body.push('\n');
    }
    Zeroizing::new(format!(
        "-----BEGIN {label}-----\n{}-----END {label}-----\n",
        body.as_str()
    ))
}

const B64STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_std(data: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64STD[(n >> 18) as usize & 0x3f] as char);
        out.push(B64STD[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            B64STD[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64STD[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Zeroizing::new(Vec::new());
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// URLs from the CA's directory.
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

pub enum Provision<'a> {
    Dns01(&'a dyn Fn(&str, &str)),

    Http01(&'a dyn Fn(&str, &str)),
}

pub struct AcmeClient {
    key: AccountKey,
    dir: Directory,
    nonce: Option<String>,
    account_url: Option<String>,
    timeout: Duration,
    resolver: http::HostResolver,
}

impl AcmeClient {
    pub fn new(
        key: AccountKey,
        directory_url: &str,
        timeout: Duration,
        resolver: http::HostResolver,
    ) -> Result<Self, String> {
        let resp = http::get(directory_url)
            .timeout(timeout)
            .resolver(resolver.clone())
            .call()
            .map_err(|e| format!("Could not fetch the ACME directory: {e}"))?;
        let body = String::from_utf8_lossy(&resp.body);
        let j = json::parse(&body).map_err(|e| format!("ACME directory is not valid JSON: {e}"))?;
        let get = |k: &str| j.get(k).and_then(|v| v.as_str()).map(String::from);
        let dir = Directory {
            new_nonce: get("newNonce").ok_or("ACME directory has no newNonce URL")?,
            new_account: get("newAccount")
                .ok_or("ACME directory has no account registration URL")?,
            new_order: get("newOrder").ok_or("ACME directory has no certificate order URL")?,
        };
        Ok(AcmeClient {
            key,
            dir,
            nonce: None,
            account_url: None,
            timeout,
            resolver,
        })
    }

    /// Uses the nonce from the previous response when there is one, saving a round trip.
    fn fresh_nonce(&mut self) -> Result<String, String> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let resp = http::get(&self.dir.new_nonce)
            .timeout(self.timeout)
            .resolver(self.resolver.clone())
            .call()
            .map_err(|e| format!("Could not fetch a nonce: {e}"))?;
        resp.header("replay-nonce")
            .ok_or("Response has no Replay-Nonce header".to_string())
    }

    /// Keeps the nonce the response carries.
    fn post(&mut self, url: &str, payload: &str, jwk: bool) -> Result<http::Resp, String> {
        let nonce = self.fresh_nonce()?;
        let kid = if jwk {
            None
        } else {
            self.account_url.as_deref()
        };
        let body = self.key.jws(url, payload, &nonce, kid);
        let resp = http::post(url)
            .header("Content-Type", "application/jose+json")
            .timeout(self.timeout)
            .resolver(self.resolver.clone())
            .body_bytes(body.into_bytes())
            .call()
            .map_err(|e| format!("Could not send the request to the ACME server ({url}): {e}"))?;
        if let Some(n) = resp.header("replay-nonce") {
            self.nonce = Some(n);
        }
        Ok(resp)
    }

    pub fn register_account(&mut self, contact_email: Option<&str>) -> Result<String, String> {
        let payload = match contact_email {
            Some(email) => format!(
                "{{\"termsOfServiceAgreed\":true,\"contact\":[{}]}}",
                json::escape(&format!("mailto:{email}"))
            ),
            None => "{\"termsOfServiceAgreed\":true}".to_string(),
        };
        let url = self.dir.new_account.clone();
        let resp = self.post(&url, &payload, true)?;
        if resp.status != 200 && resp.status != 201 {
            return Err(format!(
                "Could not register the ACME account (HTTP {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let loc = resp
            .header("location")
            .ok_or("Account response has no Location header")?;
        self.account_url = Some(loc.clone());
        Ok(loc)
    }

    /// Places the order, answers each domain's challenge, submits the CSR and waits for issuance.
    pub fn issue(
        &mut self,
        domains: &[String],
        cert_key: &AccountKey,
        provision: &Provision,
    ) -> Result<String, String> {
        if self.account_url.is_none() {
            return Err(
                "The ACME account is not registered yet; register the account first".to_string(),
            );
        }
        let order = self.new_order(domains)?;
        for authz_url in &order.authorizations {
            self.do_authz(authz_url, provision)?;
        }
        let csr = build_csr(domains, cert_key);
        self.finalize(&order.finalize, &csr)?;
        let cert_url = self.poll_order_cert(&order.url)?;
        self.download_cert(&cert_url)
    }

    fn new_order(&mut self, domains: &[String]) -> Result<Order, String> {
        let ids: Vec<String> = domains
            .iter()
            .map(|d| format!("{{\"type\":\"dns\",\"value\":{}}}", json::escape(d)))
            .collect();
        let payload = format!("{{\"identifiers\":[{}]}}", ids.join(","));
        let url = self.dir.new_order.clone();
        let resp = self.post(&url, &payload, false)?;
        if resp.status != 201 && resp.status != 200 {
            return Err(format!(
                "Could not create the ACME certificate order (HTTP {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        let loc = resp
            .header("location")
            .ok_or("Order response has no Location header")?;
        let body = String::from_utf8_lossy(&resp.body);
        let j = json::parse(&body)
            .map_err(|e| format!("Could not parse the ACME order response JSON: {e}"))?;
        let finalize = j
            .get("finalize")
            .and_then(|v| v.as_str())
            .ok_or("Order response has no finalize URL")?
            .to_string();
        let authorizations = str_array(&j, "authorizations");
        Ok(Order {
            url: loc,
            finalize,
            authorizations,
        })
    }

    /// Sets the answer before asking for validation and clears it afterwards; otherwise the name
    /// keeps answering the challenge value.
    fn do_authz(&mut self, authz_url: &str, provision: &Provision) -> Result<(), String> {
        let resp = self.post(authz_url, "", false)?;
        let body = String::from_utf8_lossy(&resp.body);
        let j = json::parse(&body)
            .map_err(|e| format!("Could not parse the ACME authorization response JSON: {e}"))?;
        let domain = j
            .get("identifier")
            .and_then(|i| i.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let challenges = j.get("challenges").and_then(|v| v.as_array());
        let want_type = match provision {
            Provision::Dns01(_) => "dns-01",
            Provision::Http01(_) => "http-01",
        };
        let (chall_url, token) = challenges
            .into_iter()
            .flatten()
            .find_map(|c| {
                let t = c.get("type").and_then(|v| v.as_str())?;
                if t != want_type {
                    return None;
                }
                Some((
                    c.get("url").and_then(|v| v.as_str())?.to_string(),
                    c.get("token").and_then(|v| v.as_str())?.to_string(),
                ))
            })
            .ok_or(format!(
                "No {want_type} challenge in the domain authorization"
            ))?;

        match provision {
            Provision::Dns01(f) => {
                let name = format!("_acme-challenge.{domain}");
                f(&name, &self.key.dns01_value(&token));
            }
            Provision::Http01(f) => {
                f(&token, &self.key.key_authorization(&token));
            }
        }

        let result = self
            .post(&chall_url, "{}", false)
            .and_then(|_| self.poll_authz(authz_url));
        match provision {
            Provision::Dns01(_) => clear_dns01(&format!("_acme-challenge.{domain}")),
            Provision::Http01(_) => onetdns_control::clear_acme_http01(&token),
        }
        result
    }

    fn poll_authz(&mut self, authz_url: &str) -> Result<(), String> {
        for _ in 0..20 {
            let resp = self.post(authz_url, "", false)?;
            let body = String::from_utf8_lossy(&resp.body);
            let j = json::parse(&body)
                .map_err(|e| format!("Could not parse the ACME authorization status JSON: {e}"))?;
            match j.get("status").and_then(|v| v.as_str()) {
                Some("valid") => return Ok(()),
                Some("invalid") => return Err(format!("ACME domain authorization failed: {body}")),
                _ => std::thread::sleep(Duration::from_secs(2)),
            }
        }
        Err("ACME domain validation did not finish in time".to_string())
    }

    fn finalize(&mut self, finalize_url: &str, csr_der: &[u8]) -> Result<(), String> {
        let payload = format!("{{\"csr\":{}}}", json::escape(&b64url(csr_der)));
        let resp = self.post(finalize_url, &payload, false)?;
        if resp.status >= 400 {
            return Err(format!(
                "Could not finalize the ACME certificate order (HTTP {}): {}",
                resp.status,
                String::from_utf8_lossy(&resp.body)
            ));
        }
        Ok(())
    }

    fn poll_order_cert(&mut self, order_url: &str) -> Result<String, String> {
        for _ in 0..20 {
            let resp = self.post(order_url, "", false)?;
            let body = String::from_utf8_lossy(&resp.body);
            let j = json::parse(&body)
                .map_err(|e| format!("Could not parse the ACME order status JSON: {e}"))?;
            match j.get("status").and_then(|v| v.as_str()) {
                Some("valid") => {
                    return j
                        .get("certificate")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .ok_or("Order has no certificate download URL".to_string());
                }
                Some("invalid") => return Err(format!("ACME certificate order failed: {body}")),
                _ => std::thread::sleep(Duration::from_secs(2)),
            }
        }
        Err("ACME order finalization did not finish in time".to_string())
    }

    fn download_cert(&mut self, cert_url: &str) -> Result<String, String> {
        let resp = self.post(cert_url, "", false)?;
        if resp.status != 200 {
            return Err(format!(
                "Could not download the ACME certificate (HTTP {})",
                resp.status
            ));
        }
        String::from_utf8(resp.body)
            .map_err(|_| "Downloaded certificate is not UTF-8 text".to_string())
    }
}

struct Order {
    url: String,
    finalize: String,
    authorizations: Vec<String>,
}

pub struct IssueParams {
    pub directory_url: String,
    pub domains: Vec<String>,
    pub contact: Option<String>,
    pub challenge: String,
    /// Generated when absent.
    pub account_key_pem: Option<Zeroizing<String>>,
    /// Registers the account without requesting a certificate.
    pub account_only: bool,
}

/// The account key is reused for the next issuance.
pub struct IssueResult {
    pub account_url: String,
    pub account_key_pem: Zeroizing<String>,
    pub cert_pem: Option<String>,
    pub cert_key_pem: Option<Zeroizing<String>>,
}

/// With `account_only` it stops after registration, to obtain the account key ahead of issuance.
pub fn run_issue(
    p: IssueParams,
    timeout: Duration,
    resolver: http::HostResolver,
) -> Result<IssueResult, String> {
    let account_key = match &p.account_key_pem {
        Some(pem) => {
            AccountKey::from_pkcs8_pem(pem.as_str()).ok_or("Could not parse the account key PEM")?
        }
        None => AccountKey::generate(),
    };
    let account_key_pem = account_key.to_pkcs8_pem();

    let mut client = AcmeClient::new(account_key, &p.directory_url, timeout, resolver)?;
    let account_url = client.register_account(p.contact.as_deref())?;

    if p.account_only {
        return Ok(IssueResult {
            account_url,
            account_key_pem,
            cert_pem: None,
            cert_key_pem: None,
        });
    }
    if p.domains.is_empty() {
        return Err("No domains to issue a certificate for; set acme_domains".to_string());
    }

    let cert_key = AccountKey::generate();
    let cert_key_pem = cert_key.to_pkcs8_pem();

    let http01 = |token: &str, keyauth: &str| onetdns_control::set_acme_http01(token, keyauth);
    let dns01 = |name: &str, txt: &str| set_dns01(name, txt);
    let provision = match p.challenge.as_str() {
        "dns01" => Provision::Dns01(&dns01),
        "http01" => Provision::Http01(&http01),
        other => return Err(format!("Unsupported ACME challenge type: {other}")),
    };

    let cert_pem = client.issue(&p.domains, &cert_key, &provision)?;

    Ok(IssueResult {
        account_url,
        account_key_pem,
        cert_pem: Some(cert_pem),
        cert_key_pem: Some(cert_key_pem),
    })
}

fn str_array(j: &Json, key: &str) -> Vec<String> {
    j.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_no_padding() {
        assert_eq!(b64url(b"abc"), "YWJj");
        assert_eq!(b64url(b"a"), "YQ");
        assert_eq!(b64url(b"ab"), "YWI");

        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn jwk_is_canonical_and_thumbprint_stable() {
        let k = AccountKey::generate();
        let jwk = k.jwk_json();

        assert!(jwk.starts_with("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""));
        assert!(jwk.contains("\",\"y\":\""));

        assert_eq!(k.thumbprint(), k.thumbprint());
        assert!(!k.thumbprint().contains('='));
    }

    #[test]
    fn key_authorization_and_dns01() {
        let k = AccountKey::generate();
        let ka = k.key_authorization("tok123");
        assert!(ka.starts_with("tok123."));
        assert_eq!(ka, format!("tok123.{}", k.thumbprint()));

        let d = k.dns01_value("tok123");
        assert_eq!(d.len(), 43);
    }

    #[test]
    fn dns01_challenge_can_be_removed() {
        set_dns01("_Acme-Challenge.Example.", "proof");
        assert_eq!(
            dns01_txt("_acme-challenge.example"),
            Some("proof".to_string())
        );
        clear_dns01("_ACME-CHALLENGE.EXAMPLE.");
        assert_eq!(dns01_txt("_acme-challenge.example"), None);
    }

    #[test]
    fn account_key_pem_roundtrip() {
        let k = AccountKey::generate();
        let pem = k.to_pkcs8_pem();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let k2 = AccountKey::from_pkcs8_pem(&pem).unwrap();

        assert_eq!(k.thumbprint(), k2.thumbprint());
    }

    #[test]
    fn jws_structure_and_signature_verifies() {
        let k = AccountKey::generate();
        let jws = k.jws("https://acme.test/x", "{\"a\":1}", "nonce123", None);
        let j = json::parse(&jws).unwrap();
        let protected = j.get("protected").and_then(|v| v.as_str()).unwrap();
        let payload = j.get("payload").and_then(|v| v.as_str()).unwrap();
        let sig = j.get("signature").and_then(|v| v.as_str()).unwrap();

        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let vk: VerifyingKey = *k.signing.verifying_key();
        let signing_input = format!("{protected}.{payload}");
        let sig_bytes = b64_decode(&sig.replace('-', "+").replace('_', "/")).unwrap();
        let signature = Signature::from_slice(sig_bytes.as_slice()).unwrap();
        assert!(vk.verify(signing_input.as_bytes(), &signature).is_ok());

        let mut hdr_bytes = b64_decode(protected).unwrap();
        let hdr = String::from_utf8(std::mem::take(&mut *hdr_bytes)).unwrap();
        assert!(hdr.contains("\"alg\":\"ES256\"") && hdr.contains("\"jwk\""));
    }

    #[test]
    fn csr_has_spki_and_san() {
        let k = AccountKey::generate();
        let domains = vec!["a.test".to_string(), "b.test".to_string()];
        let csr = build_csr(&domains, &k);
        assert_eq!(csr[0], 0x30);

        assert!(csr.windows(6).any(|w| w == b"a.test"));
        assert!(csr.windows(6).any(|w| w == b"b.test"));
    }
}
