//! Dashboard password hashing with PBKDF2-HMAC-SHA256. The iteration count is stored in the hash
//! string, so it can grow later without breaking older hashes.
//!
//! Verification is CPU-heavy and reachable before authentication, so concurrent runs are capped;
//! otherwise login attempts alone could stall the server.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::{AtomicUsize, Ordering};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_ITERS: u32 = 600_000;
/// Stored hashes below this are refused.
const MIN_ITERS: u32 = 100_000;
/// So a tampered stored value cannot burn this server's CPU.
const MAX_ITERS: u32 = 1_000_000;
const SALT_LEN: usize = 16;
const HLEN: usize = 32;
/// Long input is hashing cost in itself.
const MAX_PASSWORD_BYTES: usize = 4096;
/// So login attempts cannot take all CPUs.
const MAX_CONCURRENT_KDF: usize = 4;
static ACTIVE_KDF: AtomicUsize = AtomicUsize::new(0);

/// Holds one KDF slot until dropped.
struct KdfGuard;

impl KdfGuard {
    /// `None` when every slot is taken.
    fn acquire() -> Option<Self> {
        ACTIVE_KDF
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |active| {
                (active < MAX_CONCURRENT_KDF).then_some(active + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Saturation and mismatch are kept apart; folding saturation into failure would tell a legitimate
/// user their password is wrong because of someone else's load.
pub(crate) enum VerifyResult {
    Match,
    Mismatch,
    /// No KDF slot free; cannot check right now.
    Busy,
}

impl Drop for KdfGuard {
    fn drop(&mut self) {
        ACTIVE_KDF.fetch_sub(1, Ordering::AcqRel);
    }
}

fn pbkdf2(password: &[u8], salt: &[u8], iters: u32, out: &mut [u8]) {
    let iters = iters.max(1);
    let blocks = out.len().div_ceil(HLEN);
    let template = HmacSha256::new_from_slice(password).expect("HMAC accepts any key length");
    for block in 1..=blocks {
        let mut mac = template.clone();
        mac.update(salt);
        mac.update(&(block as u32).to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..iters {
            let mut mac = template.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= *ui;
            }
        }
        let start = (block - 1) * HLEN;
        let end = (start + HLEN).min(out.len());
        out[start..end].copy_from_slice(&t[..end - start]);
    }
}

const MIN_PASSWORD_CHARS: usize = 12;
/// A UTF-8 character is at most 4 bytes, so this many characters never exceed MAX_PASSWORD_BYTES;
/// otherwise a password could be stored that always fails verification.
const MAX_PASSWORD_CHARS: usize = 1024;
const _: () = assert!(MAX_PASSWORD_CHARS * 4 <= MAX_PASSWORD_BYTES);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    TooShort,
    TooLong,
    /// No KDF slot free; cannot hash right now.
    Busy,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::TooShort => write!(
                f,
                "Password must be at least {MIN_PASSWORD_CHARS} characters"
            ),
            PasswordError::TooLong => {
                write!(
                    f,
                    "Password must be at most {MAX_PASSWORD_CHARS} characters"
                )
            }
            PasswordError::Busy => write!(f, "Too many password checks. Try again shortly"),
        }
    }
}

/// Stores salt and iteration count in the result. Length rules are checked here; left to each
/// caller, one forgotten check would store a hash nobody can sign in with. Shares the verification
/// concurrency cap, since creating the first account is reachable before authentication.
pub fn hash_password(pw: &str) -> Result<String, PasswordError> {
    hash_password_with_acquire(pw, KdfGuard::acquire)
}

/// `acquire` is replaced in tests to simulate saturation.
fn hash_password_with_acquire(
    pw: &str,
    acquire: impl FnOnce() -> Option<KdfGuard>,
) -> Result<String, PasswordError> {
    check_new_password(pw)?;
    let _guard = acquire().ok_or(PasswordError::Busy)?;
    Ok(derive_password_hash(pw))
}

/// hash_password checks the same; for callers that want to reject early, before expensive work.
pub fn check_new_password(pw: &str) -> Result<(), PasswordError> {
    let chars = pw.chars().count();
    if chars < MIN_PASSWORD_CHARS {
        return Err(PasswordError::TooShort);
    }
    if chars > MAX_PASSWORD_CHARS {
        return Err(PasswordError::TooLong);
    }
    Ok(())
}

/// Without the length rules.
fn derive_password_hash(pw: &str) -> String {
    let salt = onetdns_core::rng::random_array::<SALT_LEN>();
    let mut dk = [0u8; HLEN];
    pbkdf2(pw.as_bytes(), &salt, DEFAULT_ITERS, &mut dk);
    format!(
        "pbkdf2-sha256${}${}${}",
        DEFAULT_ITERS,
        hex(&salt),
        hex(&dk)
    )
}

/// Checks that the stored iteration count is in range first; the comparison is constant-time.
/// `acquire` is replaced in tests to simulate saturation.
fn verify_password_with_acquire(
    pw: &str,
    stored: &str,
    acquire: impl FnOnce() -> Option<KdfGuard>,
) -> VerifyResult {
    if pw.len() > MAX_PASSWORD_BYTES || stored.len() > 160 {
        return VerifyResult::Mismatch;
    }
    let mut parts = stored.split('$');
    if parts.next() != Some("pbkdf2-sha256") {
        return VerifyResult::Mismatch;
    }
    let iters: u32 = match parts.next().and_then(|s| s.parse().ok()) {
        Some(i) if (MIN_ITERS..=MAX_ITERS).contains(&i) => i,
        _ => return VerifyResult::Mismatch,
    };
    let salt_hex = match parts.next() {
        Some(value) if value.len() == SALT_LEN * 2 => value,
        _ => return VerifyResult::Mismatch,
    };
    let expect_hex = match parts.next() {
        Some(value) if value.len() == HLEN * 2 => value,
        _ => return VerifyResult::Mismatch,
    };
    if parts.next().is_some() {
        return VerifyResult::Mismatch;
    }
    let Some(salt) = unhex(salt_hex) else {
        return VerifyResult::Mismatch;
    };
    let Some(expect) = unhex(expect_hex) else {
        return VerifyResult::Mismatch;
    };
    let Some(_guard) = acquire() else {
        return VerifyResult::Busy;
    };
    let mut dk = [0u8; HLEN];
    pbkdf2(pw.as_bytes(), &salt, iters, &mut dk);
    if ct_eq(&dk, &expect) {
        VerifyResult::Match
    } else {
        VerifyResult::Mismatch
    }
}

pub(crate) fn verify_password_result(pw: &str, stored: &str) -> VerifyResult {
    verify_password_with_acquire(pw, stored, KdfGuard::acquire)
}

/// Saturation counts as false.
pub fn verify_password(pw: &str, stored: &str) -> bool {
    verify_password_result(pw, stored) == VerifyResult::Match
}

/// From the RNG, so it cannot be predicted.
pub(crate) fn new_session_token() -> String {
    hex(&onetdns_core::rng::random_array::<32>())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in b.chunks(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

/// Constant-time. Do not add an early return: timing would reveal the right hash byte by byte.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Retries past saturation until a real verdict. KDF slots are process-wide and shared with
    /// other tests that sign in during the same run; a single call would measure contention, not
    /// the verdict.
    fn verify_result_eventually(pw: &str, stored: &str) -> VerifyResult {
        loop {
            match verify_password_with_acquire(pw, stored, KdfGuard::acquire) {
                VerifyResult::Busy => std::thread::yield_now(),
                other => return other,
            }
        }
    }

    fn verify_password_eventually(pw: &str, stored: &str) -> bool {
        loop {
            match verify_password_result(pw, stored) {
                VerifyResult::Busy => std::thread::yield_now(),
                VerifyResult::Match => return true,
                VerifyResult::Mismatch => return false,
            }
        }
    }

    fn hash_password_eventually(pw: &str) -> Result<String, PasswordError> {
        loop {
            match hash_password(pw) {
                Err(PasswordError::Busy) => std::thread::yield_now(),
                result => return result,
            }
        }
    }

    #[test]
    fn hash_verify_roundtrip() {
        let h = hash_password_eventually("correct horse battery staple").unwrap();
        assert!(h.starts_with("pbkdf2-sha256$600000$"));
        assert!(verify_password_eventually(
            "correct horse battery staple",
            &h
        ));
        assert!(!verify_password_eventually("wrong password", &h));
    }

    #[test]
    fn distinct_salts_distinct_hashes() {
        let a = derive_password_hash("same");
        let b = derive_password_hash("same");
        assert_ne!(a, b, "임의 솔트로 해시가 달라야 함");
        assert!(verify_password_eventually("same", &a));
        assert!(verify_password_eventually("same", &b));
    }

    #[test]
    /// A stored account that cannot sign in has no recovery after the first account is created. The
    /// longest password is filled with 4-byte characters to check the largest byte count.
    fn every_accepted_password_can_sign_in() {
        assert_eq!(
            hash_password_eventually("elevenchars"),
            Err(PasswordError::TooShort)
        );
        assert!(hash_password_eventually("비밀번호는열두글자입니다").is_ok());
        assert_eq!(
            hash_password_eventually(&"x".repeat(MAX_PASSWORD_CHARS + 1)),
            Err(PasswordError::TooLong)
        );
        let longest = "😀".repeat(MAX_PASSWORD_CHARS);
        let hash = hash_password_eventually(&longest).unwrap();
        assert!(verify_password_eventually(&longest, &hash));
    }

    #[test]
    fn hashing_respects_the_kdf_limit() {
        assert_eq!(
            hash_password_with_acquire("correct horse battery staple", || None),
            Err(PasswordError::Busy)
        );
    }

    #[test]
    fn rejects_malformed() {
        assert!(!verify_password("x", "not-a-hash"));
        assert!(!verify_password("x", "pbkdf2-sha256$abc$00$00"));
        assert!(!verify_password("x", "pbkdf2-sha256$1000$zz$00"));
    }

    #[test]
    /// Checks PBKDF2 against a published vector.
    fn pbkdf2_rfc_style_vector() {
        let mut dk = [0u8; 32];
        pbkdf2(b"password", b"salt", 1, &mut dk);
        assert_eq!(
            hex(&dk),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn hex_unhex_roundtrip() {
        let b = [0x00u8, 0x1f, 0xa0, 0xff];
        assert_eq!(hex(&b), "001fa0ff");
        assert_eq!(unhex("001fa0ff").unwrap(), b);
        assert!(unhex("0").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    /// A tampered value must not burn CPU.
    fn rejects_unbounded_work_parameters() {
        assert!(!verify_password("x", "pbkdf2-sha256$4294967295$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"));
        assert!(!verify_password("x", "pbkdf2-sha256$100000$00$00"));
        let huge = format!("pbkdf2-sha256$100000${}${}", "00".repeat(1024), "$00");
        assert!(!verify_password("x", &huge));
        assert!(!verify_password(
            &"x".repeat(MAX_PASSWORD_BYTES + 1),
            &derive_password_hash("x")
        ));
    }

    #[test]
    fn reports_kdf_saturation_separately_from_a_wrong_password() {
        let hash = derive_password_hash("correct");
        assert_eq!(
            verify_password_with_acquire("correct", &hash, || None),
            VerifyResult::Busy
        );
        assert_eq!(
            verify_result_eventually("wrong", &hash),
            VerifyResult::Mismatch
        );
    }
}
