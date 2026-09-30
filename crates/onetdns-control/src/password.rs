/*!
 * @brief 대시보드 로그인 비밀번호 해시.
 *
 * @details PBKDF2-HMAC-SHA256으로 해시한다. 반복 횟수를 저장 형식에 함께 담아,
 *          나중에 늘려도 이전 해시를 그대로 검증할 수 있다.
 * @warning 검증은 CPU를 크게 쓴다. 인증 전에 닿는 경로이므로 동시 실행 수에 상한이 있어야
 *          로그인 시도만으로 서버를 마비시킬 수 없다.
 */

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::{AtomicUsize, Ordering};

/** @brief PBKDF2의 의사난수 함수. */
type HmacSha256 = Hmac<Sha256>;

/** @brief 새 해시에 쓸 반복 횟수. */
const DEFAULT_ITERS: u32 = 600_000;
/** @brief 받아들일 최소 반복. 이보다 낮은 값이 담긴 해시는 거부한다. */
const MIN_ITERS: u32 = 100_000;
/** @brief 받아들일 최대 반복. 조작된 저장값으로 이 서버의 CPU를 태우지 못하게 한다. */
const MAX_ITERS: u32 = 1_000_000;
/** @brief salt 길이. */
const SALT_LEN: usize = 16;
/** @brief 파생 키 길이. 해시 출력과 같다. */
const HLEN: usize = 32;
/** @brief 받아들일 비밀번호 길이 상한. 긴 입력은 그 자체로 해시 비용이 된다. */
const MAX_PASSWORD_BYTES: usize = 4096;
/** @brief 동시에 돌릴 수 있는 파생 연산 수. 로그인 시도로 CPU를 다 쓰지 못하게 한다. */
const MAX_CONCURRENT_KDF: usize = 4;
/** @brief 지금 돌고 있는 파생 연산 수. */
static ACTIVE_KDF: AtomicUsize = AtomicUsize::new(0);

/** @brief 파생 연산 슬롯을 잡았다 놓는 보호자. */
struct KdfGuard;

impl KdfGuard {
    /** @brief 슬롯을 잡는다. 이미 꽉 찼으면 잡지 않는다. */
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
/**
 * @brief 비밀번호 검증 결과.
 * @note 포화와 불일치를 구분한다. 포화를 실패로 합치면 정상 사용자가 남의 부하 때문에
 *       비밀번호가 틀렸다는 답을 받는다.
 */
pub(crate) enum VerifyResult {
    /** @brief 맞았다. */
    Match,
    /** @brief 틀렸다. */
    Mismatch,
    /** @brief 계산 슬롯이 없어 지금은 확인하지 못한다. */
    Busy,
}

impl Drop for KdfGuard {
    /** @brief 슬롯을 돌려준다. */
    fn drop(&mut self) {
        ACTIVE_KDF.fetch_sub(1, Ordering::AcqRel);
    }
}

/** @brief PBKDF2-HMAC-SHA256. 필요한 만큼 블록을 이어 만든다. */
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

/** @brief 새 비밀번호에 요구하는 최소 글자 수. */
const MIN_PASSWORD_CHARS: usize = 12;
/**
 * @brief 새 비밀번호에 허용하는 최대 글자 수.
 * @invariant UTF-8 한 글자는 최대 4바이트이므로 이 글자 수는 MAX_PASSWORD_BYTES 를 넘지 않는다.
 *            넘으면 저장은 되지만 검증이 항상 불일치로 답하는 비밀번호가 생긴다.
 */
const MAX_PASSWORD_CHARS: usize = 1024;
const _: () = assert!(MAX_PASSWORD_CHARS * 4 <= MAX_PASSWORD_BYTES);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 새 비밀번호를 해시하지 못한 이유. */
pub enum PasswordError {
    /** @brief 최소 글자 수보다 짧다. */
    TooShort,
    /** @brief 최대 글자 수보다 길다. */
    TooLong,
    /** @brief 계산 슬롯이 없어 지금은 해시하지 못한다. */
    Busy,
}

impl std::fmt::Display for PasswordError {
    /** @brief 사용자에게 보일 문구. */
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

/**
 * @brief 새 비밀번호를 해시한다. salt와 반복 횟수를 결과 문자열에 함께 담는다.
 * @details 길이 규칙을 여기서 검사한다. 호출자마다 검사하게 두면 한 곳이 빠졌을 때 로그인할 수
 *          없는 해시가 저장된다. 검증과 같은 동시 실행 상한을 쓴다. 첫 계정 생성은 인증 전에
 *          닿는 경로이기 때문이다.
 */
pub fn hash_password(pw: &str) -> Result<String, PasswordError> {
    hash_password_with_acquire(pw, KdfGuard::acquire)
}

/**
 * @brief 슬롯 잡기 방식을 주입받아 해시한다.
 * @param acquire 슬롯 잡기 방식. 테스트에서 포화 상황을 만들 때 교체한다.
 */
fn hash_password_with_acquire(
    pw: &str,
    acquire: impl FnOnce() -> Option<KdfGuard>,
) -> Result<String, PasswordError> {
    check_new_password(pw)?;
    let _guard = acquire().ok_or(PasswordError::Busy)?;
    Ok(derive_password_hash(pw))
}

/**
 * @brief 새 비밀번호가 길이 규칙을 지키는지 본다.
 * @details hash_password 도 같은 검사를 한다. 값비싼 검증을 하기 전에 먼저 거르려는 호출자가 쓴다.
 */
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

/** @brief 길이 규칙 없이 해시 문자열을 만든다. */
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

/**
 * @brief 저장된 해시와 비교한다. 슬롯 잡기 방식을 주입받는다.
 * @details 저장값의 반복 횟수가 허용 범위 안인지 먼저 본다. 비교는 상수 시간이다.
 * @param acquire 슬롯 잡기 방식. 테스트에서 포화 상황을 만들 때 교체한다.
 */
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

/** @brief 검증하고 포화 여부까지 구분해 돌려준다. */
pub(crate) fn verify_password_result(pw: &str, stored: &str) -> VerifyResult {
    verify_password_with_acquire(pw, stored, KdfGuard::acquire)
}

/** @brief 검증 결과를 참거짓으로만 돌려준다. 포화는 거짓이다. */
pub fn verify_password(pw: &str, stored: &str) -> bool {
    verify_password_result(pw, stored) == VerifyResult::Match
}

/** @brief 새 세션 토큰. 예측할 수 없어야 하므로 난수에서 만든다. */
pub(crate) fn new_session_token() -> String {
    hex(&onetdns_core::rng::random_array::<32>())
}

/** @brief 바이트를 소문자 16진 문자열로. */
pub(crate) fn hex(bytes: &[u8]) -> String {
    /** @brief 16진 문자표. */
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

/** @brief 16진 문자열을 바이트로. 형식이 어긋나면 None. */
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

/**
 * @brief 상수 시간 비교.
 * @warning 조기 반환을 넣지 마라. 걸린 시간으로 옳은 해시를 한 바이트씩 알아낼 수 있다.
 */
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
/** @brief 해시 왕복, 형식 거부, 그리고 포화와 불일치의 구분. */
mod tests {
    use super::*;

    /**
     * @brief 포화를 지나 실제 판정이 나올 때까지 다시 시도한다.
     * @details 동시 허가는 프로세스 전역이라 같은 실행에서 로그인하는 다른 테스트와 곳을
     *          다툰다. 한 번만 부르면 판정이 아니라 혼잡을 재게 된다.
     */
    fn verify_result_eventually(pw: &str, stored: &str) -> VerifyResult {
        loop {
            match verify_password_with_acquire(pw, stored, KdfGuard::acquire) {
                VerifyResult::Busy => std::thread::yield_now(),
                other => return other,
            }
        }
    }

    /** @brief 포화로 실패하면 잠시 뒤 다시 시도해 실제 판정을 얻는다. */
    fn verify_password_eventually(pw: &str, stored: &str) -> bool {
        loop {
            match verify_password_result(pw, stored) {
                VerifyResult::Busy => std::thread::yield_now(),
                VerifyResult::Match => return true,
                VerifyResult::Mismatch => return false,
            }
        }
    }

    /** @brief 포화로 실패하면 잠시 뒤 다시 시도해 해시를 얻는다. */
    fn hash_password_eventually(pw: &str) -> Result<String, PasswordError> {
        loop {
            match hash_password(pw) {
                Err(PasswordError::Busy) => std::thread::yield_now(),
                result => return result,
            }
        }
    }

    #[test]
    /** @brief 해시한 비밀번호가 다시 검증되는지. */
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
    /** @brief 같은 비밀번호라도 salt가 달라 해시가 달라지는지. */
    fn distinct_salts_distinct_hashes() {
        let a = derive_password_hash("same");
        let b = derive_password_hash("same");
        assert_ne!(a, b, "임의 솔트로 해시가 달라야 함");
        assert!(verify_password_eventually("same", &a));
        assert!(verify_password_eventually("same", &b));
    }

    #[test]
    /**
     * @brief 길이 규칙을 글자 수로 적용하고, 허용한 비밀번호는 모두 로그인에 쓸 수 있는지.
     * @details 저장만 되고 로그인할 수 없는 계정이 생기면 첫 계정 생성 뒤 복구할 길이 없다.
     *          가장 긴 비밀번호를 4바이트 문자로 채워 바이트 수가 가장 큰 경우를 확인한다.
     */
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
    /** @brief 해시 생성도 검증과 같은 동시 실행 상한을 받는지. */
    fn hashing_respects_the_kdf_limit() {
        assert_eq!(
            hash_password_with_acquire("correct horse battery staple", || None),
            Err(PasswordError::Busy)
        );
    }

    #[test]
    /** @brief 형식이 깨진 저장값을 거부하는지. */
    fn rejects_malformed() {
        assert!(!verify_password("x", "not-a-hash"));
        assert!(!verify_password("x", "pbkdf2-sha256$abc$00$00"));
        assert!(!verify_password("x", "pbkdf2-sha256$1000$zz$00"));
    }

    #[test]
    /** @brief PBKDF2 구현을 공표된 벡터에 대조한다. */
    fn pbkdf2_rfc_style_vector() {
        let mut dk = [0u8; 32];
        pbkdf2(b"password", b"salt", 1, &mut dk);
        assert_eq!(
            hex(&dk),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    /** @brief 16진 왕복. */
    fn hex_unhex_roundtrip() {
        let b = [0x00u8, 0x1f, 0xa0, 0xff];
        assert_eq!(hex(&b), "001fa0ff");
        assert_eq!(unhex("001fa0ff").unwrap(), b);
        assert!(unhex("0").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    /** @brief 반복 횟수가 범위 밖인 저장값을 거부하는지. 조작된 값으로 CPU를 태울 수 없다. */
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
    /** @brief 포화와 불일치를 구분해 알리는지. */
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
