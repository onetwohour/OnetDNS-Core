/*!
 * @brief 서명된 릴리스 매니페스트.
 *
 * @details 릴리스의 버전과 대상별 실행 파일 해시는 이 매니페스트만 정한다. GitHub API 응답과
 *          내려받은 주소는 믿지 않는다.
 * @warning 서명을 확인하기 전에는 내용을 해석하지 않는다. 해석기가 받는 입력은 신뢰 키로
 *          서명된 바이트뿐이어야 한다.
 */

use ed25519_dalek::{Signature, VerifyingKey};

use super::{decode_sha256, version::Version, CONTRACT};
use crate::PRODUCT_NAME;

/** @brief 매니페스트 자산 이름. */
pub(crate) const MANIFEST_FILE: &str = "OnetDNS-release.toml";
/** @brief 서명 자산 이름. 매니페스트 원문 바이트에 대한 Ed25519 서명 64바이트다. */
pub(crate) const SIGNATURE_FILE: &str = "OnetDNS-release.toml.sig";
/** @brief 매니페스트를 받을 때 거는 상한. 대상 수십 개를 적어도 한참 남는다. */
pub(crate) const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/** @brief 실행 파일 크기의 상한. 매니페스트가 이보다 크게 적으면 받지 않는다. */
pub(crate) const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
/** @brief 대상 이름의 길이 상한. */
const MAX_TARGET_LEN: usize = 64;

/** @brief 믿는 공개 키 목록. 릴리스 워크플로도 이 파일로 서명을 검증한다. */
const TRUSTED_KEYS: &str = include_str!("../../release-keys.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 서명을 확인한 매니페스트. */
pub(crate) struct Manifest {
    /** @brief 릴리스 버전. 고른 태그의 버전과 같음을 확인했다. */
    pub(crate) version: String,
    /** @brief 대상별 실행 파일. 대상은 겹치지 않는다. */
    pub(crate) assets: Vec<Asset>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 대상 하나의 실행 파일. */
pub(crate) struct Asset {
    /** @brief 자산 키. 빌드할 때 넣은 대상 트리플이다. */
    pub(crate) target: String,
    /** @brief 릴리스에 올라간 파일 이름. asset_file_name 규칙을 따른다. */
    pub(crate) file: String,
    /** @brief 바이트 수. 내려받을 때 상한으로 쓴다. */
    pub(crate) size: u64,
    /** @brief 파일의 SHA-256. */
    pub(crate) sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 매니페스트를 받아들이지 않은 이유. */
pub(crate) enum ManifestError {
    /** @brief 맞는 신뢰 키가 없다. 내용은 보지 않았다. */
    Signature,
    /** @brief 계약 번호가 이 바이너리와 다르다. 이 릴리스는 수동으로 설치해야 한다. */
    Contract(i64),
    /** @brief 서명은 맞지만 내용이 계약과 다르다. */
    Invalid(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Signature => {
                f.write_str("The release manifest is not signed by a trusted release key")
            }
            ManifestError::Contract(found) => write!(
                f,
                "The release uses update format {found}, but this version reads format {CONTRACT}; install it manually"
            ),
            ManifestError::Invalid(reason) => write!(f, "The release manifest is invalid: {reason}"),
        }
    }
}

impl Manifest {
    /** @brief 이 대상의 실행 파일. 없으면 이 플랫폼용 실행 파일이 없는 릴리스다. */
    pub(crate) fn asset_for(&self, target: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.target == target)
    }
}

/**
 * @brief 대상의 실행 파일 이름.
 * @details Windows 는 확장자가 있어야 실행되므로 .exe 를 붙인다. 이 규칙은 업데이트 계약에 든다.
 */
pub(crate) fn asset_file_name(version: &str, target: &str) -> String {
    let extension = if target.contains("-windows-") {
        ".exe"
    } else {
        ""
    };
    format!("{PRODUCT_NAME}-{version}-{target}{extension}")
}

/**
 * @brief 신뢰 키 목록을 읽는다.
 * @return 한 줄이라도 틀리면 오류다. 틀린 줄을 건너뛰면 소유자가 넣은 키가 조용히 빠진다.
 */
pub(crate) fn trusted_keys() -> Result<Vec<VerifyingKey>, String> {
    parse_keys(TRUSTED_KEYS)
}

/** @brief 신뢰 키 목록 형식을 읽는다. */
fn parse_keys(text: &str) -> Result<Vec<VerifyingKey>, String> {
    let mut keys = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = decode_sha256(line).ok_or_else(|| {
            format!(
                "Line {} of the release key list is not 64 lowercase hexadecimal characters",
                index + 1
            )
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
            format!(
                "Line {} of the release key list is not a valid Ed25519 public key",
                index + 1
            )
        })?;
        keys.push(key);
    }
    Ok(keys)
}

/**
 * @brief 서명을 확인하고 매니페스트를 읽는다.
 * @param tag_version 고른 릴리스 태그의 버전. 매니페스트의 버전이 이것과 같아야 한다.
 */
pub(crate) fn open(
    bytes: &[u8],
    signature: &[u8],
    keys: &[VerifyingKey],
    tag_version: &str,
) -> Result<Manifest, ManifestError> {
    verify(bytes, signature, keys)?;
    let manifest = parse(bytes)?;
    if manifest.version != tag_version {
        return Err(ManifestError::Invalid(format!(
            "it describes version {}, but the release tag is version {tag_version}",
            manifest.version
        )));
    }
    Ok(manifest)
}

/**
 * @brief 신뢰 키 가운데 하나로 서명이 맞는지 본다.
 * @details verify_strict 는 작은 위수의 키와 정규형이 아닌 서명도 거절한다.
 */
fn verify(bytes: &[u8], signature: &[u8], keys: &[VerifyingKey]) -> Result<(), ManifestError> {
    let signature = Signature::from_slice(signature).map_err(|_| ManifestError::Signature)?;
    if keys
        .iter()
        .any(|key| key.verify_strict(bytes, &signature).is_ok())
    {
        Ok(())
    } else {
        Err(ManifestError::Signature)
    }
}

/** @brief 서명을 확인한 바이트를 계약 형식으로 읽는다. 모르는 키는 받지 않는다. */
fn parse(bytes: &[u8]) -> Result<Manifest, ManifestError> {
    use onetdns_config::toml::Value;

    let invalid = |reason: &str| ManifestError::Invalid(reason.to_string());
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("it is not UTF-8"))?;
    let root = onetdns_config::toml::parse(text).map_err(ManifestError::Invalid)?;
    let table = root
        .as_table()
        .ok_or_else(|| invalid("it is not a table"))?;

    let format = table
        .get("format")
        .and_then(Value::as_int)
        .ok_or_else(|| invalid("format is missing"))?;
    if format != i64::from(CONTRACT) {
        return Err(ManifestError::Contract(format));
    }
    if let Some(key) = table
        .keys()
        .find(|key| !matches!(key.as_str(), "format" | "product" | "version" | "asset"))
    {
        return Err(ManifestError::Invalid(format!("unknown key {key}")));
    }
    if table.get("product").and_then(Value::as_str) != Some(PRODUCT_NAME) {
        return Err(invalid("it is not an OnetDNS release"));
    }
    let version = table
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| Version::parse(version).is_some())
        .ok_or_else(|| invalid("version is missing or is not a release version"))?
        .to_string();

    let entries = table
        .get("asset")
        .and_then(Value::as_array)
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| invalid("it lists no executables"))?;
    let mut assets: Vec<Asset> = Vec::with_capacity(entries.len());
    for entry in entries {
        let asset = parse_asset(entry, &version)?;
        if assets.iter().any(|seen| seen.target == asset.target) {
            return Err(ManifestError::Invalid(format!(
                "target {} is listed twice",
                asset.target
            )));
        }
        assets.push(asset);
    }
    Ok(Manifest { version, assets })
}

/** @brief 자산 항목 하나를 읽는다. */
fn parse_asset(entry: &onetdns_config::toml::Value, version: &str) -> Result<Asset, ManifestError> {
    use onetdns_config::toml::Value;

    let invalid = |reason: &str| ManifestError::Invalid(reason.to_string());
    let table = entry
        .as_table()
        .ok_or_else(|| invalid("an asset entry is not a table"))?;
    if let Some(key) = table
        .keys()
        .find(|key| !matches!(key.as_str(), "target" | "file" | "size" | "sha256"))
    {
        return Err(ManifestError::Invalid(format!("unknown asset key {key}")));
    }
    let target = table
        .get("target")
        .and_then(Value::as_str)
        .filter(|target| {
            !target.is_empty()
                && target.len() <= MAX_TARGET_LEN
                && target
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
        .ok_or_else(|| invalid("an asset has no valid target"))?
        .to_string();
    let file = table
        .get("file")
        .and_then(Value::as_str)
        .filter(|file| *file == asset_file_name(version, &target))
        .ok_or_else(|| {
            ManifestError::Invalid(format!(
                "the file name of target {target} does not follow the release naming rule"
            ))
        })?
        .to_string();
    let size = table
        .get("size")
        .and_then(Value::as_int)
        .and_then(|size| u64::try_from(size).ok())
        .filter(|size| (1..=MAX_EXECUTABLE_BYTES).contains(size))
        .ok_or_else(|| ManifestError::Invalid(format!("target {target} has no valid size")))?;
    let sha256 = table
        .get("sha256")
        .and_then(Value::as_str)
        .and_then(decode_sha256)
        .ok_or_else(|| ManifestError::Invalid(format!("target {target} has no valid sha256")))?;
    Ok(Asset {
        target,
        file,
        size,
        sha256,
    })
}

#[cfg(test)]
/** @brief 서명 확인과 형식 검사. */
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /** @brief 테스트 서명 키. 실제 릴리스 키와 관계없다. */
    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /** @brief 계약 형식을 따르는 매니페스트. */
    fn manifest_text(version: &str) -> String {
        format!(
            "format = 1\nproduct = \"OnetDNS\"\nversion = \"{version}\"\n\n[[asset]]\ntarget = \"x86_64-unknown-linux-musl\"\nfile = \"OnetDNS-{version}-x86_64-unknown-linux-musl\"\nsize = 11836928\nsha256 = \"{}\"\n\n[[asset]]\ntarget = \"x86_64-pc-windows-msvc\"\nfile = \"OnetDNS-{version}-x86_64-pc-windows-msvc.exe\"\nsize = 9437184\nsha256 = \"{}\"\n",
            "ab".repeat(32),
            "cd".repeat(32)
        )
    }

    /** @brief 이 키로 서명해 연다. */
    fn open_signed(text: &str, key: &SigningKey, tag: &str) -> Result<Manifest, ManifestError> {
        let signature = key.sign(text.as_bytes()).to_bytes();
        open(
            text.as_bytes(),
            &signature,
            &[signing_key(7).verifying_key()],
            tag,
        )
    }

    #[test]
    /** @brief 믿는 키로 서명한 매니페스트는 읽히는지. */
    fn manifest_signed_by_a_trusted_key_opens() {
        let manifest = open_signed(
            &manifest_text("0.1.0-alpha.6"),
            &signing_key(7),
            "0.1.0-alpha.6",
        )
        .expect("믿는 키로 서명한 매니페스트");
        assert_eq!(manifest.version, "0.1.0-alpha.6");
        let linux = manifest
            .asset_for("x86_64-unknown-linux-musl")
            .expect("Linux 자산");
        assert_eq!(linux.size, 11_836_928);
        assert_eq!(linux.sha256, [0xab; 32]);
        assert_eq!(
            manifest
                .asset_for("x86_64-pc-windows-msvc")
                .expect("Windows 자산")
                .file,
            "OnetDNS-0.1.0-alpha.6-x86_64-pc-windows-msvc.exe"
        );
        assert!(manifest.asset_for("aarch64-apple-darwin").is_none());
    }

    #[test]
    /**
     * @brief 바이트 하나만 바뀌어도, 다른 키로 서명해도 거절하는지.
     * @details 서명이 틀리면 해석하지 않아야 하므로 TOML 로도 읽히지 않는 바이트를 서명 없이 넣어
     *          보고 Signature 로 끝나는지 본다. 해석했다면 Invalid 가 나왔을 것이다.
     */
    fn tampered_or_foreign_signatures_are_rejected_before_parsing() {
        let text = manifest_text("0.1.0-alpha.6");
        let trusted = signing_key(7);
        let signature = trusted.sign(text.as_bytes()).to_bytes();
        let keys = [trusted.verifying_key()];

        let mut altered = text.clone().into_bytes();
        let at = altered.iter().position(|byte| *byte == b'1').expect("숫자");
        altered[at] = b'2';
        assert_eq!(
            open(&altered, &signature, &keys, "0.1.0-alpha.6"),
            Err(ManifestError::Signature)
        );

        assert_eq!(
            open_signed(&text, &signing_key(8), "0.1.0-alpha.6"),
            Err(ManifestError::Signature)
        );

        let mut flipped = signature;
        flipped[10] ^= 1;
        assert_eq!(
            open(text.as_bytes(), &flipped, &keys, "0.1.0-alpha.6"),
            Err(ManifestError::Signature)
        );
        assert_eq!(
            open(text.as_bytes(), &signature[..63], &keys, "0.1.0-alpha.6"),
            Err(ManifestError::Signature)
        );
        assert_eq!(
            open(b"\xff not toml", &signature, &keys, "0.1.0-alpha.6"),
            Err(ManifestError::Signature)
        );
        assert_eq!(
            open(text.as_bytes(), &signature, &[], "0.1.0-alpha.6"),
            Err(ManifestError::Signature),
            "믿는 키가 없으면 아무것도 믿지 않아야 합니다"
        );
    }

    #[test]
    /** @brief 계약 번호가 다르면 내용을 더 보지 않고 수동 설치로 알리는지. */
    fn other_contract_numbers_need_a_manual_install() {
        let text = "format = 2\nproduct = \"OnetDNS\"\nsomething_new = true\n";
        assert_eq!(
            open_signed(text, &signing_key(7), "0.2.0"),
            Err(ManifestError::Contract(2))
        );
    }

    #[test]
    /** @brief 서명은 맞아도 계약과 다른 내용은 받지 않는지. */
    fn signed_but_malformed_manifests_are_rejected() {
        let good = manifest_text("0.1.0-alpha.6");
        let cases = [
            ("다른 태그", good.clone(), "0.1.0-alpha.7"),
            (
                "다른 제품",
                good.replace("product = \"OnetDNS\"", "product = \"Other\""),
                "0.1.0-alpha.6",
            ),
            (
                "모르는 키",
                good.replace("format = 1\n", "format = 1\nchannel = \"beta\"\n"),
                "0.1.0-alpha.6",
            ),
            (
                "이름 규칙 위반",
                good.replace(
                    "file = \"OnetDNS-0.1.0-alpha.6-x86_64-unknown-linux-musl\"",
                    "file = \"../OnetDNS\"",
                ),
                "0.1.0-alpha.6",
            ),
            (
                "Windows 확장자 누락",
                good.replace("x86_64-pc-windows-msvc.exe", "x86_64-pc-windows-msvc"),
                "0.1.0-alpha.6",
            ),
            (
                "대문자 해시",
                good.replace(&"ab".repeat(32), &"AB".repeat(32)),
                "0.1.0-alpha.6",
            ),
            (
                "크기 0",
                good.replace("size = 11836928", "size = 0"),
                "0.1.0-alpha.6",
            ),
            (
                "크기 상한 초과",
                good.replace("size = 11836928", "size = 268435457"),
                "0.1.0-alpha.6",
            ),
            (
                "겹친 대상",
                good.replace("x86_64-pc-windows-msvc", "x86_64-unknown-linux-musl")
                    .replace("x86_64-unknown-linux-musl.exe", "x86_64-unknown-linux-musl"),
                "0.1.0-alpha.6",
            ),
            (
                "자산 없음",
                "format = 1\nproduct = \"OnetDNS\"\nversion = \"0.1.0-alpha.6\"\n".to_string(),
                "0.1.0-alpha.6",
            ),
            (
                "버전이 아님",
                good.replace("version = \"0.1.0-alpha.6\"", "version = \"latest\""),
                "latest",
            ),
        ];
        for (name, text, tag) in cases {
            assert!(
                matches!(
                    open_signed(&text, &signing_key(7), tag),
                    Err(ManifestError::Invalid(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    /** @brief 저장소의 신뢰 키 목록이 읽히는지. 틀린 줄이 있으면 릴리스가 모두 막힌다. */
    fn repository_key_list_parses() {
        trusted_keys().expect("onetdns-bin/release-keys.txt");
    }

    #[test]
    /** @brief 키 목록의 주석과 빈 줄은 건너뛰고, 틀린 줄은 건너뛰지 않고 오류로 내는지. */
    fn key_list_rejects_malformed_lines() {
        let key = signing_key(7).verifying_key();
        let hex = super::super::hex(key.as_bytes());
        let parsed = parse_keys(&format!("# 주석\n\n{hex}\n")).expect("올바른 목록");
        assert_eq!(parsed, vec![key]);
        assert!(parse_keys(&format!("{}\n", hex.to_uppercase())).is_err());
        assert!(parse_keys("abcd\n").is_err());
        assert!(parse_keys(&format!("{hex} # 끝 주석\n")).is_err());
    }
}
