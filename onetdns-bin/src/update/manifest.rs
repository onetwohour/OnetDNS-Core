//! Signed release manifest. Only the manifest decides a release's version and each target's
//! executable hash; GitHub API responses and download URLs are not trusted.
//!
//! Nothing is parsed before the signature checks out, so the parser only ever sees bytes signed by
//! a trusted key.

use ed25519_dalek::{Signature, VerifyingKey};

use super::{decode_sha256, version::Version, CONTRACT};
use crate::PRODUCT_NAME;

pub(crate) const MANIFEST_FILE: &str = "OnetDNS-release.toml";
/// A 64-byte Ed25519 signature over the raw manifest bytes.
pub(crate) const SIGNATURE_FILE: &str = "OnetDNS-release.toml.sig";
/// Room for dozens of targets.
pub(crate) const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// A manifest declaring a larger size is rejected.
pub(crate) const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TARGET_LEN: usize = 64;

/// The release workflow verifies signatures with this file too.
const TRUSTED_KEYS: &str = include_str!("../../release-keys.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
/// Signature already checked.
pub(crate) struct Manifest {
    /// Checked to equal the chosen tag's version.
    pub(crate) version: String,
    /// No target appears twice.
    pub(crate) assets: Vec<Asset>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Asset {
    /// The target triple set at build time.
    pub(crate) target: String,
    /// Follows asset_file_name.
    pub(crate) file: String,
    /// Also the download limit.
    pub(crate) size: u64,
    pub(crate) sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManifestError {
    /// No trusted key matches; the contents were not read.
    Signature,
    /// The contract number differs from this binary's; this release needs a manual install.
    Contract(i64),
    /// The signature is good, but the contents break the contract.
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
    /// None when the release has no executable for this platform.
    pub(crate) fn asset_for(&self, target: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.target == target)
    }
}

/// Windows needs .exe to run it. This naming is part of the update contract.
pub(crate) fn asset_file_name(version: &str, target: &str) -> String {
    let extension = if target.contains("-windows-") {
        ".exe"
    } else {
        ""
    };
    format!("{PRODUCT_NAME}-{version}-{target}{extension}")
}

/// Any bad line is an error; skipping it would silently drop a key the owner added.
pub(crate) fn trusted_keys() -> Result<Vec<VerifyingKey>, String> {
    parse_keys(TRUSTED_KEYS)
}

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

/// The manifest version must equal `tag_version`, the chosen release tag's.
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

/// verify_strict also rejects small-order keys and non-canonical signatures.
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

/// Unknown keys are rejected.
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
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Unrelated to the release key.
    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn manifest_text(version: &str) -> String {
        format!(
            "format = 1\nproduct = \"OnetDNS\"\nversion = \"{version}\"\n\n[[asset]]\ntarget = \"x86_64-unknown-linux-musl\"\nfile = \"OnetDNS-{version}-x86_64-unknown-linux-musl\"\nsize = 11836928\nsha256 = \"{}\"\n\n[[asset]]\ntarget = \"x86_64-pc-windows-msvc\"\nfile = \"OnetDNS-{version}-x86_64-pc-windows-msvc.exe\"\nsize = 9437184\nsha256 = \"{}\"\n",
            "ab".repeat(32),
            "cd".repeat(32)
        )
    }

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
    /// A bad signature must stop before parsing, so bytes that are not even TOML go in unsigned and
    /// must fail with Signature; parsing them would give Invalid.
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
    fn other_contract_numbers_need_a_manual_install() {
        let text = "format = 2\nproduct = \"OnetDNS\"\nsomething_new = true\n";
        assert_eq!(
            open_signed(text, &signing_key(7), "0.2.0"),
            Err(ManifestError::Contract(2))
        );
    }

    #[test]
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
    /// A bad line would block every release.
    fn repository_key_list_parses() {
        trusted_keys().expect("onetdns-bin/release-keys.txt");
    }

    #[test]
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
