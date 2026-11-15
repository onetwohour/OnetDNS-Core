//! Finds new versions among GitHub releases and downloads executables. Only tag names are read from
//! the listing; download URLs are built under the fixed repository, and versions and hashes come
//! only from the signed manifest.

use std::time::Duration;

use ed25519_dalek::VerifyingKey;

use super::manifest::{self, Asset, ManifestError};
use super::version::Version;
use crate::http::{self, HostResolver};

/// The first page holds the 30 most recent releases.
const RELEASES_API: &str = "https://api.github.com/repos/onetwohour/OnetDNS-Core/releases";
const DOWNLOAD_BASE: &str = "https://github.com/onetwohour/OnetDNS-Core/releases/download";
const RELEASE_PAGE_BASE: &str = "https://github.com/onetwohour/OnetDNS-Core/releases/tag";
/// Room for long release notes.
const MAX_LISTING_BYTES: u64 = 4 * 1024 * 1024;
const SIGNATURE_BYTES: u64 = 64;
const SMALL_TIMEOUT: Duration = Duration::from_secs(30);
const EXECUTABLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Added to response limits: the http client caps all received bytes, not the body, so this leaves
/// room for headers and chunk markers. The body size is checked separately afterwards.
const FRAMING_ALLOWANCE: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A verified release and the executable this binary takes from it.
pub(crate) struct Release {
    pub(crate) version: String,
    /// The one matching this binary's asset key.
    pub(crate) asset: Asset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Finding {
    UpToDate,
    Available(Release),
    /// This binary cannot install the highest candidate automatically; lower candidates are not
    /// tried.
    Manual {
        version: String,
        reason: String,
    },
}

pub(crate) fn release_page(version: &str) -> String {
    format!("{RELEASE_PAGE_BASE}/v{version}")
}

/// A bad manifest signature or a failed fetch is an error; a release that needs a manual install is
/// a result.
pub(crate) fn check(
    current: &Version,
    target: &str,
    keys: &[VerifyingKey],
    resolver: &HostResolver,
) -> Result<Finding, String> {
    let listing = fetch(RELEASES_API, MAX_LISTING_BYTES, SMALL_TIMEOUT, resolver)?
        .ok_or_else(|| "GitHub did not find the OnetDNS release list".to_string())?;
    let listing = String::from_utf8(listing)
        .map_err(|_| "The GitHub release list is not UTF-8 text".to_string())?;
    let Some(candidate) = newest_candidate(&listing, current)? else {
        return Ok(Finding::UpToDate);
    };
    let version = candidate.to_string();
    let manifest = fetch(
        &asset_url(&version, manifest::MANIFEST_FILE),
        manifest::MAX_MANIFEST_BYTES as u64,
        SMALL_TIMEOUT,
        resolver,
    )?;
    let signature = match manifest {
        Some(_) => fetch(
            &asset_url(&version, manifest::SIGNATURE_FILE),
            SIGNATURE_BYTES,
            SMALL_TIMEOUT,
            resolver,
        )?,
        None => None,
    };
    open_release(
        manifest.as_deref(),
        signature.as_deref(),
        &version,
        target,
        keys,
    )
}

/// Checks size and SHA-256 against the manifest.
pub(crate) fn download(release: &Release, resolver: &HostResolver) -> Result<Vec<u8>, String> {
    let body = fetch(
        &asset_url(&release.version, &release.asset.file),
        release.asset.size,
        EXECUTABLE_TIMEOUT,
        resolver,
    )?
    .ok_or_else(|| {
        format!(
            "The update manifest of version {} lists {}, but the release does not have that file",
            release.version, release.asset.file
        )
    })?;
    verify_executable(&body, &release.asset)?;
    Ok(body)
}

/// The version is signature-checked or parsed from a tag, so it goes into the path as is.
fn asset_url(version: &str, file: &str) -> String {
    format!("{DOWNLOAD_BASE}/v{version}/{file}")
}

/// None for a 404. Names resolve only through `resolver`, and internal addresses are never
/// connected to, redirects included.
fn fetch(
    url: &str,
    limit: u64,
    timeout: Duration,
    resolver: &HostResolver,
) -> Result<Option<Vec<u8>>, String> {
    let response = http::get(url)
        .timeout(timeout)
        .max_response(limit.saturating_add(FRAMING_ALLOWANCE))
        .resolver(resolver.clone())
        .deny_private_targets()
        .call()
        .map_err(|error| format!("Could not download {url}: {error}"))?;
    match response.status {
        200 if response.body.len() as u64 <= limit => Ok(Some(response.body)),
        200 => Err(format!(
            "{url} is larger than the {limit} bytes allowed for it"
        )),
        404 => Ok(None),
        status => Err(format!("{url} answered with HTTP status {status}")),
    }
}

/// Only tag names are read; tags that do not start with v or do not parse as versions are skipped.
fn newest_candidate(listing: &str, current: &Version) -> Result<Option<Version>, String> {
    let parsed = onetdns_core::json::parse_with_limit(listing, MAX_LISTING_BYTES as usize)
        .map_err(|error| format!("Could not read the GitHub release list: {error}"))?;
    let releases = parsed
        .as_array()
        .ok_or_else(|| "The GitHub release list is not a JSON array".to_string())?;
    Ok(releases
        .iter()
        .filter_map(|release| release.get("tag_name")?.as_str())
        .filter_map(Version::from_tag)
        .filter(|candidate| current.accepts(candidate))
        .max())
}

/// `manifest` and `signature` are None when the release lacks them. A bad signature is an error
/// rather than a manual-install notice: it may be a key change, but it may also be a replaced
/// asset.
fn open_release(
    manifest: Option<&[u8]>,
    signature: Option<&[u8]>,
    version: &str,
    target: &str,
    keys: &[VerifyingKey],
) -> Result<Finding, String> {
    let manual = |reason: String| {
        Ok(Finding::Manual {
            version: version.to_string(),
            reason,
        })
    };
    let (Some(manifest), Some(signature)) = (manifest, signature) else {
        return manual(format!(
            "Version {version} has no signed update manifest, so it cannot be installed automatically"
        ));
    };
    let opened = match manifest::open(manifest, signature, keys, version) {
        Ok(opened) => opened,
        Err(ManifestError::Signature) => {
            return Err(format!(
                "The update manifest of version {version} is not signed by a trusted release key, so it was not used"
            ))
        }
        Err(error) => return manual(error.to_string()),
    };
    match opened.asset_for(target) {
        Some(asset) => Ok(Finding::Available(Release {
            version: opened.version.clone(),
            asset: asset.clone(),
        })),
        None => manual(format!(
            "Version {version} has no executable for this platform ({target})"
        )),
    }
}

fn verify_executable(body: &[u8], asset: &Asset) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    if body.len() as u64 != asset.size {
        return Err(format!(
            "The downloaded {} is {} bytes, but the update manifest says {} bytes",
            asset.file,
            body.len(),
            asset.size
        ));
    }
    if <[u8; 32]>::from(Sha256::digest(body)) != asset.sha256 {
        return Err(format!(
            "The downloaded {} does not match the SHA-256 in the update manifest",
            asset.file
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    const TARGET: &str = "x86_64-unknown-linux-musl";

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} 를 읽지 못했습니다"))
    }

    /// With other fields, like a GitHub response.
    fn listing(tags: &[&str]) -> String {
        let items: Vec<String> = tags
            .iter()
            .map(|tag| {
                format!(
                    "{{\"tag_name\":{},\"name\":\"OnetDNS {tag}\",\"prerelease\":false,\"assets\":[{{\"name\":\"x\",\"browser_download_url\":\"https://example.invalid/x\"}}]}}",
                    onetdns_core::json::escape(tag)
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }

    /// Unrelated to the release key.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    fn manifest_for(version: &str, target: &str, executable: &[u8]) -> String {
        format!(
            "format = 1\nproduct = \"OnetDNS\"\nversion = \"{version}\"\n\n[[asset]]\ntarget = \"{target}\"\nfile = \"{}\"\nsize = {}\nsha256 = \"{}\"\n",
            manifest::asset_file_name(version, target),
            executable.len(),
            super::super::hex(&Sha256::digest(executable))
        )
    }

    #[test]
    fn newest_candidate_follows_the_version_rules() {
        let tags = listing(&[
            "v0.1.0-alpha.7",
            "v0.1.0-alpha.12",
            "v0.1.0",
            "v0.2.0-beta.1",
            "v0.0.9",
            "nightly",
            "0.9.0",
            "v1.0.0+build.5",
            "v01.0.0",
        ]);
        assert_eq!(
            newest_candidate(&tags, &v("0.1.0-alpha.5")),
            Ok(Some(v("0.2.0-beta.1"))),
            "시험판은 시험판과 정식판을 모두 봅니다"
        );
        assert_eq!(
            newest_candidate(&tags, &v("0.0.9")),
            Ok(Some(v("0.1.0"))),
            "정식판은 시험판으로 가지 않습니다"
        );
        assert_eq!(
            newest_candidate(&tags, &v("0.2.0-beta.1")),
            Ok(None),
            "같은 버전으로는 가지 않습니다"
        );
        assert_eq!(newest_candidate(&listing(&[]), &v("0.1.0")), Ok(None));
    }

    #[test]
    fn malformed_listings_fail_the_check() {
        for body in ["{\"message\":\"API rate limit exceeded\"}", "not json", ""] {
            assert!(newest_candidate(body, &v("0.1.0")).is_err(), "{body:?}");
        }
        assert_eq!(
            newest_candidate("[{\"tag_name\":7},{\"name\":\"v9.0.0\"}]", &v("0.1.0")),
            Ok(None),
            "태그 이름이 문자열이 아닌 항목은 건너뜁니다"
        );
    }

    #[test]
    fn signed_release_with_this_target_is_available() {
        let executable = b"new executable".as_slice();
        let text = manifest_for("0.1.0", TARGET, executable);
        let key = signing_key();
        let signature = key.sign(text.as_bytes()).to_bytes();
        let finding = open_release(
            Some(text.as_bytes()),
            Some(&signature),
            "0.1.0",
            TARGET,
            &[key.verifying_key()],
        );
        let Ok(Finding::Available(release)) = finding else {
            panic!("설치할 수 있는 릴리스여야 합니다: {finding:?}");
        };
        assert_eq!(release.version, "0.1.0");
        assert_eq!(release.asset.target, TARGET);
        assert_eq!(verify_executable(executable, &release.asset), Ok(()));
    }

    #[test]
    /// Releases without a manifest or signature, with another contract number, or without an
    /// executable for this target.
    fn releases_this_build_cannot_install_need_a_manual_install() {
        let key = signing_key();
        let keys = [key.verifying_key()];
        let sign = |text: &str| key.sign(text.as_bytes()).to_bytes();

        let text = manifest_for("0.1.0", TARGET, b"x");
        let signature = sign(&text);
        let other_target = manifest_for("0.1.0", "aarch64-apple-darwin", b"x");
        let other_target_signature = sign(&other_target);
        let other_contract = "format = 2\nproduct = \"OnetDNS\"\n";
        let other_contract_signature = sign(other_contract);
        let cases: [(&str, Option<&[u8]>, Option<&[u8]>); 4] = [
            ("매니페스트 없음", None, None),
            ("서명 없음", Some(text.as_bytes()), None),
            (
                "다른 계약 번호",
                Some(other_contract.as_bytes()),
                Some(&other_contract_signature),
            ),
            (
                "이 대상의 실행 파일 없음",
                Some(other_target.as_bytes()),
                Some(&other_target_signature),
            ),
        ];
        for (name, manifest, signature) in cases {
            assert!(
                matches!(
                    open_release(manifest, signature, "0.1.0", TARGET, &keys),
                    Ok(Finding::Manual { ref version, .. }) if version == "0.1.0"
                ),
                "{name}"
            );
        }
        assert!(matches!(
            open_release(
                Some(text.as_bytes()),
                Some(&signature),
                "0.1.0",
                TARGET,
                &keys
            ),
            Ok(Finding::Available(_))
        ));
    }

    #[test]
    fn foreign_signatures_fail_the_check() {
        let text = manifest_for("0.1.0", TARGET, b"x");
        let foreign = SigningKey::from_bytes(&[10; 32])
            .sign(text.as_bytes())
            .to_bytes();
        assert!(open_release(
            Some(text.as_bytes()),
            Some(&foreign),
            "0.1.0",
            TARGET,
            &[signing_key().verifying_key()],
        )
        .is_err());
    }

    #[test]
    fn downloaded_executables_must_match_the_manifest() {
        let executable = b"new executable".to_vec();
        let asset = Asset {
            target: TARGET.to_string(),
            file: manifest::asset_file_name("0.1.0", TARGET),
            size: executable.len() as u64,
            sha256: Sha256::digest(&executable).into(),
        };
        assert_eq!(verify_executable(&executable, &asset), Ok(()));

        let mut altered = executable.clone();
        altered[0] ^= 1;
        assert!(verify_executable(&altered, &asset).is_err(), "바뀐 바이트");
        assert!(
            verify_executable(&executable[1..], &asset).is_err(),
            "짧은 파일"
        );
        let mut longer = executable.clone();
        longer.push(0);
        assert!(verify_executable(&longer, &asset).is_err(), "긴 파일");
    }

    #[test]
    fn addresses_come_from_the_fixed_repository() {
        assert_eq!(
            asset_url("0.1.0-alpha.6", manifest::MANIFEST_FILE),
            "https://github.com/onetwohour/OnetDNS-Core/releases/download/v0.1.0-alpha.6/OnetDNS-release.toml"
        );
        assert_eq!(
            release_page("0.1.0"),
            "https://github.com/onetwohour/OnetDNS-Core/releases/tag/v0.1.0"
        );
    }
}
