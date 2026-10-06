/*!
 * @brief GitHub 릴리스에서 새 버전을 찾고 실행 파일을 받는다.
 *
 * @details 릴리스 목록 응답에서는 태그 이름만 읽는다. 내려받을 주소는 고정된 저장소 아래에서
 *          만들고, 버전과 파일 해시는 서명을 확인한 매니페스트에서만 얻는다.
 */

use std::time::Duration;

use ed25519_dalek::VerifyingKey;

use super::manifest::{self, Asset, ManifestError};
use super::version::Version;
use crate::http::{self, HostResolver};

/** @brief 릴리스 목록 API. 첫 쪽에 최근 릴리스 30개가 온다. */
const RELEASES_API: &str = "https://api.github.com/repos/onetwohour/OnetDNS-Core/releases";
/** @brief 릴리스 자산 주소의 앞부분. 뒤에 태그와 파일 이름을 붙인다. */
const DOWNLOAD_BASE: &str = "https://github.com/onetwohour/OnetDNS-Core/releases/download";
/** @brief 릴리스 안내 쪽 주소의 앞부분. 뒤에 태그를 붙인다. */
const RELEASE_PAGE_BASE: &str = "https://github.com/onetwohour/OnetDNS-Core/releases/tag";
/** @brief 릴리스 목록 응답의 상한. 릴리스마다 설명이 길어도 남는다. */
const MAX_LISTING_BYTES: u64 = 4 * 1024 * 1024;
/** @brief 서명 파일의 크기. */
const SIGNATURE_BYTES: u64 = 64;
/** @brief 목록, 매니페스트, 서명을 받는 데 거는 시간. */
const SMALL_TIMEOUT: Duration = Duration::from_secs(30);
/** @brief 실행 파일을 받는 데 거는 시간. */
const EXECUTABLE_TIMEOUT: Duration = Duration::from_secs(600);
/**
 * @brief 응답 상한에 더하는 여유.
 * @details http 클라이언트의 상한은 본문이 아니라 받은 바이트 전체에 걸린다. 헤더와 조각 전송
 *          표지가 들어갈 자리이며, 본문 크기는 받은 뒤에 따로 확인한다.
 */
const FRAMING_ALLOWANCE: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 서명을 확인한 릴리스와 그 가운데 이 바이너리가 받을 실행 파일. */
pub(crate) struct Release {
    /** @brief 릴리스 버전. */
    pub(crate) version: String,
    /** @brief 이 바이너리의 자산 키에 맞는 실행 파일. */
    pub(crate) asset: Asset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/** @brief 새 릴리스를 확인한 결과. */
pub(crate) enum Finding {
    /** @brief 지금 버전보다 높은 후보가 없다. */
    UpToDate,
    /** @brief 자동으로 설치할 수 있는 새 버전이 있다. */
    Available(Release),
    /** @brief 가장 높은 후보를 이 바이너리가 자동으로 설치할 수 없다. 더 낮은 후보로 내려가지 않는다. */
    Manual {
        /** @brief 그 후보의 버전. */
        version: String,
        /** @brief 자동으로 설치할 수 없는 이유. */
        reason: String,
    },
}

/** @brief 이 버전의 릴리스 안내 쪽 주소. */
pub(crate) fn release_page(version: &str) -> String {
    format!("{RELEASE_PAGE_BASE}/v{version}")
}

/**
 * @brief 지금 버전보다 높은 릴리스를 찾는다.
 * @param current 지금 버전.
 * @param target 이 바이너리의 자산 키.
 * @param keys 믿는 릴리스 서명 키.
 * @return 서명이 맞지 않는 매니페스트와 받지 못한 응답은 오류다. 수동 설치가 필요한 릴리스는
 *         오류가 아니라 결과다.
 */
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

/** @brief 릴리스의 실행 파일을 받아 크기와 SHA-256 을 매니페스트와 맞댄다. */
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

/** @brief 릴리스 자산 하나의 주소. 버전은 서명으로 확인했거나 태그에서 읽은 것이라 경로에 그대로 쓴다. */
fn asset_url(version: &str, file: &str) -> String {
    format!("{DOWNLOAD_BASE}/v{version}/{file}")
}

/**
 * @brief 주소 하나를 받는다.
 * @param limit 본문의 상한.
 * @return 없는 파일(404)이면 없다.
 * @warning 이름 해석은 넘겨받은 해석기로만 하고 내부망 주소로는 접속하지 않는다. 넘김을 따라간
 *          곳도 같다.
 */
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

/**
 * @brief 릴리스 목록에서 옮겨 갈 수 있는 가장 높은 버전을 고른다.
 * @details 목록에서 읽는 것은 태그 이름뿐이다. v 로 시작하지 않거나 나머지가 버전으로 읽히지
 *          않는 태그는 건너뛴다.
 */
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

/**
 * @brief 받은 매니페스트와 서명으로 이 바이너리가 설치할 실행 파일을 정한다.
 * @param manifest 매니페스트 원문. 릴리스에 없으면 없다.
 * @param signature 서명. 릴리스에 없으면 없다.
 * @return 서명이 맞지 않으면 오류다. 키를 바꾼 릴리스일 수도 있지만 바뀐 자산일 수도 있어서,
 *         수동 설치 안내보다 눈에 띄는 확인 실패로 알린다.
 */
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

/** @brief 받은 실행 파일이 매니페스트에 적힌 크기와 해시와 같은지. */
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
/** @brief 후보 고르기, 매니페스트 판정, 받은 실행 파일 확인. 네트워크는 쓰지 않는다. */
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    /** @brief 이 바이너리의 자산 키로 쓰는 값. */
    const TARGET: &str = "x86_64-unknown-linux-musl";

    /** @brief 테스트용으로 반드시 읽히는 버전. */
    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|| panic!("{text} 를 읽지 못했습니다"))
    }

    /** @brief 이 태그들이 든 릴리스 목록. GitHub 응답처럼 다른 필드도 붙인다. */
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

    /** @brief 테스트 서명 키. 실제 릴리스 키와 관계없다. */
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    /** @brief 이 실행 파일 하나를 이 대상으로 적은 매니페스트. */
    fn manifest_for(version: &str, target: &str, executable: &[u8]) -> String {
        format!(
            "format = 1\nproduct = \"OnetDNS\"\nversion = \"{version}\"\n\n[[asset]]\ntarget = \"{target}\"\nfile = \"{}\"\nsize = {}\nsha256 = \"{}\"\n",
            manifest::asset_file_name(version, target),
            executable.len(),
            super::super::hex(&Sha256::digest(executable))
        )
    }

    #[test]
    /** @brief 목록에서 지금 버전이 받을 수 있는 가장 높은 버전을 고르는지. */
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
    /** @brief 목록이 배열이 아니거나 JSON 이 아니면 확인 실패로 알리는지. */
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
    /** @brief 서명을 확인한 매니페스트에서 이 대상의 실행 파일을 고르는지. */
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
    /**
     * @brief 이 바이너리가 설치할 수 없는 릴리스는 수동 설치로 알리는지.
     * @details 매니페스트나 서명이 없는 릴리스, 계약 번호가 다른 릴리스, 이 대상의 실행 파일이
     *          없는 릴리스가 여기에 든다.
     */
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
    /** @brief 믿지 않는 키로 서명한 매니페스트는 수동 설치 안내가 아니라 확인 실패인지. */
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
    /** @brief 크기나 해시가 매니페스트와 다른 실행 파일을 받아들이지 않는지. */
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
    /** @brief 주소를 응답이 아니라 고정된 저장소와 서명된 버전에서 만드는지. */
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
