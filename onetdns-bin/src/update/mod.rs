/*!
 * @brief 자체 업데이트.
 *
 * @details 새 릴리스를 확인하고, 서명한 매니페스트로 실행 파일을 검증해 설치 경로에서 맞바꾸고,
 *          새 버전을 시험 실행해 확정하거나 되돌린다. 설계와 그 이유는
 *          docs/architecture/self-update.md 가 맡는다.
 */

pub(crate) mod apply;
pub(crate) mod install;
pub(crate) mod launch;
pub(crate) mod manifest;
pub(crate) mod record;
pub(crate) mod release;
#[cfg(test)]
mod scratch;
pub(crate) mod task;
pub(crate) mod trial;
pub(crate) mod version;

/**
 * @brief 업데이트 계약 번호. 매니페스트와 업데이트 기록의 format 이 이 값이다.
 * @warning 매니페스트 형식, 서명 방식, 자산 이름 규칙, 기록 형식, 교체 파일 이름, --version 출력과
 *          check 의 종료 코드, 서버를 띄우는 명령줄 가운데 하나라도 바꾸면 올린다. 이전 버전은
 *          번호가 다른 릴리스를 자동으로 설치하지 않으므로 그 릴리스로는 한 번 수동으로 넘어간다.
 */
pub(crate) const CONTRACT: u32 = 1;

/** @brief 이 바이너리의 버전. */
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/**
 * @brief 이 바이너리의 자산 키. 릴리스 워크플로가 빌드할 때만 넣는다.
 * @details 없으면 업데이트에 참여하지 않는다. 기능을 골라 직접 빌드한 바이너리를 공식 빌드로
 *          바꿔 버리지 않으려는 것이다.
 */
pub(crate) const RELEASE_TARGET: Option<&str> = option_env!("ONETDNS_RELEASE_TARGET");

/** @brief 바이트를 소문자 16진수로. */
pub(crate) fn hex(bytes: &[u8]) -> String {
    /** @brief 16진 문자표. */
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/**
 * @brief 소문자 16진수 64자를 32바이트로 읽는다.
 * @details 대문자를 받지 않아 한 값의 표기가 하나뿐이다. 기록과 매니페스트를 글자 그대로 비교해도
 *          값을 비교한 것과 같다.
 */
pub(crate) fn decode_sha256(text: &str) -> Option<[u8; 32]> {
    /** @brief 소문자 16진 숫자 하나의 값. */
    fn nibble(digit: u8) -> Option<u8> {
        match digit {
            b'0'..=b'9' => Some(digit - b'0'),
            b'a'..=b'f' => Some(digit - b'a' + 10),
            _ => None,
        }
    }
    let digits = text.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
/**
 * @brief 업데이트 계약을 고정한다.
 *
 * @details 이전 버전이 새 버전을 내려받아 점검하고 띄우며, 새 버전은 이전 버전이 쓴 기록을
 *          읽는다. 그래서 여기 고정한 모양은 두 버전에 걸친 약속이다.
 * @warning 이 테스트가 깨지면 계약을 바꾼 것이다. 예제를 새 모양으로 고칠 때 CONTRACT 를 함께
 *          올린다. 올리지 않으면 이전 버전이 새 형식의 릴리스를 자동으로 설치하다 실패한다.
 */
mod tests {
    use super::manifest;
    use super::record::{Record, State};
    use super::*;
    use crate::cli::{parse_argv, version_line, Command, ServiceAction};
    use ed25519_dalek::{Signer, SigningKey};

    /** @brief 계약 1 의 매니페스트. */
    const MANIFEST: &str = "format = 1
product = \"OnetDNS\"
version = \"0.1.0-alpha.6\"

[[asset]]
target = \"x86_64-unknown-linux-musl\"
file = \"OnetDNS-0.1.0-alpha.6-x86_64-unknown-linux-musl\"
size = 11836928
sha256 = \"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0\"

[[asset]]
target = \"x86_64-pc-windows-msvc\"
file = \"OnetDNS-0.1.0-alpha.6-x86_64-pc-windows-msvc.exe\"
size = 9437184
sha256 = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"
";

    /** @brief 계약 1 의 업데이트 기록. */
    const RECORD: &str = "format=1
state=reverted
from=0.1.0-alpha.5
to=0.1.0-alpha.6
from_sha256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
to_sha256=0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
reason=The new version did not become ready before the trial deadline
";

    /** @brief 문자열 인수 목록. */
    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    /** @brief 계약 1 의 매니페스트와 서명 방식. 원문 바이트에 대한 Ed25519 서명 64바이트다. */
    fn manifest_fixture_opens() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let signature = key.sign(MANIFEST.as_bytes()).to_bytes();
        assert_eq!(signature.len(), 64);
        let opened = manifest::open(
            MANIFEST.as_bytes(),
            &signature,
            &[key.verifying_key()],
            "0.1.0-alpha.6",
        )
        .expect("계약 1 의 매니페스트");
        assert_eq!(opened.assets.len(), 2);
        assert_eq!(
            hex(&opened
                .asset_for("x86_64-unknown-linux-musl")
                .expect("Linux 자산")
                .sha256),
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
        );
        assert_eq!(manifest::MANIFEST_FILE, "OnetDNS-release.toml");
        assert_eq!(manifest::SIGNATURE_FILE, "OnetDNS-release.toml.sig");
        assert_eq!(
            manifest::asset_file_name("1.2.3", "aarch64-unknown-linux-musl"),
            "OnetDNS-1.2.3-aarch64-unknown-linux-musl"
        );
        assert_eq!(
            manifest::asset_file_name("1.2.3", "x86_64-pc-windows-msvc"),
            "OnetDNS-1.2.3-x86_64-pc-windows-msvc.exe"
        );
    }

    #[test]
    /** @brief 계약 1 의 기록. 읽은 것을 다시 쓰면 글자 하나 다르지 않아야 한다. */
    fn record_fixture_round_trips() {
        let record = Record::parse(RECORD).expect("계약 1 의 기록");
        assert_eq!(record.state, State::Reverted);
        assert_eq!(record.from, "0.1.0-alpha.5");
        assert_eq!(record.to, "0.1.0-alpha.6");
        assert_eq!(record.encode(), RECORD);
    }

    #[test]
    /** @brief 사전 점검이 맞대는 --version 출력. */
    fn version_line_is_product_and_version() {
        assert_eq!(version_line("0.1.0-alpha.6"), "OnetDNS 0.1.0-alpha.6");
    }

    #[test]
    /**
     * @brief 이전 버전이 만든 명령줄을 새 버전이 읽는지.
     * @details 이전 감독자는 자기 인수 그대로 새 바이너리를 띄우고, 서비스 등록도 이전 버전이 만든
     *          명령줄을 쓴다. 새 버전이 이 인수를 읽지 못하면 기록을 보기 전에 끝나 시험 실행이
     *          돌지 않는다. 사전 점검의 설정 검사 명령도 여기 든다.
     */
    fn server_start_command_lines_parse() {
        let Ok(Command::Run {
            config,
            no_web,
            no_supervisor,
        }) = parse_argv(&argv(&[
            "run",
            "--config",
            "/etc/onetdns.toml",
            "--no-web",
            "--no-supervisor",
        ]))
        else {
            panic!("감독자가 자식을 띄우는 명령줄");
        };
        assert_eq!(
            config.as_deref(),
            Some(std::path::Path::new("/etc/onetdns.toml"))
        );
        assert!(no_web && no_supervisor);

        assert!(matches!(
            parse_argv(&argv(&["run", "--config", "/etc/onetdns.toml"])),
            Ok(Command::Run {
                no_web: false,
                no_supervisor: false,
                ..
            })
        ));
        assert!(matches!(
            parse_argv(&argv(&["--config", "/etc/onetdns.toml"])),
            Ok(Command::Run { .. })
        ));
        assert!(matches!(parse_argv(&[]), Ok(Command::Run { .. })));

        let service = parse_argv(&argv(&[
            "service",
            "run",
            "--config",
            "C:\\OnetDNS\\OnetDNS.toml",
        ]));
        #[cfg(windows)]
        assert!(matches!(
            service,
            Ok(Command::Service {
                action: ServiceAction::Run { config: Some(_) }
            })
        ));
        #[cfg(not(windows))]
        assert!(matches!(
            service,
            Ok(Command::Service {
                action: ServiceAction::Run {}
            })
        ));

        assert!(matches!(
            parse_argv(&argv(&["--cli", "check", "--config", "/etc/onetdns.toml"])),
            Ok(Command::Check { config: Some(_) })
        ));
    }

    #[test]
    /**
     * @brief 릴리스 워크플로가 매니페스트의 format 에 이 계약 번호를 적는지.
     * @details 워크플로는 UPDATE_CONTRACT 값을 format 으로 쓴다. CONTRACT 만 올리고 이 값을 두면
     *          형식이 바뀐 릴리스가 옛 번호를 달고 나가, 이전 버전이 그 릴리스를 자동으로 설치하다
     *          실패한다.
     */
    fn release_workflow_writes_this_contract_number() {
        let declared: Vec<&str> = include_str!("../../../.github/workflows/release.yml")
            .lines()
            .filter_map(|line| line.trim().strip_prefix("UPDATE_CONTRACT:"))
            .map(str::trim)
            .collect();
        assert_eq!(declared, [CONTRACT.to_string()]);
    }
}
