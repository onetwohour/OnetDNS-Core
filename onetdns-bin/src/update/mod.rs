//! Self-update: checks for releases, verifies the binary against a signed manifest, swaps it at the
//! install path, and trial-runs the new version to confirm or roll back.
//! docs/architecture/self-update.md owns the design.

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

/// The format of manifests and update records.
///
/// Bump it when any of these change: the manifest format, the signature scheme, asset naming, the
/// record format, replacement file names, the --version output and check exit codes, or the server
/// start command line. Older versions do not install a release with another number automatically,
/// so that release takes one manual step.
pub(crate) const CONTRACT: u32 = 1;

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Asset key, set only by the release workflow. Without it the binary takes no part in updates, so
/// a custom build with chosen features is never replaced by an official one.
pub(crate) const RELEASE_TARGET: Option<&str> = option_env!("ONETDNS_RELEASE_TARGET");

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Lowercase only, so each value has one spelling and comparing record and manifest text compares
/// values.
pub(crate) fn decode_sha256(text: &str) -> Option<[u8; 32]> {
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
/// Pins the update contract. An older version downloads, checks, and launches the newer one, and
/// the newer one reads the older one's records, so these shapes bind two versions.
///
/// If this breaks, the contract changed: update the fixtures and bump CONTRACT with them, or older
/// versions will fail installing the new format automatically.
mod tests {
    use super::manifest;
    use super::record::{Record, State};
    use super::*;
    use crate::cli::{parse_argv, version_line, Command, ServiceAction};
    use ed25519_dalek::{Signer, SigningKey};

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

    const RECORD: &str = "format=1
state=reverted
from=0.1.0-alpha.5
to=0.1.0-alpha.6
from_sha256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
to_sha256=0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
reason=The new version did not become ready before the trial deadline
";

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    /// A 64-byte Ed25519 signature over the raw bytes.
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
    /// Writing back what was read must be byte-identical.
    fn record_fixture_round_trips() {
        let record = Record::parse(RECORD).expect("계약 1 의 기록");
        assert_eq!(record.state, State::Reverted);
        assert_eq!(record.from, "0.1.0-alpha.5");
        assert_eq!(record.to, "0.1.0-alpha.6");
        assert_eq!(record.encode(), RECORD);
    }

    #[test]
    /// The --version output the preflight compares.
    fn version_line_is_product_and_version() {
        assert_eq!(version_line("0.1.0-alpha.6"), "OnetDNS 0.1.0-alpha.6");
    }

    #[test]
    /// An older supervisor launches the new binary with its own arguments, and the service
    /// registration uses the older version's command line; if the new version cannot parse them, it
    /// exits before reading the record and the trial never runs. The preflight's config check
    /// command is included.
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
    /// The workflow writes UPDATE_CONTRACT as format. Bumping only CONTRACT would ship a changed
    /// format under the old number, and older versions would fail installing it automatically.
    fn release_workflow_writes_this_contract_number() {
        let declared: Vec<&str> = include_str!("../../../.github/workflows/release.yml")
            .lines()
            .filter_map(|line| line.trim().strip_prefix("UPDATE_CONTRACT:"))
            .map(str::trim)
            .collect();
        assert_eq!(declared, [CONTRACT.to_string()]);
    }
}
