/*!
 * @brief 명령줄 인자를 읽어 실행할 명령으로 바꾼다.
 */

use std::path::PathBuf;

use crate::PRODUCT_NAME;

/** @brief 실행할 명령. */
pub(crate) enum Command {
    /** @brief 서버로 시작한다. */
    Run {
        /** @brief 쓸 설정 파일. */
        config: Option<PathBuf>,
        /** @brief 대시보드를 시작하지 않는다. */
        no_web: bool,
        /** @brief 프로세스 감독 없이 곧장 돈다. */
        no_supervisor: bool,
    },
    /** @brief 이름 하나를 물어본다. */
    Query { name: String, qtype: Option<String> },
    /** @brief 자체 서명 인증서를 만든다. */
    Cert {
        /** @brief 인증서에 적을 이름. */
        host: String,
        /** @brief 인증서를 쓸 곳. */
        cert_out: PathBuf,
        /** @brief 키를 쓸 곳. */
        key_out: PathBuf,
    },
    /** @brief 지표를 본다. */
    Stats { ctl: CtlArgs },
    /** @brief 설정을 다시 읽게 한다. */
    Reload { ctl: CtlArgs },
    /** @brief 차단 목록에 넣는다. */
    Block { domain: String, ctl: CtlArgs },
    /** @brief 허용 목록에 넣는다. */
    Allow { domain: String, ctl: CtlArgs },
    /** @brief 서비스로 등록하거나 제거한다. */
    Service { action: ServiceAction },
    /** @brief 설정만 검사한다. */
    Check { config: Option<PathBuf> },
    /** @brief 많이 물은 이름을 본다. */
    Top { ctl: CtlArgs },
    /** @brief 차단할 수 있는 서비스 목록을 본다. */
    Services,
    /** @brief 대시보드 로그인에 쓸 암호 해시를 만든다. */
    Passwd { name: Option<String> },
    /** @brief 새 릴리스를 확인하고, 시키면 설치 경로의 실행 파일을 맞바꾼다. */
    Update {
        /** @brief 할 일. */
        action: UpdateAction,
        /** @brief 서버가 쓰는 설정 파일. 이름 해석과 새 버전의 설정 검사에 쓴다. */
        config: Option<PathBuf>,
    },
}

/** @brief update 명령이 할 일. */
pub(crate) enum UpdateAction {
    /** @brief 새 릴리스를 확인만 한다. */
    Check,
    /** @brief 새 릴리스를 설치한다. */
    Apply {
        /** @brief 설치할 버전. 주면 확인한 새 버전이 이것일 때만 설치한다. */
        version: Option<String>,
    },
    /** @brief 확정된 업데이트를 되돌려 바꾸기 전 버전을 다시 설치한다. */
    Rollback,
}

/** @brief 서비스 관련 동작. */
pub(crate) enum ServiceAction {
    /** @brief 서비스로 등록한다. */
    Install {
        #[cfg(windows)]
        /** @brief 서비스로 등록할 때 고정해 둘 설정 파일. */
        config: Option<PathBuf>,
    },
    /** @brief 등록한 서비스를 지운다. */
    Uninstall,
    /** @brief 서비스로 돈다. */
    Run {
        #[cfg(windows)]
        /** @brief 서비스로 돌 때 쓸 설정 파일. */
        config: Option<PathBuf>,
    },
}

#[derive(Default)]
/** @brief 컨트롤 플레인에 붙을 때 쓰는 인수. */
pub(crate) struct CtlArgs {
    /** @brief 설정 파일 경로. */
    pub(crate) config: Option<PathBuf>,
    /** @brief 컨트롤 플레인 주소. */
    pub(crate) url: Option<String>,
    /** @brief 컨트롤 플레인 토큰. */
    pub(crate) token: Option<String>,
}

/** @brief 사용법 안내. */
const HELP: &str = "\
OnetDNS: ad-blocking DNS resolver

Usage:
  OnetDNS [--config PATH] [--no-web] [--no-supervisor]
                                      # Default: start the DNS server and web dashboard (127.0.0.1:8553)
  OnetDNS --cli <command> [...]       # Run a management command (below)
  OnetDNS run [--config PATH] [--no-web]   # Same as the default, stated explicitly

Management commands (require --cli):
  OnetDNS --cli query NAME [--type TYPE]
  OnetDNS --cli cert --host HOST [--cert-out PATH] [--key-out PATH]
  OnetDNS --cli stats|reload|top [--config PATH] [--url URL] [--token TOKEN]
  OnetDNS --cli block DOMAIN [ctl options]
  OnetDNS --cli allow DOMAIN [ctl options]
  OnetDNS --cli check [--config PATH]
  OnetDNS --cli services
  OnetDNS --cli passwd [--name NAME]  # Create a web console [[users]] entry (prompts for the password)
  OnetDNS --cli update [apply [VERSION] | rollback] [--config PATH]
  OnetDNS service install|uninstall|run [--config PATH]

Notes:
  query      Asks the configured upstream directly, not the running server.
             It skips access control, filters, and the cache, so the answer can
             differ from what the server would return.
  --no-web   Start only the DNS server, without the default web dashboard (headless).
             A control_listen setting in the config always takes precedence.
  --no-supervisor  Run the server directly without Linux process self-recovery
                   (for an external supervisor).
  update     Checks GitHub for a newer release signed by the OnetDNS release key.
             apply installs it and rollback reinstalls the version the last
             update replaced. Restart OnetDNS afterwards to start the installed
             version. Pass the --config the server uses so the new version
             checks that configuration before it is installed.
";

/** @brief 뒤에 값을 하나 받는 플래그들. */
const VALUE_FLAGS: &[&str] = &[
    "--config",
    "--url",
    "--token",
    "--type",
    "--host",
    "--cert-out",
    "--key-out",
    "--name",
];

/** @brief 관리 명령이 쓰는 접속 플래그. */
const CTL_FLAGS: &[&str] = &["--config", "--url", "--token"];

/**
 * @brief 명령마다 받는 긴 플래그의 전부.
 *
 * @details 목록에 없는 플래그를 조용히 흘리면 진단이 거짓이 된다. query 에 서버를
 *          지정했다고 믿는 운영자는 사실 기본 업스트림이 돌려준 답을 자기 서버의
 *          답으로 읽게 된다. 오타 하나가 자신 있게 틀린 답으로 바뀌므로, 모르는
 *          플래그는 무시하지 않고 거부한다.
 * @invariant 새 플래그를 붙이는 사람은 여기에도 적어야 한다. 빠뜨리면 그 플래그가
 *            거부되므로 빠뜨린 사실이 첫 실행에서 드러난다.
 */
const COMMAND_FLAGS: &[(&str, &[&str])] = &[
    ("run", &["--config", "--no-web", "--no-supervisor"]),
    ("query", &["--type"]),
    ("cert", &["--host", "--cert-out", "--key-out"]),
    ("stats", CTL_FLAGS),
    ("reload", CTL_FLAGS),
    ("top", CTL_FLAGS),
    ("block", CTL_FLAGS),
    ("allow", CTL_FLAGS),
    ("check", &["--config"]),
    ("services", &[]),
    ("passwd", &["--name"]),
    ("service", &["--config"]),
    ("update", &["--config"]),
];

/**
 * @brief 이 명령이 모르는 긴 플래그가 있으면 거부한다.
 * @note 목록에 없는 명령은 검사하지 않는다. 도움말과 판본 표시가 그렇다.
 * @param sub 하위 명령 이름.
 * @param rest 하위 명령 뒤에 남은 인수 전부.
 * @return 모르는 플래그를 만나면 그 이름을 담은 오류.
 */
fn reject_unknown_flags(sub: &str, rest: &[String]) -> Result<(), String> {
    let Some((_, allowed)) = COMMAND_FLAGS.iter().find(|(name, _)| *name == sub) else {
        return Ok(());
    };
    for arg in rest {
        let Some(body) = arg.strip_prefix("--") else {
            continue;
        };
        let name = body.split('=').next().unwrap_or(body);
        if name.is_empty() {
            continue;
        }
        let flag = format!("--{name}");
        if !allowed.contains(&flag.as_str()) {
            return Err(format!("{sub}: unknown option {flag} (see OnetDNS help)"));
        }
    }
    Ok(())
}

/** @brief 이 플래그의 값. 붙여 쓴 형태와 띄어 쓴 형태를 모두 받는다. */
fn opt_val(args: &[String], flag: &str) -> Option<String> {
    let pref = format!("{flag}=");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&pref) {
            return Some(v.to_string());
        }
    }
    None
}

/** @brief 이 플래그의 값을 경로로. */
fn opt_path(args: &[String], flag: &str) -> Option<PathBuf> {
    opt_val(args, flag).map(PathBuf::from)
}

/** @brief 플래그와 그 값을 뺀 인수들. 순서는 그대로다. */
fn positionals(args: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with("--") && a.contains('=') {
            i += 1;
        } else if VALUE_FLAGS.contains(&a.as_str()) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            found.push(a.clone());
            i += 1;
        }
    }
    found
}

/** @brief 플래그가 아닌 첫 인수. */
fn positional(args: &[String]) -> Option<String> {
    positionals(args).into_iter().next()
}

/** @brief 컨트롤 플레인 인수를 모은다. */
fn ctl_args(args: &[String]) -> CtlArgs {
    CtlArgs {
        config: opt_path(args, "--config"),
        url: opt_val(args, "--url"),
        token: opt_val(args, "--token"),
    }
}

/** @brief 실행 인수를 읽는다. */
pub(crate) fn parse_args() -> Result<Command, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    parse_argv(&argv)
}

/**
 * @brief --version 이 출력하는 한 줄.
 * @note 업데이트 사전 점검이 새 실행 파일의 출력을 이 모양과 맞댄다. 바꾸면 업데이트 계약이 바뀐다.
 */
pub(crate) fn version_line(version: &str) -> String {
    format!("{PRODUCT_NAME} {version}")
}

/** @brief 인수 목록을 명령으로. */
pub(crate) fn parse_argv(argv: &[String]) -> Result<Command, String> {
    if argv.first().map(String::as_str) == Some("--cli") {
        let sub = argv
            .get(1)
            .cloned()
            .ok_or("--cli: a subcommand is required (see OnetDNS --cli help)")?;
        return parse_subcommand(&sub, &argv[2..]);
    }

    let Some(first) = argv.first().map(String::as_str) else {
        return Ok(Command::Run {
            config: None,
            no_web: false,
            no_supervisor: false,
        });
    };

    if matches!(
        first,
        "-h" | "--help" | "help" | "-V" | "--version" | "version" | "run" | "service"
    ) {
        return parse_subcommand(first, &argv[1..]);
    }

    if first.starts_with('-') {
        reject_unknown_flags("run", argv)?;
        return Ok(Command::Run {
            config: opt_path(argv, "--config"),
            no_web: argv.iter().any(|a| a == "--no-web"),
            no_supervisor: argv.iter().any(|a| a == "--no-supervisor"),
        });
    }

    Err(format!("Unknown command: {first} (see OnetDNS help)"))
}

/**
 * @brief 하위 명령을 읽는다.
 * @warning 관리 명령은 앞에 표시가 있어야 받는다. 없이 받으면 서버로 시작하려던 것이
 *          엉뚱한 관리 명령으로 실행된다.
 */
fn parse_subcommand(sub: &str, rest: &[String]) -> Result<Command, String> {
    reject_unknown_flags(sub, rest)?;
    match sub {
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            std::process::exit(0);
        }
        "-V" | "--version" | "version" => {
            println!("{}", version_line(crate::update::VERSION));
            std::process::exit(0);
        }
        "run" => Ok(Command::Run {
            config: opt_path(rest, "--config"),
            no_web: rest.iter().any(|a| a == "--no-web"),
            no_supervisor: rest.iter().any(|a| a == "--no-supervisor"),
        }),
        "query" => Ok(Command::Query {
            name: positional(rest).ok_or("query needs a domain to look up")?,
            qtype: opt_val(rest, "--type"),
        }),
        "cert" => Ok(Command::Cert {
            host: opt_val(rest, "--host").ok_or("cert needs the --host option")?,
            cert_out: opt_path(rest, "--cert-out").unwrap_or_else(|| "cert.pem".into()),
            key_out: opt_path(rest, "--key-out").unwrap_or_else(|| "key.pem".into()),
        }),
        "stats" => Ok(Command::Stats {
            ctl: ctl_args(rest),
        }),
        "reload" => Ok(Command::Reload {
            ctl: ctl_args(rest),
        }),
        "top" => Ok(Command::Top {
            ctl: ctl_args(rest),
        }),
        "block" => Ok(Command::Block {
            domain: positional(rest).ok_or("block needs a domain to block")?,
            ctl: ctl_args(rest),
        }),
        "allow" => Ok(Command::Allow {
            domain: positional(rest).ok_or("allow needs a domain to allow")?,
            ctl: ctl_args(rest),
        }),
        "check" => Ok(Command::Check {
            config: opt_path(rest, "--config"),
        }),
        "services" => Ok(Command::Services),
        "passwd" => {
            if positional(rest).is_some() {
                return Err(
                    "passwd: a plaintext password argument is not allowed; type it at the prompt or pipe it through standard input"
                        .into(),
                );
            }
            Ok(Command::Passwd {
                name: opt_val(rest, "--name"),
            })
        }
        "service" => {
            let action = match rest.first().map(|s| s.as_str()) {
                Some("install") => ServiceAction::Install {
                    #[cfg(windows)]
                    config: opt_path(rest, "--config"),
                },
                Some("uninstall") => ServiceAction::Uninstall,
                Some("run") => ServiceAction::Run {
                    #[cfg(windows)]
                    config: opt_path(rest, "--config"),
                },
                _ => return Err("service needs one of install, uninstall, or run".into()),
            };
            Ok(Command::Service { action })
        }
        "update" => {
            let words = positionals(rest);
            let action = match words.iter().map(String::as_str).collect::<Vec<_>>()[..] {
                [] => UpdateAction::Check,
                ["apply"] => UpdateAction::Apply { version: None },
                ["apply", version] => UpdateAction::Apply {
                    version: Some(version.to_string()),
                },
                ["rollback"] => UpdateAction::Rollback,
                _ => return Err("update takes nothing, apply [VERSION], or rollback".into()),
            };
            Ok(Command::Update {
                action,
                config: opt_path(rest, "--config"),
            })
        }
        other => Err(format!("Unknown command: {other} (see OnetDNS help)")),
    }
}

#[cfg(test)]
/** @brief 명령줄 인자 해석과 잘못된 인자의 거부. */
mod tests {
    use super::*;

    #[test]
    /** @brief 관리 명령이 표시 없이 실행되지 않는지. 서버로 시작하려던 것이 엉뚱한 명령이 되면 안 된다. */
    fn management_commands_require_cli_prefix() {
        for command in [
            "query", "cert", "stats", "reload", "top", "block", "allow", "check", "services",
            "passwd", "update",
        ] {
            assert!(parse_argv(&[command.to_string()]).is_err(), "{command}");
        }
        assert!(matches!(
            parse_argv(&[
                "--cli".to_string(),
                "query".to_string(),
                "example.test".to_string()
            ]),
            Ok(Command::Query { .. })
        ));
    }

    #[test]
    /**
     * @brief 도움말이 안내하는 옵션을 전부 받는지.
     *
     * @details 도움말과 COMMAND_FLAGS 가 따로 놀면, 안내를 보고 그대로 친 운영자가
     *          알 수 없는 옵션이라는 말을 듣는다. 주석은 부탁일 뿐이므로 여기서 판정한다.
     */
    fn every_documented_option_is_accepted() {
        // 하위 명령을 고르는 표시라서 명령별 목록에 들어갈 슬롯이 없다.
        const NOT_A_COMMAND_FLAG: &[&str] = &["--cli"];
        let accepted: Vec<&str> = COMMAND_FLAGS
            .iter()
            .flat_map(|(_, flags)| flags.iter().copied())
            .chain(NOT_A_COMMAND_FLAG.iter().copied())
            .collect();

        let mut documented: Vec<String> = Vec::new();
        let mut rest = HELP;
        while let Some(at) = rest.find("--") {
            rest = &rest[at..];
            let end = rest
                .find(|c: char| !(c.is_ascii_lowercase() || c == '-'))
                .unwrap_or(rest.len());
            let (flag, tail) = rest.split_at(end);
            rest = tail;
            if flag.len() > 2 && !documented.iter().any(|seen| seen == flag) {
                documented.push(flag.to_string());
            }
        }
        assert!(
            documented.len() > 5,
            "도움말에서 옵션을 읽어내지 못했습니다: {documented:?}"
        );

        for flag in &documented {
            assert!(
                accepted.contains(&flag.as_str()),
                "도움말은 {flag} 를 안내하는데 어느 명령도 받지 않습니다"
            );
        }
    }

    #[test]
    /** @brief update 의 세 가지 형태를 읽고, 그 밖의 인수는 받지 않는지. */
    fn update_forms_parse() {
        /** @brief --cli update 뒤에 이 인수들을 붙여 읽는다. */
        fn parse(args: &[&str]) -> Result<Command, String> {
            let mut argv = vec!["--cli".to_string(), "update".to_string()];
            argv.extend(args.iter().map(|arg| (*arg).to_string()));
            parse_argv(&argv)
        }

        assert!(matches!(
            parse(&[]),
            Ok(Command::Update {
                action: UpdateAction::Check,
                config: None
            })
        ));
        let Ok(Command::Update {
            action: UpdateAction::Apply { version },
            config,
        }) = parse(&["apply", "0.2.0-beta.1", "--config", "/etc/onetdns.toml"])
        else {
            panic!("버전을 준 apply");
        };
        assert_eq!(version.as_deref(), Some("0.2.0-beta.1"));
        assert_eq!(
            config.as_deref(),
            Some(std::path::Path::new("/etc/onetdns.toml"))
        );
        assert!(matches!(
            parse(&["--config=/etc/onetdns.toml", "apply"]),
            Ok(Command::Update {
                action: UpdateAction::Apply { version: None },
                config: Some(_)
            })
        ));
        assert!(matches!(
            parse(&["rollback"]),
            Ok(Command::Update {
                action: UpdateAction::Rollback,
                ..
            })
        ));
        for wrong in [
            &["install"][..],
            &["apply", "1.0.0", "2.0.0"],
            &["rollback", "1.0.0"],
            &["apply", "--version", "1.0.0"],
        ] {
            assert!(parse(wrong).is_err(), "{wrong:?}");
        }
    }

    #[test]
    /** @brief 모르는 옵션이 조용히 무시되지 않는지. 무시되면 진단이 자신 있게 틀린다. */
    fn unknown_options_are_rejected_instead_of_ignored() {
        let unknown = parse_argv(&[
            "--cli".to_string(),
            "query".to_string(),
            "example.test".to_string(),
            "--server".to_string(),
            "127.0.0.1:15353".to_string(),
        ]);
        let Err(message) = unknown else {
            panic!("모르는 옵션은 거부되어야 합니다");
        };
        assert!(
            message.contains("--server"),
            "어느 옵션이 문제인지 알려야 합니다: {message}"
        );

        assert!(
            parse_argv(&["--no-wbe".to_string()]).is_err(),
            "서버로 시작하는 길에서도 오타를 잡아야 합니다"
        );

        assert!(
            matches!(
                parse_argv(&[
                    "--cli".to_string(),
                    "query".to_string(),
                    "example.test".to_string(),
                    "--type=AAAA".to_string(),
                ]),
                Ok(Command::Query { .. })
            ),
            "아는 옵션은 붙여 쓴 형태도 받아야 합니다"
        );

        assert!(
            matches!(
                parse_argv(&["--no-web".to_string(), "--no-supervisor".to_string()]),
                Ok(Command::Run { .. })
            ),
            "아는 옵션만 주면 서버로 떠야 합니다"
        );
    }
}
