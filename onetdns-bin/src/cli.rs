//! Parses command-line arguments into the command to run.

use std::path::PathBuf;

use crate::PRODUCT_NAME;

pub(crate) enum Command {
    Run {
        config: Option<PathBuf>,
        no_web: bool,
        no_supervisor: bool,
    },
    Query {
        name: String,
        qtype: Option<String>,
    },
    Cert {
        host: String,
        cert_out: PathBuf,
        key_out: PathBuf,
    },
    Stats {
        ctl: CtlArgs,
    },
    Reload {
        ctl: CtlArgs,
    },
    Block {
        domain: String,
        ctl: CtlArgs,
    },
    Allow {
        domain: String,
        ctl: CtlArgs,
    },
    Service {
        action: ServiceAction,
    },
    Check {
        config: Option<PathBuf>,
    },
    Top {
        ctl: CtlArgs,
    },
    Services,
    Passwd {
        name: Option<String>,
    },
    Update {
        action: UpdateAction,
        /// The server's config: resolves names and checks the new version against it.
        config: Option<PathBuf>,
    },
}

pub(crate) enum UpdateAction {
    Check,
    Apply {
        /// When given, installs only if the new release is this version.
        version: Option<String>,
    },
    /// Reinstalls the version the last update replaced.
    Rollback,
}

pub(crate) enum ServiceAction {
    Install {
        /// Pinned into the service definition.
        config: Option<PathBuf>,
    },
    Uninstall,
    Run {
        #[cfg(windows)]
        config: Option<PathBuf>,
    },
}

#[derive(Default)]
pub(crate) struct CtlArgs {
    pub(crate) config: Option<PathBuf>,
    pub(crate) url: Option<String>,
    pub(crate) token: Option<String>,
}

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
  service    install registers OnetDNS to start at boot: a Windows service, a
             systemd unit, or a launchd daemon. Windows asks for administrator
             rights. Linux and macOS need sudo and --config. run is for the
             Windows service manager only.
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

const CTL_FLAGS: &[&str] = &["--config", "--url", "--token"];

/// Every long flag each command accepts. Unknown flags are rejected: a mistyped `query` option
/// would otherwise pass the default upstream's answer off as this server's.
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

/// Commands missing from `COMMAND_FLAGS`, such as help and version, are not checked.
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

/// Accepts both `--flag=value` and `--flag value`.
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

fn opt_path(args: &[String], flag: &str) -> Option<PathBuf> {
    opt_val(args, flag).map(PathBuf::from)
}

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

fn positional(args: &[String]) -> Option<String> {
    positionals(args).into_iter().next()
}

fn ctl_args(args: &[String]) -> CtlArgs {
    CtlArgs {
        config: opt_path(args, "--config"),
        url: opt_val(args, "--url"),
        token: opt_val(args, "--token"),
    }
}

pub(crate) fn parse_args() -> Result<Command, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    parse_argv(&argv)
}

/// The update preflight compares a new executable's output with this line.
pub(crate) fn version_line(version: &str) -> String {
    format!("{PRODUCT_NAME} {version}")
}

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
mod tests {
    use super::*;

    #[test]
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
    // Help and `COMMAND_FLAGS` must agree, or typing what the help says gets an error.
    fn every_documented_option_is_accepted() {
        // Selects a subcommand, so no command's list holds it.
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
    fn update_forms_parse() {
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
