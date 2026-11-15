//! Update records and the startup decision. The record is the only state saying how far this node's
//! update has come: one key=value per line. A record that differs from the contract format in any
//! way is stale and removed. A new version reads records an older one wrote, so the format is part
//! of the update contract.

use super::{decode_sha256, hex, version::Version, CONTRACT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// Record written; swapping, or swapped and waiting to start.
    Pending,
    /// The new version is on trial.
    Trial,
    /// The new version got ready and was committed.
    Committed,
    /// The trial failed and the previous version was restored.
    Reverted,
}

impl State {
    pub(crate) fn name(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Trial => "trial",
            State::Committed => "committed",
            State::Reverted => "reverted",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [
            State::Pending,
            State::Trial,
            State::Committed,
            State::Reverted,
        ]
        .into_iter()
        .find(|state| state.name() == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) state: State,
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) from_sha256: [u8; 32],
    pub(crate) to_sha256: [u8; 32],
    /// Only on reverted records; one line.
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupAction {
    /// Mark the record trial and start a trial run.
    StartTrial,
    /// Swapped; only the start remains. The record is left alone.
    AwaitActivation,
    /// An earlier trial ended with neither commit nor revert; revert it.
    Revert,
    /// A committed update, kept for rollback.
    Keep,
    /// A reverted update; report the reason and keep it.
    ReportReverted,
    /// A stale record that does not match the current executable; remove it.
    Discard,
}

fn version_field(value: &str) -> Option<String> {
    Version::parse(value).map(|_| value.to_string())
}

impl Record {
    /// None outside the contract format: an unknown, repeated, or missing key, another contract
    /// number, or a reason on a record that is not reverted. The caller removes such records.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut format = None;
        let mut state = None;
        let mut from = None;
        let mut to = None;
        let mut from_sha256 = None;
        let mut to_sha256 = None;
        let mut reason = None;
        for line in text.lines() {
            let (key, value) = line.split_once('=')?;
            let slot_filled = match key {
                "format" => format.replace(value.parse::<u32>().ok()?).is_some(),
                "state" => state.replace(State::from_name(value)?).is_some(),
                "from" => from.replace(version_field(value)?).is_some(),
                "to" => to.replace(version_field(value)?).is_some(),
                "from_sha256" => from_sha256.replace(decode_sha256(value)?).is_some(),
                "to_sha256" => to_sha256.replace(decode_sha256(value)?).is_some(),
                "reason" if !value.is_empty() => reason.replace(value.to_string()).is_some(),
                _ => return None,
            };
            if slot_filled {
                return None;
            }
        }
        if format? != CONTRACT {
            return None;
        }
        let state = state?;
        if (state == State::Reverted) != reason.is_some() {
            return None;
        }
        Some(Self {
            state,
            from: from?,
            to: to?,
            from_sha256: from_sha256?,
            to_sha256: to_sha256?,
            reason,
        })
    }

    /// Newlines in the reason become spaces.
    pub(crate) fn encode(&self) -> String {
        let mut text = format!(
            "format={CONTRACT}\nstate={}\nfrom={}\nto={}\nfrom_sha256={}\nto_sha256={}\n",
            self.state.name(),
            self.from,
            self.to,
            hex(&self.from_sha256),
            hex(&self.to_sha256)
        );
        if let Some(reason) = &self.reason {
            text.push_str("reason=");
            text.push_str(&reason.replace(['\r', '\n'], " "));
            text.push('\n');
        }
        text
    }

    /// `own_version` is the starting binary's version, `installed` the SHA-256 of the executable at
    /// the install path. The hash is compared too because the record and the file can diverge:
    /// after a crash before the swap, or a file replaced by hand, the version can match while the
    /// record is stale.
    pub(crate) fn startup_action(&self, own_version: &str, installed: &[u8; 32]) -> StartupAction {
        let runs_to = own_version == self.to && *installed == self.to_sha256;
        let runs_from_with_to_installed = own_version == self.from && *installed == self.to_sha256;
        let runs_from = own_version == self.from && *installed == self.from_sha256;
        match self.state {
            State::Pending if runs_to => StartupAction::StartTrial,
            State::Pending if runs_from_with_to_installed => StartupAction::AwaitActivation,
            State::Trial if runs_to => StartupAction::Revert,
            State::Committed if runs_to => StartupAction::Keep,
            State::Reverted if runs_from => StartupAction::ReportReverted,
            _ => StartupAction::Discard,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: [u8; 32] = [0x11; 32];
    const NEW: [u8; 32] = [0x22; 32];
    const OTHER: [u8; 32] = [0x33; 32];

    fn record(state: State) -> Record {
        Record {
            state,
            from: "0.1.0-alpha.5".to_string(),
            to: "0.1.0-alpha.6".to_string(),
            from_sha256: OLD,
            to_sha256: NEW,
            reason: (state == State::Reverted).then(|| "not ready within 120 s".to_string()),
        }
    }

    #[test]
    fn records_round_trip() {
        for state in [
            State::Pending,
            State::Trial,
            State::Committed,
            State::Reverted,
        ] {
            let written = record(state);
            assert_eq!(Record::parse(&written.encode()), Some(written));
        }
        let mut multiline = record(State::Reverted);
        multiline.reason = Some("line one\nline two\r\n".to_string());
        let reread = Record::parse(&multiline.encode()).expect("이유가 여러 줄인 기록");
        assert_eq!(reread.reason.as_deref(), Some("line one line two  "));
    }

    #[test]
    fn records_outside_the_contract_are_not_read() {
        let good = record(State::Pending).encode();
        let reverted = record(State::Reverted).encode();
        let cases = [
            ("빈 기록", String::new()),
            ("다른 계약 번호", good.replace("format=1", "format=2")),
            ("계약 번호 없음", good.replace("format=1\n", "")),
            ("모르는 상태", good.replace("state=pending", "state=done")),
            ("모르는 키", format!("{good}extra=1\n")),
            ("겹친 키", format!("{good}state=trial\n")),
            (
                "해시 없음",
                good.lines()
                    .filter(|line| !line.starts_with("to_sha256"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            ("버전이 아님", good.replace("to=0.1.0-alpha.6", "to=latest")),
            (
                "대문자 해시",
                good.replace(&"22".repeat(32), &"AA".repeat(32)),
            ),
            (
                "이유 없는 되돌림",
                reverted
                    .lines()
                    .filter(|line| !line.starts_with("reason"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            ("이유 붙은 대기", format!("{good}reason=x\n")),
            (
                "빈 이유",
                reverted.replace("reason=not ready within 120 s", "reason="),
            ),
            ("등호 없는 줄", format!("{good}garbage\n")),
            ("빈 줄", good.replace("\nstate", "\n\nstate")),
        ];
        for (name, text) in cases {
            assert_eq!(Record::parse(&text), None, "{name}");
        }
    }

    #[test]
    /// Any mismatched version or hash means a stale record.
    fn startup_actions_follow_the_table() {
        let from = "0.1.0-alpha.5";
        let to = "0.1.0-alpha.6";
        let table = [
            (State::Pending, to, NEW, StartupAction::StartTrial),
            (State::Pending, from, NEW, StartupAction::AwaitActivation),
            (State::Trial, to, NEW, StartupAction::Revert),
            (State::Committed, to, NEW, StartupAction::Keep),
            (State::Reverted, from, OLD, StartupAction::ReportReverted),
            (State::Pending, from, OLD, StartupAction::Discard),
            (State::Pending, to, OLD, StartupAction::Discard),
            (State::Trial, from, OLD, StartupAction::Discard),
            (State::Trial, from, NEW, StartupAction::Discard),
            (State::Committed, from, OLD, StartupAction::Discard),
            (State::Committed, to, OTHER, StartupAction::Discard),
            (State::Reverted, to, NEW, StartupAction::Discard),
            (State::Reverted, from, NEW, StartupAction::Discard),
            (State::Pending, "0.1.0-alpha.7", NEW, StartupAction::Discard),
        ];
        for (state, own, installed, expected) in table {
            assert_eq!(
                record(state).startup_action(own, &installed),
                expected,
                "{state:?} own={own} installed={:02x}",
                installed[0]
            );
        }
    }

    #[test]
    /// The record is written before the swap. A crash before the swap leaves the old executable, so
    /// only the record is removed; a crash after the swap but before startup starts the new version
    /// on trial; a crash during the trial makes the restarted new version revert.
    fn crashes_between_steps_resolve_to_a_consistent_state() {
        let pending = record(State::Pending);
        assert_eq!(
            pending.startup_action("0.1.0-alpha.5", &OLD),
            StartupAction::Discard,
            "기록을 쓴 뒤 맞바꾸기 전에 죽음"
        );
        assert_eq!(
            pending.startup_action("0.1.0-alpha.6", &NEW),
            StartupAction::StartTrial,
            "맞바꾼 뒤 기동 전에 죽음"
        );
        assert_eq!(
            record(State::Trial).startup_action("0.1.0-alpha.6", &NEW),
            StartupAction::Revert,
            "확정하기 전에 죽음"
        );
        assert_eq!(
            record(State::Trial).startup_action("0.1.0-alpha.5", &OLD),
            StartupAction::Discard,
            "되돌려 놓고 기록을 고치기 전에 죽음"
        );
    }
}
