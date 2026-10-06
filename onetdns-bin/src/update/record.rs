/*!
 * @brief 업데이트 기록과 서버가 시작할 때의 판정.
 *
 * @details 기록은 이 노드의 업데이트가 어디까지 왔는지 정하는 유일한 상태다. 한 줄에
 *          key=value 하나씩 쓴다. 계약 형식과 조금이라도 다른 기록은 오래된 기록으로 보고
 *          지운다. 이전 버전이 쓴 기록을 새 버전이 읽으므로 형식은 업데이트 계약에 든다.
 */

use super::{decode_sha256, hex, version::Version, CONTRACT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 업데이트가 어디까지 왔는지. */
pub(crate) enum State {
    /** @brief 기록을 썼고 맞바꾸는 중이거나 맞바꾼 뒤 기동을 기다린다. */
    Pending,
    /** @brief 새 버전이 시험 실행 중이다. */
    Trial,
    /** @brief 새 버전이 준비 상태에 이르러 확정됐다. */
    Committed,
    /** @brief 시험이 실패해 이전 버전으로 되돌렸다. */
    Reverted,
}

impl State {
    /** @brief 기록과 상태 응답에 쓰는 이름. */
    pub(crate) fn name(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Trial => "trial",
            State::Committed => "committed",
            State::Reverted => "reverted",
        }
    }

    /** @brief 기록에 쓴 이름을 읽는다. */
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
/** @brief 업데이트 기록 하나. */
pub(crate) struct Record {
    /** @brief 지금 단계. */
    pub(crate) state: State,
    /** @brief 바꾸기 전 버전. */
    pub(crate) from: String,
    /** @brief 바꾼 뒤 버전. */
    pub(crate) to: String,
    /** @brief 바꾸기 전 실행 파일의 SHA-256. */
    pub(crate) from_sha256: [u8; 32],
    /** @brief 바꾼 뒤 실행 파일의 SHA-256. */
    pub(crate) to_sha256: [u8; 32],
    /** @brief 되돌린 이유. reverted 에만 있고 한 줄이다. */
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/** @brief 서버가 시작할 때 기록을 보고 고르는 처리. */
pub(crate) enum StartupAction {
    /** @brief trial 로 바꾸고 시험 실행으로 시작한다. */
    StartTrial,
    /** @brief 맞바꾸기는 끝났고 기동만 남았다. 기록에 손대지 않는다. */
    AwaitActivation,
    /** @brief 앞선 시험이 확정도 되돌림도 없이 끝났다. 되돌린다. */
    Revert,
    /** @brief 확정된 업데이트다. 되돌리기에 쓸 정보로 남겨 둔다. */
    Keep,
    /** @brief 되돌린 업데이트다. 이유를 알리고 남겨 둔다. */
    ReportReverted,
    /** @brief 지금 실행 파일과 맞지 않는 오래된 기록이다. 지운다. */
    Discard,
}

/** @brief 기록에 넣을 수 있는 버전인지. */
fn version_field(value: &str) -> Option<String> {
    Version::parse(value).map(|_| value.to_string())
}

impl Record {
    /**
     * @brief 기록을 읽는다.
     * @return 계약 형식이 아니면 없다. 모르는 키, 겹친 키, 빠진 키, 다른 계약 번호, reverted 가
     *         아닌데 붙은 이유가 모두 여기에 든다. 호출자는 그런 기록을 지운다.
     */
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

    /** @brief 기록 파일에 쓸 글. 이유의 줄바꿈은 공백으로 바꾼다. */
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

    /**
     * @brief 서버가 시작할 때 이 기록으로 무엇을 할지 고른다.
     * @param own_version 지금 시작하는 바이너리의 버전.
     * @param installed 설치 경로에 있는 실행 파일의 SHA-256.
     * @details 버전만 보지 않고 설치 경로의 해시까지 맞대는 이유는 기록과 실제 파일이 갈라지는
     *          경우가 있기 때문이다. 맞바꾸기 전에 죽었거나 운영자가 손으로 파일을 바꿨으면 버전이
     *          맞아도 기록은 이미 지난 것이다.
     */
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
/** @brief 기록 형식과 시작 판정표. */
mod tests {
    use super::*;

    /** @brief 바꾸기 전 실행 파일의 해시. */
    const OLD: [u8; 32] = [0x11; 32];
    /** @brief 바꾼 뒤 실행 파일의 해시. */
    const NEW: [u8; 32] = [0x22; 32];
    /** @brief 어느 쪽도 아닌 실행 파일의 해시. */
    const OTHER: [u8; 32] = [0x33; 32];

    /** @brief 이 단계의 기록. */
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
    /** @brief 쓴 기록을 다시 읽으면 같은 기록인지. */
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
    /** @brief 계약 형식과 조금이라도 다른 기록은 읽지 않는지. 호출자는 그런 기록을 지운다. */
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
    /** @brief 판정표의 각 줄. 버전이나 해시가 하나라도 어긋나면 오래된 기록이다. */
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
    /**
     * @brief 적용의 각 단계 사이에서 죽었을 때 다음 시작이 고르는 처리.
     * @details 기록은 맞바꾸기 전에 쓴다. 그래서 맞바꾸기 전에 죽으면 이전 실행 파일이 그대로라
     *          기록만 지우고, 맞바꾼 뒤 기동 전에 죽으면 새 버전이 시험 실행으로 시작한다. 시험
     *          중에 죽으면 다시 뜬 새 버전이 되돌린다.
     */
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
