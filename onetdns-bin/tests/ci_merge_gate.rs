/*!
 * @brief 병합을 막아야 하는 CI 작업이 모두 merge gate 에 묶여 있는지 확인한다.
 *
 * @details main 의 룰셋은 merge gate 작업 하나만 필수 검사로 요구한다. merge gate 는 needs 로
 *          묶은 작업이 모두 성공해야 통과하므로, needs 에서 빠진 작업은 실패해도 병합을 막지
 *          못한다. 작업 단위 if 로 일부 실행에서만 도는 작업은 반대로 needs 에 넣을 수 없다.
 *          건너뛴 결과가 성공이 아니어서 그 작업이 돌지 않는 push 와 PR 에서 merge gate 가 늘
 *          실패한다.
 */

/** @brief 검사할 워크플로. */
const CI_YML: &str = include_str!("../../.github/workflows/ci.yml");

/** @brief merge gate 작업의 식별자. */
const GATE: &str = "merge-gate";

/**
 * @brief jobs 아래의 작업마다 식별자와 그 작업에 속한 줄들.
 * @details 워크플로는 작업을 두 칸, 작업의 키를 네 칸 들여 쓴다. 이 파일의 형식만 읽는다.
 */
fn jobs(text: &str) -> Vec<(&str, Vec<&str>)> {
    let mut jobs: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line == "jobs:" {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
            break;
        }
        let id = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with([' ', '#']))
            .and_then(|rest| rest.strip_suffix(':'));
        match (id, jobs.last_mut()) {
            (Some(id), _) => jobs.push((id, Vec::new())),
            (None, Some((_, body))) => body.push(line),
            (None, None) => {}
        }
    }
    jobs
}

/** @brief 작업의 키 하나에 적힌 값. 블록으로 적은 키는 빈 문자열이다. */
fn value<'a>(body: &[&'a str], key: &str) -> Option<&'a str> {
    let prefix = format!("    {key}:");
    body.iter()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::trim)
}

/** @brief 작업의 needs 목록. 블록 목록과 한 줄 목록을 모두 읽는다. */
fn needs<'a>(body: &[&'a str]) -> Vec<&'a str> {
    match value(body, "needs") {
        None => Vec::new(),
        Some("") => {
            let start = body
                .iter()
                .position(|line| *line == "    needs:")
                .expect("needs 줄을 찾지 못했습니다");
            body[start + 1..]
                .iter()
                .map_while(|line| line.strip_prefix("      - "))
                .map(str::trim)
                .collect()
        }
        Some(inline) => inline
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(str::trim)
            .filter(|need| !need.is_empty())
            .collect(),
    }
}

#[test]
/**
 * @brief merge gate 가 작업 단위 if 가 없는 작업을 모두 needs 로 묶는지.
 * @details 작업을 새로 더하면서 needs 에 넣지 않으면 그 작업은 실패해도 병합을 막지 못한다.
 */
fn merge_gate_needs_every_unconditional_job() {
    let jobs = jobs(CI_YML);
    let (_, gate) = jobs
        .iter()
        .find(|(id, _)| *id == GATE)
        .expect("merge-gate 작업을 찾지 못했습니다");
    let mut required: Vec<&str> = jobs
        .iter()
        .filter(|(id, body)| *id != GATE && value(body, "if").is_none())
        .map(|(id, _)| *id)
        .collect();
    let mut declared = needs(gate);
    assert!(
        required.len() > 1,
        "작업을 거의 찾지 못했습니다: {required:?}"
    );
    required.sort_unstable();
    declared.sort_unstable();
    assert_eq!(
        declared, required,
        "merge gate 의 needs 가 작업 단위 if 가 없는 작업 목록과 다릅니다. 빠진 작업은 실패해도 \
         병합을 막지 못하고, 조건부 작업을 넣으면 그 작업이 돌지 않는 실행에서 merge gate 가 \
         늘 실패합니다."
    );
}

#[test]
/**
 * @brief merge gate 의 이름과 실행 조건이 그대로인지.
 * @details 룰셋은 작업 이름으로 필수 검사를 가리키므로, 이름이 바뀌면 모든 PR 이 오지 않을
 *          검사 결과를 기다린다. if: always() 가 없으면 앞선 작업이 실패했을 때 merge gate 를
 *          건너뛰는데, GitHub 은 건너뛴 필수 검사를 통과로 친다.
 */
fn merge_gate_keeps_its_name_and_always_runs() {
    let jobs = jobs(CI_YML);
    let (_, gate) = jobs
        .iter()
        .find(|(id, _)| *id == GATE)
        .expect("merge-gate 작업을 찾지 못했습니다");
    assert_eq!(value(gate, "name"), Some("merge gate"));
    assert_eq!(value(gate, "if"), Some("always()"));
}
