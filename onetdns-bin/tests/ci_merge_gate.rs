//! Every CI job that must block a merge is in merge-gate's needs. The main ruleset requires only
//! merge-gate, which passes when all its needs succeed, so a job left out can fail without blocking
//! a merge.
//!
//! A job with a job-level if cannot go in needs: a skipped result is not success, so merge-gate
//! would always fail on runs that skip that job.

const CI_YML: &str = include_str!("../../.github/workflows/ci.yml");

const GATE: &str = "merge-gate";

/// Each job under jobs, with its lines. Jobs are indented two spaces and job keys four; only this
/// file's layout is read.
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

/// Empty for a block-valued key.
fn value<'a>(body: &[&'a str], key: &str) -> Option<&'a str> {
    let prefix = format!("    {key}:");
    body.iter()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::trim)
}

/// Reads both block and inline lists.
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
/// A new job left out of needs could fail without blocking a merge.
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
/// The ruleset names the required check by job name, so a rename leaves every PR waiting for a
/// result that never comes. Without if: always(), merge-gate is skipped when an earlier job fails,
/// and GitHub counts a skipped required check as passed.
fn merge_gate_keeps_its_name_and_always_runs() {
    let jobs = jobs(CI_YML);
    let (_, gate) = jobs
        .iter()
        .find(|(id, _)| *id == GATE)
        .expect("merge-gate 작업을 찾지 못했습니다");
    assert_eq!(value(gate, "name"), Some("merge gate"));
    assert_eq!(value(gate, "if"), Some("always()"));
}
