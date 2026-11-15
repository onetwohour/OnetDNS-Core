use std::hint::black_box;
use std::time::{Duration, Instant};

fn iterations() -> u64 {
    std::env::var("ONETDNS_ISOLATION_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20_000_000)
}

#[inline(never)]
fn step(state: u64) -> u64 {
    state.wrapping_mul(6364136223846793005).wrapping_add(1)
}

fn plain(iterations: u64) -> (u64, Duration) {
    let start = Instant::now();
    let mut state = black_box(1u64);
    let operation: fn(u64) -> u64 = black_box(step);
    for _ in 0..iterations {
        state = black_box(operation(state));
    }
    (state, start.elapsed())
}

fn isolated(iterations: u64) -> (u64, Duration) {
    let start = Instant::now();
    let mut state = black_box(1u64);
    let operation: fn(u64) -> u64 = black_box(step);
    for _ in 0..iterations {
        onetdns_core::isolation::catch_request(|| {
            state = black_box(operation(state));
        })
        .unwrap();
    }
    (state, start.elapsed())
}

/// Alternating the two setups takes several rounds.
fn rounds() -> usize {
    std::env::var("ONETDNS_ISOLATION_BENCH_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(6)
}

/// Drift is (max - min) / median.
fn median_and_drift(samples: &mut [f64]) -> (f64, f64) {
    samples.sort_by(|left, right| left.partial_cmp(right).expect("측정값은 NaN이 아니다"));
    let middle = samples.len() / 2;
    let median = if samples.len() % 2 == 1 {
        samples[middle]
    } else {
        (samples[middle - 1] + samples[middle]) / 2.0
    };
    let drift = if median > 0.0 {
        (samples[samples.len() - 1] - samples[0]) * 100.0 / median
    } else {
        100.0
    };
    (median, drift)
}

/// Measures the boundary's cost. Measuring each setup once in sequence would count host drift in
/// between as overhead, so rounds alternate the order and the median decides. A round with drift
/// above the margin says nothing.
fn main() {
    let count = iterations().max(1);
    let round_count = rounds().max(2);
    let mut plain_samples = Vec::with_capacity(round_count);
    let mut isolated_samples = Vec::with_capacity(round_count);
    let mut expected = None;

    // The first round is discarded: a round with both setups cold would dominate the drift.
    black_box(plain(count));
    black_box(isolated(count));

    for round in 0..round_count {
        // Only execution order flips; the binding stays fixed regardless of round, or the samples
        // would swap. Do not "fix" the tuple order in the else branch.
        let (plain_run, isolated_run) = if round % 2 == 0 {
            let plain_run = plain(count);
            (plain_run, isolated(count))
        } else {
            let isolated_run = isolated(count);
            (plain(count), isolated_run)
        };
        let (plain_value, plain_time) = plain_run;
        let (isolated_value, isolated_time) = isolated_run;
        assert_eq!(plain_value, isolated_value);
        let baseline = *expected.get_or_insert(plain_value);
        assert_eq!(baseline, plain_value);
        plain_samples.push(plain_time.as_secs_f64() * 1e9 / count as f64);
        isolated_samples.push(isolated_time.as_secs_f64() * 1e9 / count as f64);
    }

    let (plain_ns, plain_drift) = median_and_drift(&mut plain_samples);
    let (isolated_ns, isolated_drift) = median_and_drift(&mut isolated_samples);
    let overhead = isolated_ns - plain_ns;
    // The same 5% gate as the other harnesses; values from a window above it are not quoted.
    let verdict = if plain_drift.max(isolated_drift) > 5.0 {
        "  ← 5% 게이트 초과: 이 구간의 값은 인용 금지"
    } else {
        ""
    };
    println!(
        "request boundary: iterations={count} rounds={round_count} plain={plain_ns:.3} ns (drift {plain_drift:.2}%) isolated={isolated_ns:.3} ns (drift {isolated_drift:.2}%) overhead={overhead:.3} ns{verdict}"
    );
}
