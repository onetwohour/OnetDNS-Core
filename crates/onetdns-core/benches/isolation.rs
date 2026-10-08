use std::hint::black_box;
use std::time::{Duration, Instant};

/** @brief 반복 횟수. */
fn iterations() -> u64 {
    std::env::var("ONETDNS_ISOLATION_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20_000_000)
}

#[inline(never)]
/** @brief 측정하는 동안 돌릴 계산 한 걸음. */
fn step(state: u64) -> u64 {
    state.wrapping_mul(6364136223846793005).wrapping_add(1)
}

/** @brief 가두지 않고 그냥 실행하는 비용. */
fn plain(iterations: u64) -> (u64, Duration) {
    let start = Instant::now();
    let mut state = black_box(1u64);
    let operation: fn(u64) -> u64 = black_box(step);
    for _ in 0..iterations {
        state = black_box(operation(state));
    }
    (state, start.elapsed())
}

/** @brief 패닉을 가두는 경계 안에서 실행하는 비용. */
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

/** @brief 라운드 수. 두 구성을 교차로 재려면 여러 번 돌아야 한다. */
fn rounds() -> usize {
    std::env::var("ONETDNS_ISOLATION_BENCH_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(6)
}

/** @brief 표본의 중앙값과 산포. 산포는 (max-min)/median이다. */
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

/**
 * @brief 경계가 붙는 비용을 측정한다.
 *
 * @details 두 구성을 순서대로 한 번씩 측정하면 그 사이의 호스트 드리프트가 전부
 *          "오버헤드"로 잡힌다. 라운드마다 순서를 뒤집어 교차로 재고 중앙값으로
 *          판정한다. 산포가 마진보다 크면 그 회차는 아무것도 말하지 않는다.
 */
fn main() {
    let count = iterations().max(1);
    let round_count = rounds().max(2);
    let mut plain_samples = Vec::with_capacity(round_count);
    let mut isolated_samples = Vec::with_capacity(round_count);
    let mut expected = None;

    /*
     * 첫 회차는 버린다. 두 구성 다 콜드 상태로 실행되는 라운드가 표본에 섞이면 그 회차 하나가
     * 산포를 지배한다.
     */
    black_box(plain(count));
    black_box(isolated(count));

    for round in 0..round_count {
        /*
         * 뒤집는 것은 실행 순서뿐이다. 묶는 곳은 라운드와 무관하게 고정이어야
         * 표본이 섞이지 않는다. else 가지의 튜플 순서를 "고치면" 두 표본이 뒤바뀐다.
         */
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
    /* 다른 하네스와 같은 5% 게이트다. 넘으면 이 구간에서 나온 값은 인용하지 않는다. */
    let verdict = if plain_drift.max(isolated_drift) > 5.0 {
        "  ← 5% 게이트 초과: 이 구간의 값은 인용 금지"
    } else {
        ""
    };
    println!(
        "request boundary: iterations={count} rounds={round_count} plain={plain_ns:.3} ns (drift {plain_drift:.2}%) isolated={isolated_ns:.3} ns (drift {isolated_drift:.2}%) overhead={overhead:.3} ns{verdict}"
    );
}
