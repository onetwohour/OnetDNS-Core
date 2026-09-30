/*!
 * @brief 운영체제 보안 난수원.
 *
 * @details 키 재료·논스·DNS 트랜잭션 ID·포트 무작위화가 전부 여기서 나온다. 사용자 공간
 *          의사난수 생성기를 두지 않는다. 예측 가능한 트랜잭션 ID는 캐시 오염 공격의
 *          출발점이다.
 */

/**
 * @brief 버퍼를 보안 난수로 채운다.
 * @warning 난수원 실패 시 패닉한다. 난수 없이 계속 진행하면 예측 가능한 값으로
 *          암호 연산을 하게 되므로, 조용히 약한 값을 쓰느니 멈추는 쪽을 택한다.
 */
pub fn fill_random(buf: &mut [u8]) {
    try_fill_random(buf).expect("The OS secure random source is unavailable");
}

/** @brief 실패를 오류로 돌려주는 fill_random. 시작 시 난수원 가용성 확인에 쓴다. */
pub fn try_fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        try_fill_windows(buf)
    }
    #[cfg(not(windows))]
    {
        try_fill_urandom(buf)
    }
}

/** @brief 고정 길이 난수 배열. 실패 시 패닉한다. */
pub fn random_array<const N: usize>() -> [u8; N] {
    try_random_array().expect("The OS secure random source is unavailable")
}

/** @brief 실패를 오류로 돌려주는 random_array. */
pub fn try_random_array<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut a = [0u8; N];
    try_fill_random(&mut a)?;
    Ok(a)
}

/** @brief 스레드별 난수 선인출 버퍼 크기. 시스템 호출 한 번에 이만큼을 미리 받는다. */
const EPHEMERAL_RANDOM_BUFFER_LEN: usize = 1_024;

/**
 * @brief 스레드 로컬 난수 선인출 버퍼.
 *
 * @details 질의 하나가 트랜잭션 ID 2바이트와 0x20 대소문자 인코딩용 바이트를 필요로 한다.
 *          그때마다 시스템 호출을 하면 해석당 비용이 붙으므로, 한 번에 크게 받아 나눠 쓴다.
 * @warning 수명이 짧고 노출돼도 무해한 값 전용이다. 키 재료는 반드시 fill_random을 쓴다.
 *          버퍼에 남은 바이트는 이후 다른 요청 처리에서 재사용될 메모리에 머문다.
 */
struct EphemeralRandomBuffer {
    /** @brief 미리 받아 둔 난수. */
    bytes: [u8; EPHEMERAL_RANDOM_BUFFER_LEN],
    /** @brief 어디까지 꺼내 썼는지. */
    cursor: usize,
}

impl EphemeralRandomBuffer {
    /** @brief 소진 상태로 시작한다. 첫 사용 시 채워진다. */
    const fn empty() -> Self {
        Self {
            bytes: [0; EPHEMERAL_RANDOM_BUFFER_LEN],
            cursor: EPHEMERAL_RANDOM_BUFFER_LEN,
        }
    }
}

thread_local! {
    /**
     * @brief 스레드마다 미리 받아 둔 난수 뭉치.
     * @details 자주 쓰는 짧은 난수를 매번 시스템에 물으면 그것이 비용이다.
     * @note 한꺼번에 받아 두고 꺼내 쓴다.
     */
    static EPHEMERAL_RANDOM: std::cell::RefCell<EphemeralRandomBuffer> =
        const { std::cell::RefCell::new(EphemeralRandomBuffer::empty()) };
    #[cfg(test)]
    /** @brief 뭉치를 다시 채운 횟수. 테스트용. */
    static EPHEMERAL_RANDOM_REFILLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/**
 * @brief 선인출 버퍼에서 난수를 꺼낸다. 수명이 짧은 값 전용이다.
 * @param out 버퍼 크기를 넘으면 나누지 않고 곧장 운영체제에서 채운다.
 * @warning 키·논스 등 장기 비밀에는 쓰지 않는다. fill_random을 쓴다.
 */
pub fn fill_ephemeral_random(out: &mut [u8]) {
    if out.is_empty() {
        return;
    }
    if out.len() > EPHEMERAL_RANDOM_BUFFER_LEN {
        fill_random(out);
        return;
    }
    EPHEMERAL_RANDOM.with(|slot| {
        let mut state = slot.borrow_mut();
        if state.bytes.len() - state.cursor < out.len() {
            fill_random(&mut state.bytes);
            state.cursor = 0;
            #[cfg(test)]
            EPHEMERAL_RANDOM_REFILLS.with(|count| count.set(count.get() + 1));
        }
        let end = state.cursor + out.len();
        out.copy_from_slice(&state.bytes[state.cursor..end]);
        state.cursor = end;
    });
}

/** @brief 선인출 버퍼에서 추출한 고정 길이 배열. 수명이 짧은 값 전용이다. */
pub fn ephemeral_random_array<const N: usize>() -> [u8; N] {
    let mut out = [0; N];
    fill_ephemeral_random(&mut out);
    out
}

/**
 * @brief Windows 난수원. 시스템 선호 RNG를 직접 호출한다.
 * @details 알고리즘 핸들을 열지 않고 플래그로 시스템 기본을 쓴다. 상태를 가지고 있지 않아
 *          초기화 실패 경로가 없다.
 * @safety 호출마다 chunk의 유효한 포인터와 그 길이를 넘긴다. 길이는 u32 범위로
 *         쪼개져 있어 인자 폭을 넘지 않는다.
 */
#[cfg(windows)]
fn try_fill_windows(buf: &mut [u8]) -> std::io::Result<()> {
    #[link(name = "bcrypt")]
    extern "system" {
        /** @brief 시스템 난수를 받는다. */
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }
    /** @brief 시스템이 정한 난수원을 쓴다. */
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    if buf.is_empty() {
        return Ok(());
    }

    for chunk in buf.chunks_mut(u32::MAX as usize) {
        let rc = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::other(format!(
                "BCryptGenRandom failed (NTSTATUS {rc:#x})"
            )));
        }
    }
    Ok(())
}

/**
 * @brief 유닉스 난수원. /dev/urandom을 한 번 열어 재사용한다.
 * @note 매번 열면 요청당 파일 디스크립터 비용이 붙고, fd 고갈 상황에서 난수원을 잃는다.
 */
#[cfg(not(windows))]
fn try_fill_urandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    use std::sync::OnceLock;

    /** @brief 난수원 파일. 한 번만 열어 둔다. */
    static URANDOM: OnceLock<std::fs::File> = OnceLock::new();
    if URANDOM.get().is_none() {
        let file = std::fs::File::open("/dev/urandom")?;
        let _ = URANDOM.set(file);
    }
    let mut file = URANDOM
        .get()
        .ok_or_else(|| std::io::Error::other("Could not initialize the OS random device"))?;
    file.read_exact(buf)
}

#[cfg(test)]
/** @brief 난수가 채워지고 서로 다른지, 그리고 뭉치가 제때 다시 차는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 부른 만큼 채워지고 값이 매번 다른지. */
    fn fills_and_varies() {
        let a: [u8; 32] = random_array();
        let b: [u8; 32] = random_array();

        assert_ne!(a, b);

        assert!(a.iter().any(|&x| x != 0));
        assert!(try_random_array::<32>().is_ok());
    }

    #[test]
    /** @brief 꺼낸 값이 서로 다르고, 뭉치가 한꺼번에 다시 차는지. */
    fn ephemeral_random_is_distinct_and_refills_in_chunks() {
        EPHEMERAL_RANDOM.with(|slot| *slot.borrow_mut() = EphemeralRandomBuffer::empty());
        EPHEMERAL_RANDOM_REFILLS.with(|count| count.set(0));

        let first = ephemeral_random_array::<32>();
        let second = ephemeral_random_array::<32>();
        assert_ne!(first, second);
        assert!(first.iter().any(|byte| *byte != 0));

        for _ in 0..100 {
            let _ = ephemeral_random_array::<2>();
        }
        assert_eq!(EPHEMERAL_RANDOM_REFILLS.with(std::cell::Cell::get), 1);
    }

    #[test]
    #[ignore = "마이크로벤치: cargo test -p onetdns-core --release bench_ephemeral_random -- --ignored --nocapture"]
    /** @brief 미리 받아 둔 난수를 꺼내는 비용. */
    fn bench_ephemeral_random() {
        /** @brief 반복 횟수. */
        const ITERATIONS: usize = 200_000;

        let started = std::time::Instant::now();
        let mut direct_sink = 0u8;
        for _ in 0..ITERATIONS {
            let case = random_array::<32>();
            let id = random_array::<2>();
            direct_sink ^= case[0] ^ id[0];
        }
        let direct = started.elapsed();

        let started = std::time::Instant::now();
        let mut buffered_sink = 0u8;
        for _ in 0..ITERATIONS {
            let case = ephemeral_random_array::<32>();
            let id = ephemeral_random_array::<2>();
            buffered_sink ^= case[0] ^ id[0];
        }
        let buffered = started.elapsed();
        std::hint::black_box((direct_sink, buffered_sink));

        println!(
            "DNS entropy pair: direct={:.1} ns buffered={:.1} ns speedup={:.2}x",
            direct.as_nanos() as f64 / ITERATIONS as f64,
            buffered.as_nanos() as f64 / ITERATIONS as f64,
            direct.as_secs_f64() / buffered.as_secs_f64()
        );
    }
}
