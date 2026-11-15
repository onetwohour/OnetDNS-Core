//! The OS secure random source. Key material, nonces, DNS transaction IDs, and port randomization
//! all come from here; there is no user-space PRNG, since predictable transaction IDs are where
//! cache poisoning starts.

/// Panics if the source fails: continuing would run crypto on predictable values, so stopping beats
/// silently using weak ones.
pub fn fill_random(buf: &mut [u8]) {
    try_fill_random(buf).expect("The OS secure random source is unavailable");
}

/// For checking the source at startup.
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

/// Panics on failure.
pub fn random_array<const N: usize>() -> [u8; N] {
    try_random_array().expect("The OS secure random source is unavailable")
}

pub fn try_random_array<const N: usize>() -> std::io::Result<[u8; N]> {
    let mut a = [0u8; N];
    try_fill_random(&mut a)?;
    Ok(a)
}

/// Bytes fetched per system call.
const EPHEMERAL_RANDOM_BUFFER_LEN: usize = 1_024;

/// Per-thread prefetch. Each query needs 2 bytes of transaction ID plus bytes for 0x20 case
/// randomization; a system call each time adds cost per resolution, so bytes are fetched in bulk
/// and handed out.
///
/// Only for short-lived values that are harmless if exposed: unused bytes stay in memory later
/// reused for other requests. Key material must use fill_random.
struct EphemeralRandomBuffer {
    bytes: [u8; EPHEMERAL_RANDOM_BUFFER_LEN],
    cursor: usize,
}

impl EphemeralRandomBuffer {
    const fn empty() -> Self {
        Self {
            bytes: [0; EPHEMERAL_RANDOM_BUFFER_LEN],
            cursor: EPHEMERAL_RANDOM_BUFFER_LEN,
        }
    }
}

thread_local! {
    static EPHEMERAL_RANDOM: std::cell::RefCell<EphemeralRandomBuffer> =
        const { std::cell::RefCell::new(EphemeralRandomBuffer::empty()) };
    #[cfg(test)]
    /// Refill count, for tests.
    static EPHEMERAL_RANDOM_REFILLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Short-lived values only; keys and nonces use fill_random. Requests larger than the buffer are
/// filled straight from the OS.
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

/// Short-lived values only.
pub fn ephemeral_random_array<const N: usize>() -> [u8; N] {
    let mut out = [0; N];
    fill_ephemeral_random(&mut out);
    out
}

/// Calls the system-preferred RNG through a flag instead of opening an algorithm handle, so there
/// is no initialization to fail.
#[cfg(windows)]
fn try_fill_windows(buf: &mut [u8]) -> std::io::Result<()> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut core::ffi::c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    if buf.is_empty() {
        return Ok(());
    }

    for chunk in buf.chunks_mut(u32::MAX as usize) {
        // SAFETY: each call passes chunk's pointer and length; chunks_mut keeps every length within
        // u32.
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

/// Opens /dev/urandom once and reuses it; opening per call costs a descriptor each time and loses
/// the source when descriptors run out.
#[cfg(not(windows))]
fn try_fill_urandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    use std::sync::OnceLock;

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
mod tests {
    use super::*;

    #[test]
    fn fills_and_varies() {
        let a: [u8; 32] = random_array();
        let b: [u8; 32] = random_array();

        assert_ne!(a, b);

        assert!(a.iter().any(|&x| x != 0));
        assert!(try_random_array::<32>().is_ok());
    }

    #[test]
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
    fn bench_ephemeral_random() {
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
