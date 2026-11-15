use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::hint::black_box;
use std::io::{Seek, SeekFrom, Write as IoWrite};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use onetdns_core::{BlockResponse, ClientInfo, FilterEngine, Transport};
use onetdns_filter::{
    build_from_str, decode_engine_cache, encode_engine_cache, write_engine_cache, BlockEngine,
    EngineParts,
};
use onetdns_proto::{Name, RecordType};

/// Counts live bytes and their peak.
struct TrackingAllocator;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn add_allocation(bytes: usize) {
    let current = CURRENT.fetch_add(bytes, Ordering::Relaxed) + bytes;
    let mut peak = PEAK.load(Ordering::Relaxed);
    while current > peak {
        match PEAK.compare_exchange_weak(peak, current, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

// SAFETY: only counts; every allocation is passed to the system allocator.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            add_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            add_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    /// When the block moved, the old and new buffers are both live during the copy. Counting that
    /// overlap is what shows the peaks of a doubling container; counting only the growth would make
    /// the peak always equal what is held. Growing in place has no overlap, so only the difference
    /// counts.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if new_pointer.is_null() {
            return new_pointer;
        }
        if new_pointer == pointer {
            if new_size >= layout.size() {
                add_allocation(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        } else {
            add_allocation(new_size);
            CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// To check that what was stored matches.
fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x1000_0000_01b3)
    })
}

#[derive(Default)]
struct CountingWriter {
    position: u64,
    len: u64,
}

impl IoWrite for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.position = self
            .position
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| std::io::Error::other("counting writer position overflow"))?;
        self.len = self.len.max(self.position);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for CountingWriter {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(offset) => i128::from(self.len) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        self.position = u64::try_from(next)
            .map_err(|_| std::io::Error::other("counting writer seek out of range"))?;
        Ok(self.position)
    }
}

/// Memory and stored size by rule count.
fn main() {
    let rule_count = std::env::var("ONETDNS_DOMAIN_BENCH_RULES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2_400_000);
    let track_hits = std::env::var_os("ONETDNS_DOMAIN_BENCH_HITS").is_some();
    let source_count = std::env::var("ONETDNS_DOMAIN_BENCH_SOURCES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    if std::env::var_os("ONETDNS_DOMAIN_BENCH_CACHE").is_some() {
        cache_benchmark(rule_count, source_count, baseline);
        return;
    }

    let mut rules = String::with_capacity(rule_count.saturating_mul(32));
    for index in 0..rule_count {
        writeln!(
            rules,
            "||ad{index}.tenant{}.tracking.example^",
            index % 4093
        )
        .expect("String 쓰기는 실패하지 않음");
    }

    let build_started = Instant::now();
    let engine = build_from_str(&rules, "", BlockResponse::NxDomain).with_hit_tracking(track_hits);
    let build_elapsed = build_started.elapsed();
    drop(rules);

    let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(baseline);
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    println!(
        "domain-memory({rule_count} rules, hits={track_hits}): retained={:.1} MiB packed={:.1} MiB peak={:.1} MiB build={build_elapsed:?}",
        mib(retained),
        mib(engine.domain_storage_bytes()),
        mib(peak)
    );

    benchmark_lookup(&engine, rule_count);
    black_box(engine);
}

fn benchmark_lookup(engine: &BlockEngine, rule_count: usize) {
    let client = ClientInfo {
        source_ip: "192.0.2.1".parse().expect("고정 IP"),
        client_id: None,
        transport: Transport::Do53Udp,
        authenticated: false,
    };
    let last = rule_count.saturating_sub(1);
    let names = [
        Name::from_str(&format!("ad{last}.tenant{}.tracking.example", last % 4093))
            .expect("고정 이름"),
        Name::from_str("safe.example.net").expect("고정 이름"),
    ];
    let iterations = 1_000_000usize;
    let run = |count: usize| {
        let query_started = Instant::now();
        for index in 0..count {
            black_box(engine.verdict(
                black_box(&names[index & 1]),
                RecordType::A,
                black_box(&client),
            ));
        }
        query_started.elapsed().as_nanos()
    };
    black_box(run(100_000));
    let mut samples = [0u128; 5];
    for sample in &mut samples {
        *sample = run(iterations);
    }
    samples.sort_unstable();
    println!(
        "domain-memory lookup: median={:.1} best={:.1} ns/query (5 samples)",
        samples[samples.len() / 2] as f64 / iterations as f64,
        samples[0] as f64 / iterations as f64
    );
}

fn cache_benchmark(rule_count: usize, source_count: usize, baseline: usize) {
    let mut parts = EngineParts::default();
    let wide_dawg = std::env::var_os("ONETDNS_DOMAIN_BENCH_WIDE").is_some();
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let tlds = ["com", "net", "org", "io", "ru", "cn", "info"];
    let mut lookup_domain = String::new();
    let input_started = Instant::now();
    for index in 0..rule_count {
        let domain = if wide_dawg {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let value = seed;
            let len = 5 + (value % 9) as usize;
            let mut label = String::with_capacity(len + 5);
            let mut bits = value.rotate_left(29);
            for _ in 0..len {
                label.push((b'a' + (bits % 26) as u8) as char);
                bits /= 26;
                if bits == 0 {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    bits = seed;
                }
            }
            format!("{label}.{}", tlds[(value >> 32) as usize % tlds.len()])
        } else {
            format!("ad{index}.tenant{}.tracking.example", index % 4093)
        };
        if index + 1 == rule_count {
            lookup_domain.clone_from(&domain);
        }
        if source_count == 0 {
            parts.block.add_suffix(&domain);
        } else {
            parts
                .block
                .add_suffix_src(&domain, (index % source_count) as u32);
        }
    }
    let input_elapsed = input_started.elapsed();
    let input_retained = CURRENT.load(Ordering::Relaxed).saturating_sub(baseline);
    let input_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);

    if std::env::var_os("ONETDNS_DOMAIN_BENCH_STREAM").is_some() {
        let stream_baseline = CURRENT.load(Ordering::Relaxed);
        PEAK.store(stream_baseline, Ordering::Relaxed);
        let stream_started = Instant::now();
        let mut output = CountingWriter::default();
        write_engine_cache(&mut parts, [0x5a; 32], &mut output).expect("stream cache encode");
        let stream_elapsed = stream_started.elapsed();
        let stream_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        let stream_extra_peak = PEAK.load(Ordering::Relaxed).saturating_sub(stream_baseline);
        let engine = BlockEngine::new(parts, BlockResponse::NxDomain);
        let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(baseline);
        println!(
            "domain-stream({rule_count} rules, sources={source_count}, wide={wide_dawg}): input={input_elapsed:?} stream={stream_elapsed:?} file={:.1} MiB input_retained={:.1} MiB input_peak={:.1} MiB stream_peak={:.1} MiB stream_extra_peak={:.1} MiB retained={:.1} MiB packed={:.1} MiB",
            mib(output.len as usize),
            mib(input_retained),
            mib(input_peak),
            mib(stream_peak),
            mib(stream_extra_peak),
            mib(retained),
            mib(engine.domain_storage_bytes())
        );
        benchmark_lookup(&engine, rule_count);
        black_box(engine);
        return;
    }

    if std::env::var_os("ONETDNS_DOMAIN_BENCH_FINALIZE").is_some() {
        let finalize_baseline = CURRENT.load(Ordering::Relaxed);
        PEAK.store(finalize_baseline, Ordering::Relaxed);
        let finalize_started = Instant::now();
        let engine = BlockEngine::new(parts, BlockResponse::NxDomain);
        let finalize_elapsed = finalize_started.elapsed();
        let finalize_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        let finalize_extra_peak = PEAK
            .load(Ordering::Relaxed)
            .saturating_sub(finalize_baseline);
        let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(baseline);
        println!(
            "domain-finalize({rule_count} rules, sources={source_count}, wide={wide_dawg}): input={input_elapsed:?} finalize={finalize_elapsed:?} input_retained={:.1} MiB input_peak={:.1} MiB finalize_peak={:.1} MiB finalize_extra_peak={:.1} MiB retained={:.1} MiB packed={:.1} MiB",
            mib(input_retained),
            mib(input_peak),
            mib(finalize_peak),
            mib(finalize_extra_peak),
            mib(retained),
            mib(engine.domain_storage_bytes())
        );
        benchmark_lookup(&engine, rule_count);
        black_box(engine);
        return;
    }

    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);

    let encode_started = Instant::now();
    let encoded = encode_engine_cache(&mut parts, [0x5a; 32]).expect("cache encode");
    let encode_elapsed = encode_started.elapsed();
    let encode_peak = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    let encoded_len = encoded.len();
    let encoded_checksum = checksum(&encoded);
    drop(parts);

    let cache_baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(cache_baseline, Ordering::Relaxed);
    let decode_started = Instant::now();
    let restored = decode_engine_cache(&encoded, [0x5a; 32]).expect("cache decode");
    let decode_elapsed = decode_started.elapsed();
    let decode_peak = PEAK.load(Ordering::Relaxed).saturating_sub(cache_baseline);
    drop(encoded);

    let engine = BlockEngine::new(restored, BlockResponse::NxDomain);
    let retained = CURRENT.load(Ordering::Relaxed).saturating_sub(baseline);
    println!(
        "domain-cache({rule_count} rules, sources={source_count}, wide={wide_dawg}): input={input_elapsed:?} encode={encode_elapsed:?} decode={decode_elapsed:?} file={:.1} MiB checksum={encoded_checksum:016x} input_retained={:.1} MiB input_peak={:.1} MiB encode_peak={:.1} MiB decode_extra_peak={:.1} MiB retained={:.1} MiB packed={:.1} MiB",
        mib(encoded_len),
        mib(input_retained),
        mib(input_peak),
        mib(encode_peak),
        mib(decode_peak),
        mib(retained),
        mib(engine.domain_storage_bytes())
    );

    let name = Name::from_str(&lookup_domain).expect("마지막 생성 이름");
    let client = ClientInfo {
        source_ip: "192.0.2.1".parse().expect("고정 IP"),
        client_id: None,
        transport: Transport::Do53Udp,
        authenticated: false,
    };
    assert!(matches!(
        engine.verdict(&name, RecordType::A, &client),
        onetdns_core::FilterVerdict::Block(_)
    ));
    black_box(engine);
}
