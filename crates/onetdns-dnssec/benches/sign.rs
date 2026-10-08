/*!
 * @brief 온라인 서명 비용을 측정한다. 이 축은 지금까지 계량된 적이 없다.
 *
 * @details 서명은 질의마다가 아니라 영역을 로드하거나 DDNS로 고칠 때 영역 전체에
 *          일어난다. 따라서 이 수치가 곧 서명된 영역의 시작 지연·리로드 지연이고,
 *          그 동안 그 영역은 이전 내용으로 답한다.
 * @note 부재 증명 방식(NSEC/NSEC3)마다 따로 측정한다. NSEC3는 이름마다 해시를 돌리므로
 *       비용 구조가 다르다.
 */

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use onetdns_dnssec::sign::{sign_zone_with, DenialMode, Nsec3Params, SignAlgorithm, ZoneSigner};
use onetdns_proto::{Name, RData, Record, Soa};

/** @brief 잡힌 메모리와 최고점을 세는 할당기. */
struct TrackingAllocator;

/** @brief 지금 잡혀 있는 바이트. */
static CURRENT: AtomicUsize = AtomicUsize::new(0);
/** @brief 잡혔던 최고 바이트. */
static PEAK: AtomicUsize = AtomicUsize::new(0);

/** @brief 잡은 만큼 세고 최고점을 갱신한다. */
fn add_allocation(size: usize) {
    let current = CURRENT.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(current, Ordering::Relaxed);
}

/** @safety 세기만 하고 실제 할당은 시스템 할당기에 그대로 넘긴다. */
unsafe impl GlobalAlloc for TrackingAllocator {
    /** @brief 잡고 센다. */
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            add_allocation(layout.size());
        }
        pointer
    }

    /** @brief 비워서 잡고 센다. */
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            add_allocation(layout.size());
        }
        pointer
    }

    /** @brief 돌려주고 뺀다. */
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }

    /** @brief 늘리거나 줄이고 그만큼 센다. */
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, old, new_size) };
        if new_pointer.is_null() {
            return new_pointer;
        }
        if new_pointer == pointer {
            if new_size >= old.size() {
                add_allocation(new_size - old.size());
            } else {
                CURRENT.fetch_sub(old.size() - new_size, Ordering::Relaxed);
            }
        } else {
            add_allocation(new_size);
            CURRENT.fetch_sub(old.size(), Ordering::Relaxed);
        }
        new_pointer
    }
}

#[global_allocator]
/** @brief 이 벤치가 쓰는 할당기. */
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

/** @brief 측정할 때 쓸 영역 기록들. 이름 하나에 A 하나인 평범한 모양이다. */
fn zone_records(origin: &Name, host_count: usize) -> Vec<Record> {
    let origin_text = origin.to_ascii_lower();
    let ns = Name::from_str(&format!("ns.{origin_text}")).unwrap();
    let hostmaster = Name::from_str(&format!("hostmaster.{origin_text}")).unwrap();
    let mut records = Vec::with_capacity(host_count + 3);
    records.push(Record::new(
        origin.clone(),
        300,
        RData::soa(Soa {
            mname: ns.clone(),
            rname: hostmaster,
            serial: 1,
            refresh: 300,
            retry: 60,
            expire: 3600,
            minimum: 60,
        }),
    ));
    records.push(Record::new(origin.clone(), 300, RData::Ns(ns.clone())));
    records.push(Record::new(ns, 300, RData::A(Ipv4Addr::new(192, 0, 2, 53))));
    for index in 0..host_count {
        records.push(Record::new(
            Name::from_str(&format!("host{index}.{origin_text}")).unwrap(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, (index % 250 + 1) as u8)),
        ));
    }
    records
}

/** @brief 최고점을 다시 재기 위해 카운터를 지금 값으로 되돌린다. */
fn reset_peak() {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
}

/** @brief 이번 구간의 추가 최고점(MiB). */
fn peak_mib(baseline: usize) -> f64 {
    PEAK.load(Ordering::Relaxed).saturating_sub(baseline) as f64 / (1024.0 * 1024.0)
}

/** @brief 한 방식으로 영역 하나를 서명하는 데 드는 시간과 추가 최고점. */
fn measure(records: &[Record], signer: &ZoneSigner, mode: &DenialMode) -> (f64, f64, usize) {
    let baseline = CURRENT.load(Ordering::Relaxed);
    reset_peak();
    let started = Instant::now();
    let signed = sign_zone_with(black_box(records), signer, 1_700_000_000, mode);
    let elapsed = started.elapsed().as_secs_f64();
    let peak = peak_mib(baseline);
    let count = signed.len();
    black_box(&signed);
    drop(signed);
    (elapsed, peak, count)
}

/**
 * @brief 서명 한 건의 비용을 곡선 연산과 그 앞단으로 구분한다.
 *
 * @details 대조 엔진보다 느릴 때 고칠 수 있는 곳이 어디인지 정하려는 것이다. 곡선 연산이
 *          지배하면 암호 라이브러리 선택의 문제이고, 앞단이 지배하면 이 서버가 고칠 수 있다.
 */
fn breakdown(signer: &ZoneSigner) {
    let origin = Name::from_str("bench.test").unwrap();
    let rrset = vec![Record::new(
        Name::from_str("host12345.bench.test").unwrap(),
        60,
        RData::A(Ipv4Addr::new(192, 0, 2, 7)),
    )];
    let iterations = 20_000usize;

    let started = Instant::now();
    for _ in 0..iterations {
        black_box(signer.sign_rrset(black_box(&rrset), 1_700_000_000));
    }
    let full = started.elapsed().as_secs_f64() * 1e6 / iterations as f64;

    /* 같은 키로 고정 digest만 서명한다. 앞단(정규 직렬화·SHA-256·레코드 조립)이 빠진 값이다. */
    let curve = signer.bench_raw_sign_us(iterations);
    let _ = &origin;
    println!("sign_rrset_us,{full:.2}");
    println!("raw_ecdsa_us,{curve:.2}");
    println!("prep_us,{:.2}", full - curve);
    /* 알고리즘 15로 바꿀 때 닫히는 폭. 이미 트리에 있는 크레이트라 새 의존성이 없다. */
    println!(
        "raw_ed25519_us,{:.2}",
        ZoneSigner::bench_ed25519_sign_us(iterations)
    );
}

/**
 * @brief 레코드 하나를 고친 뒤 다시 서명하는 값을 측정한다.
 *
 * @details DDNS 갱신과 컨트롤 플레인 편집이 실제로 하는 일이다. 전부 다시 서명하면 이 값이 영역
 *          크기에 비례하고, 그 동안 그 영역은 이전 내용으로 답한다.
 */
fn incremental(origin: &Name, signer: &ZoneSigner) {
    let owners: usize = std::env::var("ONETDNS_SIGN_OWNERS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(100_000);
    let mode = DenialMode::Nsec;
    let records = zone_records(origin, owners);

    let started = Instant::now();
    let signed = sign_zone_with(&records, signer, 1_700_000_000, &mode);
    println!("first_sign_secs,{:.3}", started.elapsed().as_secs_f64());

    /* 이름 하나의 주소만 바꾼다. NSEC 체인은 그대로이므로 새로 서명할 것은 그 RRset뿐이다. */
    let mut changed = records.clone();
    let target =
        Name::from_str(&format!("host{}.{}", owners / 2, origin.to_ascii_lower())).unwrap();
    for record in &mut changed {
        if record.name.eq_ignore_case(&target) {
            record.rdata = RData::A(Ipv4Addr::new(203, 0, 113, 9));
        }
    }

    for round in 1..=3 {
        let started = Instant::now();
        let out = onetdns_dnssec::sign::sign_zone_reusing(
            &changed,
            signer,
            1_700_000_060,
            &mode,
            &signed,
        );
        let secs = started.elapsed().as_secs_f64();
        println!(
            "resign_round{round}_secs,{secs:.3},records_out,{}",
            out.len()
        );
        black_box(&out);
    }

    let full = Instant::now();
    let out = sign_zone_with(&changed, signer, 1_700_000_060, &mode);
    println!(
        "resign_full_secs,{:.3},records_out,{}",
        full.elapsed().as_secs_f64(),
        out.len()
    );
}

/** @brief 방식별·크기별로 서명 비용을 출력한다. */
fn main() {
    let origin = Name::from_str("bench.test").unwrap();
    let signer = ZoneSigner::generate(origin.clone(), [7u8; 32]);

    if std::env::var("ONETDNS_SIGN_BREAKDOWN").is_ok() {
        breakdown(&signer);
        return;
    }
    if std::env::var("ONETDNS_SIGN_INCREMENTAL").is_ok() {
        incremental(&origin, &signer);
        return;
    }

    /* 대조 엔진과 나란히 측정할 때는 한 크기만 돌려야 CPU 시간이 그 크기의 것이 된다. */
    let sizes: Vec<usize> = match std::env::var("ONETDNS_SIGN_OWNERS") {
        Ok(raw) => raw
            .split(',')
            .filter_map(|part| part.trim().parse().ok())
            .collect(),
        Err(_) => vec![1_000, 10_000, 100_000],
    };
    let rounds: usize = std::env::var("ONETDNS_SIGN_ROUNDS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(3);

    /* 알고리즘을 고를 수 있다. 대조 엔진과 비교할 때 이 축이 곧 결론이다. */
    let algorithm = match std::env::var("ONETDNS_SIGN_ALGORITHM").as_deref() {
        Ok("ed25519") => SignAlgorithm::Ed25519,
        _ => SignAlgorithm::EcdsaP256,
    };
    let signer = ZoneSigner::generate_with(origin.clone(), [7u8; 32], algorithm);

    println!("algorithm,{}", signer.algorithm().number());
    println!("mode,owners,records_in,records_out,secs,us_per_owner,peak_mib");
    for owners in sizes {
        let records = zone_records(&origin, owners);
        for (label, mode) in [
            ("nsec", DenialMode::Nsec),
            (
                "nsec3",
                DenialMode::Nsec3(Nsec3Params {
                    iterations: 0,
                    salt: vec![0xab, 0xcd],
                }),
            ),
        ] {
            /*
             * 첫 회차는 버린다. 할당기와 캐시가 데워지지 않은 상태를 측정하면 방식 비교가 흐려진다.
             */
            let _ = measure(&records, &signer, &mode);
            let mut best = f64::MAX;
            let mut peak = 0.0f64;
            let mut out = 0usize;
            for _ in 0..rounds {
                let (secs, this_peak, count) = measure(&records, &signer, &mode);
                if secs < best {
                    best = secs;
                    peak = this_peak;
                    out = count;
                }
            }
            println!(
                "{label},{owners},{},{out},{best:.3},{:.2},{peak:.1}",
                records.len(),
                best * 1_000_000.0 / owners as f64
            );
        }
    }
}
