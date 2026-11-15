//! Measures online signing cost. Signing covers the whole zone when it loads or when DDNS edits it,
//! not each query, so this number is the start and reload delay of a signed zone, during which the
//! zone answers with its old content. Each denial method (NSEC, NSEC3) is measured separately;
//! NSEC3 hashes every name, so its cost differs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use onetdns_dnssec::sign::{sign_zone_with, DenialMode, Nsec3Params, SignAlgorithm, ZoneSigner};
use onetdns_proto::{Name, RData, Record, Soa};

/// Tracks live bytes and the peak.
struct TrackingAllocator;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn add_allocation(size: usize) {
    let current = CURRENT.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(current, Ordering::Relaxed);
}

// SAFETY: Only counts; every allocation is passed to the system allocator.
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
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }

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
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

/// One A record per name.
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

fn reset_peak() {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
}

fn peak_mib(baseline: usize) -> f64 {
    PEAK.load(Ordering::Relaxed).saturating_sub(baseline) as f64 / (1024.0 * 1024.0)
}

/// Time and extra peak memory to sign the zone once with `mode`.
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

/// Splits the cost of one signature into the curve operation and everything before it, to tell
/// where a gap to the comparison engine can be closed: if the curve dominates it is the crypto
/// library's choice, if the front dominates this server can fix it.
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

    // Signs a fixed digest with the same key, leaving out canonical serialisation, SHA-256 and
    // record assembly.
    let curve = signer.bench_raw_sign_us(iterations);
    let _ = &origin;
    println!("sign_rrset_us,{full:.2}");
    println!("raw_ecdsa_us,{curve:.2}");
    println!("prep_us,{:.2}", full - curve);
    // The gap that switching to algorithm 15 would close. The crate is already in the tree, so no
    // new dependency.
    println!(
        "raw_ed25519_us,{:.2}",
        ZoneSigner::bench_ed25519_sign_us(iterations)
    );
}

/// Re-signing after editing one record, which is what DDNS updates and control plane edits do.
/// Re-signing everything makes this grow with the zone, and the zone answers with its old content
/// meanwhile.
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

    // Only one name's address changes; the NSEC chain stays, so only that RRset needs a new
    // signature.
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

    // Next to the comparison engine, run one size only so the CPU time belongs to that size.
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

    // Against the comparison engine, the algorithm decides the result.
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
            // The first run is discarded: a cold allocator and cache blur the comparison.
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
