use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write as _;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use onetdns_authority::{parse_zone, Zone, ZoneStore};
use onetdns_proto::{Name, RData, Record, RecordType, Soa};

/// Counts live bytes and the peak.
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

    /// A moved block keeps the old and new buffers alive at once during the copy. Leaving that
    /// overlap out of the peak hides every peak of data that grows by doubling; counting only the
    /// growth makes the peak always equal the live size. An in-place resize has no overlap, so only
    /// the difference counts.
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

fn zone_records(origin: &Name, host_count: usize) -> Vec<Record> {
    let origin_text = origin.to_ascii_lower();
    let ns = Name::from_str(&format!("ns.{origin_text}")).unwrap();
    let hostmaster = Name::from_str(&format!("hostmaster.{origin_text}")).unwrap();
    let mut records = Vec::with_capacity(host_count + 5);
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

/// Repeating one name.
fn measure_query(zone: &Zone, name: &Name, iterations: usize) -> f64 {
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(zone.query(black_box(name), RecordType::A));
    }
    started.elapsed().as_nanos() as f64 / iterations as f64
}

/// Different names, where caching does not help.
fn measure_spread(zone: &Zone, names: &[Name], iterations: usize) -> f64 {
    let started = Instant::now();
    let mut cursor = 0usize;
    for _ in 0..iterations {
        black_box(zone.query(black_box(&names[cursor]), RecordType::A));
        cursor += 1;
        if cursor == names.len() {
            cursor = 0;
        }
    }
    started.elapsed().as_nanos() as f64 / iterations as f64
}

fn spread_names(origin_text: &str, owner_count: usize) -> Vec<Name> {
    let mut order: Vec<usize> = (0..owner_count).collect();
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for index in (1..order.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        order.swap(index, (state >> 33) as usize % (index + 1));
    }
    order
        .into_iter()
        .map(|index| Name::from_str(&format!("host{index}.{origin_text}")).unwrap())
        .collect()
}

fn zone_text(host_count: usize) -> String {
    let mut text = String::with_capacity(host_count * 36);
    text.push_str("$ORIGIN parsed.test.\n$TTL 300\n@ IN SOA ns hostmaster 1 300 60 3600 60\n@ IN NS ns\nns IN A 192.0.2.53\n");
    for index in 0..host_count {
        writeln!(text, "h{index:06} IN A 192.0.2.1").unwrap();
    }
    text
}

/// Measures query cost and the memory one zone takes.
fn main() {
    let origin = Name::from_str("bench.test").unwrap();
    let allocation_baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(allocation_baseline, Ordering::Relaxed);
    // Fixture generation stays outside the timer: 100,000 format! calls and Name parses cost more
    // than building the zone, so timing them together would leave build= measuring nothing clear.
    // The parse section below works the same way. The live and peak baselines stay before the
    // fixture; moving them after would undercount by what from_records frees when it drops its
    // input Vec.
    let records = zone_records(&origin, 100_000);
    let build_started = Instant::now();
    let zone = Zone::from_records(records).unwrap();
    let build_elapsed = build_started.elapsed();
    let retained = CURRENT
        .load(Ordering::Relaxed)
        .saturating_sub(allocation_baseline);
    let peak = PEAK
        .load(Ordering::Relaxed)
        .saturating_sub(allocation_baseline);
    println!(
        "authority-memory(100k owners): retained={:.1} MiB peak={:.1} MiB build={build_elapsed:?}",
        retained as f64 / 1_048_576.0,
        peak as f64 / 1_048_576.0,
    );
    let exact = Name::from_str("host99999.bench.test").unwrap();
    let missing = Name::from_str("a.b.c.d.e.f.missing.bench.test").unwrap();

    for _ in 0..10_000 {
        black_box(zone.query(black_box(&exact), RecordType::A));
        black_box(zone.query(black_box(&missing), RecordType::A));
    }
    let iterations = 500_000usize;
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(zone.query(black_box(&exact), RecordType::A));
        black_box(zone.query(black_box(&missing), RecordType::A));
    }
    let elapsed = started.elapsed();
    let query_count = iterations * 2;
    let ns_per_query = elapsed.as_nanos() as f64 / query_count as f64;
    println!(
        "authority(100k owners, exact+NXDOMAIN): {query_count} queries / {elapsed:?} -> {ns_per_query:.1} ns/query"
    );
    println!(
        "authority-query-split: exact={:.1} ns/query nxdomain={:.1} ns/query",
        measure_query(&zone, &exact, iterations),
        measure_query(&zone, &missing, iterations),
    );
    let spread = spread_names("bench.test", 100_000);
    for index in 0..10_000 {
        black_box(zone.query(black_box(&spread[index % spread.len()]), RecordType::A));
    }
    println!(
        "authority-query-spread(100k owners, shuffled): {:.1} ns/query",
        measure_spread(&zone, &spread, iterations),
    );

    let text = zone_text(100_000);
    let allocation_baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(allocation_baseline, Ordering::Relaxed);
    let parse_started = Instant::now();
    let parsed = parse_zone(&text, "parsed.test").unwrap();
    let parse_elapsed = parse_started.elapsed();
    let retained = CURRENT
        .load(Ordering::Relaxed)
        .saturating_sub(allocation_baseline);
    let peak = PEAK
        .load(Ordering::Relaxed)
        .saturating_sub(allocation_baseline);
    println!(
        "authority-parse(100k owners): retained={:.1} MiB peak={:.1} MiB parse={parse_elapsed:?}",
        retained as f64 / 1_048_576.0,
        peak as f64 / 1_048_576.0,
    );
    black_box(&parsed);

    let mut store = ZoneStore::new();
    for index in 0..10_000 {
        let origin = Name::from_str(&format!("z{index}.store.test")).unwrap();
        store.add(Zone::from_records(zone_records(&origin, 0)).unwrap());
    }
    let selected = Name::from_str("deep.z9999.store.test").unwrap();
    let started = Instant::now();
    for _ in 0..1_000_000 {
        black_box(store.zone_for(black_box(&selected)).unwrap());
    }
    let elapsed = started.elapsed();
    println!(
        "zone-select(10k zones): 1000000 lookups / {elapsed:?} -> {:.1} ns/lookup",
        elapsed.as_nanos() as f64 / 1_000_000.0
    );
}
