use std::hint::black_box;
use std::time::Instant;

use onetdns_core::{BlockResponse, ClientInfo, FilterEngine, Transport};
use onetdns_filter::build_from_str;
use onetdns_proto::{Name, RecordType};

fn make_block_text(n: usize, regexes: bool) -> String {
    let mut s = String::with_capacity(n * 24);
    for i in 0..n {
        s.push_str(&format!("||ads{i}.tracker{}.example^\n", i % 997));
    }

    if regexes {
        for i in 0..32 {
            s.push_str(&format!("/^pixel{i}[0-9]*\\./\n"));
        }
    }
    s
}

fn client() -> ClientInfo {
    ClientInfo {
        source_ip: "192.168.1.10".parse().unwrap(),
        client_id: None,
        transport: Transport::Do53Udp,
        authenticated: false,
    }
}

fn measure(label: &str, eng: &onetdns_filter::BlockEngine, names: &[Name], cl: &ClientInfo) {
    let run_once = || {
        for n in names {
            black_box(eng.verdict(black_box(n), RecordType::A, cl));
        }
    };

    for _ in 0..2_000 {
        run_once();
    }

    let iters = 200_000usize;
    let start = Instant::now();
    for _ in 0..iters {
        run_once();
    }
    let elapsed = start.elapsed();

    let total = iters * names.len();
    let per_ns = elapsed.as_nanos() as f64 / total as f64;
    let mqps = if per_ns > 0.0 {
        1_000.0 / per_ns
    } else {
        f64::INFINITY
    };
    println!("{label}: {total} 판정 / {elapsed:?} → {per_ns:.1} ns/query (~{mqps:.1} Mqps)");
}

/// Verdict cost by rule count and kind.
fn main() {
    let names: Vec<Name> = [
        "ads5.tracker5.example.",
        "deep.sub.domain.ads9.tracker9.example.",
        "www.google.com.",
        "a.b.c.d.e.f.example.org.",
        "pixel7tracking.cdn.net.",
        "safe.normal-site.com.",
    ]
    .iter()
    .map(|s| Name::from_str(s).unwrap())
    .collect();

    let cl = client();
    let domains = build_from_str(
        &make_block_text(100_000, false),
        "",
        BlockResponse::NxDomain,
    );
    let regexes = build_from_str(&make_block_text(0, true), "", BlockResponse::NxDomain);
    let combined = build_from_str(&make_block_text(100_000, true), "", BlockResponse::NxDomain);

    measure("verdict(100k 서픽스)", &domains, &names, &cl);
    measure("verdict(32 정규식)", &regexes, &names, &cl);
    measure("verdict(100k 서픽스 + 32 정규식)", &combined, &names, &cl);
}
