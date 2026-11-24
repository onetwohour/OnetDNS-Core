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

    for _ in 0..(12_000 / names.len()).max(1) {
        run_once();
    }

    let iters = (1_200_000 / names.len()).max(1);
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

/// One name asked repeatedly, then 20,000 different names in turn, for hits, misses, and names
/// under a listed one. `list` holds `||domain^` rules; `misses` holds names it does not block.
fn measure_list(list: &str, misses: &str, cl: &ClientInfo) {
    let text = std::fs::read_to_string(list).expect("list");
    let started = Instant::now();
    let engine = build_from_str(&text, "", BlockResponse::NxDomain);
    println!("build({list}): {:?}", started.elapsed());

    let listed: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("||")?.strip_suffix('^'))
        .collect();
    let step = (listed.len() / 20_000).max(1);
    let names = |domains: &mut dyn Iterator<Item = String>| -> Vec<Name> {
        domains
            .take(20_000)
            .map(|domain| Name::from_str(&format!("{domain}.")).unwrap())
            .collect()
    };
    let hits = names(&mut listed.iter().step_by(step).map(|d| d.to_string()));
    let parents = names(&mut listed.iter().step_by(step).map(|d| format!("sub.{d}")));
    let missed = std::fs::read_to_string(misses).expect("misses");
    let misses = names(&mut missed.lines().map(str::to_string));

    for (case, names) in [("hit", &hits), ("miss", &misses), ("parent hit", &parents)] {
        measure(
            &format!("verdict({case}, 1 name)"),
            &engine,
            &names[..1],
            cl,
        );
        measure(
            &format!("verdict({case}, {} names)", names.len()),
            &engine,
            names,
            cl,
        );
    }
}

/// Verdict cost by rule count and kind. With `LIST MISSES` arguments, measures that list instead.
fn main() {
    let cl = client();
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with("--"))
        .collect();
    if let [list, misses] = &args[..] {
        measure_list(list, misses, &cl);
        return;
    }

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

    // Synthetic `||dNNNNNN.block.test^` lists, one name asked repeatedly per case. The names
    // share one suffix, so the automaton is far smaller than for a real list.
    for n in [100_000usize, 500_000, 1_000_000] {
        let text: String = (0..n).map(|i| format!("||d{i:06}.block.test^\n")).collect();
        let started = Instant::now();
        let engine = build_from_str(&text, "", BlockResponse::NxDomain);
        println!("build({n}): {:?}", started.elapsed());
        for (case, name) in [
            ("hit", format!("d{:06}.block.test.", n / 2)),
            ("miss", "miss.example.test.".to_string()),
            ("parent hit", format!("sub.d{:06}.block.test.", n / 3)),
        ] {
            let name = [Name::from_str(&name).unwrap()];
            measure(&format!("verdict({n}, {case})"), &engine, &name, &cl);
        }
    }
}
