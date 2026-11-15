use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use onetdns_proto::{Edns, Message, Name, RData, Record, RecordType, Writer};

fn response() -> Message {
    let name = Name::from_str("www.performance.example").unwrap();
    let mut message = Message::query(0x5151, name.clone(), RecordType::A);
    message.header.response = true;
    message.header.recursion_available = true;
    message.answers.push(Record::new(
        name.clone(),
        300,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    message.answers.push(Record::new(
        name,
        300,
        RData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    ));
    message.additionals.push(
        Edns {
            udp_payload: 1232,
            dnssec_ok: true,
            ..Default::default()
        }
        .try_to_record()
        .unwrap(),
    );
    message
}

/// Measures the cost of encoding a response.
fn main() {
    let message = response();
    let iterations = 2_000_000usize;

    let started = Instant::now();
    for _ in 0..iterations {
        black_box(message.try_encode().unwrap());
    }
    let allocating = started.elapsed();

    let mut writer = Writer::new();
    writer.buf.reserve(512);
    let started = Instant::now();
    for _ in 0..iterations {
        writer.clear();
        message.try_encode_into(&mut writer).unwrap();
        black_box(writer.buf.as_slice());
    }
    let reused = started.elapsed();

    println!(
        "dns-encode({iterations} responses): allocating={:.1} ns/op reused={:.1} ns/op speedup={:.2}x",
        allocating.as_nanos() as f64 / iterations as f64,
        reused.as_nanos() as f64 / iterations as f64,
        allocating.as_secs_f64() / reused.as_secs_f64()
    );

    let response_wire = message.try_encode().unwrap();
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(Message::parse(&response_wire).unwrap());
    }
    let parsed_response = started.elapsed();
    println!(
        "dns-parse({iterations} ordinary EDNS responses): {:.1} ns/op",
        parsed_response.as_nanos() as f64 / iterations as f64
    );

    let mut option_heavy = Message::query(
        0x6161,
        Name::from_str("options.performance.example").unwrap(),
        RecordType::A,
    );
    let mut edns = Edns::default();
    edns.options = (0..4096).map(|code| (code, Vec::new())).collect();
    option_heavy.additionals.push(edns.try_to_record().unwrap());
    let option_heavy_wire = option_heavy.try_encode().unwrap();
    let parse_iterations = 5_000usize;
    let started = Instant::now();
    for _ in 0..parse_iterations {
        black_box(Message::parse(&option_heavy_wire).unwrap());
    }
    let parsed = started.elapsed();
    println!(
        "dns-parse({parse_iterations} messages, 4096 empty EDNS options): {:.1} us/op",
        parsed.as_micros() as f64 / parse_iterations as f64
    );
}
