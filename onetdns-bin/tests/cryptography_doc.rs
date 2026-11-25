//! `docs/cryptography.md` must list exactly the algorithms the code offers.

use onetdns_tls::conn::{CLIENT_SIGNATURE_SCHEMES, TLS13_GROUPS, TLS13_SUITES};
use onetdns_tls::tls12;

fn doc() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/cryptography.md"
    ))
    .expect("read docs/cryptography.md")
}

/// The second cell of the table row whose first cell is `label`.
fn row(doc: &str, label: &str) -> String {
    let prefix = format!("| {label} |");
    let line = doc
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("docs/cryptography.md has no `{label}` row"));
    line[prefix.len()..]
        .trim_end()
        .trim_end_matches('|')
        .trim()
        .to_string()
}

fn tls_name(id: u16) -> &'static str {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0x001d => "x25519",
        0x0017 => "secp256r1",
        0x11ec => "X25519MLKEM768",
        0x0807 => "ed25519",
        0x0904 => "mldsa44",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0401 => "rsa_pkcs1_sha256",
        other => panic!("{other:#06x} needs its IANA name here and in docs/cryptography.md"),
    }
}

#[test]
fn tls_lists_match_the_code() {
    let doc = doc();
    for (label, ids) in [
        ("TLS 1.3 cipher suites", TLS13_SUITES.to_vec()),
        ("TLS 1.3 key exchange", TLS13_GROUPS.to_vec()),
        ("TLS 1.2 cipher suites", tls12::client_suites().to_vec()),
        ("TLS 1.2 key exchange", tls12::supported_groups().to_vec()),
        ("Server signatures", CLIENT_SIGNATURE_SCHEMES.to_vec()),
    ] {
        let cell = row(&doc, label);
        let listed: Vec<&str> = cell.split('`').skip(1).step_by(2).collect();
        let offered: Vec<&str> = ids.into_iter().map(tls_name).collect();
        assert_eq!(listed, offered, "{label}");
    }
}

#[test]
fn dnssec_lists_match_the_code() {
    let doc = doc();
    let listed = |label: &str| -> Vec<u8> {
        row(&doc, label)
            .split(", ")
            .map(|item| {
                let number = item.split(' ').next().unwrap_or_default();
                number
                    .parse()
                    .unwrap_or_else(|_| panic!("{label}: `{item}` must start with its number"))
            })
            .collect()
    };
    let supported = |algorithm: u8, digest_type: u8| {
        onetdns_dnssec::ds_is_supported(&onetdns_dnssec::Ds {
            key_tag: 0,
            algorithm,
            digest_type,
            digest: Vec::new(),
        })
    };
    let algorithms: Vec<u8> = (0..=255).filter(|&a| supported(a, 2)).collect();
    let digests: Vec<u8> = (0..=255).filter(|&d| supported(13, d)).collect();
    assert_eq!(listed("Signature algorithms"), algorithms);
    assert_eq!(listed("DS digests"), digests);
}
