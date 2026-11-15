use onetdns_dnssec::anchor::AnchorManager;
use onetdns_dnssec::sign::ZoneSigner;
use onetdns_proto::Name;

fn signer_for(zsk_pem: &str, ksk_pem: &str, owner: &str) -> ZoneSigner {
    let owner = Name::from_str(owner).expect("owner 이름");
    ZoneSigner::from_pkcs8_pems(zsk_pem, Some(ksk_pem), owner).expect("PEM 키 로드")
}

/// Builds signed zones for the signing benchmarks.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: dnssec_bench_fixtures <ds|anchor> <zsk.pem> <ksk.pem> <owner>...";
    if args.len() < 5 {
        eprintln!("{usage}");
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let zsk = std::fs::read_to_string(&args[2]).expect("ZSK PEM 읽기");
    let ksk = std::fs::read_to_string(&args[3]).expect("KSK PEM 읽기");

    match mode {
        "ds" => {
            let owners: Vec<String> = if args[4..] == ["-".to_string()] {
                std::io::read_to_string(std::io::stdin())
                    .expect("표준 입력")
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            } else {
                args[4..].to_vec()
            };
            for owner in &owners {
                let signer = signer_for(&zsk, &ksk, owner);
                let ds = signer.ds().expect("DS 계산");
                let digest: String = ds.digest.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "{owner} 3600 IN DS {} {} {} {}",
                    ds.key_tag, ds.algorithm, ds.digest_type, digest
                );
            }
        }
        "anchor" => {
            let zone = &args[4];
            let signer = signer_for(&zsk, &ksk, zone);
            let ksk_key = signer.ksk_dnskey().expect("KSK DNSKEY");
            let zone_name = Name::from_str(zone).expect("zone 이름");
            let mgr = AnchorManager::bootstrap(zone_name, vec![ksk_key], 0);
            print!("{}", mgr.serialize());
        }
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    }
}
