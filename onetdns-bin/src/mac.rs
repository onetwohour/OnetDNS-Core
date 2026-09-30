/*!
 * @brief 클라이언트 하드웨어 주소와 제조사 조회.
 *
 * @details 대시보드에 어떤 기기가 무엇을 물었는지 보여 주려는 것이다. 시스템의 이웃
 *          테이블을 주기적으로 읽어 주소와 하드웨어 주소를 잇는다.
 * @note 실패해도 질의 처리에는 영향이 없다. 표시할 이름이 없을 뿐이다.
 */

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use onetdns_core::ArcSwap;

/** @brief 제조사 목록 파일 크기 상한. */
const MAX_VENDOR_DB_FILE: u64 = 16 * 1024 * 1024;
/** @brief 담을 제조사 항목 수 상한. */
const MAX_VENDOR_ENTRIES: usize = 200_000;
/** @brief 담을 이웃 수 상한. 큰 망에서 메모리가 끌려가지 않게 한다. */
const MAX_NEIGHBORS: usize = 65_536;

/** @brief 크기 상한을 걸어 파일을 읽는다. */
fn read_text_limited(path: impl AsRef<std::path::Path>, max: u64) -> std::io::Result<String> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    String::from_utf8(bytes).map_err(|_| std::io::ErrorKind::InvalidData.into())
}

/** @brief 주소에서 하드웨어 주소로 가는 캐시. */
pub struct NeighborCache {
    /** @brief 주소에서 하드웨어 주소로 가는 테이블. 한꺼번에 교체한다. */
    map: ArcSwap<HashMap<IpAddr, String>>,
}

impl NeighborCache {
    /** @brief 빈 캐시. */
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            map: ArcSwap::from_pointee(HashMap::new()),
        })
    }

    /** @brief 이 주소의 하드웨어 주소. */
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.map.load().get(&ip).cloned()
    }

    /** @brief 주기적으로 이웃 테이블을 다시 읽는 스레드를 시작한다. */
    pub fn spawn_refresh(
        self: Arc<Self>,
        interval: Duration,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        let mut healthy = true;
        std::thread::Builder::new()
            .name("neighbor-cache-refresh".into())
            .spawn(move || loop {
                if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match read_neighbors() {
                    Ok(m) => {
                        if !healthy {
                            healthy = true;
                            onetdns_core::info!(event = "mac.neighbors_recovered", entries = m.len(), "Reading the neighbor table again; device names are back");
                        }
                        self.map.store(Arc::new(m));
                    }
                    Err(e) => {
                        if healthy {
                            healthy = false;
                            onetdns_core::warn!(event = "mac.neighbors_read_failed", error = %e, "Could not read the neighbor table; queries are unaffected but the dashboard shows no device names");
                        }
                    }
                }
                if wait_or_shutdown(interval, &shutdown) {
                    break;
                }
            })
    }
}

/**
 * @brief 기다리되 종료 신호가 오면 곧장 돌아온다.
 * @note 한 번에 길게 자면 종료가 그 주기만큼 늦어진다. 잘게 나눠 자며 신호를 확인한다.
 */
fn wait_or_shutdown(duration: Duration, shutdown: &std::sync::atomic::AtomicBool) -> bool {
    use std::sync::atomic::Ordering;
    let deadline = Instant::now().checked_add(duration);
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        let Some(remaining) = deadline.and_then(|end| end.checked_duration_since(Instant::now()))
        else {
            return false;
        };
        std::thread::sleep(remaining.min(Duration::from_millis(250)));
    }
}

/** @brief 하드웨어 주소 표기를 한 형태로 맞춘다. 구분자와 대소문자가 제각각이라 필요하다. */
pub fn normalize_mac(s: &str) -> String {
    s.trim().to_ascii_lowercase().replace('-', ":")
}

/** @brief 제조사 조회 테이블. */
pub struct VendorDb {
    /** @brief 제조사 번호에서 이름으로 가는 테이블. */
    map: HashMap<u32, String>,
}

/** @brief 내장 제조사 목록. 파일이 없어도 흔한 것은 알아본다. */
const BUILTIN_OUI: &[(u32, &str)] = &[
    (0x00_0C_29, "VMware"),
    (0x00_50_56, "VMware"),
    (0x00_1C_14, "VMware"),
    (0x08_00_27, "VirtualBox"),
    (0x52_54_00, "QEMU/KVM"),
    (0x00_15_5D, "Microsoft (Hyper-V)"),
    (0x00_50_F2, "Microsoft"),
    (0xB8_27_EB, "Raspberry Pi"),
    (0xDC_A632, "Raspberry Pi"),
    (0xE4_5F_01, "Raspberry Pi"),
    (0x00_00_0C, "Cisco"),
    (0x00_14_51, "Apple"),
    (0x00_17_F2, "Apple"),
    (0x3C_07_54, "Apple"),
    (0x00_A0_C9, "Intel"),
    (0x00_1B_21, "Intel"),
    (0x00_23_D7, "Samsung"),
    (0x24_0A_C4, "Espressif"),
    (0xA4_CF_12, "Espressif"),
    (0xFC_A1_83, "Amazon"),
    (0x00_E0_FC, "Huawei"),
    (0x28_6C_07, "Xiaomi"),
    (0x00_18_8B, "Dell"),
    (0x00_30_6E, "HP"),
    (0x04_18_D6, "Ubiquiti"),
    (0x2C_30_33, "Netgear"),
    (0x00_E0_4C, "Realtek"),
    (0x3C_5A_B4, "Google"),
    (0x50_C7_BF, "TP-Link"),
];

impl VendorDb {
    /** @brief 내장 목록만으로 만든다. */
    pub fn builtin() -> Self {
        let map = BUILTIN_OUI
            .iter()
            .map(|(o, n)| (*o, (*n).to_string()))
            .collect();
        VendorDb { map }
    }

    /** @brief 파일에서 읽는다. 없거나 깨졌으면 내장 목록으로 전환한다. */
    pub fn load(path: Option<&str>) -> Self {
        let mut db = Self::builtin();
        let Some(p) = path else { return db };
        match read_text_limited(p, MAX_VENDOR_DB_FILE) {
            Ok(text) => {
                let mut n = 0usize;
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((oui, name)) = parse_oui_line(line) {
                        db.map.insert(oui, name);
                        n += 1;
                        if n >= MAX_VENDOR_ENTRIES {
                            break;
                        }
                    }
                }
                onetdns_core::info!(event = "mac.vendor_db_loaded", path = %p, entries = n, "Loaded the MAC vendor database");
            }
            Err(e) => {
                onetdns_core::warn!(event = "mac.vendor_db_fallback", path = %p, error = %e, "Could not read the MAC vendor database; using the built-in list")
            }
        }
        db
    }

    /** @brief 이 하드웨어 주소의 제조사. */
    pub fn lookup(&self, mac: [u8; 6]) -> Option<&str> {
        let oui = ((mac[0] as u32) << 16) | ((mac[1] as u32) << 8) | mac[2] as u32;
        self.map.get(&oui).map(String::as_str)
    }

    /** @brief 항목 수. */
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/** @brief 제조사 목록 한 줄을 읽는다. 형식이 여럿이라 몇 가지를 받는다. */
fn parse_oui_line(line: &str) -> Option<(u32, String)> {
    let (prefix, rest) = match line.find('\t') {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => {
            let i = line.find(char::is_whitespace)?;
            (&line[..i], line[i..].trim())
        }
    };

    let name = rest.rsplit('\t').next().unwrap_or(rest).trim();
    if name.is_empty() {
        return None;
    }
    let hex: String = prefix
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect();
    if hex.len() != 6 {
        return None;
    }
    let oui = u32::from_str_radix(&hex, 16).ok()?;
    Some((oui, name.to_string()))
}

/** @brief 시스템의 이웃 테이블을 읽는다. 방법이 플랫폼마다 다르다. */
fn read_neighbors() -> std::io::Result<HashMap<IpAddr, String>> {
    #[cfg(windows)]
    {
        read_arp_a()
    }
    #[cfg(not(windows))]
    {
        read_proc_arp()
    }
}

#[cfg(windows)]
/** @brief 명령 출력에서 이웃 테이블을 읽는다. */
fn read_arp_a() -> std::io::Result<HashMap<IpAddr, String>> {
    use std::os::windows::process::CommandExt;

    /** @brief 명령을 구간 없이 실행한다. 서비스로 돌 때 구간이 뜨면 안 된다. */
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut out = HashMap::new();
    let Some(exe) = crate::osnet::resolve_tool("arp") else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find the arp command",
        ));
    };
    let mut command = std::process::Command::new(exe);
    command.arg("-a").creation_flags(CREATE_NO_WINDOW);
    crate::osnet::harden_child_env(&mut command);
    let output = command.output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let mut toks = line.split_whitespace();
        let (Some(ip_s), Some(mac_s)) = (toks.next(), toks.next()) else {
            continue;
        };
        if let Ok(ip) = ip_s.parse::<IpAddr>() {
            if mac_s.contains('-') || mac_s.contains(':') {
                out.insert(ip, normalize_mac(mac_s));
                if out.len() >= MAX_NEIGHBORS {
                    break;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(not(windows))]
/** @brief 커널이 내놓는 파일에서 이웃 테이블을 읽는다. */
fn read_proc_arp() -> std::io::Result<HashMap<IpAddr, String>> {
    let mut out = HashMap::new();
    let text = read_text_limited("/proc/net/arp", 8 * 1024 * 1024)?;

    for line in text.lines().skip(1) {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 4 {
            continue;
        }
        if let Ok(ip) = toks[0].parse::<IpAddr>() {
            let mac = toks[3];
            if mac != "00:00:00:00:00:00" && (mac.contains(':') || mac.contains('-')) {
                out.insert(ip, normalize_mac(mac));
                if out.len() >= MAX_NEIGHBORS {
                    break;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
/** @brief 표기 정규화, 조회, 그리고 종료가 지연되지 않는지. */
mod tests {
    use super::*;

    #[test]
    /** @brief 갱신 주기가 길어도 종료가 곧바로 되는지. */
    fn long_neighbor_refresh_wait_stops_promptly() {
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(wait_or_shutdown(Duration::from_secs(60), &worker_shutdown))
                .unwrap();
        });
        std::thread::sleep(Duration::from_millis(20));
        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
        worker.join().unwrap();
    }

    #[test]
    /** @brief 여러 표기가 한 형태로 맞춰지는지. */
    fn normalize() {
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    /** @brief 캐시 조회. */
    fn cache_lookup() {
        let c = NeighborCache::new();
        let mut m = HashMap::new();
        m.insert(
            "192.168.1.5".parse().unwrap(),
            "aa:bb:cc:dd:ee:ff".to_string(),
        );
        c.map.store(Arc::new(m));
        assert_eq!(
            c.lookup("192.168.1.5".parse().unwrap()).as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert!(c.lookup("10.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    /** @brief 내장 목록 조회. */
    fn vendor_builtin_lookup() {
        let db = VendorDb::builtin();

        assert_eq!(
            db.lookup([0xb8, 0x27, 0xeb, 0x12, 0x34, 0x56]),
            Some("Raspberry Pi")
        );
        assert_eq!(db.lookup([0x00, 0x0c, 0x29, 0, 0, 1]), Some("VMware"));
        assert!(db.lookup([0xde, 0xad, 0xbe, 0xef, 0, 0]).is_none());
    }

    #[test]
    /** @brief 여러 형식의 목록 줄이 읽히는지. */
    fn vendor_parse_line_formats() {
        assert_eq!(
            parse_oui_line("00:11:22  Acme Corp"),
            Some((0x001122, "Acme Corp".to_string()))
        );

        assert_eq!(
            parse_oui_line("AA-BB-CC\tFoo Inc"),
            Some((0xaabbcc, "Foo Inc".to_string()))
        );

        assert_eq!(
            parse_oui_line("00:00:0c\tCisco\tCisco Systems, Inc"),
            Some((0x00000c, "Cisco Systems, Inc".to_string()))
        );

        assert_eq!(
            parse_oui_line("b827eb RaspberryPi"),
            Some((0xb827eb, "RaspberryPi".to_string()))
        );

        assert!(parse_oui_line("0011 Short").is_none());
        assert!(parse_oui_line("001122").is_none());
    }
}
