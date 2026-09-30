/*!
 * @brief dnstap 형식 질의 로그.
 *
 * @details Frame Streams 컨테이너에 protobuf 메시지를 담는다. 외부 protobuf 라이브러리를
 *          쓰지 않고 이 서버가 쓰는 필드만 직접 인코딩한다.
 * @note 기록 실패는 세기만 하고 질의 처리를 막지 않는다. 로그 때문에 응답이 늦어지면 안 된다.
 */

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use onetdns_core::MutexExt;

/** @brief Frame Streams 내용 형식. 수집기가 이것으로 형식을 안다. */
const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";
/**
 * @brief 스트림 시작 제어 프레임.
 * @details Frame Streams 에서 0x01 은 양방향 연결의 ACCEPT 다. 단방향 파일 스트림은 START 로
 *          연다.
 */
const CONTROL_START: u32 = 0x02;
/** @brief 스트림 종료 제어 프레임. */
const CONTROL_STOP: u32 = 0x03;
/** @brief 제어 프레임의 내용 형식 필드 번호. */
const FIELD_CONTENT_TYPE: u32 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/** @brief 질의가 어느 전송으로 왔는지. */
pub enum DnstapProtocol {
    /** @brief 평문 UDP. */
    Udp,
    /** @brief 평문 TCP. */
    Tcp,
    /** @brief TLS 위. */
    Dot,
    /** @brief HTTP 위. */
    Doh,
    /** @brief DNSCrypt UDP. */
    DnscryptUdp,
    /** @brief QUIC 위. */
    Doq,
}

impl DnstapProtocol {
    /** @brief dnstap 규격의 소켓 프로토콜 번호. */
    fn code(self) -> u64 {
        match self {
            DnstapProtocol::Udp => 1,
            DnstapProtocol::Tcp => 2,
            DnstapProtocol::Dot => 3,
            DnstapProtocol::Doh => 4,
            DnstapProtocol::DnscryptUdp => 5,
            DnstapProtocol::Doq => 7,
        }
    }
}

/**
 * @brief 시작 프레임으로 열고 종료 프레임으로 닫는 Frame Streams 파일 하나.
 * @invariant 한 파일에는 이 값 하나만 쓴다. 둘이 같은 파일을 열면 한쪽의 종료 프레임 뒤에
 *            다른 쪽 기록이 이어져 수집기가 그 뒤를 버린다.
 */
struct Stream {
    /** @brief 기록을 쓸 파일. */
    out: Mutex<BufWriter<File>>,
    /** @brief 연 경로. */
    path: PathBuf,
    /** @brief 쓰지 못한 횟수. */
    failures: std::sync::atomic::AtomicU64,
}

impl Drop for Stream {
    /** @brief 종료 프레임을 쓴다. 수집기가 스트림이 정상 종료됐음을 안다. */
    fn drop(&mut self) {
        let mut w = self.out.lock_recover();
        if let Err(e) = write_control_stop(&mut *w).and_then(|()| w.flush()) {
            onetdns_core::warn!(event = "dnstap.stop_frame_failed", error = %e, "Could not write the dnstap stop frame; the collector will see this stream as ending abnormally");
        }
    }
}

/** @brief dnstap 파일에 쓰는 기록기. */
pub struct DnstapWriter {
    /** @brief 기록을 쓸 스트림. 서버 이름만 다른 기록기끼리 나눠 쓴다. */
    stream: Arc<Stream>,
    /** @brief 기록에 적을 서버 이름. */
    identity: Vec<u8>,
    /** @brief 기록에 적을 서버 버전. */
    version: Vec<u8>,
}

impl DnstapWriter {
    /** @brief 파일을 만들고 시작 프레임을 쓴다. */
    pub fn create(path: &Path, identity: &str) -> io::Result<Self> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts.open(path)?;
        let mut w = BufWriter::new(file);
        write_control_start(&mut w)?;
        w.flush()?;
        Ok(DnstapWriter {
            stream: Arc::new(Stream {
                out: Mutex::new(w),
                path: path.to_path_buf(),
                failures: std::sync::atomic::AtomicU64::new(0),
            }),
            identity: identity.as_bytes().to_vec(),
            version: b"OnetDNS".to_vec(),
        })
    }

    /**
     * @brief 같은 스트림에 서버 이름만 바꿔 쓰는 기록기.
     * @details 서버 이름은 메시지마다 담기는 값이라 스트림을 다시 열 까닭이 없다.
     */
    pub fn with_identity(&self, identity: &str) -> Self {
        DnstapWriter {
            stream: self.stream.clone(),
            identity: identity.as_bytes().to_vec(),
            version: self.version.clone(),
        }
    }

    /** @brief 기록하는 파일 경로. */
    pub fn path(&self) -> &Path {
        &self.stream.path
    }

    /** @brief 기록에 실패한 횟수. 지표로 내보낸다. */
    pub fn failures(&self) -> u64 {
        self.stream
            .failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /**
     * @brief 클라이언트에게 보낸 응답 하나를 기록한다.
     * @note 실패해도 오류를 올리지 않고 세기만 한다. 로그가 질의 처리를 막으면 안 된다.
     */
    pub fn log_client_response(
        &self,
        client: SocketAddr,
        proto: DnstapProtocol,
        query_time: SystemTime,
        response_wire: &[u8],
    ) {
        let msg = encode_message(client, proto.code(), query_time, response_wire);
        let frame = encode_dnstap(&self.identity, &self.version, &msg);
        let mut w = self.stream.out.lock_recover();
        if let Err(e) = write_data_frame(&mut *w, &frame).and_then(|()| w.flush()) {
            if self
                .stream
                .failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                onetdns_core::warn!(
                    event = "dnstap.write_failed",
                    error = %e,
                    "Could not write dnstap frame"
                );
            }
        }
    }
}

/** @brief 시작 제어 프레임을 쓴다. 내용 형식이 여기 담긴다. */
fn write_control_start<W: Write>(w: &mut W) -> io::Result<()> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&CONTROL_START.to_be_bytes());
    payload.extend_from_slice(&FIELD_CONTENT_TYPE.to_be_bytes());
    payload.extend_from_slice(&(CONTENT_TYPE.len() as u32).to_be_bytes());
    payload.extend_from_slice(CONTENT_TYPE);
    write_control_frame(w, &payload)
}

/** @brief 종료 제어 프레임을 쓴다. */
fn write_control_stop<W: Write>(w: &mut W) -> io::Result<()> {
    write_control_frame(w, &CONTROL_STOP.to_be_bytes())
}

/** @brief 제어 프레임을 쓴다. 길이 0을 앞에 두어 데이터 프레임과 구분한다. */
fn write_control_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    w.write_all(&0u32.to_be_bytes())?;
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)
}

/** @brief 데이터 프레임을 쓴다. 길이 접두사가 붙는다. */
fn write_data_frame<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)
}

/** @brief protobuf 가변 길이 정수. */
fn pb_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(b | 0x80);
        } else {
            out.push(b);
            break;
        }
    }
}

/** @brief protobuf 필드 키. 번호와 형식을 합친 값이다. */
fn pb_key(out: &mut Vec<u8>, field: u32, wire: u32) {
    pb_varint(out, ((field << 3) | wire) as u64);
}

/** @brief 부호 없는 정수 필드. */
fn pb_uint(out: &mut Vec<u8>, field: u32, v: u64) {
    pb_key(out, field, 0);
    pb_varint(out, v);
}

/** @brief 바이트열 필드. 길이 접두사가 붙는다. */
fn pb_bytes(out: &mut Vec<u8>, field: u32, d: &[u8]) {
    pb_key(out, field, 2);
    pb_varint(out, d.len() as u64);
    out.extend_from_slice(d);
}

/** @brief 고정 32비트 필드. */
fn pb_fixed32(out: &mut Vec<u8>, field: u32, v: u32) {
    pb_key(out, field, 5);
    out.extend_from_slice(&v.to_le_bytes());
}

/** @brief dnstap 메시지 본문을 인코딩한다. 이 서버가 쓰는 필드만 담는다. */
fn encode_message(
    client: SocketAddr,
    proto_code: u64,
    qtime: SystemTime,
    response_wire: &[u8],
) -> Vec<u8> {
    let mut m = Vec::new();
    pb_uint(&mut m, 1, 6);
    let (family, addr) = match client.ip() {
        std::net::IpAddr::V4(a) => (1u64, a.octets().to_vec()),
        std::net::IpAddr::V6(a) => (2u64, a.octets().to_vec()),
    };
    pb_uint(&mut m, 2, family);
    pb_uint(&mut m, 3, proto_code);
    pb_bytes(&mut m, 4, &addr);
    pb_uint(&mut m, 6, client.port() as u64);
    let (sec, nsec) = match qtime.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), d.subsec_nanos()),
        Err(_) => (0, 0),
    };
    pb_uint(&mut m, 8, sec);
    pb_fixed32(&mut m, 9, nsec);
    pb_bytes(&mut m, 14, response_wire);
    m
}

/** @brief 신원과 버전 정보를 붙여 최종 dnstap 메시지를 만든다. */
fn encode_dnstap(identity: &[u8], version: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if !identity.is_empty() {
        pb_bytes(&mut out, 1, identity);
    }
    if !version.is_empty() {
        pb_bytes(&mut out, 2, version);
    }
    pb_bytes(&mut out, 14, message);
    pb_uint(&mut out, 15, 1);
    out
}

#[cfg(test)]
/** @brief 인코딩 결과를 되읽어 확인하고, 파일이 규격대로 시작하는지 본다. */
mod tests {
    use super::*;
    use std::io::Read;

    /** @brief 인코딩된 버퍼에서 특정 필드의 바이트열을 찾는다. */
    fn pb_find_bytes(buf: &[u8], field: u32) -> Option<Vec<u8>> {
        let mut p = 0;
        while p < buf.len() {
            let (key, n) = read_varint(&buf[p..])?;
            p += n;
            let f = (key >> 3) as u32;
            let wire = (key & 7) as u32;
            match wire {
                0 => {
                    let (_, n) = read_varint(&buf[p..])?;
                    p += n;
                }
                5 => p += 4,
                2 => {
                    let (len, n) = read_varint(&buf[p..])?;
                    p += n;
                    let end = p + len as usize;
                    let v = buf.get(p..end)?.to_vec();
                    if f == field {
                        return Some(v);
                    }
                    p = end;
                }
                _ => return None,
            }
        }
        None
    }

    /** @brief 가변 길이 정수를 읽는다. */
    fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
        let mut v = 0u64;
        let mut shift = 0;
        for (i, &b) in buf.iter().enumerate() {
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some((v, i + 1));
            }
            shift += 7;
        }
        None
    }

    #[test]
    /** @brief 응답 와이어가 인코딩을 거쳐 그대로 되나오는지. */
    fn protobuf_message_roundtrips_response_wire() {
        let resp = b"\xAB\xCD fake dns response wire";
        let m = encode_message(
            "203.0.113.9:5353".parse().unwrap(),
            1,
            SystemTime::UNIX_EPOCH,
            resp,
        );

        assert_eq!(pb_find_bytes(&m, 14).as_deref(), Some(resp.as_slice()));

        assert_eq!(pb_find_bytes(&m, 4), Some(vec![203, 0, 113, 9]));

        let dt = encode_dnstap(b"id", b"onetdns", &m);

        let inner = pb_find_bytes(&dt, 14).unwrap();
        assert_eq!(pb_find_bytes(&inner, 14).as_deref(), Some(resp.as_slice()));
    }

    #[test]
    /** @brief 파일이 시작 프레임으로 열리고 데이터 프레임이 이어지는지. */
    fn file_has_framestreams_start_and_data() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("onetdns_dnstap_test_{}.fstrm", std::process::id()));
        {
            let w = DnstapWriter::create(&path, "test-id").unwrap();
            w.log_client_response(
                "192.0.2.1:1234".parse().unwrap(),
                DnstapProtocol::Udp,
                SystemTime::UNIX_EPOCH,
                b"\x00\x01response",
            );
        }

        let mut bytes = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut bytes).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(&bytes[0..4], &[0, 0, 0, 0], "escape");
        let ctrl_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let ctrl = &bytes[8..8 + ctrl_len];
        assert_eq!(&ctrl[0..4], &[0, 0, 0, 2], "단방향 스트림은 START 로 연다");

        assert!(
            ctrl.windows(CONTENT_TYPE.len()).any(|w| w == CONTENT_TYPE),
            "content-type in START frame"
        );

        let mut p = 8 + ctrl_len;
        let dlen =
            u32::from_be_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]) as usize;
        assert!(dlen > 0, "data frame 길이 > 0");
        p += 4;
        let dnstap = &bytes[p..p + dlen];
        let inner = pb_find_bytes(dnstap, 14).expect("Dnstap.message");
        assert_eq!(
            pb_find_bytes(&inner, 14).as_deref(),
            Some(b"\x00\x01response".as_slice())
        );
    }

    /** @brief 파일을 프레임으로 나눈다. 제어 프레임은 종류 번호로, 데이터 프레임은 0으로 적는다. */
    fn frame_kinds(bytes: &[u8]) -> Vec<u32> {
        let word = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        let mut kinds = Vec::new();
        let mut p = 0;
        while p < bytes.len() {
            let len = word(p) as usize;
            if len == 0 {
                let ctrl_len = word(p + 4) as usize;
                kinds.push(word(p + 8));
                p += 8 + ctrl_len;
            } else {
                kinds.push(0);
                p += 4 + len;
            }
        }
        kinds
    }

    #[test]
    /**
     * @brief 서버 이름만 바꾼 기록기가 스트림을 새로 열지 않는지.
     * @details 같은 파일에 스트림을 하나 더 열면 이전 스트림의 종료 프레임이 새 스트림 한가운데
     *          끼어 수집기가 그 뒤를 버린다.
     */
    fn identity_change_keeps_one_stream() {
        let path = std::env::temp_dir().join(format!(
            "onetdns_dnstap_identity_{}.fstrm",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let first = DnstapWriter::create(&path, "a").unwrap();
            let second = first.with_identity("b");
            drop(first);
            second.log_client_response(
                "192.0.2.1:1234".parse().unwrap(),
                DnstapProtocol::Udp,
                SystemTime::UNIX_EPOCH,
                b"\x00\x01response",
            );
        }
        let mut bytes = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut bytes).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(frame_kinds(&bytes), vec![CONTROL_START, 0, CONTROL_STOP]);
    }
}
