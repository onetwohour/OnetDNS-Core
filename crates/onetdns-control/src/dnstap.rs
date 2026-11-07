//! dnstap query log: protobuf messages in a Frame Streams file, encoding only the fields
//! this server writes. A failed write is counted and never delays the query.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use onetdns_core::MutexExt;

const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";
/// A one-way file stream opens with START; 0x01 is ACCEPT, which only bidirectional
/// connections use.
const CONTROL_START: u32 = 0x02;
const CONTROL_STOP: u32 = 0x03;
const FIELD_CONTENT_TYPE: u32 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnstapProtocol {
    Udp,
    Tcp,
    Dot,
    Doh,
    DnscryptUdp,
    Doq,
}

impl DnstapProtocol {
    /// Socket protocol number in the dnstap schema.
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

/// One Frame Streams file. Only one value may write a file: a second stream's stop frame
/// would land in the middle of the first, and the collector drops what follows.
struct Stream {
    out: Mutex<BufWriter<File>>,
    path: PathBuf,
    failures: std::sync::atomic::AtomicU64,
}

impl Drop for Stream {
    fn drop(&mut self) {
        let mut w = self.out.lock_recover();
        if let Err(e) = write_control_stop(&mut *w).and_then(|()| w.flush()) {
            onetdns_core::warn!(event = "dnstap.stop_frame_failed", error = %e, "Could not write the dnstap stop frame; the collector will see this stream as ending abnormally");
        }
    }
}

pub struct DnstapWriter {
    /// Shared by writers that differ only in identity.
    stream: Arc<Stream>,
    identity: Vec<u8>,
    version: Vec<u8>,
}

impl DnstapWriter {
    /// Opens the file and writes the start frame. A new file is readable only by the owner,
    /// since it records client addresses and every query.
    pub fn create(path: &Path, identity: &str) -> io::Result<Self> {
        let file = onetdns_core::fs::open_private(path, onetdns_core::fs::PrivateOpen::Append)?;
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

    /// A writer with another server identity on the same stream. The identity is stored per
    /// message, so there is no reason to open a new stream.
    pub fn with_identity(&self, identity: &str) -> Self {
        DnstapWriter {
            stream: self.stream.clone(),
            identity: identity.as_bytes().to_vec(),
            version: self.version.clone(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.stream.path
    }

    /// Failed writes, exported as a metric.
    pub fn failures(&self) -> u64 {
        self.stream
            .failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records one response sent to a client. A failure is only counted.
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

fn write_control_start<W: Write>(w: &mut W) -> io::Result<()> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&CONTROL_START.to_be_bytes());
    payload.extend_from_slice(&FIELD_CONTENT_TYPE.to_be_bytes());
    payload.extend_from_slice(&(CONTENT_TYPE.len() as u32).to_be_bytes());
    payload.extend_from_slice(CONTENT_TYPE);
    write_control_frame(w, &payload)
}

fn write_control_stop<W: Write>(w: &mut W) -> io::Result<()> {
    write_control_frame(w, &CONTROL_STOP.to_be_bytes())
}

/// A zero length in front tells control frames apart from data frames.
fn write_control_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    w.write_all(&0u32.to_be_bytes())?;
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)
}

fn write_data_frame<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)
}

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

fn pb_key(out: &mut Vec<u8>, field: u32, wire: u32) {
    pb_varint(out, ((field << 3) | wire) as u64);
}

fn pb_uint(out: &mut Vec<u8>, field: u32, v: u64) {
    pb_key(out, field, 0);
    pb_varint(out, v);
}

fn pb_bytes(out: &mut Vec<u8>, field: u32, d: &[u8]) {
    pb_key(out, field, 2);
    pb_varint(out, d.len() as u64);
    out.extend_from_slice(d);
}

fn pb_fixed32(out: &mut Vec<u8>, field: u32, v: u32) {
    pb_key(out, field, 5);
    out.extend_from_slice(&v.to_le_bytes());
}

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
mod tests {
    use super::*;
    use std::io::Read;

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

    /// Splits a file into frames: control frames as their type, data frames as 0.
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
    // Opening a second stream on the same file would put the first one's stop frame in the
    // middle of the second, and the collector drops what follows.
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

    #[cfg(windows)]
    #[test]
    fn a_new_dnstap_file_is_readable_only_by_the_owner_on_windows() {
        let path = std::env::temp_dir().join(format!(
            "onetdns_dnstap_acl_{}_{:016x}.fstrm",
            std::process::id(),
            u64::from_le_bytes(onetdns_core::rng::random_array::<8>())
        ));
        drop(DnstapWriter::create(&path, "a").unwrap());
        let rules = onetdns_core::fs::access_rules(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(rules, "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)");
    }
}
