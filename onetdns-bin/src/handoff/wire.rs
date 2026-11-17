//! Frames between processes, with listening sockets passed alongside, and the handoff messages in
//! them. Both ends run different versions during an update, so the layout here is a contract
//! between versions.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{
    Carried, FromPredecessor, FromSuccessor, Link, LinkError, ListeningSocket, SocketPool,
    SocketRole, LINK_POLL,
};
use crate::listeners::TicketKeys;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
use windows as sys;

#[cfg(any(target_os = "linux", windows))]
pub(crate) use sys::pair;
#[cfg(test)]
pub(crate) use sys::stream_pair;
pub(crate) use sys::{Passed, Stream};

/// The handoff protocol: the frames on the supervisor channel and on the link between two workers,
/// the messages in them, and the formats of the state they carry. Each process states its number
/// in its first frame, and both must use the same; it is separate from the update contract so a
/// change here does not cut off self-updates.
pub(crate) const PROTOCOL: u32 = 1;

/// Kind, payload length, and socket count.
const HEADER: usize = 9;
const MAX_PAYLOAD: usize = 1 << 28;
const MAX_FDS: usize = 4096;
/// A peer that stops reading for this long is treated as gone.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

const HELLO: u8 = 1;
const REQUEST: u8 = 2;
const READING: u8 = 3;
const READY: u8 = 4;
const SOCKETS: u8 = 5;
const RELEASED: u8 = 6;

pub(crate) struct Frame {
    pub(crate) kind: u8,
    pub(crate) payload: Zeroizing<Vec<u8>>,
    pub(crate) fds: Vec<Passed>,
}

/// SO_TYPE of a passed socket.
pub(super) enum SocketType {
    Datagram,
    Stream,
    Other,
}

impl Frame {
    pub(crate) fn new(kind: u8) -> Self {
        Self {
            kind,
            payload: Zeroizing::new(Vec::new()),
            fds: Vec::new(),
        }
    }
}

pub(crate) fn send(stream: &Stream, frame: &Frame) -> io::Result<()> {
    if frame.payload.len() > MAX_PAYLOAD || frame.fds.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The handoff message is too large",
        ));
    }
    stream.set_write_timeout(Some(SEND_TIMEOUT))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(HEADER + frame.payload.len()));
    bytes.push(frame.kind);
    bytes.extend_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(frame.fds.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&frame.payload);
    sys::write_frame(stream, &bytes, &frame.fds)
}

/// The next frame, waiting until `deadline` or until `abort` returns true.
pub(crate) fn recv(
    stream: &Stream,
    deadline: Instant,
    abort: &dyn Fn() -> bool,
) -> Result<Frame, LinkError> {
    let mut reader = FrameReader::default();
    loop {
        if abort() {
            return Err(LinkError::Aborted);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(LinkError::TimedOut);
        }
        stream
            .set_read_timeout(Some(left.min(LINK_POLL)))
            .map_err(|_| LinkError::Gone)?;
        if let Some(frame) = reader.read(stream)? {
            return Ok(frame);
        }
    }
}

/// Puts a frame together from what has arrived, across calls.
#[derive(Default)]
pub(crate) struct FrameReader {
    header: [u8; HEADER],
    /// Allocated once the header is complete.
    payload: Option<Zeroizing<Vec<u8>>>,
    /// What follows the payload about each passed socket; allocated once the payload is complete.
    attached: Option<Vec<u8>>,
    filled: usize,
    fds: Vec<Passed>,
}

impl FrameReader {
    /// Reads until the socket has nothing more, by its timeout or because it does not block. Some
    /// once a whole frame has arrived.
    pub(crate) fn read(&mut self, stream: &Stream) -> Result<Option<Frame>, LinkError> {
        loop {
            if self.payload.is_none() && self.filled == HEADER {
                let length = self.declared(1) as usize;
                if length > MAX_PAYLOAD || self.declared(5) as usize > MAX_FDS {
                    return Err(LinkError::Unreadable);
                }
                self.payload = Some(Zeroizing::new(vec![0u8; length]));
                self.filled = 0;
            }
            if self.attached.is_none()
                && self
                    .payload
                    .as_ref()
                    .is_some_and(|payload| payload.len() == self.filled)
            {
                self.attached = Some(vec![0u8; self.declared(5) as usize * sys::ATTACHED]);
                self.filled = 0;
            }
            if let Some(attached) = self
                .attached
                .take_if(|attached| attached.len() == self.filled)
            {
                self.filled = 0;
                let payload = self.payload.take().expect("the payload comes first");
                let mut fds = std::mem::take(&mut self.fds);
                fds.extend(sys::attach(&attached)?);
                if fds.len() != self.declared(5) as usize {
                    return Err(LinkError::Unreadable);
                }
                return Ok(Some(Frame {
                    kind: self.header[0],
                    payload,
                    fds,
                }));
            }
            let buf = match (&mut self.payload, &mut self.attached) {
                (None, _) => &mut self.header[self.filled..],
                (Some(payload), None) => &mut payload[self.filled..],
                (Some(_), Some(attached)) => &mut attached[self.filled..],
            };
            match sys::read_some(stream, buf, &mut self.fds) {
                Ok(0) => return Err(LinkError::Gone),
                Ok(received) => self.filled += received,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None)
                }
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    return Err(LinkError::Unreadable)
                }
                Err(_) => return Err(LinkError::Gone),
            }
        }
    }

    /// The u32 in the header at `at`: the payload length at 1, the descriptor count at 5.
    fn declared(&self, at: usize) -> u32 {
        u32::from_be_bytes(self.header[at..at + 4].try_into().expect("four bytes"))
    }
}

/// A handoff message as a frame.
pub(crate) trait Message: Sized {
    fn encode(self) -> Frame;
    fn decode(frame: Frame) -> Result<Self, LinkError>;
}

impl<Out: Message, In: Message> Link<Out, In> {
    pub(crate) fn over(stream: Stream) -> Self {
        Self {
            stream,
            messages: std::marker::PhantomData,
        }
    }

    pub(crate) fn send(&self, message: Out) -> Result<(), LinkError> {
        send(&self.stream, &message.encode()).map_err(|_| LinkError::Gone)
    }

    /// The next message, waiting until `deadline` or until `abort` returns true.
    pub(crate) fn recv(
        &self,
        deadline: Instant,
        abort: &dyn Fn() -> bool,
    ) -> Result<In, LinkError> {
        In::decode(recv(&self.stream, deadline, abort)?)
    }
}

/// Tells the successor the protocol and the credential key, which it needs before it builds
/// anything that makes digests. The predecessor's first message on the link.
pub(crate) fn introduce(stream: &Stream, credential_key: &[u8; 32]) -> Result<(), LinkError> {
    let mut frame = Frame::new(HELLO);
    let mut out = Writer(&mut frame.payload);
    out.u32(PROTOCOL);
    out.key(credential_key);
    send(stream, &frame).map_err(|_| LinkError::Gone)
}

/// The predecessor's credential key, once it has shown it speaks this protocol.
pub(crate) fn introduced(
    stream: &Stream,
    deadline: Instant,
) -> Result<Zeroizing<[u8; 32]>, LinkError> {
    let frame = recv(stream, deadline, &|| false)?;
    if frame.kind != HELLO || !frame.fds.is_empty() {
        return Err(LinkError::Unreadable);
    }
    let mut input = Reader(&frame.payload);
    if input.u32()? != PROTOCOL {
        return Err(LinkError::Unreadable);
    }
    let key = input.key()?;
    input.finish()?;
    Ok(key)
}

impl Message for FromSuccessor {
    fn encode(self) -> Frame {
        Frame::new(match self {
            FromSuccessor::Request => REQUEST,
            FromSuccessor::Reading => READING,
            FromSuccessor::Ready => READY,
        })
    }

    fn decode(frame: Frame) -> Result<Self, LinkError> {
        if !frame.payload.is_empty() || !frame.fds.is_empty() {
            return Err(LinkError::Unreadable);
        }
        match frame.kind {
            REQUEST => Ok(FromSuccessor::Request),
            READING => Ok(FromSuccessor::Reading),
            READY => Ok(FromSuccessor::Ready),
            _ => Err(LinkError::Unreadable),
        }
    }
}

impl Message for FromPredecessor {
    fn encode(self) -> Frame {
        match self {
            FromPredecessor::Sockets(pool) => encode_sockets(pool),
            FromPredecessor::Released(carried) => encode_released(carried),
        }
    }

    fn decode(frame: Frame) -> Result<Self, LinkError> {
        match frame.kind {
            SOCKETS => decode_sockets(frame).map(FromPredecessor::Sockets),
            RELEASED if frame.fds.is_empty() => {
                decode_released(&frame.payload).map(FromPredecessor::Released)
            }
            _ => Err(LinkError::Unreadable),
        }
    }
}

const UDP: u8 = 0;
const TCP: u8 = 1;

fn encode_sockets(pool: SocketPool) -> Frame {
    let mut frame = Frame::new(SOCKETS);
    let mut out = Writer(&mut frame.payload);
    out.u32(pool.entries.len() as u32);
    for (role, addr, socket) in pool.entries {
        out.u8(role.code());
        out.u8(match socket {
            ListeningSocket::Udp(_) => UDP,
            ListeningSocket::Tcp(_) => TCP,
        });
        out.addr(addr);
        frame.fds.push(match socket {
            ListeningSocket::Udp(socket) => socket.into(),
            ListeningSocket::Tcp(socket) => socket.into(),
        });
    }
    out.u32(pool.dnscrypt_keys.len() as u32);
    for (addr, key) in &pool.dnscrypt_keys {
        out.addr(*addr);
        out.key(key);
    }
    for key in pool.tickets.each() {
        out.optional_key(key.map(|key| &**key));
    }
    frame
}

fn decode_sockets(frame: Frame) -> Result<SocketPool, LinkError> {
    let mut input = Reader(&frame.payload);
    let count = input.u32()? as usize;
    if count != frame.fds.len() {
        return Err(LinkError::Unreadable);
    }
    let mut pool = SocketPool::default();
    for fd in frame.fds {
        let role = SocketRole::from_code(input.u8()?).ok_or(LinkError::Unreadable)?;
        let kind = input.u8()?;
        let addr = input.addr()?;
        let socket = match (kind, sys::socket_type(&fd)?) {
            (UDP, SocketType::Datagram) => ListeningSocket::Udp(fd.into()),
            (TCP, SocketType::Stream) => ListeningSocket::Tcp(fd.into()),
            _ => return Err(LinkError::Unreadable),
        };
        pool.put(role, addr, socket);
    }
    for _ in 0..input.u32()? {
        let addr = input.addr()?;
        pool.put_dnscrypt_key(addr, input.key()?);
    }
    pool.put_ticket_keys(TicketKeys::from_each([
        input.optional_key()?,
        input.optional_key()?,
        input.optional_key()?,
        input.optional_key()?,
    ]));
    input.finish()?;
    Ok(pool)
}

fn encode_released(carried: Carried) -> Frame {
    let mut frame = Frame::new(RELEASED);
    let mut out = Writer(&mut frame.payload);
    out.optional_bytes(carried.stats.as_deref());
    out.optional_bytes(carried.upstreams.as_deref().map(str::as_bytes));
    out.optional_bytes(carried.sessions.as_deref());
    out.optional_bytes(carried.jobs.as_deref().map(str::as_bytes));
    frame
}

fn decode_released(payload: &[u8]) -> Result<Carried, LinkError> {
    let mut input = Reader(payload);
    let carried = Carried {
        stats: input.optional_bytes()?,
        upstreams: input.optional_text()?,
        sessions: input.optional_bytes()?,
        jobs: input.optional_text()?,
    };
    input.finish()?;
    Ok(carried)
}

impl SocketRole {
    fn code(self) -> u8 {
        match self {
            SocketRole::Do53 => 0,
            SocketRole::Dot => 1,
            SocketRole::Doh => 2,
            SocketRole::Doq => 3,
            SocketRole::Doh3 => 4,
            SocketRole::Dnscrypt => 5,
            SocketRole::Control => 6,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => SocketRole::Do53,
            1 => SocketRole::Dot,
            2 => SocketRole::Doh,
            3 => SocketRole::Doq,
            4 => SocketRole::Doh3,
            5 => SocketRole::Dnscrypt,
            6 => SocketRole::Control,
            _ => return None,
        })
    }
}

/// Big-endian numbers; byte strings carry a u32 length.
pub(crate) struct Writer<'a>(pub(crate) &'a mut Vec<u8>);

impl Writer<'_> {
    pub(crate) fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.0.extend_from_slice(value);
    }

    fn key(&mut self, key: &[u8; 32]) {
        self.0.extend_from_slice(key);
    }

    fn optional_key(&mut self, key: Option<&[u8; 32]>) {
        match key {
            None => self.u8(0),
            Some(key) => {
                self.u8(1);
                self.key(key);
            }
        }
    }

    fn optional_bytes(&mut self, value: Option<&[u8]>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.bytes(value);
            }
        }
    }

    /// The scope and flow label of IPv6 addresses are kept: listeners match addresses exactly.
    fn addr(&mut self, addr: SocketAddr) {
        match addr {
            SocketAddr::V4(addr) => {
                self.u8(4);
                self.0.extend_from_slice(&addr.ip().octets());
                self.0.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                self.u8(6);
                self.0.extend_from_slice(&addr.ip().octets());
                self.0.extend_from_slice(&addr.port().to_be_bytes());
                self.u32(addr.flowinfo());
                self.u32(addr.scope_id());
            }
        }
    }
}

/// Fails on anything short, unknown, or left over.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], LinkError> {
        if self.0.len() < len {
            return Err(LinkError::Unreadable);
        }
        let (taken, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(taken)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, LinkError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, LinkError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], LinkError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn key(&mut self) -> Result<Zeroizing<[u8; 32]>, LinkError> {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(self.take(32)?);
        Ok(key)
    }

    fn present(&mut self) -> Result<bool, LinkError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(LinkError::Unreadable),
        }
    }

    fn optional_key(&mut self) -> Result<Option<Zeroizing<[u8; 32]>>, LinkError> {
        if self.present()? {
            self.key().map(Some)
        } else {
            Ok(None)
        }
    }

    fn optional_bytes(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        if self.present()? {
            self.bytes().map(|bytes| Some(bytes.to_vec()))
        } else {
            Ok(None)
        }
    }

    fn optional_text(&mut self) -> Result<Option<String>, LinkError> {
        match self.optional_bytes()? {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| LinkError::Unreadable),
        }
    }

    fn addr(&mut self) -> Result<SocketAddr, LinkError> {
        match self.u8()? {
            4 => {
                let ip: [u8; 4] = self.take(4)?.try_into().expect("four bytes");
                let port = u16::from_be_bytes(self.take(2)?.try_into().expect("two bytes"));
                Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            6 => {
                let ip: [u8; 16] = self.take(16)?.try_into().expect("sixteen bytes");
                let port = u16::from_be_bytes(self.take(2)?.try_into().expect("two bytes"));
                let flowinfo = self.u32()?;
                let scope_id = self.u32()?;
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    flowinfo,
                    scope_id,
                )))
            }
            _ => Err(LinkError::Unreadable),
        }
    }

    pub(crate) fn finish(self) -> Result<(), LinkError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(LinkError::Unreadable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn frame(kind: u8, payload: &str, fds: Vec<Passed>) -> Frame {
        Frame {
            kind,
            payload: Zeroizing::new(hex(payload)),
            fds,
        }
    }

    const RELEASED_BYTES: &str = "01 00000002 0102  01 00000002 7b7d  00  01 00000001 5b";

    fn sockets_bytes() -> String {
        format!(
            "00000002
             00 00 04 7f000001 0035
             06 01 06 {} 1f40 00000000 00000003
             00000001 04 c0000201 0d05 {}
             01 {} 00 00 01 {}",
            "00".repeat(15) + "01",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        )
    }

    fn sockets_frame() -> Frame {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        frame(SOCKETS, &sockets_bytes(), vec![udp.into(), tcp.into()])
    }

    #[test]
    /// A change to these bytes is a change to the handoff protocol.
    fn the_messages_read_and_write_fixed_bytes() {
        for (kind, message) in [
            (2, FromSuccessor::Request),
            (3, FromSuccessor::Reading),
            (4, FromSuccessor::Ready),
        ] {
            assert_eq!(
                FromSuccessor::decode(frame(kind, "", Vec::new())).unwrap(),
                message
            );
            let written = message.encode();
            assert_eq!((written.kind, written.payload.len()), (kind, 0));
        }

        for (kind, fixed) in [
            (RELEASED, frame(RELEASED, RELEASED_BYTES, Vec::new())),
            (SOCKETS, sockets_frame()),
        ] {
            let bytes = fixed.payload.to_vec();
            let fds = fixed.fds.len();
            let written = FromPredecessor::decode(fixed).unwrap().encode();
            assert_eq!(
                (written.kind, written.payload.to_vec(), written.fds.len()),
                (kind, bytes, fds)
            );
        }

        let released = frame(RELEASED, RELEASED_BYTES, Vec::new());
        let Ok(FromPredecessor::Released(carried)) = FromPredecessor::decode(released) else {
            panic!("not a release");
        };
        assert_eq!(carried.stats, Some(vec![1, 2]));
        assert_eq!(carried.upstreams.as_deref(), Some("{}"));
        assert_eq!(carried.sessions, None);
        assert_eq!(carried.jobs.as_deref(), Some("["));

        let Ok(FromPredecessor::Sockets(mut pool)) = FromPredecessor::decode(sockets_frame())
        else {
            panic!("not sockets");
        };
        assert_eq!(
            pool.take_udp(SocketRole::Do53, "127.0.0.1:53".parse().unwrap())
                .len(),
            1
        );
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8000, 0, 3));
        assert_eq!(pool.take_tcp(SocketRole::Control, v6).len(), 1);
        assert!(pool.is_empty());
        assert_eq!(
            *pool
                .take_dnscrypt_key("192.0.2.1:3333".parse().unwrap())
                .unwrap(),
            [0x11; 32]
        );
        let [dot, doh, doq, doh3] = pool
            .take_ticket_keys()
            .each()
            .map(|key| key.map(|key| **key));
        assert_eq!(
            (dot, doh, doq, doh3),
            (Some([0x22; 32]), None, None, Some([0x33; 32]))
        );
    }

    #[test]
    fn messages_off_the_format_are_unreadable() {
        let udp = || -> Passed { UdpSocket::bind("127.0.0.1:0").unwrap().into() };
        let entry = "00000001 00 00 04 7f000001 0035 00000000 00 00 00 00";
        let cases = [
            ("payload on a step", frame(2, "00", Vec::new())),
            ("unknown kind", frame(9, "", Vec::new())),
            ("short", frame(6, "01 00000002 01", Vec::new())),
            ("left over", frame(6, "00 00 00 00 00", Vec::new())),
            ("presence not 0 or 1", frame(6, "02 00 00 00", Vec::new())),
            (
                "text not UTF-8",
                frame(6, "00 01 00000001 ff 00 00", Vec::new()),
            ),
            (
                "descriptor on a release",
                frame(6, "00 00 00 00", vec![udp()]),
            ),
            ("fewer descriptors", frame(5, entry, Vec::new())),
            (
                "TCP entry on a UDP socket",
                frame(5, &entry.replacen("00 00 04", "00 01 04", 1), vec![udp()]),
            ),
            (
                "unknown role",
                frame(5, &entry.replacen("00 00 04", "07 00 04", 1), vec![udp()]),
            ),
            (
                "unknown family",
                frame(5, &entry.replacen("00 00 04", "00 00 05", 1), vec![udp()]),
            ),
        ];
        for (case, frame) in cases {
            let decoded = if frame.kind <= READY {
                FromSuccessor::decode(frame).map(|_| ())
            } else {
                FromPredecessor::decode(frame).map(|_| ())
            };
            assert_eq!(decoded, Err(LinkError::Unreadable), "{case}");
        }
    }

    #[test]
    /// Sockets beyond what one sendmsg may carry still arrive with their frame, and the next frame
    /// keeps its own.
    fn many_descriptors_arrive_with_their_frame() {
        let (a, b) = stream_pair();
        let sockets: Vec<UdpSocket> = (0..300)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<u16> = sockets
            .iter()
            .map(|socket| socket.local_addr().unwrap().port())
            .collect();
        let mut first = Frame::new(SOCKETS);
        first.payload = Zeroizing::new(vec![7; 1000]);
        first.fds = sockets.into_iter().map(Passed::from).collect();
        let mut second = Frame::new(RELEASED);
        second
            .fds
            .push(UdpSocket::bind("127.0.0.1:0").unwrap().into());
        let sender = std::thread::spawn(move || {
            send(&a, &first).unwrap();
            send(&a, &second).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let got = recv(&b, deadline, &|| false).unwrap();
        assert_eq!(*got.payload, vec![7; 1000]);
        let got_ports: Vec<u16> = got
            .fds
            .into_iter()
            .map(|fd| UdpSocket::from(fd).local_addr().unwrap().port())
            .collect();
        assert_eq!(got_ports, ports);
        assert_eq!(recv(&b, deadline, &|| false).unwrap().fds.len(), 1);
        sender.join().unwrap();
    }

    #[test]
    fn a_closed_peer_and_a_missing_reply_are_told_apart() {
        let (a, b) = stream_pair();
        let soon = Instant::now() + Duration::from_millis(50);
        assert!(matches!(
            recv(&b, soon, &|| false),
            Err(LinkError::TimedOut)
        ));
        let later = Instant::now() + Duration::from_secs(10);
        assert!(matches!(recv(&b, later, &|| true), Err(LinkError::Aborted)));
        drop(a);
        assert!(matches!(recv(&b, later, &|| false), Err(LinkError::Gone)));
    }

    #[test]
    fn the_successor_learns_the_key_only_under_the_same_protocol() {
        let (a, b) = stream_pair();
        let deadline = Instant::now() + Duration::from_secs(10);
        introduce(&a, &[5; 32]).unwrap();
        assert_eq!(*introduced(&b, deadline).unwrap(), [5; 32]);

        let fixed = frame(HELLO, &format!("00000001 {}", "05".repeat(32)), Vec::new());
        send(&a, &fixed).unwrap();
        assert_eq!(*introduced(&b, deadline).unwrap(), [5; 32]);

        let other = frame(HELLO, &format!("00000002 {}", "05".repeat(32)), Vec::new());
        send(&a, &other).unwrap();
        assert!(matches!(
            introduced(&b, deadline),
            Err(LinkError::Unreadable)
        ));
    }
}
