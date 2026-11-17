//! The channel between the supervisor and a worker process it started: one link per worker. The
//! worker finds its end through `CHANNEL_ENV`, speaks first with its protocol and version, and
//! starts the way the supervisor answers: on its own, or taking over from the worker it succeeds.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::MutexExt;

use super::sys;
use crate::error::BoxResult;
use crate::handoff::wire::{self, Frame, Reader, Stream, Writer, PROTOCOL};
use crate::handoff::LinkError;
use crate::update::VERSION;

/// Names the worker's end: a descriptor on Unix, a handle on Windows.
pub(super) const CHANNEL_ENV: &str = "ONETDNS_SUPERVISOR_CHANNEL";

/// Worker to supervisor. Its layout stays the same in every protocol, so a supervisor can turn
/// away a worker that speaks another one.
pub(super) const HELLO: u8 = 0x10;
pub(super) const READY: u8 = 0x11;
/// Asks for a successor to take over, after an update was swapped in.
pub(super) const SUCCESSOR: u8 = 0x12;

/// Supervisor to worker: start on your own.
pub(super) const RUN: u8 = 0x20;
/// Start as a successor; carries the link to the predecessor.
pub(super) const TAKE_OVER: u8 = 0x21;
/// Answers SUCCESSOR; carries the link to the successor.
pub(super) const LINK: u8 = 0x22;
/// Answers SUCCESSOR: no successor will come, so restart the way a process without one does. Carries
/// the reason.
pub(super) const NO_SUCCESSOR: u8 = 0x23;
/// The successor is ready and its version committed; the predecessor ends.
pub(super) const END: u8 = 0x24;
/// The successor failed and the update was put back; the predecessor serves on. Answers SUCCESSOR,
/// or follows LINK.
pub(super) const CANCEL: u8 = 0x25;

/// The supervisor answers within one poll, so this only bounds a supervisor that stopped working.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// Starting the successor and putting it on trial comes before the answer to SUCCESSOR.
const SUCCESSOR_WAIT: Duration = Duration::from_secs(120);

pub(super) struct Hello {
    pub(super) protocol: u32,
    pub(super) version: String,
}

impl Hello {
    fn own() -> Frame {
        let mut frame = Frame::new(HELLO);
        let mut out = Writer(&mut frame.payload);
        out.u32(PROTOCOL);
        out.bytes(VERSION.as_bytes());
        frame
    }

    pub(super) fn read(frame: &Frame) -> Result<Self, LinkError> {
        if frame.kind != HELLO || !frame.fds.is_empty() {
            return Err(LinkError::Unreadable);
        }
        let mut input = Reader(&frame.payload);
        let protocol = input.u32()?;
        let version =
            String::from_utf8(input.bytes()?.to_vec()).map_err(|_| LinkError::Unreadable)?;
        input.finish()?;
        Ok(Self { protocol, version })
    }
}

/// True for a frame of `kind` with nothing in it.
pub(super) fn is_bare(frame: &Frame, kind: u8) -> bool {
    frame.kind == kind && frame.payload.is_empty() && frame.fds.is_empty()
}

pub(super) fn no_successor(reason: &str) -> Frame {
    let mut frame = Frame::new(NO_SUCCESSOR);
    Writer(&mut frame.payload).bytes(reason.as_bytes());
    frame
}

fn read_reason(frame: &Frame) -> Result<String, LinkError> {
    let mut input = Reader(&frame.payload);
    let reason = String::from_utf8(input.bytes()?.to_vec()).map_err(|_| LinkError::Unreadable)?;
    input.finish()?;
    Ok(reason)
}

/// This worker's end, kept for the life of the process. A request holds the lock until its answer
/// arrives.
static CHANNEL: OnceLock<Mutex<Stream>> = OnceLock::new();

pub(super) enum Start {
    Fresh,
    /// The link to the worker this one takes over from.
    Successor(Stream),
}

/// Introduces this process to the supervisor that started it and waits for its answer. None when
/// no supervisor started it.
pub(super) fn join() -> BoxResult<Option<Start>> {
    let Ok(named) = std::env::var(CHANNEL_ENV) else {
        return Ok(None);
    };
    std::env::remove_var(CHANNEL_ENV);
    let stream = sys::adopt(&named)?;
    wire::send(&stream, &Hello::own()).map_err(|error| {
        crate::anyhow!(format!(
            "Could not introduce this process to the supervisor: {error}"
        ))
    })?;
    let answer = wire::recv(&stream, Instant::now() + ANSWER_WAIT, &|| false)
        .map_err(|error| crate::anyhow!(format!("The supervisor did not answer: {error}")))?;
    let start = match answer.kind {
        RUN if is_bare(&answer, RUN) => Start::Fresh,
        TAKE_OVER => Start::Successor(sys::take_stream(answer).map_err(|error| {
            crate::anyhow!(format!("The supervisor's answer is unreadable: {error}"))
        })?),
        _ => {
            return Err(crate::anyhow!(
                "The supervisor answered with a message this version does not know"
            ))
        }
    };
    let _ = CHANNEL.set(Mutex::new(stream));
    Ok(Some(start))
}

fn channel() -> std::io::Result<&'static Mutex<Stream>> {
    CHANNEL.get().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotConnected, "No supervisor channel")
    })
}

/// Tells the supervisor this process is ready.
pub(super) fn ready() -> std::io::Result<()> {
    wire::send(&channel()?.lock_recover(), &Frame::new(READY))
}

pub(super) enum Reply {
    /// The link to the successor, which waits for this process to introduce itself.
    Link(Stream),
    /// Restart the way a process without a successor does.
    Fallback(String),
    /// The successor failed and the update was put back.
    Cancelled,
}

/// Asks the supervisor for a successor and waits for its answer.
pub(super) fn request_successor() -> Result<Reply, String> {
    let channel = channel().map_err(|error| error.to_string())?;
    let channel = channel.lock_recover();
    wire::send(&channel, &Frame::new(SUCCESSOR))
        .map_err(|error| format!("Could not ask the supervisor: {error}"))?;
    let answer = wire::recv(&channel, Instant::now() + SUCCESSOR_WAIT, &|| false)
        .map_err(|error| format!("The supervisor did not answer: {error}"))?;
    let unreadable = |error: LinkError| format!("The supervisor's answer is unreadable: {error}");
    match answer.kind {
        LINK => sys::take_stream(answer)
            .map(Reply::Link)
            .map_err(unreadable),
        NO_SUCCESSOR => read_reason(&answer)
            .map(Reply::Fallback)
            .map_err(unreadable),
        CANCEL if is_bare(&answer, CANCEL) => Ok(Reply::Cancelled),
        _ => Err(unreadable(LinkError::Unreadable)),
    }
}

/// After handing over, whether this process ends: END says so, CANCEL says it serves on. Without
/// an answer it goes by `handed`, whether the successor said it runs everything.
pub(super) fn settle(handed: bool, abort: &dyn Fn() -> bool) -> bool {
    let Ok(channel) = channel() else {
        return handed;
    };
    let deadline = Instant::now() + crate::update::trial::TRIAL_DEADLINE;
    match wire::recv(&channel.lock_recover(), deadline, abort) {
        Ok(frame) if is_bare(&frame, END) => true,
        Ok(frame) if is_bare(&frame, CANCEL) => false,
        Ok(frame) => {
            onetdns_core::warn!(
                event = "handoff.unexpected_answer",
                kind = frame.kind,
                "The supervisor answered the handoff with a message this version does not know"
            );
            handed
        }
        Err(error) => {
            onetdns_core::warn!(event = "handoff.no_answer", %error, "The supervisor did not say how the handoff ended");
            handed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// A change to these bytes is a change to the handoff protocol; every supervisor reads the
    /// hello first.
    fn the_messages_read_and_write_fixed_bytes() {
        let own = Hello::own();
        let mut expected = PROTOCOL.to_be_bytes().to_vec();
        expected.extend_from_slice(&(VERSION.len() as u32).to_be_bytes());
        expected.extend_from_slice(VERSION.as_bytes());
        assert_eq!((own.kind, own.payload.to_vec()), (0x10, expected));

        let mut fixed = Frame::new(HELLO);
        fixed
            .payload
            .extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 5, b'1', b'.', b'2', b'.', b'3']);
        let hello = Hello::read(&fixed).unwrap();
        assert_eq!((hello.protocol, hello.version.as_str()), (7, "1.2.3"));
        fixed.payload.push(0);
        assert!(Hello::read(&fixed).is_err());

        assert_eq!(
            [
                READY,
                SUCCESSOR,
                RUN,
                TAKE_OVER,
                LINK,
                NO_SUCCESSOR,
                END,
                CANCEL
            ],
            [0x11, 0x12, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25]
        );
        let refusal = no_successor("memory");
        assert_eq!(
            *refusal.payload,
            [0, 0, 0, 6, b'm', b'e', b'm', b'o', b'r', b'y']
        );
        assert_eq!(read_reason(&refusal).unwrap(), "memory");
    }
}
