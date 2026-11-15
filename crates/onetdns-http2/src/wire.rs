use std::io::{Read, Write};

use crate::frame::{self, flags, FrameHeader, DEFAULT_MAX_FRAME, FRAME_HEADER_LEN};
use crate::H2Error;

/// Checks the length cap before allocating the payload; trusting the declared length would let one
/// 9-byte header allocate 16 MiB.
pub(crate) fn read_frame<S: Read>(stream: &mut S) -> Result<(FrameHeader, Vec<u8>), H2Error> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(H2Error::Closed),
        Err(_) => return Err(H2Error::Io),
    }
    let h = FrameHeader::parse(&hdr).ok_or(H2Error::Protocol)?;
    if h.length as usize > DEFAULT_MAX_FRAME {
        return Err(H2Error::Protocol);
    }
    let mut payload = vec![0u8; h.length as usize];
    read_exact(stream, &mut payload)?;
    Ok((h, payload))
}

/// Header and payload go out in one write.
pub(crate) fn send_frame<S: Write>(
    stream: &mut S,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), H2Error> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame::write_frame(&mut buf, frame_type, flags, stream_id, payload);
    stream.write_all(&buf).map_err(|_| H2Error::Io)
}

/// Distinguishes a closed connection from other errors.
pub(crate) fn read_exact<S: Read>(stream: &mut S, buf: &mut [u8]) -> Result<(), H2Error> {
    match stream.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(H2Error::Closed),
        Err(_) => Err(H2Error::Io),
    }
}

/// Removes padding and priority fields from a HEADERS payload, leaving the header block. A pad
/// length larger than the remaining payload is refused instead of underflowing.
pub(crate) fn strip_headers(payload: &[u8], fl: u8) -> Result<&[u8], H2Error> {
    let mut p = payload;
    let mut pad = 0usize;
    if fl & flags::PADDED != 0 {
        pad = *p.first().ok_or(H2Error::Protocol)? as usize;
        p = &p[1..];
    }
    if fl & flags::PRIORITY != 0 {
        if p.len() < 5 {
            return Err(H2Error::Protocol);
        }
        p = &p[5..];
    }
    if pad > p.len() {
        return Err(H2Error::Protocol);
    }
    Ok(&p[..p.len() - pad])
}

/// Removes padding from a DATA payload, with the same length check as `strip_headers`.
pub(crate) fn strip_padding(payload: &[u8], fl: u8) -> Result<&[u8], H2Error> {
    if fl & flags::PADDED == 0 {
        return Ok(payload);
    }
    let pad = *payload.first().ok_or(H2Error::Protocol)? as usize;
    let body = &payload[1..];
    if pad > body.len() {
        return Err(H2Error::Protocol);
    }
    Ok(&body[..body.len() - pad])
}

#[cfg(test)]
pub(crate) fn header<'a>(headers: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
}
