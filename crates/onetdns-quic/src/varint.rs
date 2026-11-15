//! QUIC variable-length integers. The top two bits of the first byte give the length: 1, 2, 4 or 8
//! bytes.
//!
//! Reading accepts non-minimal encodings; writing always uses the shortest one.

/// Returns the value and the bytes consumed; None when truncated.
pub fn read(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let mut val = (first & 0x3f) as u64;
    for i in 1..len {
        val = (val << 8) | *buf.get(i)? as u64;
    }
    Some((val, len))
}

pub fn write(out: &mut Vec<u8>, v: u64) {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < (1 << 30) {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

pub fn len(v: u64) -> usize {
    if v < (1 << 6) {
        1
    } else if v < (1 << 14) {
        2
    } else if v < (1 << 30) {
        4
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9000_examples() {
        let mut o = Vec::new();
        write(&mut o, 151_288_809_941_952_652);
        assert_eq!(o, vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        assert_eq!(read(&o).unwrap(), (151_288_809_941_952_652, 8));

        let mut o = Vec::new();
        write(&mut o, 494_878_333);
        assert_eq!(o, vec![0x9d, 0x7f, 0x3e, 0x7d]);

        let mut o = Vec::new();
        write(&mut o, 15293);
        assert_eq!(o, vec![0x7b, 0xbd]);

        let mut o = Vec::new();
        write(&mut o, 37);
        assert_eq!(o, vec![0x25]);
        assert_eq!(read(&[0x25]).unwrap(), (37, 1));
    }

    #[test]
    fn roundtrip_boundaries() {
        for v in [
            0u64,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut o = Vec::new();
            write(&mut o, v);
            assert_eq!(o.len(), len(v));
            assert_eq!(read(&o).unwrap(), (v, len(v)));
        }
    }

    #[test]
    fn two_byte_decode_value_masks_prefix() {
        assert_eq!(read(&[0x7b, 0xbd]).unwrap(), (15293, 2));
    }
}
