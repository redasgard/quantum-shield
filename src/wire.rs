//! Shared helpers for the v2 wire header.
//!
//! Every serialized object starts with `magic[4] || version: u8 || suite: u8`.

use crate::constants::{HEADER_LEN, SUITE_ID, WIRE_VERSION};
use crate::error::{Error, Result};
use alloc::vec::Vec;

/// Append the 6-byte header for `magic` to `out`.
pub(crate) fn write_header(out: &mut Vec<u8>, magic: [u8; 4]) {
    out.extend_from_slice(&magic);
    out.push(WIRE_VERSION);
    out.push(SUITE_ID);
}

/// Validate the 6-byte header at the start of `bytes`.
///
/// Returns the remaining payload on success. `bad_magic` is the error used
/// when the input is not this object type at all; v1 JSON artifacts are
/// detected and reported as [`Error::LegacyV1Artifact`].
pub(crate) fn read_header(bytes: &[u8], magic: [u8; 4], bad_magic: Error) -> Result<&[u8]> {
    // quantum-shield 0.1.x serialized everything as JSON objects.
    if bytes.first() == Some(&b'{') {
        return Err(Error::LegacyV1Artifact);
    }
    if bytes.len() < HEADER_LEN {
        return Err(bad_magic);
    }
    if bytes[..4] != magic {
        return Err(bad_magic);
    }
    if bytes[4] != WIRE_VERSION {
        return Err(Error::UnsupportedVersion(bytes[4]));
    }
    if bytes[5] != SUITE_ID {
        return Err(Error::UnsupportedSuite(bytes[5]));
    }
    Ok(&bytes[HEADER_LEN..])
}

/// Split a fixed-size array off the front of `input`, or fail with `err`.
pub(crate) fn take<const N: usize>(input: &mut &[u8], err: Error) -> Result<[u8; N]> {
    if input.len() < N {
        return Err(err);
    }
    let (head, rest) = input.split_at(N);
    *input = rest;
    Ok(head.try_into().expect("split_at guarantees length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAGIC_ENVELOPE;

    #[test]
    fn header_roundtrip() {
        let mut buf = Vec::new();
        write_header(&mut buf, MAGIC_ENVELOPE);
        buf.extend_from_slice(b"payload");
        let rest = read_header(&buf, MAGIC_ENVELOPE, Error::InvalidEnvelope).unwrap();
        assert_eq!(rest, b"payload");
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut buf = Vec::new();
        write_header(&mut buf, MAGIC_ENVELOPE);
        assert_eq!(
            read_header(&buf, *b"QSS2", Error::InvalidSignature),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn rejects_unknown_version_and_suite() {
        let mut buf = Vec::new();
        write_header(&mut buf, MAGIC_ENVELOPE);
        buf[4] = 3;
        assert_eq!(
            read_header(&buf, MAGIC_ENVELOPE, Error::InvalidEnvelope),
            Err(Error::UnsupportedVersion(3))
        );
        buf[4] = WIRE_VERSION;
        buf[5] = 0;
        assert_eq!(
            read_header(&buf, MAGIC_ENVELOPE, Error::InvalidEnvelope),
            Err(Error::UnsupportedSuite(0))
        );
    }

    #[test]
    fn detects_v1_json() {
        let v1 = br#"{"version":1,"ciphertext":"..."}"#;
        assert_eq!(
            read_header(v1, MAGIC_ENVELOPE, Error::InvalidEnvelope),
            Err(Error::LegacyV1Artifact)
        );
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(
            read_header(b"QSE", MAGIC_ENVELOPE, Error::InvalidEnvelope),
            Err(Error::InvalidEnvelope)
        );
    }
}
