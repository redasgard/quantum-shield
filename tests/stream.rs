//! Streaming envelope tests: roundtrips, boundary sizes, and the
//! reorder/truncate/duplicate/corruption tamper suite.

use quantum_shield::{Error, HybridCrypto, StreamSealer, STREAM_CHUNK_SIZE};

/// Seal `data` as a stream, returning (header, chunk frames).
fn seal_stream(recipient: &HybridCrypto, data: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let (mut sealer, header) = StreamSealer::new(recipient.public_keys()).unwrap();
    let mut frames = Vec::new();
    if data.is_empty() {
        frames.push(sealer.seal_chunk(b"", true).unwrap());
    } else {
        let chunks: Vec<&[u8]> = data.chunks(STREAM_CHUNK_SIZE).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;
            frames.push(sealer.seal_chunk(chunk, last).unwrap());
        }
    }
    (header, frames)
}

/// Open a stream, returning the reassembled plaintext.
fn open_stream(
    recipient: &HybridCrypto,
    header: &[u8],
    frames: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let mut opener = recipient.stream_opener(header)?;
    let mut out = Vec::new();
    for frame in frames {
        let (pt, _) = opener.open_chunk(frame)?;
        out.extend_from_slice(&pt);
    }
    opener.finish()?;
    Ok(out)
}

#[test]
fn roundtrip_boundary_sizes() {
    let bob = HybridCrypto::generate().unwrap();
    for size in [
        0,
        1,
        STREAM_CHUNK_SIZE - 1,
        STREAM_CHUNK_SIZE,
        STREAM_CHUNK_SIZE + 1,
        3 * STREAM_CHUNK_SIZE + 123,
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (header, frames) = seal_stream(&bob, &data);
        assert_eq!(
            open_stream(&bob, &header, &frames).unwrap(),
            data,
            "size={size}"
        );
    }
}

#[test]
fn exceeds_single_shot_limit() {
    // 64 MiB + 1: larger than MAX_PLAINTEXT_LEN, so `seal` would reject it, but
    // the stream handles it in chunks.
    let bob = HybridCrypto::generate().unwrap();
    let data = vec![0xABu8; 64 * 1024 * 1024 + 1];
    let (header, frames) = seal_stream(&bob, &data);
    assert!(frames.len() > 1024);
    assert_eq!(open_stream(&bob, &header, &frames).unwrap(), data);
}

#[test]
fn wrong_recipient_fails() {
    let bob = HybridCrypto::generate().unwrap();
    let mallory = HybridCrypto::generate().unwrap();
    let (header, frames) = seal_stream(&bob, b"for bob only");
    // Decapsulation yields a wrong key; the first chunk fails to authenticate.
    let mut opener = mallory.stream_opener(&header).unwrap();
    assert_eq!(
        opener.open_chunk(&frames[0]).unwrap_err(),
        Error::DecryptionFailed
    );
}

#[test]
fn reordering_chunks_fails() {
    let bob = HybridCrypto::generate().unwrap();
    let data: Vec<u8> = (0..3 * STREAM_CHUNK_SIZE).map(|i| i as u8).collect();
    let (header, frames) = seal_stream(&bob, &data);
    assert!(frames.len() >= 3);

    let mut opener = bob.stream_opener(&header).unwrap();
    // Feed chunk 1 where chunk 0 is expected: nonce/AAD index mismatch.
    assert_eq!(
        opener.open_chunk(&frames[1]).unwrap_err(),
        Error::DecryptionFailed
    );
}

#[test]
fn duplicating_a_chunk_fails() {
    let bob = HybridCrypto::generate().unwrap();
    let data: Vec<u8> = (0..3 * STREAM_CHUNK_SIZE).map(|i| i as u8).collect();
    let (header, frames) = seal_stream(&bob, &data);

    let mut opener = bob.stream_opener(&header).unwrap();
    opener.open_chunk(&frames[0]).unwrap();
    // Replaying chunk 0 now fails (opener expects index 1).
    assert_eq!(
        opener.open_chunk(&frames[0]).unwrap_err(),
        Error::DecryptionFailed
    );
}

#[test]
fn truncation_detected_at_finish() {
    let bob = HybridCrypto::generate().unwrap();
    let data: Vec<u8> = (0..3 * STREAM_CHUNK_SIZE).map(|i| i as u8).collect();
    let (header, frames) = seal_stream(&bob, &data);

    let mut opener = bob.stream_opener(&header).unwrap();
    // Consume all but the final chunk, then finish without it.
    for frame in &frames[..frames.len() - 1] {
        opener.open_chunk(frame).unwrap();
    }
    assert_eq!(opener.finish().unwrap_err(), Error::StreamTruncated);
}

#[test]
fn corrupting_a_chunk_fails_only_that_chunk() {
    let bob = HybridCrypto::generate().unwrap();
    let data: Vec<u8> = (0..2 * STREAM_CHUNK_SIZE).map(|i| i as u8).collect();
    let (header, mut frames) = seal_stream(&bob, &data);

    // Flip a ciphertext byte in the first chunk.
    let n = frames[0].len();
    frames[0][n - 1] ^= 0x01;

    let mut opener = bob.stream_opener(&header).unwrap();
    assert_eq!(
        opener.open_chunk(&frames[0]).unwrap_err(),
        Error::DecryptionFailed
    );
}

#[test]
fn seal_after_last_is_rejected() {
    let bob = HybridCrypto::generate().unwrap();
    let (mut sealer, _header) = StreamSealer::new(bob.public_keys()).unwrap();
    sealer.seal_chunk(b"final", true).unwrap();
    assert_eq!(
        sealer.seal_chunk(b"extra", false).unwrap_err(),
        Error::StreamFinished
    );
}

#[test]
fn swapping_last_flag_fails() {
    // A non-final chunk cannot be passed off as final (the last-flag is in both
    // the nonce and the AAD).
    let bob = HybridCrypto::generate().unwrap();
    let data: Vec<u8> = (0..2 * STREAM_CHUNK_SIZE).map(|i| i as u8).collect();
    let (header, mut frames) = seal_stream(&bob, &data);
    frames[0][0] = 1; // claim chunk 0 is the last chunk
    let mut opener = bob.stream_opener(&header).unwrap();
    assert_eq!(
        opener.open_chunk(&frames[0]).unwrap_err(),
        Error::DecryptionFailed
    );
}
