//! Length-prefixed frame read/write over arbitrary streams.

use std::io::{Read, Write};

use crate::error::TransportError;

/// Map an I/O error from a timed socket operation onto
/// [`TransportError::Timeout`] when the OS reports a timeout.
pub(crate) fn map_timeout_io(e: std::io::Error, op: &'static str) -> TransportError {
    if matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ) {
        TransportError::Timeout { op }
    } else {
        TransportError::Io(e)
    }
}

/// Default maximum frame payload size: 1 MiB.
///
/// Large enough for any realistic command payload, small enough that a
/// hostile length prefix cannot cause an unbounded allocation.
pub const DEFAULT_MAX_FRAME_SIZE: u64 = 1024 * 1024;

/// Limits governing frame reads/writes.
#[derive(Debug, Clone, Copy)]
pub struct FrameLimits {
    /// Maximum accepted payload size in bytes.
    pub max_frame_size: u64,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

impl FrameLimits {
    /// Create limits with an explicit maximum payload size.
    #[must_use]
    pub const fn new(max_frame_size: u64) -> Self {
        Self { max_frame_size }
    }
}

/// Write one length-prefixed frame: `[u32 BE len][payload]`.
///
/// # Errors
///
/// Returns [`TransportError::Io`] on write failure, or
/// [`TransportError::FrameTooLarge`] if `payload` exceeds the limit
/// (checked before any bytes are written).
pub fn write_frame(
    stream: &mut impl Write,
    payload: &[u8],
    limits: FrameLimits,
) -> Result<(), TransportError> {
    let len = payload.len() as u64;
    if len > limits.max_frame_size {
        return Err(TransportError::FrameTooLarge {
            size: len,
            max: limits.max_frame_size,
        });
    }
    // len ≤ max_frame_size ≤ u32::MAX is guaranteed by callers using the
    // default/reasonable limits; enforce explicitly for safety.
    let len_u32 = u32::try_from(len).map_err(|_| TransportError::FrameTooLarge {
        size: len,
        max: u64::from(u32::MAX),
    })?;
    stream
        .write_all(&len_u32.to_be_bytes())
        .and_then(|()| stream.write_all(payload))
        .and_then(|()| stream.flush())
        .map_err(|e| map_timeout_io(e, "write"))?;
    Ok(())
}

/// Read one length-prefixed frame.
///
/// The length prefix is validated against `limits` **before** allocating the
/// payload buffer, so a hostile `0xFFFFFFFF` prefix causes an immediate
/// [`TransportError::FrameTooLarge`] rather than a 4 GiB allocation attempt.
///
/// # Errors
///
/// - [`TransportError::UnexpectedEof`] if the stream ends mid-frame.
/// - [`TransportError::FrameTooLarge`] if the length exceeds the limit.
/// - [`TransportError::Io`] on other read failures.
pub fn read_frame(stream: &mut impl Read, limits: FrameLimits) -> Result<Vec<u8>, TransportError> {
    let mut len_be = [0u8; 4];
    read_exact(stream, &mut len_be)?;
    let len = u64::from(u32::from_be_bytes(len_be));
    if len > limits.max_frame_size {
        return Err(TransportError::FrameTooLarge {
            size: len,
            max: limits.max_frame_size,
        });
    }
    let cap = usize::try_from(len).map_err(|_| TransportError::FrameTooLarge {
        size: len,
        max: usize::MAX as u64,
    })?;
    let mut buf = vec![0u8; cap];
    read_exact(stream, &mut buf)?;
    Ok(buf)
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8]) -> Result<(), TransportError> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(TransportError::UnexpectedEof),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(map_timeout_io(e, "read")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const LIMITS: FrameLimits = FrameLimits::new(1024);

    #[test]
    fn roundtrip_single_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello", LIMITS).unwrap();
        let mut cur = Cursor::new(buf);
        let payload = read_frame(&mut cur, LIMITS).unwrap();
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn roundtrip_empty_payload() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"", LIMITS).unwrap();
        assert_eq!(buf.len(), 4);
        let mut cur = Cursor::new(buf);
        assert_eq!(read_frame(&mut cur, LIMITS).unwrap(), b"");
    }

    #[test]
    fn roundtrip_multiple_frames_sequential() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"one", LIMITS).unwrap();
        write_frame(&mut buf, b"two", LIMITS).unwrap();
        write_frame(&mut buf, b"", LIMITS).unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_frame(&mut cur, LIMITS).unwrap(), b"one");
        assert_eq!(read_frame(&mut cur, LIMITS).unwrap(), b"two");
        assert_eq!(read_frame(&mut cur, LIMITS).unwrap(), b"");
        assert!(read_frame(&mut cur, LIMITS).is_err());
    }

    #[test]
    fn write_rejects_oversized_payload_before_writing() {
        let mut buf = Vec::new();
        let big = vec![0u8; 2048];
        let err = write_frame(&mut buf, &big, LIMITS).unwrap_err();
        assert!(matches!(err, TransportError::FrameTooLarge { .. }));
        assert!(buf.is_empty(), "nothing should be written on rejection");
    }

    #[test]
    fn read_rejects_hostile_length_prefix_without_allocating() {
        // Prefix claims 0xFFFFFFFF (4 GiB-1) — must fail fast.
        let mut input = Vec::new();
        input.extend_from_slice(&u32::MAX.to_be_bytes());
        input.extend_from_slice(&[0u8; 16]); // a little data after, irrelevant
        let mut cur = Cursor::new(input);
        let err = read_frame(&mut cur, LIMITS).unwrap_err();
        match err {
            TransportError::FrameTooLarge { size, max } => {
                assert_eq!(size, u64::from(u32::MAX));
                assert_eq!(max, 1024);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_length_just_over_limit() {
        let mut input = Vec::new();
        input.extend_from_slice(&1025u32.to_be_bytes());
        let mut cur = Cursor::new(input);
        assert!(matches!(
            read_frame(&mut cur, LIMITS),
            Err(TransportError::FrameTooLarge { size: 1025, .. })
        ));
    }

    #[test]
    fn read_accepts_length_exactly_at_limit() {
        let mut buf = Vec::new();
        let payload = vec![0xAB; 1024];
        write_frame(&mut buf, &payload, LIMITS).unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_frame(&mut cur, LIMITS).unwrap(), payload);
    }

    #[test]
    fn read_truncated_length_prefix_is_eof() {
        let mut cur = Cursor::new(vec![0x00u8, 0x01]);
        assert!(matches!(
            read_frame(&mut cur, LIMITS),
            Err(TransportError::UnexpectedEof)
        ));
    }

    #[test]
    fn read_truncated_payload_is_eof() {
        // Says 10 bytes follow, only 3 present.
        let mut input = Vec::new();
        input.extend_from_slice(&10u32.to_be_bytes());
        input.extend_from_slice(b"abc");
        let mut cur = Cursor::new(input);
        assert!(matches!(
            read_frame(&mut cur, LIMITS),
            Err(TransportError::UnexpectedEof)
        ));
    }

    #[test]
    fn read_empty_stream_is_eof() {
        let mut cur = Cursor::new(Vec::new());
        assert!(matches!(
            read_frame(&mut cur, LIMITS),
            Err(TransportError::UnexpectedEof)
        ));
    }

    #[test]
    fn default_limits_are_1mib() {
        assert_eq!(DEFAULT_MAX_FRAME_SIZE, 1024 * 1024);
        assert_eq!(
            FrameLimits::default().max_frame_size,
            DEFAULT_MAX_FRAME_SIZE
        );
    }
}
