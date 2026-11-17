//! The request-body read: the body is read whole from the bytes already buffered and then the
//! stream, framed by what the head declared (`Head::content_length`), and the bytes after it
//! stay in the buffer for the next request. Every failure is `Error when parsing request` (400),
//! except a deadline that passes while waiting for the bytes of a fixed-length read or for the
//! digits of a chunk size, which is answered `408 Request timeout`, and a trailer block that
//! does not fit the read buffer (431); [`BodyState::timeout_is_408`] and
//! [`BodyState::too_big`] tell the caller which one it was.

use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::head_parser::{self, HeadError};

/// A request body: the bytes and the trailers a chunked body carried.
#[derive(Default)]
pub struct Body {
    pub data: Vec<u8>,
    pub trailers: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Where a read stands, for the caller to classify a deadline that passed meanwhile.
#[derive(Default)]
pub struct BodyState {
    in_raw_read: AtomicBool,
    small_buffer: AtomicBool,
    silent_eof: AtomicBool,
}

impl BodyState {
    /// The deadline passed while waiting for a fixed-length read or a chunk size: 408, else 400.
    pub fn timeout_is_408(&self) -> bool {
        self.in_raw_read.load(Ordering::Relaxed)
    }

    /// The stream ended where a chunk size should start (a closed connection): no answer, the
    /// connection just ends.
    pub fn closed_silently(&self) -> bool {
        self.silent_eof.load(Ordering::Relaxed)
    }

    /// The read failed because the trailers did not fit the read buffer: answered
    /// `431 Too big request header` instead of 400.
    pub fn too_big(&self) -> bool {
        self.small_buffer.load(Ordering::Relaxed)
    }
}

/// The most hex digits a chunk size may have.
const MAX_HEX_CHARS: usize = 15;

struct Rd<'a, R> {
    io: &'a mut R,
    buffer: &'a mut BytesMut,
    /// The read buffer size: what a trailer block may take from its first byte.
    cap: usize,
}

impl<R: AsyncRead + Unpin> Rd<'_, R> {
    /// Reads more bytes; end of stream or an I/O error is `Err`.
    async fn fill(&mut self) -> Result<(), ()> {
        self.buffer.reserve(8192);
        match self.io.read_buf(self.buffer).await {
            Ok(n) if n > 0 => Ok(()),
            _ => Err(()),
        }
    }

    async fn peek(&mut self) -> Result<u8, ()> {
        while self.buffer.is_empty() {
            self.fill().await?;
        }
        Ok(self.buffer[0])
    }

    async fn byte(&mut self) -> Result<u8, ()> {
        let b = self.peek().await?;
        self.buffer.advance(1);
        Ok(b)
    }

    /// At least `n` bytes buffered.
    async fn need(&mut self, n: usize) -> Result<(), ()> {
        while self.buffer.len() < n {
            self.fill().await?;
        }
        Ok(())
    }

    /// The chunk size, with the rest of the line (extension, optional blanks, CRLF) consumed.
    async fn read_chunk_length(&mut self, st: &BodyState) -> Result<usize, ()> {
        st.in_raw_read.store(true, Ordering::Relaxed);
        let (mut n, mut i) = (0usize, 0usize);
        loop {
            let c = match self.peek().await {
                Ok(c) => c,
                // The end of the stream after some digits still gives the number.
                Err(()) if i > 0 => break,
                Err(()) => {
                    st.silent_eof.store(true, Ordering::Relaxed);
                    return Err(());
                }
            };
            let Some(k) = (c as char).to_digit(16) else {
                if i == 0 {
                    return Err(());
                }
                break;
            };
            if i >= MAX_HEX_CHARS {
                return Err(());
            }
            n = (n << 4) | k as usize;
            i += 1;
            self.buffer.advance(1);
        }
        st.in_raw_read.store(false, Ordering::Relaxed);
        let (mut in_ext, mut after_ows) = (false, false);
        loop {
            let c = self.peek().await?;
            if c == b'\r' {
                break;
            }
            self.buffer.advance(1);
            if c == b'\n' {
                return Err(());
            }
            if in_ext {
                continue;
            }
            match c {
                b' ' | b'\t' => after_ows = true,
                b';' if !after_ows => in_ext = true,
                _ => return Err(()),
            }
        }
        // The CRLF after the chunk data.
        if self.byte().await? != b'\r' || self.byte().await? != b'\n' {
            return Err(());
        }
        Ok(n)
    }

    /// The trailers after the last chunk and the blank line that ends them. The block must end
    /// within `cap` bytes (431), unless those bytes are all CR/LF (a broken chunk, 400).
    async fn trailer(&mut self, st: &BodyState) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ()> {
        loop {
            if !self.buffer.is_empty() {
                let window = &self.buffer[..self.buffer.len().min(self.cap)];
                match head_parser::parse_trailer_names(window) {
                    Ok((n, t)) => {
                        self.buffer.advance(n);
                        return Ok(t);
                    }
                    Err(HeadError::NeedMore) if window.len() >= self.cap => {
                        let only_crlf = window.iter().all(|&c| c == b'\r' || c == b'\n');
                        st.small_buffer.store(!only_crlf, Ordering::Relaxed);
                        return Err(());
                    }
                    Err(HeadError::NeedMore) => {}
                    Err(HeadError::Bad) => return Err(()),
                }
            }
            self.fill().await?;
        }
    }
}

/// Reads the body the head declares from `buf` (bytes already read) and then `io`. `limit` is
/// the listener's body size limit, `cap` its read buffer size; `st` classifies a deadline that
/// cuts the read off and a trailer that is too big.
#[allow(clippy::result_unit_err)]
pub async fn read_framed_body<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut BytesMut,
    content_length: i64,
    limit: usize,
    cap: usize,
    st: &BodyState,
) -> Result<Body, ()> {
    let mut rd = Rd {
        io,
        buffer: buf,
        cap,
    };
    match content_length {
        // Neither a length nor chunked: a request has no body.
        -2 => Ok(Body::default()),
        -1 => {
            let mut data: Vec<u8> = Vec::new();
            loop {
                let size = rd.read_chunk_length(st).await?;
                if size == 0 {
                    break;
                }
                if data.len() + size > limit {
                    return Err(());
                }
                st.in_raw_read.store(true, Ordering::Relaxed);
                rd.need(size + 2).await?;
                if &rd.buffer[size..size + 2] != b"\r\n" {
                    return Err(());
                }
                data.extend_from_slice(&rd.buffer[..size]);
                rd.buffer.advance(size + 2);
            }
            st.in_raw_read.store(false, Ordering::Relaxed);
            let trailers = rd.trailer(st).await?;
            Ok(Body { data, trailers })
        }
        n => {
            let n = usize::try_from(n).map_err(|_| ())?;
            if n > limit {
                return Err(());
            }
            st.in_raw_read.store(true, Ordering::Relaxed);
            rd.need(n).await?;
            let data = rd.buffer.split_to(n).to_vec();
            Ok(Body {
                data,
                trailers: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(input: &[u8], cl: i64, limit: usize) -> (Result<Body, ()>, Vec<u8>) {
        let mut io = input;
        let mut buf = BytesMut::new();
        let st = BodyState::default();
        let r = read_framed_body(&mut io, &mut buf, cl, limit, 16 << 10, &st).await;
        (r, buf.to_vec())
    }

    #[tokio::test]
    async fn chunked_body_framing() {
        let (r, rest) = run(b"3\r\nabc\r\n2;x=1\r\nde\r\n0 \r\n\r\nNEXT", -1, 100).await;
        let b = r.unwrap();
        assert_eq!(
            (b.data.as_slice(), rest.as_slice()),
            (&b"abcde"[..], &b"NEXT"[..])
        );
        let (r, _) = run(b"3\r\nabc\r\n0\r\nX-Tr: 1\r\nx-b : 2\r\n\r\n", -1, 100).await;
        assert_eq!(
            r.unwrap().trailers,
            vec![
                (b"X-Tr".to_vec(), b"1".to_vec()),
                (b"X-B".to_vec(), b"2".to_vec())
            ]
        );
        for bad in [
            &b"z\r\nabc\r\n0\r\n\r\n"[..],
            b"\r\nabc\r\n0\r\n\r\n",
            b"5\r\nhelloXX0\r\n\r\n",
            b"5\nhello\r\n0\r\n\r\n",
            b"5 ;a\r\nhello\r\n0\r\n\r\n",
            b"5x\r\nhello\r\n0\r\n\r\n",
            b"5;a\nb\r\nhello\r\n0\r\n\r\n",
            b"FFFFFFFFFFFFFFFFF\r\nabc\r\n0\r\n\r\n",
            b"7FFFFFFF\r\nabc\r\n0\r\n\r\n",
            b"3\r\nabc\r\n0\r\nContent-Length: 5\r\n\r\n",
            b"3\r\nabc\r\n0\r\nbroken\r\n\r\n",
            b"3\r\nabc\r\n0\r\nHost: x\r\n\r\n",
            b"3\r\nabc",
        ] {
            assert!(
                run(bad, -1, 100).await.0.is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// The end of the stream where a chunk size should start is a closed connection (no
    /// answer); inside a size, a chunk or the trailer it is a broken chunk (400).
    #[tokio::test]
    async fn eof_at_a_chunk_boundary_is_silent() {
        let silent = |input: &'static [u8]| async move {
            let mut io = input;
            let mut buf = BytesMut::new();
            let st = BodyState::default();
            let r = read_framed_body(&mut io, &mut buf, -1, 100, 16 << 10, &st).await;
            (r.is_err(), st.closed_silently())
        };
        assert_eq!(silent(b"").await, (true, true));
        assert_eq!(silent(b"5\r\nhello\r\n").await, (true, true));
        assert_eq!(silent(b"5").await, (true, false));
        assert_eq!(silent(b"5\r\nhel").await, (true, false));
        assert_eq!(silent(b"3\r\nabc\r\n0\r\n").await, (true, false));
        assert_eq!(silent(b"3\r\nabc\r\n0\r\n\r\n").await, (false, false));
    }

    /// A trailer block must end within the read buffer (431), counted from its first byte,
    /// whatever else was already read; CR/LF only is a broken chunk (400).
    #[tokio::test]
    async fn trailer_must_fit_the_read_buffer() {
        let cap = 64;
        let run_trailer_case = |tail: Vec<u8>| async move {
            let st = BodyState::default();
            let mut buf = BytesMut::from(&b"0\r\n"[..]);
            buf.extend_from_slice(&tail);
            let mut io: &[u8] = b"";
            let r = read_framed_body(&mut io, &mut buf, -1, 100, cap, &st).await;
            (r.is_ok(), st.too_big())
        };
        // X-T: <pad>\r\n\r\n is `pad + 9` bytes from the trailer's first byte.
        let block =
            |pad: usize| [b"X-T: ".to_vec(), vec![b'a'; pad], b"\r\n\r\n".to_vec()].concat();
        assert_eq!(run_trailer_case(block(cap - 9)).await, (true, false));
        assert_eq!(run_trailer_case(block(cap - 8)).await, (false, true));
        // Bytes past the buffer's worth are not looked at, so a fitting block with more behind it is fine.
        let mut more = block(cap - 9);
        more.extend_from_slice(&[b'z'; 200]);
        assert_eq!(run_trailer_case(more).await, (true, false));
        assert_eq!(run_trailer_case(vec![b'\n'; cap]).await, (false, false));
    }

    #[tokio::test]
    async fn fixed_and_none() {
        let (r, rest) = run(b"abcNEXT", 3, 100).await;
        assert_eq!((r.unwrap().data, rest), (b"abc".to_vec(), b"NEXT".to_vec()));
        assert!(run(b"abc", 5000, 100).await.0.is_err());
        assert!(run(b"ab", 3, 100).await.0.is_err());
        let (r, rest) = run(b"GET /next", -2, 100).await;
        assert_eq!((r.unwrap().data.len(), rest), (0, b"".to_vec()));
    }
}
