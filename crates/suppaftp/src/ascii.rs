//! Line-ending conversion for uploads in the ASCII transfer type (`TYPE A`).
//!
//! RFC 959 §3.1.1.1 requires the sender to convert text to NVT-ASCII, whose line ending is
//! CRLF. Every LF not preceded by CR is sent as CRLF; CRLF and a lone CR are sent unchanged, so
//! text that already uses CRLF is not altered.

use std::io::{self, Read, Write};

/// Size of the buffer each copy reads into.
const COPY_BUFFER_SIZE: usize = 8 * 1024;

/// Converts bare LF to CRLF, keeping state across calls so a CRLF split between two chunks is
/// recognized.
#[derive(Debug, Default)]
pub(crate) struct CrlfEncoder {
    /// Whether the last byte seen was CR.
    last_was_cr: bool,
}

impl CrlfEncoder {
    /// Appends `input` to `output`, inserting a CR before every LF not preceded by CR.
    pub(crate) fn encode(&mut self, input: &[u8], output: &mut Vec<u8>) {
        for &byte in input {
            if byte == b'\n' && !self.last_was_cr {
                output.push(b'\r');
            }
            output.push(byte);
            self.last_was_cr = byte == b'\r';
        }
    }
}

/// Copies `reader` to `writer`, converting line endings with a [`CrlfEncoder`].
///
/// Returns the number of bytes written, including any added CRs.
pub(crate) fn copy_crlf<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let mut encoder = CrlfEncoder::default();
    let mut input = vec![0; COPY_BUFFER_SIZE];
    let mut output = Vec::with_capacity(COPY_BUFFER_SIZE * 2);
    let mut written = 0;
    loop {
        let read = match reader.read(&mut input) {
            Ok(0) => return Ok(written),
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        output.clear();
        encoder.encode(&input[..read], &mut output);
        writer.write_all(&output)?;
        written += output.len() as u64;
    }
}

/// Async [`copy_crlf`] for tokio readers and writers.
#[cfg(feature = "tokio")]
pub(crate) async fn copy_crlf_tokio<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    use std::future::poll_fn;
    use std::pin::Pin;
    use std::task::Poll;

    use tokio::io::{AsyncWriteExt as _, ReadBuf};

    let mut encoder = CrlfEncoder::default();
    let mut input = vec![0; COPY_BUFFER_SIZE];
    let mut output = Vec::with_capacity(COPY_BUFFER_SIZE * 2);
    let mut written = 0;
    let mut needs_flush = false;
    loop {
        let mut read = 0;
        poll_fn(|context| {
            let mut buffer = ReadBuf::new(&mut input);
            match Pin::new(&mut *reader).poll_read(context, &mut buffer) {
                Poll::Ready(Ok(())) => {
                    read = buffer.filled().len();
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => {
                    if needs_flush {
                        match Pin::new(&mut *writer).poll_flush(context) {
                            Poll::Ready(Ok(())) => needs_flush = false,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    Poll::Pending
                }
            }
        })
        .await?;
        if read == 0 {
            writer.flush().await?;
            return Ok(written);
        }
        output.clear();
        encoder.encode(&input[..read], &mut output);
        writer.write_all(&output).await?;
        written += output.len() as u64;
        needs_flush = true;
    }
}

/// Async [`copy_crlf`] for smol readers and writers.
#[cfg(feature = "smol")]
pub(crate) async fn copy_crlf_smol<R, W>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: smol::io::AsyncRead + Unpin + ?Sized,
    W: smol::io::AsyncWrite + Unpin + ?Sized,
{
    use smol::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut encoder = CrlfEncoder::default();
    let mut input = vec![0; COPY_BUFFER_SIZE];
    let mut output = Vec::with_capacity(COPY_BUFFER_SIZE * 2);
    let mut written = 0;
    loop {
        let read = reader.read(&mut input).await?;
        if read == 0 {
            writer.flush().await?;
            return Ok(written);
        }
        output.clear();
        encoder.encode(&input[..read], &mut output);
        writer.write_all(&output).await?;
        written += output.len() as u64;
    }
}

#[cfg(test)]
mod test_io;

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::*;

    fn encode(input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        CrlfEncoder::default().encode(input, &mut output);
        output
    }

    #[test]
    fn should_encode_line_endings() {
        for (input, expected) in [
            (b"".as_slice(), b"".as_slice()),
            (b"\n\na".as_slice(), b"\r\n\r\na".as_slice()),
            (b"a\r\r\n".as_slice(), b"a\r\r\n".as_slice()),
        ] {
            assert_eq!(encode(input), expected, "input: {input:?}");
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tokio_tests {
    use std::future::Future as _;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt as _, BufWriter, ReadBuf};
    use tokio::sync::oneshot;

    use super::copy_crlf_tokio;

    struct ReaderWaitingForFlush {
        first_chunk: Option<&'static [u8]>,
        flush_seen: oneshot::Receiver<()>,
        done: bool,
    }

    impl AsyncRead for ReaderWaitingForFlush {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if let Some(chunk) = this.first_chunk.take() {
                buffer.put_slice(chunk);
                return Poll::Ready(Ok(()));
            }
            if this.done {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.flush_seen).poll(context) {
                Poll::Ready(Ok(())) => {
                    this.done = true;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "peer stopped waiting for flushed output",
                ))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    #[tokio::test]
    async fn should_flush_when_source_waits_for_previous_output() {
        let (stream, mut peer) = tokio::io::duplex(64);
        let mut writer = BufWriter::with_capacity(64, stream);
        let (flush_sender, flush_receiver) = oneshot::channel();
        let peer_task = tokio::spawn(async move {
            let mut received = [0; 6];
            peer.read_exact(&mut received).await?;
            flush_sender
                .send(())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "upload reader stopped"))?;
            Ok::<_, io::Error>(received)
        });
        let mut reader = ReaderWaitingForFlush {
            first_chunk: Some(b"line\n"),
            flush_seen: flush_receiver,
            done: false,
        };

        let written = tokio::time::timeout(
            Duration::from_secs(1),
            copy_crlf_tokio(&mut reader, &mut writer),
        )
        .await
        .expect("copy should flush output while the source waits")
        .unwrap();

        assert_eq!(written, 6);
        assert_eq!(peer_task.await.unwrap().unwrap(), *b"line\r\n");
    }
}
