//! Controlled I/O for testing ASCII copy output and failure propagation.

use std::io::{self, ErrorKind, Read, Write};
#[cfg(any(feature = "smol", feature = "tokio"))]
use std::pin::Pin;
#[cfg(any(feature = "smol", feature = "tokio"))]
use std::task::{Context, Poll};

use pretty_assertions::assert_eq;

#[derive(Default)]
struct Reader {
    input: &'static [u8],
    fail_at_eof: bool,
    interrupt_once: bool,
    #[cfg(feature = "tokio")]
    pending_at_eof: bool,
}

impl Read for Reader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if std::mem::take(&mut self.interrupt_once) {
            return Err(ErrorKind::Interrupted.into());
        }
        if self.input.is_empty() && self.fail_at_eof {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        let len = buffer.len().min(self.input.len()).min(2);
        buffer[..len].copy_from_slice(&self.input[..len]);
        self.input = &self.input[len..];
        Ok(len)
    }
}

struct Writer {
    output: Vec<u8>,
    remaining: usize,
    write_error: Option<ErrorKind>,
    flush_error: bool,
}

impl Default for Writer {
    fn default() -> Self {
        Self {
            output: Vec::new(),
            remaining: usize::MAX,
            write_error: None,
            flush_error: false,
        }
    }
}

impl Write for Writer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0
            && let Some(error) = self.write_error
        {
            return Err(error.into());
        }
        let len = buffer.len().min(self.remaining).min(2);
        self.output.extend_from_slice(&buffer[..len]);
        self.remaining -= len;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flush_error {
            Err(ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
}

struct Case {
    name: &'static str,
    reader: Reader,
    writer: Writer,
    result: Result<u64, ErrorKind>,
    output: &'static [u8],
}

fn cases() -> [Case; 5] {
    [
        Case {
            name: "empty input",
            reader: Reader::default(),
            writer: Writer::default(),
            result: Ok(0),
            output: b"",
        },
        Case {
            name: "short reads and writes",
            reader: Reader {
                input: b"a\nb\n",
                ..Reader::default()
            },
            writer: Writer::default(),
            result: Ok(6),
            output: b"a\r\nb\r\n",
        },
        Case {
            name: "read failure after a line",
            reader: Reader {
                input: b"a\n",
                fail_at_eof: true,
                ..Reader::default()
            },
            writer: Writer::default(),
            result: Err(ErrorKind::UnexpectedEof),
            output: b"a\r\n",
        },
        Case {
            name: "write failure after a line",
            reader: Reader {
                input: b"a\nb\n",
                ..Reader::default()
            },
            writer: Writer {
                remaining: 3,
                write_error: Some(ErrorKind::PermissionDenied),
                ..Writer::default()
            },
            result: Err(ErrorKind::PermissionDenied),
            output: b"a\r\n",
        },
        Case {
            name: "zero write",
            reader: Reader {
                input: b"a\n",
                ..Reader::default()
            },
            writer: Writer {
                remaining: 0,
                ..Writer::default()
            },
            result: Err(ErrorKind::WriteZero),
            output: b"",
        },
    ]
}

#[test]
fn should_copy_sync_output_and_propagate_failures() {
    for mut case in cases() {
        let result = super::copy_crlf(&mut case.reader, &mut case.writer);
        assert_eq!(
            result.map_err(|error| error.kind()),
            case.result,
            "{name}",
            name = case.name
        );
        assert_eq!(case.writer.output, case.output, "{name}", name = case.name);
    }
}

#[test]
fn should_retry_interrupted_sync_reads() {
    let mut reader = Reader {
        input: b"a\n",
        interrupt_once: true,
        ..Reader::default()
    };
    let mut writer = Writer::default();
    assert_eq!(super::copy_crlf(&mut reader, &mut writer).unwrap(), 3);
    assert_eq!(writer.output, b"a\r\n");
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending_at_eof && self.input.is_empty() {
            return Poll::Pending;
        }
        let result = self.read(buffer.initialize_unfilled());
        Poll::Ready(result.map(|len| buffer.advance(len)))
    }
}

#[cfg(feature = "smol")]
impl smol::io::AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.read(buffer))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.write(buffer))
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.flush())
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(context)
    }
}

#[cfg(feature = "smol")]
impl smol::io::AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.write(buffer))
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.flush())
    }
    fn poll_close(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(context)
    }
}

#[cfg(any(feature = "smol", feature = "tokio"))]
fn flush_failure() -> Case {
    Case {
        name: "flush failure at EOF",
        reader: Reader {
            input: b"a\n",
            ..Reader::default()
        },
        writer: Writer {
            flush_error: true,
            ..Writer::default()
        },
        result: Err(ErrorKind::BrokenPipe),
        output: b"a\r\n",
    }
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn should_copy_tokio_output_and_propagate_failures() {
    let mut pending_flush_failure = flush_failure();
    pending_flush_failure.name = "flush failure while reader is pending";
    pending_flush_failure.reader.pending_at_eof = true;
    for mut case in cases()
        .into_iter()
        .chain([flush_failure(), pending_flush_failure])
    {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            super::copy_crlf_tokio(&mut case.reader, &mut case.writer),
        )
        .await
        .expect("copy must return the I/O error without hanging");
        assert_eq!(
            result.map_err(|error| error.kind()),
            case.result,
            "{name}",
            name = case.name
        );
        assert_eq!(case.writer.output, case.output, "{name}", name = case.name);
    }
}

#[cfg(feature = "smol")]
#[test]
fn should_copy_smol_output_and_propagate_failures() {
    smol::block_on(async {
        for mut case in cases().into_iter().chain([flush_failure()]) {
            let result = super::copy_crlf_smol(&mut case.reader, &mut case.writer).await;
            assert_eq!(
                result.map_err(|error| error.kind()),
                case.result,
                "{name}",
                name = case.name
            );
            assert_eq!(case.writer.output, case.output, "{name}", name = case.name);
        }
    });
}
