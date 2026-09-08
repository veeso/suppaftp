//! Control-connection state shared between the tokio FTP client and its in-flight data transfer.
//!
//! The control connection (command socket, reply reader, and the "data connection open" flag)
//! lives behind an [`Arc`]`<`[`Mutex`]`>` so that a [`super::TransferStream`] can finalize itself:
//! once the data socket is shut down, the stream locks the control connection, clears the flag
//! and reads the server's completion reply. FTP allows a single data connection per session, so
//! the lock never serializes anything that could have run concurrently before.
//!
//! Async `Drop` cannot await, so a transfer stream that is dropped without
//! [`super::TransferStream::finish`] only closes its socket and flags a *pending transfer reply*;
//! the next command drains that reply before sending anything, keeping the control connection in
//! sync.

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard};

use super::data_stream::DataStream;
use super::tls::TokioTlsStream;
use crate::Status;
use crate::command::Command;
use crate::types::{FtpError, FtpResult, Response};

/// Replies that complete a data transfer: `226` or `250`.
pub(super) const TRANSFER_COMPLETE: &[Status] =
    &[Status::ClosingDataConnection, Status::RequestedFileActionOk];

/// Shared, lockable handle to a [`ControlChannel`].
pub(super) type SharedControl<T> = Arc<Mutex<ControlChannel<T>>>;

/// Command socket plus the reply reader and the data-connection bookkeeping.
#[derive(Debug)]
pub(super) struct ControlChannel<T>
where
    T: TokioTlsStream + Send,
{
    /// Buffered reader over the control socket; writes go through [`BufReader::get_mut`].
    pub(super) reader: BufReader<DataStream<T>>,
    /// Whether a data connection is currently open.
    ///
    /// FTP forbids more than one data connection at a time, so this flag guards every data
    /// command against opening a second one.
    pub(super) data_connection_open: bool,
    /// Whether a transfer stream was dropped without `finish()` and its reply is still unread.
    pub(super) pending_transfer_reply: Arc<AtomicBool>,
    /// Reply bytes survive cancellation while waiting for a complete line or multiline reply.
    response_line: Vec<u8>,
    response_body: Vec<u8>,
}

/// Unwraps a shared control channel that is no longer referenced by any transfer.
///
/// # Errors
///
/// Returns [`FtpError::DataConnectionAlreadyOpen`] if a [`super::TransferStream`] still holds a
/// reference to the control channel.
#[cfg(feature = "async-secure")]
pub(super) fn into_exclusive<T>(control: SharedControl<T>) -> FtpResult<ControlChannel<T>>
where
    T: TokioTlsStream + Send,
{
    Arc::try_unwrap(control)
        .map(Mutex::into_inner)
        .map_err(|_| FtpError::DataConnectionAlreadyOpen)
}

impl<T> ControlChannel<T>
where
    T: TokioTlsStream + Send,
{
    /// Wraps `stream` as a fresh control channel with no data connection open.
    pub(super) fn new(stream: DataStream<T>) -> Self {
        Self {
            reader: BufReader::new(stream),
            data_connection_open: false,
            pending_transfer_reply: Arc::new(AtomicBool::new(false)),
            response_line: Vec::new(),
            response_body: Vec::new(),
        }
    }

    /// Wraps `stream` into a [`SharedControl`].
    pub(super) fn shared(stream: DataStream<T>) -> SharedControl<T> {
        Arc::new(Mutex::new(Self::new(stream)))
    }

    /// Returns the control socket.
    pub(super) fn socket(&self) -> &TcpStream {
        self.reader.get_ref().get_ref()
    }

    /// Sends `command` on the control connection.
    pub(super) async fn perform(&mut self, command: Command) -> FtpResult<()> {
        let command = command.to_string();
        crate::command::validate_command_line(&command)?;
        trace!("CC OUT: {}", command.trim_end_matches("\r\n"));

        self.reader
            .get_mut()
            .write_all(command.as_bytes())
            .await
            .map_err(FtpError::ConnectionError)
    }

    /// Reads one reply and checks that its status is `expected_code`.
    pub(super) async fn read_response(&mut self, expected_code: Status) -> FtpResult<Response> {
        self.read_response_in(&[expected_code]).await
    }

    /// Reads one (possibly multi-line) reply and checks that its status is in `expected_code`.
    pub(super) async fn read_response_in(
        &mut self,
        expected_code: &[Status],
    ) -> FtpResult<Response> {
        loop {
            let bytes_read = self
                .reader
                .read_until(b'\n', &mut self.response_line)
                .await
                .map_err(FtpError::ConnectionError)?;
            if bytes_read == 0 && !self.response_body.is_empty() {
                return Err(FtpError::ConnectionError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during multiline response",
                )));
            }
            self.response_body.extend_from_slice(&self.response_line);
            trace!("CC IN: {line:?}", line = self.response_line);

            if self.response_body.len() < 5 {
                self.response_line.clear();
                self.response_body.clear();
                return Err(FtpError::BadResponse);
            }
            let opening_code = match code_from_buffer(&self.response_body, 3) {
                Ok(code) => code,
                Err(err) => {
                    self.response_line.clear();
                    self.response_body.clear();
                    return Err(err);
                }
            };
            let opening = &self.response_body[..3];
            let line = &self.response_line;
            // Accept mismatched terminal codes for servers such as glFTPd. FEAT leaves its
            // continuation lines for `feat()` to consume after returning the `211-` opener.
            let terminal = line.len() >= 4
                && line[..3].iter().all(u8::is_ascii_digit)
                && (line[3] == b' '
                    || (expected_code.contains(&Status::System)
                        && line[..3] == *opening
                        && line[3] == b'-'));
            if terminal {
                let code = if line[..3] == *opening {
                    opening_code
                } else {
                    code_from_buffer(line, 3)?
                };
                let status = Status::from(code);
                self.response_line.clear();
                let response = Response::new(status, std::mem::take(&mut self.response_body));
                return if expected_code.contains(&status) {
                    Ok(response)
                } else {
                    Err(FtpError::UnexpectedResponse(response))
                };
            }
            self.response_line.clear();
        }
    }

    /// Reads bytes from the control connection until `\n` or EOF is found.
    pub(super) async fn read_line(&mut self, line: &mut Vec<u8>) -> FtpResult<usize> {
        self.reader
            .read_until(0x0A, line.as_mut())
            .await
            .map_err(FtpError::ConnectionError)?;
        Ok(line.len())
    }

    /// Fails with [`FtpError::DataConnectionAlreadyOpen`] if a data connection is open.
    pub(super) fn guard_multiple_data_connections(&self) -> FtpResult<()> {
        if self.data_connection_open {
            Err(FtpError::DataConnectionAlreadyOpen)
        } else {
            Ok(())
        }
    }

    /// Marks the data connection as closed and reads the transfer completion reply.
    ///
    /// The data socket must already be closed, otherwise the server never sends the reply.
    pub(super) async fn complete_transfer(&mut self) -> FtpResult<()> {
        self.data_connection_open = false;
        trace!("data connection closed; reading transfer reply");
        let reply = self.read_response_in(TRANSFER_COMPLETE).await.map(|_| ());
        self.pending_transfer_reply.store(false, Ordering::Release);
        reply
    }

    /// Consumes the reply of a transfer stream that was dropped without `finish()`.
    ///
    /// The transfer outcome was abandoned by the caller, so a failure reply is only logged.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::ConnectionError`] if the control connection cannot be read.
    pub(super) async fn drain_pending_transfer_reply(&mut self) -> FtpResult<()> {
        if !self.pending_transfer_reply.load(Ordering::Acquire) {
            return Ok(());
        }
        debug!("reading the reply of a transfer stream dropped without finish()");
        match self.complete_transfer().await {
            Ok(()) => Ok(()),
            Err(FtpError::UnexpectedResponse(response)) => {
                warn!("a dropped transfer stream failed: {response}");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

/// Parses the leading `len` bytes of `buf` as a numeric reply code.
fn code_from_buffer(buf: &[u8], len: usize) -> FtpResult<u32> {
    if buf.len() < len {
        return Err(FtpError::BadResponse);
    }
    let buffer = buf[0..len].to_vec();
    let as_string = String::from_utf8(buffer).map_err(|_| FtpError::BadResponse)?;
    as_string.parse::<u32>().map_err(|_| FtpError::BadResponse)
}

/// Locked view of the control socket of an [`super::ImplAsyncFtpStream`].
///
/// Dereferences to the underlying [`TcpStream`], so socket options can be set on the control
/// connection. The control connection stays locked for as long as this value is alive: drop it
/// before finishing a [`super::TransferStream`], which needs the same lock to read the transfer
/// reply.
///
/// # Examples
///
/// ```rust,no_run
/// use suppaftp::tokio::AsyncFtpStream;
///
/// # async fn run() {
/// let stream = AsyncFtpStream::connect("127.0.0.1:21").await.unwrap();
/// stream.get_ref().await.set_nodelay(true).unwrap();
/// # }
/// ```
#[derive(Debug)]
pub struct ControlSocket<'a, T>
where
    T: TokioTlsStream + Send,
{
    guard: MutexGuard<'a, ControlChannel<T>>,
}

impl<'a, T> ControlSocket<'a, T>
where
    T: TokioTlsStream + Send,
{
    /// Wraps a locked control channel.
    pub(super) fn new(guard: MutexGuard<'a, ControlChannel<T>>) -> Self {
        Self { guard }
    }
}

impl<T> Deref for ControlSocket<'_, T>
where
    T: TokioTlsStream + Send,
{
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        self.guard.socket()
    }
}

#[cfg(all(test, feature = "async-secure"))]
mod tls_transition_tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use super::super::tls::{AsyncNoTlsStream, AsyncTlsConnector};
    use crate::tokio::AsyncFtpStream;
    use crate::{FtpError, FtpResult};

    #[derive(Debug)]
    struct UnusedConnector;

    #[async_trait::async_trait]
    impl AsyncTlsConnector for UnusedConnector {
        type Stream = AsyncNoTlsStream;

        async fn connect(&self, _: &str, _: tokio::net::TcpStream) -> FtpResult<Self::Stream> {
            panic!("TLS must not start while a transfer owns the control connection")
        }
    }

    #[tokio::test]
    async fn should_reject_tls_changes_before_sending_commands() {
        for secure in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(socket);
                reader.get_mut().write_all(b"220 ready\r\n").unwrap();
                let mut command = String::new();
                reader.read_line(&mut command).unwrap();
                if !command.is_empty() {
                    let reply: &[u8] = if secure {
                        b"234 start TLS\r\n"
                    } else {
                        b"200 cleared\r\n"
                    };
                    reader.get_mut().write_all(reply).unwrap();
                    reader.read_to_end(&mut Vec::new()).unwrap();
                }
                command
            });
            let ftp = AsyncFtpStream::connect(address).await.unwrap();
            // A live transfer retains this handle even when a TLS transition consumes the client.
            let transfer_control = Arc::clone(&ftp.control);
            let result = if secure {
                ftp.into_secure(UnusedConnector, "localhost").await
            } else {
                ftp.clear_command_channel().await
            };
            assert!(matches!(result, Err(FtpError::DataConnectionAlreadyOpen)));
            drop(transfer_control);
            assert_eq!(server.join().unwrap(), "");
        }
    }
}
