//! Control-connection state shared between an FTP client and its in-flight data transfer.
//!
//! The control connection (command socket, reply reader, and the "data connection open" flag)
//! lives behind an [`Arc`]`<`[`Mutex`]`>` so that a [`super::TransferStream`] can finalize itself:
//! once the data socket is closed, the stream locks the control connection, clears the flag and
//! reads the server's completion reply. FTP allows a single data connection per session, so the
//! lock never serializes anything that could have run concurrently before.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard};

use super::data_stream::DataStream;
use super::tls::TlsStream;
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
    T: TlsStream,
{
    /// Buffered reader over the control socket; writes go through [`BufReader::get_mut`].
    pub(super) reader: BufReader<DataStream<T>>,
    /// Whether a data connection is currently open.
    ///
    /// FTP forbids more than one data connection at a time, so this flag guards every data
    /// command against opening a second one.
    pub(super) data_connection_open: bool,
}

/// Locks `control`, recovering the inner state if a previous holder panicked.
pub(super) fn lock<T>(control: &Mutex<ControlChannel<T>>) -> MutexGuard<'_, ControlChannel<T>>
where
    T: TlsStream,
{
    control
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Unwraps a shared control channel that is no longer referenced by any transfer.
///
/// # Errors
///
/// Returns [`FtpError::DataConnectionAlreadyOpen`] if a [`super::TransferStream`] still holds a
/// reference to the control channel.
#[cfg(feature = "secure")]
pub(super) fn into_exclusive<T>(control: SharedControl<T>) -> FtpResult<ControlChannel<T>>
where
    T: TlsStream,
{
    Arc::try_unwrap(control)
        .map(|mutex| {
            mutex
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        })
        .map_err(|_| FtpError::DataConnectionAlreadyOpen)
}

impl<T> ControlChannel<T>
where
    T: TlsStream,
{
    /// Wraps `stream` as a fresh control channel with no data connection open.
    pub(super) fn new(stream: DataStream<T>) -> Self {
        Self {
            reader: BufReader::new(stream),
            data_connection_open: false,
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
    pub(super) fn perform(&mut self, command: Command) -> FtpResult<()> {
        let command = command.to_string();
        crate::command::validate_command_line(&command)?;
        trace!("CC OUT: {}", command.trim_end_matches("\r\n"));

        self.reader
            .get_mut()
            .write_all(command.as_bytes())
            .map_err(FtpError::ConnectionError)
    }

    /// Reads one reply and checks that its status is `expected_code`.
    pub(super) fn read_response(&mut self, expected_code: Status) -> FtpResult<Response> {
        self.read_response_in(&[expected_code])
    }

    /// Reads one (possibly multi-line) reply and checks that its status is in `expected_code`.
    pub(super) fn read_response_in(&mut self, expected_code: &[Status]) -> FtpResult<Response> {
        let mut line = Vec::new();
        let mut body: Vec<u8> = Vec::new();
        self.read_line(&mut line)?;
        body.extend(line.iter());

        trace!("CC IN: {:?}", line);

        if line.len() < 5 {
            return Err(FtpError::BadResponse);
        }

        let code_word: u32 = code_from_buffer(&line, 3)?;
        let mut code = Status::from(code_word);

        trace!("Code parsed from response: {} ({})", code, code_word);

        // RFC 959 requires the terminal line to repeat the opening code, but some servers,
        // including glFTPd, use a different operative code. FEAT remains special because
        // `feat` reads its continuation lines after `read_response` returns the `211-` opener.
        // FTP replies start with a three-digit code and one separator.
        let expected = [line[0], line[1], line[2], 0x20];
        let feat_opener = [line[0], line[1], line[2], b'-'];
        let is_terminal = |reply: &[u8]| {
            reply.len() >= 4
                && reply[0].is_ascii_digit()
                && reply[1].is_ascii_digit()
                && reply[2].is_ascii_digit()
                && (reply[3] == b' '
                    || (expected_code.contains(&Status::System) && reply[0..4] == feat_opener))
        };
        trace!("CC IN: {:?}", line);
        while !is_terminal(&line) {
            line.clear();
            let bytes_read = self.read_line(&mut line)?;
            if bytes_read == 0 {
                return Err(FtpError::ConnectionError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during multiline response",
                )));
            }
            body.extend(line.iter());
            trace!("CC IN: {:?}", line);
        }

        if line[0..4] != expected {
            code = Status::from(code_from_buffer(&line, 3)?);
            trace!("Code updated from terminal response: {}", code);
        }

        let response: Response = Response::new(code, body);
        // Return Ok or error with response
        if expected_code.contains(&code) {
            Ok(response)
        } else {
            Err(FtpError::UnexpectedResponse(response))
        }
    }

    /// Reads bytes from the control connection until `\n` or EOF is found.
    pub(super) fn read_line(&mut self, line: &mut Vec<u8>) -> FtpResult<usize> {
        self.reader
            .read_until(0x0A, line.as_mut())
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
    pub(super) fn complete_transfer(&mut self) -> FtpResult<()> {
        self.data_connection_open = false;
        trace!("data connection closed; reading transfer reply");
        self.read_response_in(TRANSFER_COMPLETE).map(|_| ())
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

/// Locked view of the control socket of an [`super::ImplFtpStream`].
///
/// Dereferences to the underlying [`TcpStream`], so socket options such as timeouts can be set
/// on the control connection. The control connection stays locked for as long as this value is
/// alive: drop it before finishing or dropping a [`super::TransferStream`], which needs the same
/// lock to read the transfer reply.
///
/// # Examples
///
/// ```rust,no_run
/// use std::time::Duration;
///
/// use suppaftp::FtpStream;
///
/// let stream = FtpStream::connect("127.0.0.1:21").unwrap();
/// stream
///     .get_ref()
///     .set_read_timeout(Some(Duration::from_secs(10)))
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct ControlSocket<'a, T>
where
    T: TlsStream,
{
    guard: MutexGuard<'a, ControlChannel<T>>,
}

impl<'a, T> ControlSocket<'a, T>
where
    T: TlsStream,
{
    /// Locks `control` and exposes its socket.
    pub(super) fn lock(control: &'a Mutex<ControlChannel<T>>) -> Self {
        Self {
            guard: lock(control),
        }
    }
}

impl<T> Deref for ControlSocket<'_, T>
where
    T: TlsStream,
{
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        self.guard.socket()
    }
}
