//! Self-finalizing data stream for FTP transfers.

use std::io::{Read, Result as IoResult, Write};

use super::control::{SharedControl, lock};
use super::data_stream::DataStream;
use super::tls::TlsStream;
use crate::types::FtpResult;

/// Data connection of an FTP transfer that finalizes itself.
///
/// Returned by [`ImplFtpStream::put_with_stream`], [`ImplFtpStream::append_with_stream`],
/// [`ImplFtpStream::retr_as_stream`] and [`ImplFtpStream::custom_data_command`]. It implements
/// [`Read`] and [`Write`] by delegating to the underlying [`DataStream`].
///
/// Once the payload has been written or read, call [`TransferStream::finish`]: it closes the data
/// socket and reads the server's completion reply on the control connection, which is the only
/// way to learn whether the transfer succeeded. A stream that is merely dropped performs the same
/// procedure on a best-effort basis, logging instead of returning the error, so the control
/// connection can be reused after successful cleanup. Drop can block while waiting for the
/// server, and the transfer outcome is lost in that case.
///
/// Finish the transfer before issuing any other command on the client, even when finishing
/// on another thread or task. Flush buffered writers before recovering their inner transfer.
///
/// While a `TransferStream` is alive the client refuses to open another data connection with
/// [`FtpError::DataConnectionAlreadyOpen`]. The stream owns no reference to the client and is
/// [`Send`] whenever the TLS stream is, so it can be moved to another thread and finished there.
///
/// # Examples
///
/// ```rust,no_run
/// use std::io::Write;
///
/// use suppaftp::FtpStream;
///
/// let mut ftp = FtpStream::connect("127.0.0.1:21").unwrap();
/// ftp.login("test", "test").unwrap();
/// let mut upload = ftp.put_with_stream("hello.txt").unwrap();
/// upload.write_all(b"hello, world!").unwrap();
/// // Reads the `226` reply; the control connection is ready for the next command.
/// upload.finish().unwrap();
/// assert_eq!(ftp.size("hello.txt").unwrap(), 13);
/// ```
///
/// [`ImplFtpStream::put_with_stream`]: super::ImplFtpStream::put_with_stream
/// [`ImplFtpStream::append_with_stream`]: super::ImplFtpStream::append_with_stream
/// [`ImplFtpStream::retr_as_stream`]: super::ImplFtpStream::retr_as_stream
/// [`ImplFtpStream::custom_data_command`]: super::ImplFtpStream::custom_data_command
/// [`FtpError::DataConnectionAlreadyOpen`]: crate::FtpError::DataConnectionAlreadyOpen
#[must_use = "call `finish()` to close the data connection and read the transfer reply"]
#[derive(Debug)]
pub struct TransferStream<T>
where
    T: TlsStream,
{
    /// Data socket; `None` once the transfer has been finalized or detached.
    data: Option<DataStream<T>>,
    control: SharedControl<T>,
}

impl<T> TransferStream<T>
where
    T: TlsStream,
{
    /// Wraps an open data connection so that it completes the transfer on `control`.
    pub(super) fn new(data: DataStream<T>, control: SharedControl<T>) -> Self {
        Self {
            data: Some(data),
            control,
        }
    }

    /// Returns a reference to the underlying [`DataStream`].
    pub fn get_ref(&self) -> &DataStream<T> {
        self.data
            .as_ref()
            .expect("data stream is present until the transfer is finished")
    }

    /// Returns a mutable reference to the underlying [`DataStream`].
    pub fn get_mut(&mut self) -> &mut DataStream<T> {
        self.data
            .as_mut()
            .expect("data stream is present until the transfer is finished")
    }

    /// Closes the data connection and reads the transfer completion reply.
    ///
    /// After this call the client can issue the next command.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::ConnectionError`] if the control connection cannot be read and
    /// [`FtpError::UnexpectedResponse`] if the server reports that the transfer failed (any
    /// reply other than `226` or `250`).
    ///
    /// [`FtpError::ConnectionError`]: crate::FtpError::ConnectionError
    /// [`FtpError::UnexpectedResponse`]: crate::FtpError::UnexpectedResponse
    pub fn finish(mut self) -> FtpResult<()> {
        self.finalize()
    }

    /// Detaches the data socket; the returned stream no longer completes the transfer on drop.
    ///
    /// Used by [`super::ImplFtpStream::abort`], which reads the reply itself.
    pub(super) fn detach(mut self) -> DataStream<T> {
        self.data
            .take()
            .expect("data stream is present until the transfer is finished")
    }

    /// Whether the transfer has already been finalized.
    fn is_finished(&self) -> bool {
        self.data.is_none()
    }

    /// Closes the data socket, then reads the completion reply on the control connection.
    ///
    /// Idempotent: a second call is a no-op, so `finish()` followed by `Drop` reads one reply.
    fn finalize(&mut self) -> FtpResult<()> {
        let Some(data) = self.data.take() else {
            return Ok(());
        };
        // The socket must be closed before reading the reply, otherwise the server never sends
        // it. Dropping the socket never touches the control lock, so no lock is held here.
        drop(data);
        lock(&self.control).complete_transfer()
    }
}

impl<T> Read for TransferStream<T>
where
    T: TlsStream,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.get_mut().read(buf)
    }
}

impl<T> Write for TransferStream<T>
where
    T: TlsStream,
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.get_mut().write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.get_mut().flush()
    }
}

impl<T> Drop for TransferStream<T>
where
    T: TlsStream,
{
    fn drop(&mut self) {
        if self.is_finished() {
            return;
        }
        debug!("transfer stream dropped without finish(); finalizing the transfer");
        if let Err(err) = self.finalize() {
            warn!("failed to finalize a dropped transfer stream: {err}");
        }
    }
}
