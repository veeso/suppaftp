//! Self-finalizing data stream for smol FTP transfers.

use std::pin::Pin;
use std::task::{Context, Poll};

use smol::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::control::SharedControl;
use super::data_stream::DataStream;
use super::tls::SmolTlsStream;
use crate::types::{FtpError, FtpResult};

/// Whether the transfer writes to or reads from the server.
///
/// Uploads are only complete once the write side has been closed successfully, so a close error
/// fails an upload; downloads have already read the whole payload, so a close error is ignored
/// and the server's completion reply is authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    /// `STOR` / `APPE`: data flows to the server.
    Upload,
    /// `RETR`, listings and custom data commands: data flows from the server.
    Download,
}

/// Data connection of an FTP transfer that finalizes itself.
///
/// Returned by [`ImplAsyncFtpStream::put_with_stream`], [`ImplAsyncFtpStream::append_with_stream`],
/// [`ImplAsyncFtpStream::retr_as_stream`] and [`ImplAsyncFtpStream::custom_data_command`]. It
/// implements [`AsyncRead`] and [`AsyncWrite`] by delegating to the underlying [`DataStream`].
///
/// Once the payload has been written or read, call [`TransferStream::finish`]: it closes the
/// data socket and reads the server's completion reply on the control connection, which is the
/// only way to learn whether the transfer succeeded.
///
/// A stream that is merely dropped cannot await, so it closes its socket (without a TLS
/// `close_notify`, which strict servers may report as a failed transfer) and defers the reply:
/// the next command on the client consumes it before sending anything, so the control connection
/// never desynchronizes. The transfer outcome is lost in that case and only logged.
///
/// While a `TransferStream` is alive the client refuses to open another data connection with
/// [`FtpError::DataConnectionAlreadyOpen`]. The stream owns no reference to the client and is
/// [`Send`] whenever the TLS stream is, so it can be moved to another task and finished there.
///
/// # Examples
///
/// ```rust,no_run
/// use smol::io::AsyncWriteExt;
/// use suppaftp::smol::AsyncFtpStream;
///
/// # async fn run() {
/// let mut ftp = AsyncFtpStream::connect("127.0.0.1:21").await.unwrap();
/// ftp.login("test", "test").await.unwrap();
/// let mut upload = ftp.put_with_stream("hello.txt").await.unwrap();
/// upload.write_all(b"hello, world!").await.unwrap();
/// // Reads the `226` reply; the control connection is ready for the next command.
/// upload.finish().await.unwrap();
/// assert_eq!(ftp.size("hello.txt").await.unwrap(), 13);
/// # }
/// ```
///
/// [`ImplAsyncFtpStream::put_with_stream`]: super::ImplAsyncFtpStream::put_with_stream
/// [`ImplAsyncFtpStream::append_with_stream`]: super::ImplAsyncFtpStream::append_with_stream
/// [`ImplAsyncFtpStream::retr_as_stream`]: super::ImplAsyncFtpStream::retr_as_stream
/// [`ImplAsyncFtpStream::custom_data_command`]: super::ImplAsyncFtpStream::custom_data_command
/// [`FtpError::DataConnectionAlreadyOpen`]: crate::FtpError::DataConnectionAlreadyOpen
#[must_use = "call `finish().await` to close the data connection and read the transfer reply"]
#[derive(Debug)]
pub struct TransferStream<T>
where
    T: SmolTlsStream + Send,
{
    /// Data socket; `None` once the transfer has been finalized or detached.
    data: Option<DataStream<T>>,
    control: SharedControl<T>,
    direction: Direction,
}

impl<T> TransferStream<T>
where
    T: SmolTlsStream + Send,
{
    /// Wraps an open data connection so that it completes the transfer on `control`.
    pub(super) fn new(
        data: DataStream<T>,
        control: SharedControl<T>,
        direction: Direction,
    ) -> Self {
        Self {
            data: Some(data),
            control,
            direction,
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
    /// Returns [`FtpError::ConnectionError`] if an upload cannot be closed cleanly or the
    /// control connection cannot be read, and [`FtpError::UnexpectedResponse`] if the server
    /// reports that the transfer failed (any reply other than `226` or `250`).
    pub async fn finish(mut self) -> FtpResult<()> {
        let Some(mut data) = self.data.take() else {
            return Ok(());
        };
        // Close the write side so TLS streams send close_notify before being dropped, then close
        // the socket: the server only sends the completion reply once the data connection is gone.
        let closed = data.close().await;
        drop(data);
        let reply = self.control.lock().await.complete_transfer().await;
        if self.direction == Direction::Upload {
            closed.map_err(FtpError::ConnectionError)?;
        }
        reply
    }

    /// Detaches the data socket; the returned stream no longer completes the transfer on drop.
    ///
    /// Used by [`super::ImplAsyncFtpStream::abort`], which reads the reply itself.
    pub(super) fn detach(mut self) -> DataStream<T> {
        self.data
            .take()
            .expect("data stream is present until the transfer is finished")
    }

    /// Whether the transfer has already been finalized.
    fn is_finished(&self) -> bool {
        self.data.is_none()
    }
}

impl<T> AsyncRead for TransferStream<T>
where
    T: SmolTlsStream + Send,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(Pin::into_inner(self).get_mut()).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for TransferStream<T>
where
    T: SmolTlsStream + Send,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(Pin::into_inner(self).get_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(Pin::into_inner(self).get_mut()).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(Pin::into_inner(self).get_mut()).poll_close(cx)
    }
}

impl<T> Drop for TransferStream<T>
where
    T: SmolTlsStream + Send,
{
    fn drop(&mut self) {
        if self.is_finished() {
            return;
        }
        // Closing the socket makes the server send the completion reply; it cannot be awaited
        // here, so it is left for the next command to drain.
        drop(self.data.take());
        match self.control.try_lock() {
            Some(mut cc) => {
                cc.data_connection_open = false;
                cc.pending_transfer_reply = true;
                warn!(
                    "transfer stream dropped without finish(); its reply is read by the next command"
                );
            }
            None => warn!(
                "transfer stream dropped without finish() while the control connection is busy; the control connection is out of sync"
            ),
        }
    }
}
