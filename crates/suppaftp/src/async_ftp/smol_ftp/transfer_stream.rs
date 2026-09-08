//! Self-finalizing data stream for smol FTP transfers.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
/// can be reused after successful cleanup. The transfer outcome is lost in that case and only logged.
///
/// Finish the transfer before issuing any other command on the client, even when finishing
/// on another thread or task. Flush buffered writers before recovering their inner transfer.
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
    pending_reply: Arc<AtomicBool>,
    finished: bool,
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
        pending_reply: Arc<AtomicBool>,
    ) -> Self {
        Self {
            data: Some(data),
            control,
            direction,
            pending_reply,
            finished: false,
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
    /// # Cancellation
    ///
    /// Cancelling this future closes the data socket and leaves its completion reply for the
    /// next command to drain. Partially read replies are retained, including when that next
    /// command is itself cancelled during cleanup. The transfer result is lost on cancellation.
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
        self.finished = true;
        if self.direction == Direction::Upload {
            closed.map_err(FtpError::ConnectionError)?;
        }
        reply
    }

    /// Detaches the data socket; the returned stream no longer completes the transfer on drop.
    ///
    /// Used by [`super::ImplAsyncFtpStream::abort`], which reads the reply itself.
    pub(super) fn detach(mut self) -> DataStream<T> {
        self.finished = true;
        self.data
            .take()
            .expect("data stream is present until the transfer is finished")
    }

    /// Whether the transfer has already been finalized.
    fn is_finished(&self) -> bool {
        self.finished
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
        // This notification must work even while a socket guard or another task holds the lock.
        self.pending_reply.store(true, Ordering::Release);
        warn!("transfer stream dropped without finish(); its reply is read by the next command");
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Sender};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use crate::smol::AsyncFtpStream;

    async fn delayed_transfer_reply(
        prefix: &'static [u8],
        suffix: &'static [u8],
    ) -> (AsyncFtpStream, Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release, wait) = mpsc::channel();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut control = BufReader::new(socket);
            control.get_mut().write_all(b"220 ready\r\n").unwrap();
            let mut command = String::new();
            control.read_line(&mut command).unwrap();
            assert_eq!(command, "PASV\r\n");
            let data_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = data_listener.local_addr().unwrap().port();
            write!(
                control.get_mut(),
                "227 passive (127,0,0,1,{high},{low})\r\n",
                high = port / 256,
                low = port % 256
            )
            .unwrap();
            command.clear();
            control.read_line(&mut command).unwrap();
            assert_eq!(command, "STOR test.bin\r\n");
            let (mut data, _) = data_listener.accept().unwrap();
            data.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            control.get_mut().write_all(b"150 send data\r\n").unwrap();
            data.read_to_end(&mut Vec::new()).unwrap();
            control.get_mut().write_all(prefix).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            control.get_mut().write_all(suffix).unwrap();
            command.clear();
            control.read_line(&mut command).unwrap();
            assert_eq!(command, "NOOP\r\n");
            control.get_mut().write_all(b"200 noop\r\n").unwrap();
        });
        let ftp = AsyncFtpStream::connect(address).await.unwrap();
        (ftp, release, server)
    }

    #[test]
    fn should_recover_drop_while_control_socket_is_locked() {
        smol::block_on(async {
            let (mut ftp, release, server) = delayed_transfer_reply(b"", b"226 complete\r\n").await;
            let transfer = ftp.put_with_stream("test.bin").await.unwrap();
            let guard = ftp.get_ref().await;
            drop(transfer);
            drop(guard);
            release.send(()).unwrap();
            ftp.noop().await.unwrap();
            ftp.control()
                .await
                .unwrap()
                .guard_multiple_data_connections()
                .unwrap();
            server.join().unwrap();
        });
    }

    #[test]
    fn should_recover_cancelled_finish_waiting_for_control_lock() {
        smol::block_on(async {
            use std::future::{Future, poll_fn};
            use std::task::Poll;

            let (mut ftp, release, server) = delayed_transfer_reply(b"", b"226 complete\r\n").await;
            let transfer = ftp.put_with_stream("test.bin").await.unwrap();
            let guard = ftp.get_ref().await;
            let mut finish = Box::pin(transfer.finish());
            poll_fn(|cx| {
                assert!(finish.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(finish);
            drop(guard);
            release.send(()).unwrap();
            ftp.noop().await.unwrap();
            ftp.control()
                .await
                .unwrap()
                .guard_multiple_data_connections()
                .unwrap();
            server.join().unwrap();
        });
    }

    #[test]
    fn should_resume_partial_reply_after_cancelled_finish() {
        smol::block_on(async {
            let (mut ftp, release, server) = delayed_transfer_reply(
                b"226-transferred\r\nintermediate line\r\n226 comp",
                b"lete\r\n",
            )
            .await;
            let transfer = ftp.put_with_stream("test.bin").await.unwrap();
            assert!(
                smol::future::race(
                    async {
                        let _ = transfer.finish().await;
                        false
                    },
                    async {
                        smol::Timer::after(Duration::from_millis(50)).await;
                        true
                    }
                )
                .await
            );
            release.send(()).unwrap();
            ftp.noop().await.unwrap();
            ftp.control()
                .await
                .unwrap()
                .guard_multiple_data_connections()
                .unwrap();
            server.join().unwrap();
        });
    }

    #[test]
    fn should_resume_partial_reply_after_cancelled_drain() {
        smol::block_on(async {
            let (mut ftp, release, server) = delayed_transfer_reply(
                b"226-transferred\r\nintermediate line\r\n226 comp",
                b"lete\r\n",
            )
            .await;
            let transfer = ftp.put_with_stream("test.bin").await.unwrap();
            drop(transfer);
            assert!(
                smol::future::race(
                    async {
                        let _ = ftp.noop().await;
                        false
                    },
                    async {
                        smol::Timer::after(Duration::from_millis(50)).await;
                        true
                    }
                )
                .await
            );
            release.send(()).unwrap();
            ftp.noop().await.unwrap();
            ftp.control()
                .await
                .unwrap()
                .guard_multiple_data_connections()
                .unwrap();
            server.join().unwrap();
        });
    }
}
