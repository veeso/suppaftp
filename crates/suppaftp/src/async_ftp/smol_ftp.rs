//! # Async
//!
//! This module contains the definition for smol async implementation of suppaftp

mod control;
mod data_stream;
mod tls;
mod transfer_stream;

use std::future::Future;
#[cfg(not(feature = "async-secure"))]
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
// export
pub use control::ControlSocket;
use control::{ControlChannel, SharedControl};
pub use data_stream::DataStream;
use smol::future::FutureExt;
use smol::io::{AsyncBufReadExt, AsyncRead as Read, BufReader, copy};
use smol::lock::MutexGuard;
use smol::net::{AsyncToSocketAddrs as ToSocketAddrs, TcpListener, TcpStream};
#[cfg(feature = "async-secure")]
pub use tls::AsyncTlsConnector;
#[cfg(feature = "smol-async-native-tls")]
pub use tls::{AsyncNativeTlsConnector, AsyncNativeTlsStream};
pub use tls::{AsyncNoTlsStream, SmolTlsStream};
#[cfg(any(feature = "smol-rustls-aws-lc-rs", feature = "smol-rustls-ring"))]
pub use tls::{AsyncRustlsConnector, AsyncRustlsStream};
use transfer_stream::Direction;
pub use transfer_stream::TransferStream;

use super::super::Status;
use super::super::regex::{EPSV_PORT_RE, MDTM_RE, SIZE_RE};
use super::super::types::{ActivePeerCheck, FileType, FtpError, FtpResult, Mode, Response};
use crate::FtpStream;
use crate::command::Command;
#[cfg(feature = "async-secure")]
use crate::command::ProtectionLevel;
use crate::encoding::{Encoding, Utf8Encoding};
use crate::types::Features;

/// A function that creates a new stream for the data connection in passive mode.
///
/// It takes a [`SocketAddr`] and returns a [`TcpStream`].
pub type SmolPassiveStreamBuilder = dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = FtpResult<TcpStream>> + Send + Sync>>
    + Send
    + Sync;

/// Stream to interface with the FTP server. This interface is only for the command stream.
///
/// The control connection is shared with the [`TransferStream`]s handed out by the data
/// commands, so that each transfer can close its data connection and read the completion reply
/// on its own; see [`TransferStream`] for details.
pub struct ImplAsyncFtpStream<T>
where
    T: SmolTlsStream + Send,
{
    /// Control connection, locked for the duration of each command.
    control: SharedControl<T>,
    mode: Mode,
    nat_workaround: bool,
    /// Which addresses an active-mode data connection is accepted from.
    active_peer_check: ActivePeerCheck,
    welcome_msg: Option<String>,
    active_timeout: Duration,
    passive_stream_builder: Box<SmolPassiveStreamBuilder>,
    #[cfg(not(feature = "async-secure"))]
    marker: PhantomData<T>,
    #[cfg(feature = "async-secure")]
    tls_ctx: Option<Box<dyn AsyncTlsConnector<Stream = T> + Send + Sync + 'static>>,
    #[cfg(feature = "async-secure")]
    domain: Option<String>,
}

impl<T> ImplAsyncFtpStream<T>
where
    T: SmolTlsStream + Send,
{
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> FtpResult<Self> {
        debug!("Connecting to server");
        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;
        debug!("Established connection with server");
        Self::connect_with_stream(stream).await
    }

    /// Try to connect to the remote server but with the specified timeout
    pub async fn connect_timeout(addr: SocketAddr, timeout: Duration) -> FtpResult<Self> {
        debug!("Connecting to server {addr}");
        let connect = async move { TcpStream::connect(addr).await };
        let deadline = async move {
            smol::Timer::after(timeout).await;
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection timed out",
            ))
        };
        let stream = connect
            .or(deadline)
            .await
            .map_err(FtpError::ConnectionError)?;

        Self::connect_with_stream(stream).await
    }

    /// Connect using provided configured tcp stream
    pub async fn connect_with_stream(stream: TcpStream) -> FtpResult<Self> {
        debug!("Established connection with server");
        let mut ftp_stream = ImplAsyncFtpStream {
            control: ControlChannel::shared(DataStream::Tcp(stream), Arc::new(Utf8Encoding)),
            #[cfg(not(feature = "async-secure"))]
            marker: PhantomData {},
            mode: Mode::Passive,
            nat_workaround: false,
            active_peer_check: ActivePeerCheck::default(),
            passive_stream_builder: Self::default_passive_stream_builder(),
            welcome_msg: None,
            #[cfg(feature = "async-secure")]
            tls_ctx: None,
            #[cfg(feature = "async-secure")]
            domain: None,
            active_timeout: Duration::from_secs(60),
        };
        debug!("Reading server response...");
        let ready = ftp_stream.read_response(Status::Ready).await;
        match ready {
            Ok(response) => {
                let welcome_msg = response.as_string().ok();
                debug!("Server READY; response: {:?}", welcome_msg);
                ftp_stream.welcome_msg = welcome_msg;
                Ok(ftp_stream)
            }
            Err(err) => Err(err),
        }
    }

    /// Switch to secure mode if possible (FTPS), using a provided SSL configuration.
    /// Returns [`FtpError::DataConnectionAlreadyOpen`] before sending `AUTH` if a transfer is alive.
    /// This method does nothing if the connect is already secured.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// use suppaftp::ImplAsyncFtpStream;
    /// use suppaftp::async_native_tls::{TlsConnector, TlsStream};
    /// use std::path::Path;
    ///
    /// // Create a TlsConnector
    /// // NOTE: For custom options see <https://docs.rs/native-tls/0.2.6/native_tls/struct.TlsConnectorBuilder.html>
    /// let mut ctx = TlsConnector::new();
    /// let mut ftp_stream = ImplAsyncFtpStream::connect("127.0.0.1:21").await.unwrap();
    /// let mut ftp_stream = ftp_stream.into_secure(ctx, "localhost").await.unwrap();
    /// ```
    #[cfg(feature = "async-secure")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async-secure")))]
    pub async fn into_secure(
        self,
        tls_connector: impl AsyncTlsConnector<Stream = T> + Send + Sync + 'static,
        domain: &str,
    ) -> FtpResult<Self> {
        // Reject a live transfer before asking the server to change the control protocol.
        if Arc::strong_count(&self.control) != 1 {
            return Err(FtpError::DataConnectionAlreadyOpen);
        }
        debug!("Initializing TLS auth");
        {
            let mut cc = self.control().await?;
            // Ask the server to start securing data.
            cc.perform(Command::Auth).await?;
            cc.read_response(Status::AuthOk).await?;
        }
        debug!("TLS OK; initializing ssl stream");
        let plain = control::into_exclusive(self.control)?;
        let encoding = Arc::clone(&plain.encoding);
        let plain = plain.reader.into_inner().into_tcp_stream()?;
        let stream = tls_connector
            .connect(domain, plain)
            .await
            .map_err(|e| FtpError::SecureError(format!("{e}")))?;
        let secured_ftp_tream = ImplAsyncFtpStream {
            control: ControlChannel::shared(DataStream::Ssl(Box::new(stream)), encoding),
            mode: self.mode,
            nat_workaround: self.nat_workaround,
            active_peer_check: self.active_peer_check,
            passive_stream_builder: self.passive_stream_builder,
            tls_ctx: Some(Box::new(tls_connector)),
            domain: Some(String::from(domain)),
            welcome_msg: self.welcome_msg,
            active_timeout: self.active_timeout,
        };
        {
            let mut cc = secured_ftp_tream.control().await?;
            // Set protection buffer size
            cc.perform(Command::Pbsz(0)).await?;
            cc.read_response(Status::CommandOk).await?;
            // Change the level of data protectio to Private
            cc.perform(Command::Prot(ProtectionLevel::Private)).await?;
            cc.read_response(Status::CommandOk).await?;
        }
        Ok(secured_ftp_tream)
    }

    /// Connect to remote ftps server using IMPLICIT secure connection.
    ///
    /// > Warning: mind that implicit ftps should be considered deprecated, if you can use explicit mode with `into_secure()`
    ///
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// use suppaftp::ImplAsyncFtpStream;
    /// use suppaftp::native_tls::{TlsConnector, TlsStream};
    /// use std::path::Path;
    ///
    /// // Create a TlsConnector
    /// // NOTE: For custom options see <https://docs.rs/native-tls/0.2.6/native_tls/struct.TlsConnectorBuilder.html>
    /// let mut ctx = TlsConnector::new();
    /// let mut ftp_stream = ImplAsyncFtpStream::connect_secure_implicit("127.0.0.1:990", ctx, "localhost").await.unwrap();
    /// ```
    #[cfg(all(feature = "async-secure", feature = "deprecated"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "async-secure", feature = "deprecated")))
    )]
    pub async fn connect_secure_implicit<A: ToSocketAddrs>(
        addr: A,
        tls_connector: impl AsyncTlsConnector<Stream = T> + Send + Sync + 'static,
        domain: &str,
    ) -> FtpResult<Self> {
        debug!("Connecting to server (secure)");
        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;
        debug!("Established connection with server");
        debug!("TLS OK; initializing ssl stream");
        let stream = tls_connector
            .connect(domain, stream)
            .await
            .map_err(|e| FtpError::SecureError(format!("{e}")))?;
        debug!("TLS Steam OK");
        let mut stream = ImplAsyncFtpStream {
            control: ControlChannel::shared(
                DataStream::Ssl(Box::new(stream)),
                Arc::new(Utf8Encoding),
            ),
            mode: Mode::Passive,
            nat_workaround: false,
            active_peer_check: ActivePeerCheck::default(),
            passive_stream_builder: Self::default_passive_stream_builder(),
            tls_ctx: Some(Box::new(tls_connector)),
            domain: Some(String::from(domain)),
            welcome_msg: None,
            active_timeout: Duration::from_secs(60),
        };
        debug!("Reading server response...");
        let response = stream.read_response(Status::Ready).await?;
        let welcome_msg = response.as_string().ok();
        debug!("Server READY; response: {:?}", welcome_msg);
        stream.welcome_msg = welcome_msg;

        Ok(stream)
    }

    /// Enable active mode for data channel
    pub fn active_mode(mut self, listener_timeout: Duration) -> Self {
        self.mode = Mode::Active;
        self.active_timeout = listener_timeout;
        self
    }

    /// Set a custom [`SmolPassiveStreamBuilder`] for passive mode.
    ///
    /// The stream builder is a function that takes a `SocketAddr` and returns a `TcpStream` and it's used
    /// to create the [`TcpStream`] for the data connection in passive mode.
    pub fn passive_stream_builder<F>(mut self, stream_builder: F) -> Self
    where
        F: Fn(SocketAddr) -> Pin<Box<dyn Future<Output = FtpResult<TcpStream>> + Send + Sync>>
            + Send
            + Sync
            + 'static,
    {
        self.passive_stream_builder = Box::new(stream_builder);
        self
    }

    /// Returns welcome message retrieved from server (if available)
    pub fn get_welcome_msg(&self) -> Option<&str> {
        self.welcome_msg.as_deref()
    }

    /// Set mode
    pub fn set_mode(&mut self, mode: Mode) {
        debug!("Changed mode to {:?}", mode);
        self.mode = mode;
    }

    /// Set NAT workaround for passive mode
    pub fn set_passive_nat_workaround(&mut self, nat_workaround: bool) {
        self.nat_workaround = nat_workaround;
    }

    /// Set which addresses an active-mode data connection is accepted from.
    ///
    /// The default, [`ActivePeerCheck::ControlPeer`], accepts only the server on the control
    /// connection; see [`ActivePeerCheck`] for the other choices.
    pub fn set_active_peer_check(&mut self, check: ActivePeerCheck) {
        self.active_peer_check = check;
    }

    /// Set the [`Encoding`] of file names and commands.
    ///
    /// The encoding is applied to every command sent and to the lines of `LIST`, `NLST` and
    /// `MLSD` listings and the replies of `MLST` and `PWD`. The default is [`Utf8Encoding`].
    pub async fn set_encoding(&mut self, encoding: impl Encoding + 'static) {
        self.control.lock().await.encoding = Arc::new(encoding);
    }

    /// Returns a locked view of the underlying control [`TcpStream`].
    ///
    /// The returned [`ControlSocket`] dereferences to the socket and keeps the control connection
    /// locked while alive, so drop it before finishing a [`TransferStream`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use suppaftp::smol::AsyncFtpStream;
    ///
    /// # async fn run() {
    /// let stream = AsyncFtpStream::connect("127.0.0.1:21").await.unwrap();
    /// stream.get_ref().await.set_nodelay(true).unwrap();
    /// # }
    /// ```
    pub async fn get_ref(&self) -> ControlSocket<'_, T> {
        ControlSocket::new(self.control.lock().await)
    }

    /// Log in to the FTP server.
    pub async fn login<S: AsRef<str>>(&mut self, user: S, password: S) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Signin in with user '{}'", user.as_ref());
        cc.perform(Command::User(user.as_ref().to_string())).await?;
        let response = cc
            .read_response_in(&[Status::LoggedIn, Status::NeedPassword])
            .await?;
        if response.status == Status::NeedPassword {
            debug!("Password is required");
            cc.perform(Command::Pass(password.as_ref().to_string()))
                .await?;
            cc.read_response(Status::LoggedIn).await?;
        }
        debug!("Login OK");
        Ok(())
    }

    /// Perform clear command channel (CCC).
    /// Once the command is performed, the command channel will be encrypted no more.
    /// The data stream will still be secure.
    /// Returns [`FtpError::DataConnectionAlreadyOpen`] before sending `CCC` if a transfer is alive.
    #[cfg(feature = "async-secure")]
    #[cfg_attr(docsrs, doc(cfg(feature = "async-secure")))]
    pub async fn clear_command_channel(mut self) -> FtpResult<Self> {
        // Reject a live transfer before asking the server to change the control protocol.
        if Arc::strong_count(&self.control) != 1 {
            return Err(FtpError::DataConnectionAlreadyOpen);
        }
        {
            let mut cc = self.control().await?;
            // Ask the server to stop securing data
            debug!("performing clear command channel");
            cc.perform(Command::ClearCommandChannel).await?;
            cc.read_response(Status::CommandOk).await?;
        }
        trace!("CCC OK");
        let plain = control::into_exclusive(self.control)?;
        let encoding = Arc::clone(&plain.encoding);
        let plain = plain.reader.into_inner().into_tcp_stream()?;
        self.control = ControlChannel::shared(DataStream::Tcp(plain), encoding);
        Ok(self)
    }

    /// Change the current directory to the path specified.
    pub async fn cwd<S: AsRef<str>>(&mut self, path: S) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Changing working directory to {}", path.as_ref());
        cc.perform(Command::Cwd(path.as_ref().to_string())).await?;
        cc.read_response_in(&[Status::CommandOk, Status::RequestedFileActionOk])
            .await
            .map(|_| ())
    }

    /// Move the current directory to the parent directory.
    pub async fn cdup(&mut self) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Going to parent directory");
        cc.perform(Command::Cdup).await?;
        cc.read_response_in(&[Status::CommandOk, Status::RequestedFileActionOk])
            .await
            .map(|_| ())
    }

    /// Gets the current directory
    pub async fn pwd(&mut self) -> FtpResult<String> {
        let mut cc = self.control().await?;
        debug!("Getting working directory");
        cc.perform(Command::Pwd).await?;
        let response = cc.read_response(Status::PathCreated).await?;
        let body = cc
            .encoding
            .decode(&crate::command::unescape_telnet_iac(&response.body));
        match (body.find('"'), body.rfind('"')) {
            (Some(begin), Some(end)) if begin < end => Ok(body[begin + 1..end].to_string()),
            _ => Err(FtpError::UnexpectedResponse(response)),
        }
    }

    /// This does nothing. This is usually just used to keep the connection open.
    pub async fn noop(&mut self) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Pinging server");
        cc.perform(Command::Noop).await?;
        cc.read_response(Status::CommandOk).await.map(|_| ())
    }

    /// The EPRT command allows for the specification of an extended address
    /// for the data connection. The extended address MUST consist of the
    /// network protocol as well as the network and transport addresses
    pub async fn eprt(&mut self, address: SocketAddr) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("EPRT with address {address}");
        cc.perform(Command::Eprt(address)).await?;
        cc.read_response(Status::CommandOk).await.map(|_| ())
    }

    /// This creates a new directory on the server.
    pub async fn mkdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Creating directory at {}", pathname.as_ref());
        cc.perform(Command::Mkd(pathname.as_ref().to_string()))
            .await?;
        // Some non-compliant servers (e.g. bftpd) reply with 200 instead of 257.
        cc.read_response_in(&[Status::PathCreated, Status::CommandOk])
            .await
            .map(|_| ())
    }

    /// Sets the type of file to be transferred. That is the implementation
    /// of `TYPE` command.
    pub async fn transfer_type(&mut self, file_type: FileType) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Setting transfer type {}", file_type);
        cc.perform(Command::Type(file_type)).await?;
        cc.read_response(Status::CommandOk).await.map(|_| ())
    }

    /// Quits the current FTP session.
    pub async fn quit(&mut self) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Quitting stream");
        cc.perform(Command::Quit).await?;
        cc.read_response(Status::Closing).await.map(|_| ())
    }

    /// Renames the file from_name to to_name
    pub async fn rename<S: AsRef<str>>(&mut self, from_name: S, to_name: S) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!(
            "Renaming '{}' to '{}'",
            from_name.as_ref(),
            to_name.as_ref()
        );
        cc.perform(Command::RenameFrom(from_name.as_ref().to_string()))
            .await?;
        cc.read_response(Status::RequestFilePending).await?;
        cc.perform(Command::RenameTo(to_name.as_ref().to_string()))
            .await?;
        // Some non-compliant servers (e.g. bftpd) reply with 200 instead of 250.
        cc.read_response_in(&[Status::RequestedFileActionOk, Status::CommandOk])
            .await
            .map(|_| ())
    }

    /// The implementation of `RETR` command where `filename` is the name of the file
    /// to download from FTP and `reader` is the function which operates with the
    /// data stream opened.
    ///
    /// `reader` is an async pinned closure that takes the [`TransferStream<T>`] and returns
    /// both the result `U` and the [`TransferStream<T>`] back in a tuple `(U, TransferStream<T>)`.
    /// The stream is finished on callback success. If `reader` returns an error and drops the
    /// stream, the next command drains its completion reply before sending anything.
    ///
    /// > Warning: Don't call [`TransferStream::finish`] inside `reader`; return the stream instead.
    pub async fn retr<S, F, U>(&mut self, file_name: S, mut reader: F) -> FtpResult<U>
    where
        F: FnMut(
            TransferStream<T>,
        )
            -> Pin<Box<dyn Future<Output = FtpResult<(U, TransferStream<T>)>> + Send>>,
        S: AsRef<str>,
    {
        let stream = self.retr_as_stream(file_name).await?;
        let (result, stream) = reader(stream).await?;
        stream.finish().await?;
        Ok(result)
    }

    /// Retrieves the file `file_name` from the server as a readable [`TransferStream`].
    ///
    /// Read the payload from the returned stream, then call [`TransferStream::finish`] to close
    /// the data connection and read the server's completion reply. Until then any other data
    /// command fails with [`FtpError::DataConnectionAlreadyOpen`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use suppaftp::smol::AsyncFtpStream;
    /// use smol::io::AsyncReadExt;
    ///
    /// # async fn run() {
    /// let mut ftp = AsyncFtpStream::connect("127.0.0.1:21").await.unwrap();
    /// ftp.login("test", "test").await.unwrap();
    /// let mut download = ftp.retr_as_stream("hello.txt").await.unwrap();
    /// let mut buf = Vec::new();
    /// download.read_to_end(&mut buf).await.unwrap();
    /// download.finish().await.unwrap();
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::DataConnectionAlreadyOpen`] if a transfer is still in progress, and
    /// [`FtpError::UnexpectedResponse`] if the server refuses the `RETR` command.
    pub async fn retr_as_stream<S: AsRef<str>>(
        &mut self,
        file_name: S,
    ) -> FtpResult<TransferStream<T>> {
        debug!("Retrieving '{}'", file_name.as_ref());
        let (_, stream) = self
            .open_transfer(
                Command::Retr(file_name.as_ref().to_string()),
                &[Status::AboutToSend, Status::AlreadyOpen],
                Direction::Download,
            )
            .await?;
        Ok(stream)
    }

    /// Removes the remote pathname from the server.
    pub async fn rmdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Removing directory {}", pathname.as_ref());
        cc.perform(Command::Rmd(pathname.as_ref().to_string()))
            .await?;
        // Some non-compliant servers (e.g. bftpd) reply with 200 instead of 250.
        cc.read_response_in(&[Status::RequestedFileActionOk, Status::CommandOk])
            .await
            .map(|_| ())
    }

    /// Remove the remote file from the server.
    pub async fn rm<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Removing file {}", filename.as_ref());
        cc.perform(Command::Dele(filename.as_ref().to_string()))
            .await?;
        // Some non-compliant servers (e.g. bftpd) reply with 200 instead of 250.
        cc.read_response_in(&[Status::RequestedFileActionOk, Status::CommandOk])
            .await
            .map(|_| ())
    }

    /// This stores a file on the server.
    /// r argument must be any struct which implemenents the Read trait
    pub async fn put_file<S, R>(&mut self, filename: S, r: &mut R) -> FtpResult<u64>
    where
        R: Read + std::marker::Unpin,
        S: AsRef<str>,
    {
        // Get stream
        let mut data_stream = self.put_with_stream(filename).await?;
        let bytes = copy(r, &mut data_stream)
            .await
            .map_err(FtpError::ConnectionError)?;
        data_stream.finish().await?;
        Ok(bytes)
    }

    /// Sends `STOR` and returns a writable [`TransferStream`] for the file `filename`.
    ///
    /// Write the payload to the returned stream, then call [`TransferStream::finish`] to close
    /// the data connection and read the server's completion reply. Until then any other data
    /// command fails with [`FtpError::DataConnectionAlreadyOpen`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use suppaftp::smol::AsyncFtpStream;
    /// use smol::io::AsyncWriteExt;
    ///
    /// # async fn run() {
    /// let mut ftp = AsyncFtpStream::connect("127.0.0.1:21").await.unwrap();
    /// ftp.login("test", "test").await.unwrap();
    /// let mut upload = ftp.put_with_stream("hello.txt").await.unwrap();
    /// upload.write_all(b"hello, world!").await.unwrap();
    /// upload.finish().await.unwrap();
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::DataConnectionAlreadyOpen`] if a transfer is still in progress, and
    /// [`FtpError::UnexpectedResponse`] if the server refuses the `STOR` command.
    pub async fn put_with_stream<S: AsRef<str>>(
        &mut self,
        filename: S,
    ) -> FtpResult<TransferStream<T>> {
        debug!("Put file {}", filename.as_ref());
        let (_, stream) = self
            .open_transfer(
                Command::Store(filename.as_ref().to_string()),
                &[Status::AlreadyOpen, Status::AboutToSend],
                Direction::Upload,
            )
            .await?;
        Ok(stream)
    }

    /// Sends `APPE` and returns a writable [`TransferStream`] appending to the file `filename`.
    ///
    /// Behaves like [`ImplAsyncFtpStream::put_with_stream`], except that the data is appended.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::DataConnectionAlreadyOpen`] if a transfer is still in progress, and
    /// [`FtpError::UnexpectedResponse`] if the server refuses the `APPE` command.
    pub async fn append_with_stream<S: AsRef<str>>(
        &mut self,
        filename: S,
    ) -> FtpResult<TransferStream<T>> {
        debug!("Appending to file {}", filename.as_ref());
        let (_, stream) = self
            .open_transfer(
                Command::Appe(filename.as_ref().to_string()),
                &[Status::AlreadyOpen, Status::AboutToSend],
                Direction::Upload,
            )
            .await?;
        Ok(stream)
    }

    /// Append data from reader to file at `filename`
    pub async fn append_file<R>(&mut self, filename: &str, r: &mut R) -> FtpResult<u64>
    where
        R: Read + std::marker::Unpin,
    {
        // Get stream
        let mut data_stream = self.append_with_stream(filename).await?;
        let bytes = copy(r, &mut data_stream)
            .await
            .map_err(FtpError::ConnectionError)?;
        data_stream.finish().await?;
        Ok(bytes)
    }

    /// Aborts the transfer running on `transfer` with the `ABOR` command.
    ///
    /// The data connection is closed and the server's abort replies (`426` followed by `226`,
    /// or a single `226`) are consumed, so the control connection is ready for the next command.
    /// `transfer` must have been obtained from this client.
    /// This operation is not cancellation-safe: reconnect if its future is cancelled after polling.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::UnexpectedResponse`] if the server does not acknowledge the abort.
    pub async fn abort(&mut self, transfer: TransferStream<T>) -> FtpResult<()> {
        debug!("Aborting active file transfer");
        // Detach the socket first: the stream must not flag a pending reply on drop.
        let data_stream = transfer.detach();
        let mut cc = self.control().await?;
        cc.perform(Command::Abor).await?;
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(data_stream);
        cc.data_connection_open = false;
        trace!("dropped stream");
        let response = cc
            .read_response_in(&[Status::ClosingDataConnection, Status::TransferAborted])
            .await?;
        // If server sent 426 (TransferAborted), expect a follow-up 226
        if response.status == Status::TransferAborted {
            cc.read_response(Status::ClosingDataConnection).await?;
        }
        trace!("Transfer aborted");
        Ok(())
    }

    /// Tell the server to resume the transfer from a certain offset. The offset indicates the amount of bytes to skip
    /// from the beginning of the file.
    /// the REST command does not actually initiate the transfer.
    /// After issuing a REST command, the client must send the appropriate FTP command to transfer the file
    ///
    /// It is possible to cancel the REST command, sending a REST command with offset 0
    pub async fn resume_transfer(&mut self, offset: usize) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Requesting to resume transfer at offset {}", offset);
        cc.perform(Command::Rest(offset)).await?;
        cc.read_response(Status::RequestFilePending).await?;
        debug!("Resume transfer accepted");
        Ok(())
    }

    /// Execute `LIST` command which returns the detailed file listing in human readable format.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn list(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        debug!(
            "Reading {} directory content",
            pathname.unwrap_or("working")
        );

        self.stream_lines(
            Command::List(pathname.map(|x| x.to_string())),
            Status::AboutToSend,
        )
        .await
    }

    /// Execute `NLST` command which returns the list of file names only.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn nlst(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        debug!(
            "Getting file names for {} directory",
            pathname.unwrap_or("working")
        );
        self.stream_lines(
            Command::Nlst(pathname.map(|x| x.to_string())),
            Status::AboutToSend,
        )
        .await
    }

    /// Execute `MLSD` command which returns the machine-processable listing of a directory.
    /// If `pathname` is omited then the list of files in the current directory will be
    pub async fn mlsd(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        debug!(
            "Reading {} directory content",
            pathname.unwrap_or("working")
        );

        self.stream_lines(
            Command::Mlsd(pathname.map(|x| x.to_string())),
            Status::AboutToSend,
        )
        .await
    }

    /// Execute `MLST` command which returns the machine-processable listing of a file.
    /// If `pathname` is omited then the list of files in the current directory will be
    pub async fn mlst(&mut self, pathname: Option<&str>) -> FtpResult<String> {
        let mut cc = self.control().await?;
        debug!("Reading {} path information", pathname.unwrap_or("working"));

        cc.perform(Command::Mlst(pathname.map(|x| x.to_string())))
            .await?;
        let response = cc
            .read_response_in(&[Status::RequestedFileActionOk])
            .await?;
        // read body at line 1
        let response_str = cc
            .encoding
            .decode(&crate::command::unescape_telnet_iac(&response.body));
        match response_str.lines().nth(1) {
            Some("") => Err(FtpError::BadResponse),
            Some(line) => Ok(line.trim().to_string()),
            None => Err(FtpError::BadResponse),
        }
    }

    /// Retrieves the modification time of the file at `pathname` if it exists.
    pub async fn mdtm<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<NaiveDateTime> {
        let mut cc = self.control().await?;
        debug!("Getting modification time for {}", pathname.as_ref());
        cc.perform(Command::Mdtm(pathname.as_ref().to_string()))
            .await?;
        let response: Response = cc.read_response(Status::File).await?;
        let body = response.as_string().map_err(|_| FtpError::BadResponse)?;

        match MDTM_RE.captures(&body) {
            Some(caps) => {
                let (year, month, day) = (
                    caps[1].parse::<i32>().map_err(|_| FtpError::BadResponse)?,
                    caps[2].parse::<u32>().map_err(|_| FtpError::BadResponse)?,
                    caps[3].parse::<u32>().map_err(|_| FtpError::BadResponse)?,
                );
                let (hour, minute, second) = (
                    caps[4].parse::<u32>().map_err(|_| FtpError::BadResponse)?,
                    caps[5].parse::<u32>().map_err(|_| FtpError::BadResponse)?,
                    caps[6].parse::<u32>().map_err(|_| FtpError::BadResponse)?,
                );
                let date = match NaiveDate::from_ymd_opt(year, month, day) {
                    Some(d) => d,
                    None => return Err(FtpError::BadResponse),
                };

                let time = match NaiveTime::from_hms_opt(hour, minute, second) {
                    Some(t) => t,
                    None => return Err(FtpError::BadResponse),
                };

                Ok(NaiveDateTime::new(date, time))
            }
            None => Err(FtpError::BadResponse),
        }
    }

    /// Retrieves the size of the file in bytes at `pathname` if it exists.
    pub async fn size<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<usize> {
        let mut cc = self.control().await?;
        debug!("Getting file size for {}", pathname.as_ref());
        cc.perform(Command::Size(pathname.as_ref().to_string()))
            .await?;
        let response: Response = cc.read_response(Status::File).await?;
        let body = response.as_string().map_err(|_| FtpError::BadResponse)?;

        match SIZE_RE.captures(&body) {
            Some(caps) => caps[1].parse().map_err(|_| FtpError::BadResponse),
            None => Err(FtpError::BadResponse),
        }
    }

    /// Retrieves the features supported by the server, through the FEAT command.
    pub async fn feat(&mut self) -> FtpResult<Features> {
        let mut cc = self.control().await?;
        debug!("Getting server supported features");
        cc.perform(Command::Feat).await?;

        let response = cc.read_response(Status::System).await?;

        let first_line = String::from_utf8_lossy(&response.body);
        debug!("FEAT response: {}", first_line);
        let mut feat_lines = vec![first_line.to_string()];
        let mut reply_len = response.body.len();

        loop {
            let mut line = Vec::new();
            let bytes_read = cc.read_line(&mut line, reply_len).await?;
            reply_len += bytes_read;
            if bytes_read == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&line);
            trace!("FEAT IN: {:?}", line);
            feat_lines.push(line.to_string());
            if crate::command::feat::is_last_line(&line) {
                break;
            }
        }

        crate::command::feat::parse_features(&feat_lines)
    }

    /// Set option `option` with an optional value
    pub async fn opts(
        &mut self,
        option: impl ToString,
        value: Option<impl ToString>,
    ) -> FtpResult<()> {
        let mut cc = self.control().await?;
        debug!("Getting server supported features");
        cc.perform(Command::Opts(
            option.to_string(),
            value.map(|x| x.to_string()),
        ))
        .await?;
        cc.read_response(Status::CommandOk).await?;

        Ok(())
    }

    /// Execute a command on the server and return the response
    pub async fn site(&mut self, command: impl ToString) -> FtpResult<Response> {
        let mut cc = self.control().await?;
        debug!("Sending SITE command: {}", command.to_string());
        cc.perform(Command::Site(command.to_string())).await?;
        cc.read_response(Status::CommandOk).await
    }

    /// Perform custom command.
    ///
    /// The command is sent as a single control-channel line, so it must not
    /// contain CR or LF: embedding a line break would let a second command be
    /// smuggled to the server.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::ConnectionError`] with [`std::io::ErrorKind::InvalidInput`]
    /// if `command` contains CR or LF.
    pub async fn custom_command(
        &mut self,
        command: impl ToString,
        expected_code: &[Status],
    ) -> FtpResult<Response> {
        let mut cc = self.control().await?;
        let command = command.to_string();
        debug!("Sending custom command: {}", command);
        cc.perform(Command::Custom(command)).await?;
        cc.read_response_in(expected_code).await
    }

    /// Perform a custom command using the data connection.
    ///
    /// It returns both the [`Response`] and a [`TransferStream`], which implements both
    /// [`smol::io::AsyncWrite`] and [`smol::io::AsyncRead`] and so it can be written or read to interact
    /// with the data channel.
    ///
    /// If you want you can easily parse lines from the stream using [`Self::get_lines_from_stream`].
    ///
    /// Once done, call [`TransferStream::finish`] to close the data connection and read the
    /// server's completion reply.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::DataConnectionAlreadyOpen`] if a transfer is still in progress, and
    /// [`FtpError::UnexpectedResponse`] if the server's reply is not in `expected_code`.
    pub async fn custom_data_command(
        &mut self,
        command: impl ToString,
        expected_code: &[Status],
    ) -> FtpResult<(Response, TransferStream<T>)> {
        let command = command.to_string();
        debug!("Sending custom data command: {}", command);
        self.open_transfer(Command::Custom(command), expected_code, Direction::Download)
            .await
    }

    /// Read a data stream line by line, decoding each line as lossy UTF-8.
    pub async fn get_lines_from_stream<R>(data_stream: &mut R) -> FtpResult<Vec<String>>
    where
        R: AsyncBufReadExt + Unpin,
    {
        Self::decode_lines_from_stream(data_stream, &Utf8Encoding).await
    }

    /// Reads `data_stream` line by line, decoding each non-empty line with `encoding`.
    async fn decode_lines_from_stream<R>(
        data_stream: &mut R,
        encoding: &dyn Encoding,
    ) -> FtpResult<Vec<String>>
    where
        R: AsyncBufReadExt + Unpin,
    {
        let mut lines: Vec<String> = Vec::new();

        loop {
            let mut line_buf = vec![];
            match data_stream.read_until(b'\n', &mut line_buf).await {
                Ok(0) => break,
                Ok(_) => {
                    let bytes = line_buf.strip_suffix(b"\n").unwrap_or(&line_buf);
                    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
                    if bytes.is_empty() {
                        continue;
                    }
                    let line = encoding.decode(bytes);
                    trace!("STREAM IN: {:?}", line);
                    lines.push(line);
                }
                Err(err) => {
                    error!("failed to get lines from stream: {err}");
                    return Err(FtpError::BadResponse);
                }
            }
        }
        trace!("Lines from stream {:?}", lines);
        Ok(lines)
    }

    /// Reads one reply from the control connection and checks that its status is `expected_code`.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::UnexpectedResponse`] if the reply has another status.
    pub async fn read_response(&mut self, expected_code: Status) -> FtpResult<Response> {
        self.control().await?.read_response(expected_code).await
    }

    /// Reads one reply from the control connection and checks that its status is in `expected_code`.
    ///
    /// # Errors
    ///
    /// Returns [`FtpError::UnexpectedResponse`] if the reply has another status.
    pub async fn read_response_in(&mut self, expected_code: &[Status]) -> FtpResult<Response> {
        self.control().await?.read_response_in(expected_code).await
    }

    // -- private

    /// Locks the control connection for the duration of one command.
    ///
    /// Drains the reply of a transfer stream dropped without `finish()` first, so that the
    /// control connection is in sync when the command is sent.
    async fn control(&self) -> FtpResult<MutexGuard<'_, ControlChannel<T>>> {
        let mut cc = self.control.lock().await;
        cc.drain_pending_transfer_reply().await?;
        Ok(cc)
    }

    /// Opens the data connection for `cmd` and wraps it into a self-finalizing [`TransferStream`].
    async fn open_transfer(
        &self,
        cmd: Command,
        expected_code: &[Status],
        direction: Direction,
    ) -> FtpResult<(Response, TransferStream<T>)> {
        let mut cc = self.control().await?;
        let (response, data_stream) = self
            .data_command_with_response(&mut cc, cmd, expected_code)
            .await?;
        Ok((
            response,
            TransferStream::new(
                data_stream,
                Arc::clone(&self.control),
                direction,
                Arc::clone(&cc.pending_transfer_reply),
            ),
        ))
    }

    /// Opens the data channel after the transfer command's preliminary response is accepted.
    ///
    /// Passive mode connects the raw TCP socket before sending the command. Active mode sends the
    /// command and validates its reply before accepting a data socket. Rejections drop the pending
    /// socket or listener without starting TLS or marking the data connection open.
    async fn data_command_with_response(
        &self,
        cc: &mut ControlChannel<T>,
        cmd: Command,
        expected_code: &[Status],
    ) -> FtpResult<(Response, DataStream<T>)> {
        // Reject overlapping transfers before negotiating or opening another data socket.
        cc.guard_multiple_data_connections()?;

        let (response, stream) = match self.mode {
            Mode::Active => {
                let listener = self.active(cc).await?;
                cc.perform(cmd).await?;
                let response = cc.read_response_in(expected_code).await?;

                // Anyone reaching the listener may connect first; only allowed peers are taken.
                let control_peer = cc
                    .socket()
                    .peer_addr()
                    .map_err(FtpError::ConnectionError)?
                    .ip();
                let accept = async {
                    let connection = loop {
                        match listener.accept().await {
                            Ok((stream, addr))
                                if self.active_peer_check.allows(addr.ip(), control_peer) =>
                            {
                                break Ok((stream, addr));
                            }
                            Ok((_, addr)) => {
                                warn!("Ignoring data connection from unexpected {addr}");
                            }
                            Err(error) => break Err(error),
                        }
                    };
                    Ok::<_, ()>(connection)
                };
                let deadline = async {
                    smol::Timer::after(self.active_timeout).await;
                    Err(())
                };
                let stream = match accept.or(deadline).await {
                    Ok(Ok((stream, addr))) => {
                        debug!("Connection received from {}", addr);
                        stream
                    }
                    Ok(Err(error)) => return Err(FtpError::ConnectionError(error)),
                    Err(()) => {
                        return Err(FtpError::ConnectionError(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "timed out waiting for active mode data connection",
                        )));
                    }
                };
                (response, stream)
            }
            Mode::ExtendedPassive => {
                let address = self.epsv(cc).await?;
                let stream = (self.passive_stream_builder)(address).await?;
                cc.perform(cmd).await?;
                let response = cc.read_response_in(expected_code).await?;
                (response, stream)
            }
            Mode::Passive => {
                let address = self.pasv(cc).await?;
                let stream = (self.passive_stream_builder)(address).await?;
                cc.perform(cmd).await?;
                let response = cc.read_response_in(expected_code).await?;
                (response, stream)
            }
        };

        #[cfg(not(feature = "async-secure"))]
        let data_stream = DataStream::Tcp(stream);

        #[cfg(feature = "async-secure")]
        let data_stream = match (self.tls_ctx.as_ref(), self.domain.as_ref()) {
            (Some(tls_ctx), Some(domain)) => DataStream::Ssl(Box::new(
                tls_ctx
                    .connect(domain, stream)
                    .await
                    .map_err(|error| FtpError::SecureError(format!("{error}")))?,
            )),
            (Some(_), None) => {
                return Err(FtpError::SecureError(
                    "TLS context is set but no domain is available for the secure connection"
                        .to_string(),
                ));
            }
            (None, _) => DataStream::Tcp(stream),
        };

        cc.data_connection_open = true;
        Ok((response, data_stream))
    }

    /// Runs the EPSV to enter Extended passive mode.
    async fn epsv(&self, cc: &mut ControlChannel<T>) -> FtpResult<SocketAddr> {
        debug!("EPSV command");
        cc.perform(Command::Epsv).await?;
        // PASV response format : 229 Entering Extended Passive Mode (|||PORT|)
        let response: Response = cc.read_response(Status::ExtendedPassiveMode).await?;
        let response_str = response.as_string().map_err(|_| FtpError::BadResponse)?;
        let caps = EPSV_PORT_RE
            .captures(&response_str)
            .ok_or_else(|| FtpError::UnexpectedResponse(response.clone()))?;
        let new_port = caps[1].parse::<u16>().map_err(|_| FtpError::BadResponse)?;
        trace!("Got port number from EPSV: {}", new_port);
        let mut remote = cc.socket().peer_addr().map_err(FtpError::ConnectionError)?;
        remote.set_port(new_port);
        trace!("Remote address for extended passive mode is {}", remote);
        Ok(remote)
    }

    /// Runs the PASV command.
    async fn pasv(&self, cc: &mut ControlChannel<T>) -> FtpResult<SocketAddr> {
        debug!("PASV command");
        cc.perform(Command::Pasv).await?;
        // PASV response format : 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
        let response: Response = cc.read_response(Status::PassiveMode).await?;
        let addr = FtpStream::parse_passive_address_from_response(response)?;
        trace!("Passive address: {}", addr);
        if self.nat_workaround {
            let mut remote = cc.socket().peer_addr().map_err(FtpError::ConnectionError)?;
            remote.set_port(addr.port());
            trace!("Replacing site local address {} with {}", addr, remote);
            Ok(remote)
        } else {
            Ok(addr)
        }
    }

    /// Create a new tcp listener and send a PORT command for it
    async fn active(&self, cc: &mut ControlChannel<T>) -> FtpResult<TcpListener> {
        debug!("Starting local tcp listener...");
        let conn = TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(FtpError::ConnectionError)?;

        let addr = conn.local_addr().map_err(FtpError::ConnectionError)?;
        trace!("Local address is {}", addr);

        let ip = cc
            .socket()
            .local_addr()
            .map_err(FtpError::ConnectionError)?
            .ip();

        debug!("Active mode, listening on {}:{}", ip, addr.port());

        match ip {
            std::net::IpAddr::V4(_) => {
                let msb = addr.port() / 256;
                let lsb = addr.port() % 256;
                let ip_port = format!("{},{},{}", ip.to_string().replace('.', ","), msb, lsb);
                debug!("Running PORT command");
                cc.perform(Command::Port(ip_port)).await?;
            }
            std::net::IpAddr::V6(_) => {
                debug!("Running EPRT command");
                cc.perform(Command::Eprt(SocketAddr::new(ip, addr.port())))
                    .await?;
            }
        }
        cc.read_response(Status::CommandOk).await?;

        Ok(conn)
    }

    /// Execute a command which returns list of strings in a separate stream
    async fn stream_lines(&self, cmd: Command, open_code: Status) -> FtpResult<Vec<String>> {
        let encoding = Arc::clone(&self.control.lock().await.encoding);
        let (_, stream) = self
            .open_transfer(cmd, &[open_code, Status::AlreadyOpen], Direction::Download)
            .await?;
        let mut data_stream = BufReader::new(stream);
        let lines = Self::decode_lines_from_stream(&mut data_stream, encoding.as_ref()).await;
        data_stream.into_inner().finish().await?;
        lines
    }

    fn default_passive_stream_builder() -> Box<SmolPassiveStreamBuilder> {
        Box::new(|address| {
            Box::pin(async move {
                // Connect through `smol::Async` with the concrete `SocketAddr` instead of
                // `TcpStream::connect`: the latter resolves addresses through
                // `AsyncToSocketAddrs`, whose future is `!Sync`, which would violate the
                // `Send + Sync` bound required by `SmolPassiveStreamBuilder`.
                smol::Async::<std::net::TcpStream>::connect(address)
                    .await
                    .map(TcpStream::from)
                    .map_err(FtpError::ConnectionError)
            })
        })
    }
}

#[cfg(test)]
mod test {
    #[cfg(any(
        feature = "smol-async-native-tls",
        feature = "smol-rustls-aws-lc-rs",
        feature = "smol-rustls-ring"
    ))]
    use std::collections::HashMap;
    use std::str::FromStr as _;
    use std::sync::Arc;
    use std::time::Instant;

    #[cfg(feature = "async-secure")]
    use pretty_assertions::assert_eq;
    use rand::distr::Alphanumeric;
    use rand::{RngExt, rng};
    use smol::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::smol::AsyncFtpStream;
    use super::*;
    use crate::test_container::SyncPureFtpRunner;
    #[cfg(any(
        feature = "smol-async-native-tls",
        feature = "smol-rustls-aws-lc-rs",
        feature = "smol-rustls-ring"
    ))]
    use crate::test_container::SyncTlsFtpRunner;
    use crate::types::FormatControl;
    use crate::{FtpError, Status};

    #[cfg(feature = "smol-async-native-tls")]
    type TestTlsFtpStream = crate::smol::AsyncNativeTlsFtpStream;
    #[cfg(all(not(feature = "smol-async-native-tls"), feature = "smol-rustls-ring"))]
    type TestTlsFtpStream = crate::smol::AsyncRustlsFtpStream;
    #[cfg(all(
        not(feature = "smol-async-native-tls"),
        not(feature = "smol-rustls-ring"),
        feature = "smol-rustls-aws-lc-rs"
    ))]
    type TestTlsFtpStream = crate::smol::AsyncRustlsFtpStream;

    #[cfg(feature = "async-secure")]
    #[derive(Debug)]
    struct ProbeConnector(Arc<std::sync::atomic::AtomicUsize>);

    #[cfg(feature = "async-secure")]
    #[async_trait::async_trait]
    impl AsyncTlsConnector for ProbeConnector {
        type Stream = AsyncNoTlsStream;

        async fn connect(&self, _domain: &str, _stream: TcpStream) -> FtpResult<Self::Stream> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(FtpError::SecureError("probe".into()))
        }
    }

    #[cfg(feature = "async-secure")]
    #[test]
    fn should_validate_data_reply_before_tls_or_active_accept() {
        use smol::future::FutureExt as _;

        smol::block_on(async {
            async {
                for mode in [Mode::Passive, Mode::ExtendedPassive, Mode::Active] {
                    for status in [
                        Status::BadCommand,
                        Status::FileUnavailable,
                        Status::AlreadyOpen,
                        Status::AboutToSend,
                    ] {
                        let server =
                            crate::test_data_command::ScriptedDataServer::start(mode, status);
                        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                        let mut ftp = AsyncFtpStream::connect(server.address()).await.unwrap();
                        ftp = ftp.active_mode(Duration::from_secs(1));
                        ftp.set_mode(mode);
                        ftp.tls_ctx = Some(Box::new(ProbeConnector(Arc::clone(&calls))));
                        ftp.domain = Some("localhost".into());
                        let result = ftp
                            .custom_data_command(
                                "RETR probe",
                                &[Status::AlreadyOpen, Status::AboutToSend],
                            )
                            .await;
                        let accepted = matches!(status, Status::AlreadyOpen | Status::AboutToSend);
                        if accepted {
                            assert!(matches!(result, Err(FtpError::SecureError(ref text))
                                if text == "Secure error: probe"));
                        } else {
                            assert!(
                                matches!(result, Err(FtpError::UnexpectedResponse(ref response))
                                if response.status == status)
                            );
                        }
                        assert_eq!(
                            calls.load(std::sync::atomic::Ordering::SeqCst),
                            usize::from(accepted)
                        );
                        ftp.noop().await.unwrap();
                        drop(ftp);
                        server.finish();
                    }
                }
            }
            .or(async {
                smol::Timer::after(Duration::from_secs(20)).await;
                panic!("data command ordering deadline exceeded");
            })
            .await;
        });
    }

    #[test]
    fn connect() {
        smol::block_on(async {
            crate::log_init();
            let (stream, _container) = setup_stream().await;
            finalize_stream(stream).await;
        })
    }

    #[cfg(any(
        feature = "smol-async-native-tls",
        feature = "smol-rustls-aws-lc-rs",
        feature = "smol-rustls-ring"
    ))]
    #[test]
    fn should_return_ftps_rejections_and_recover() {
        use smol::future::FutureExt as _;

        smol::block_on(async {
            async {
                for mode in [Mode::Passive, Mode::ExtendedPassive] {
                    let (mut ftp, _container) = setup_tls_stream().await;
                    ftp.set_mode(mode);
                    ftp.transfer_type(FileType::Binary).await.unwrap();
                    for _ in 0..2 {
                        let cases = [
                            (ftp.mlsd(None).await.map(|_| ()), Status::BadCommand),
                            (
                                ftp.retr_as_stream("missing-188.txt").await.map(|_| ()),
                                Status::FileUnavailable,
                            ),
                            (
                                ftp.custom_data_command(
                                    "STOR /readonly/denied.txt",
                                    &[Status::AboutToSend, Status::AlreadyOpen],
                                )
                                .await
                                .map(|_| ()),
                                Status::BadFilename,
                            ),
                        ];
                        for (result, expected) in cases {
                            match result {
                                Err(FtpError::UnexpectedResponse(reply)) => {
                                    assert_eq!(reply.status, expected);
                                }
                                other => panic!("expected {expected:?}, got {other:?}"),
                            }
                        }
                        ftp.noop().await.unwrap();
                    }
                    let payload = b"issue 188 TLS recovery\n";
                    let mut input = smol::io::Cursor::new(payload);
                    assert_eq!(
                        ftp.put_file("recovered-188.txt", &mut input).await.unwrap(),
                        payload.len() as u64
                    );
                    let mut download = ftp.retr_as_stream("recovered-188.txt").await.unwrap();
                    let mut bytes = Vec::new();
                    smol::io::AsyncReadExt::read_to_end(&mut download, &mut bytes)
                        .await
                        .unwrap();
                    download.finish().await.unwrap();
                    assert_eq!(bytes, payload);
                    ftp.rm("recovered-188.txt").await.unwrap();
                    ftp.quit().await.unwrap();
                }
            }
            .or(async {
                smol::Timer::after(Duration::from_secs(10)).await;
                panic!("FTPS rejection or recovery exceeded 10 seconds");
            })
            .await;
        });
    }

    #[test]
    fn should_change_mode() {
        smol::block_on(async {
            crate::log_init();
            let (mut stream, _container) = setup_stream().await;

            assert_eq!(stream.mode, Mode::Passive);
            stream.set_mode(Mode::Active);
            assert_eq!(stream.mode, Mode::Active);
        })
    }

    #[test]
    fn should_connect_with_timeout() {
        smol::block_on(async {
            crate::log_init();
            let container = SyncPureFtpRunner::start();
            let port = container.get_ftp_port();
            let url = format!("127.0.0.1:{port}");
            let addr: SocketAddr = url.parse().expect("invalid hostname");

            let mut stream = AsyncFtpStream::connect_timeout(addr, Duration::from_secs(15))
                .await
                .unwrap();
            assert!(stream.login("test", "test").await.is_ok());
            assert!(stream.get_welcome_msg().unwrap().contains("220 "));
        })
    }

    #[test]
    fn welcome_message() {
        smol::block_on(async {
            crate::log_init();
            let (stream, _container) = setup_stream().await;
            assert!(stream.get_welcome_msg().unwrap().contains("220 "));
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_set_passive_nat_workaround() {
        smol::block_on(async {
            crate::log_init();
            let (mut stream, _container) = setup_stream().await;
            stream.set_passive_nat_workaround(true);
            assert!(stream.nat_workaround);
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn get_ref() {
        smol::block_on(async {
            let (stream, _container) = setup_stream().await;
            assert!(stream.get_ref().await.set_ttl(255).is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn change_wrkdir() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let wrkdir: String = stream.pwd().await.unwrap();
            assert!(stream.cwd("/").await.is_ok());
            assert_eq!(stream.pwd().await.unwrap().as_str(), "/");
            assert!(stream.cwd(wrkdir.as_str()).await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn cd_up() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let wrkdir: String = stream.pwd().await.unwrap();
            assert!(stream.cdup().await.is_ok());
            assert_eq!(stream.pwd().await.unwrap().as_str(), "/home/test");
            assert!(stream.cwd(wrkdir.as_str()).await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn noop() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.noop().await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn make_and_remove_dir() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            // Make directory
            assert!(stream.mkdir("omar").await.is_ok());
            // It shouldn't allow me to re-create the directory; should return error code 550
            match stream.mkdir("omar").await.err().unwrap() {
                FtpError::UnexpectedResponse(Response { status, body: _ }) => {
                    assert_eq!(status, Status::FileUnavailable)
                }
                err => panic!("Expected UnexpectedResponse, got {}", err),
            }
            // Remove directory
            assert!(stream.rmdir("omar").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_get_feat_and_set_opts() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let features = stream.feat().await.expect("failed to get features");
            assert!(features.contains_key("UTF8"));
            assert!(stream.opts("UTF8", Some("ON")).await.is_ok());

            finalize_stream(stream).await;
        })
    }

    #[test]
    fn set_transfer_type() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            assert!(
                stream
                    .transfer_type(FileType::Ascii(FormatControl::Default))
                    .await
                    .is_ok()
            );
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_should_use_retr() {
        smol::block_on(async {
            use smol::io::Cursor;

            let (mut stream, _container) = setup_stream().await;
            // Set transfer type to Binary
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            // Write file
            let file_data = "test data\n";
            let mut reader = Cursor::new(file_data.as_bytes());
            assert!(stream.put_file("test.txt", &mut reader).await.is_ok());
            // Read file
            let reader = stream
                .retr("test.txt", |mut reader| {
                    Box::pin(async move {
                        let mut buf = Vec::new();
                        reader.read_to_end(&mut buf).await.expect("failed to read");
                        Ok((buf, reader))
                    })
                })
                .await
                .unwrap();
            assert_eq!(reader, "test data\n".as_bytes());
        })
    }

    #[test]
    fn transfer_file() {
        smol::block_on(async {
            use smol::io::Cursor;

            let (mut stream, _container) = setup_stream().await;
            // Set transfer type to Binary
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            // Write file
            let file_data = "test data\n";
            let mut reader = Cursor::new(file_data.as_bytes());
            assert!(stream.put_file("test.txt", &mut reader).await.is_ok());
            // Append file
            let mut reader = Cursor::new(file_data.as_bytes());
            assert!(stream.append_file("test.txt", &mut reader).await.is_ok());
            // Read file
            let mut reader = stream.retr_as_stream("test.txt").await.unwrap();
            let mut buffer = Vec::new();
            assert!(
                smol::io::AsyncReadExt::read_to_end(&mut reader, &mut buffer)
                    .await
                    .is_ok()
            );
            // Verify file matches
            assert_eq!(buffer.as_slice(), "test data\ntest data\n".as_bytes());
            // Finalize
            assert!(reader.finish().await.is_ok());
            // Get size
            assert_eq!(stream.size("test.txt").await.unwrap(), 20);
            // Size of non-existing file
            assert!(stream.size("omarone.txt").await.is_err());
            // List directory
            assert_eq!(stream.list(None).await.unwrap().len(), 1);
            // list names
            assert_eq!(stream.nlst(None).await.unwrap().as_slice(), &["test.txt"]);
            // modification time
            assert!(stream.mdtm("test.txt").await.is_ok());
            // Remove file
            assert!(stream.rm("test.txt").await.is_ok());
            assert!(stream.mdtm("test.txt").await.is_err());
            // Write file, rename and get
            let file_data = "test data\n";
            let mut reader = Cursor::new(file_data.as_bytes());
            assert!(stream.put_file("test.txt", &mut reader).await.is_ok());
            assert!(stream.rename("test.txt", "toast.txt").await.is_ok());
            assert!(stream.rm("toast.txt").await.is_ok());
            // List directory again
            assert_eq!(stream.list(None).await.unwrap().len(), 0);
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_resume_transfer() {
        smol::block_on(async {
            let (mut stream, container) = setup_stream().await;
            // Set transfer type to Binary
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            // get dir
            let wrkdir = stream.pwd().await.unwrap();
            // put as stream
            let mut transfer_stream = stream.put_with_stream("test.bin").await.unwrap();
            assert_eq!(
                transfer_stream
                    .write(&[0x00, 0x01, 0x02, 0x03, 0x04])
                    .await
                    .unwrap(),
                5
            );
            // Drop stream on purpose to simulate a failed connection
            drop(stream);
            drop(transfer_stream);
            // Re-connect to server
            let port = container.get_ftp_port();
            let url = format!("localhost:{port}");

            let mut stream = AsyncFtpStream::connect(url).await.unwrap();
            assert!(stream.login("test", "test").await.is_ok());
            // Create wrkdir
            let tempdir: String = generate_tempdir();
            assert!(stream.mkdir(tempdir.as_str()).await.is_ok());
            // Change directory
            assert!(stream.cwd(tempdir.as_str()).await.is_ok());

            let container_t = container.clone();

            let mut stream = stream.passive_stream_builder(move |addr| {
                let container_t = container_t.clone();
                Box::pin(async move {
                    let mut addr = addr;
                    let port = addr.port();
                    let mapped = container_t.get_mapped_port(port);

                    addr.set_port(mapped);

                    info!("mapped port {port} to {mapped} for PASV");

                    // open stream to this address instead
                    smol::Async::<std::net::TcpStream>::connect(addr)
                        .await
                        .map(TcpStream::from)
                        .map_err(FtpError::ConnectionError)
                })
            });
            // Go back to previous dir
            assert!(stream.cwd(wrkdir).await.is_ok());
            // Set transfer type to Binary
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            // Resume transfer
            assert!(stream.resume_transfer(5).await.is_ok());
            // Reopen stream
            let mut transfer_stream = stream.put_with_stream("test.bin").await.unwrap();
            assert_eq!(
                transfer_stream
                    .write(&[0x05, 0x06, 0x07, 0x08, 0x09, 0x0a])
                    .await
                    .unwrap(),
                6
            );
            // Finalize
            assert!(transfer_stream.finish().await.is_ok());
            // Get size
            //assert_eq!(stream.size("test.bin").await.unwrap(), 11);
            // Remove file
            assert!(stream.rm("test.bin").await.is_ok());
            // Drop stream
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_should_transfer_file_with_extended_passive_mode() {
        smol::block_on(async {
            crate::log_init();
            use smol::io::Cursor;

            let (mut stream, _container) = setup_stream().await;
            // Set transfer type to Binary
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            stream.set_mode(Mode::ExtendedPassive);
            // Write file
            let file_data = "test data\n";
            let mut reader = Cursor::new(file_data.as_bytes());
            assert!(stream.put_file("test.txt", &mut reader).await.is_ok());
            // Remove file
            assert!(stream.rm("test.txt").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_should_list_files_with_non_utf8_names() {
        smol::block_on(async {
            let (mut stream, container) = setup_stream().await;
            let files = stream
                .nlst(Some("/home/test/invalid-utf8/"))
                .await
                .expect("Failed to list files");
            assert_eq!(files.len(), 1);

            // list file and parse
            let files = stream
                .list(Some("/home/test/invalid-utf8/"))
                .await
                .expect("Failed to list files");
            assert_eq!(files.len(), 1);
            // parse
            crate::list::File::from_str(files[0].as_str()).expect("Failed to parse file");

            finalize_stream(stream).await;
            drop(container);
        })
    }

    #[test]
    fn test_should_perform_custom_command() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;

            let command = "PWD";
            assert!(
                stream
                    .custom_command(command, &[Status::PathCreated])
                    .await
                    .is_ok()
            );
        })
    }

    #[test]
    fn test_should_perform_custom_data_command() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let command = "LIST";
            let (response, data_stream) = stream
                .custom_data_command(command, &[Status::AboutToSend])
                .await
                .expect("Failed to perform custom data command");
            assert_eq!(response.status, Status::AboutToSend);
            let mut reader = smol::io::BufReader::new(data_stream);
            AsyncFtpStream::get_lines_from_stream(&mut reader)
                .await
                .expect("Failed to get lines from stream");
            // finalize
            assert!(reader.into_inner().finish().await.is_ok());
        })
    }

    #[test]
    fn should_reset_data_connection_after_failed_data_command() {
        smol::block_on(async {
            use smol::io::Cursor;

            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());

            // A failed data command must leave the data connection free, otherwise the next data
            // command would wrongly fail with `DataConnectionAlreadyOpen` instead of the real error.
            for _ in 0..3 {
                assert!(stream.retr_as_stream("non-existing.txt").await.is_err());
                assert!(
                    stream
                        .custom_data_command("RETR non-existing.txt", &[Status::AboutToSend])
                        .await
                        .is_err()
                );
            }

            // After the failures every kind of data command must still be usable.
            let mut reader = Cursor::new("test data\n".as_bytes());
            assert!(stream.put_file("test.txt", &mut reader).await.is_ok());
            let mut reader = Cursor::new("test data\n".as_bytes());
            assert!(stream.append_file("test.txt", &mut reader).await.is_ok());
            let data_stream = stream.retr_as_stream("test.txt").await.unwrap();
            assert!(data_stream.finish().await.is_ok());
            assert!(stream.list(None).await.is_ok());
            assert!(stream.nlst(None).await.is_ok());

            assert!(stream.rm("test.txt").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_should_prevent_multiple_data_connections() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let command = "LIST";

            let _data_stream = stream
                .custom_data_command(command, &[Status::AboutToSend])
                .await
                .expect("Failed to perform custom data command");
            // Try to open another data connection without closing the previous one
            match stream
                .custom_data_command(command, &[Status::AboutToSend])
                .await
            {
                Err(FtpError::DataConnectionAlreadyOpen) => {}
                _ => panic!("Expected DataConnectionAlreadyOpen error"),
            }

            // try with all other data commands
            match stream.retr_as_stream("somefile.txt").await {
                Err(FtpError::DataConnectionAlreadyOpen) => {}
                _ => panic!("Expected DataConnectionAlreadyOpen error"),
            }

            match stream.put_with_stream("somefile.txt").await {
                Err(FtpError::DataConnectionAlreadyOpen) => {}
                _ => panic!("Expected DataConnectionAlreadyOpen error"),
            }

            match stream.append_with_stream("somefile.txt").await {
                Err(FtpError::DataConnectionAlreadyOpen) => {}
                _ => panic!("Expected DataConnectionAlreadyOpen error"),
            }
        })
    }

    #[test]
    fn test_should_free_data_connection_after_close() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let command = "LIST";

            let (response, data_stream) = stream
                .custom_data_command(command, &[Status::AboutToSend])
                .await
                .expect("Failed to perform custom data command");
            assert_eq!(response.status, Status::AboutToSend);
            let mut reader = smol::io::BufReader::new(data_stream);
            AsyncFtpStream::get_lines_from_stream(&mut reader)
                .await
                .expect("Failed to get lines from stream");
            // finalize
            assert!(reader.into_inner().finish().await.is_ok());

            // Now it should be possible to open another data connection
            let (response, data_stream) = stream
                .custom_data_command(command, &[Status::AboutToSend])
                .await
                .expect("Failed to perform custom data command");
            assert_eq!(response.status, Status::AboutToSend);
            let mut reader = smol::io::BufReader::new(data_stream);
            AsyncFtpStream::get_lines_from_stream(&mut reader)
                .await
                .expect("Failed to get lines from stream");
            // finalize
            assert!(reader.into_inner().finish().await.is_ok());
        })
    }

    #[test]
    fn test_abort_transfer() {
        smol::block_on(async {
            crate::log_init();
            let (mut stream, _container) = setup_stream().await;

            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let file_data = "test data for abort\n";
            let mut reader = smol::io::Cursor::new(file_data.as_bytes());
            assert!(stream.put_file("abort_test.txt", &mut reader).await.is_ok());
            // Open a retr stream
            let data_stream = stream.retr_as_stream("abort_test.txt").await.unwrap();
            // Abort the transfer
            assert!(stream.abort(data_stream).await.is_ok());
            // NOTE: after abort, the server may leave extra responses in the buffer,
            // so we drop the stream without quit.
            drop(stream);
        })
    }

    #[test]
    fn test_append_with_stream() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            // Create file
            let mut reader = smol::io::Cursor::new("part1".as_bytes());
            assert!(
                stream
                    .put_file("append_stream.txt", &mut reader)
                    .await
                    .is_ok()
            );
            // Append via stream
            let mut data_stream = stream
                .append_with_stream("append_stream.txt")
                .await
                .unwrap();
            smol::io::AsyncWriteExt::write_all(&mut data_stream, b"part2")
                .await
                .unwrap();
            data_stream.finish().await.unwrap();
            // Verify content
            let mut reader = stream.retr_as_stream("append_stream.txt").await.unwrap();
            let mut buffer = Vec::new();
            smol::io::AsyncReadExt::read_to_end(&mut reader, &mut buffer)
                .await
                .unwrap();
            reader.finish().await.unwrap();
            assert_eq!(buffer, b"part1part2");
            assert!(stream.rm("append_stream.txt").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_active_mode_builder() {
        smol::block_on(async {
            crate::log_init();
            let stream = AsyncFtpStream::connect("test.rebex.net:21").await.unwrap();
            let stream = stream.active_mode(Duration::from_secs(30));
            assert_eq!(stream.mode, Mode::Active);
            assert_eq!(stream.active_timeout, Duration::from_secs(30));
        })
    }

    #[test]
    fn test_passive_stream_builder() {
        smol::block_on(async {
            crate::log_init();
            let stream = AsyncFtpStream::connect("test.rebex.net:21").await.unwrap();
            let stream = stream.passive_stream_builder(|addr| {
                Box::pin(async move {
                    smol::Async::<std::net::TcpStream>::connect(addr)
                        .await
                        .map(TcpStream::from)
                        .map_err(FtpError::ConnectionError)
                })
            });
            assert_eq!(stream.mode, Mode::Passive);
        })
    }

    #[test]
    fn test_site_command() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let result = stream.site("HELP").await;
            match result {
                Ok(response) => {
                    assert_eq!(response.status, Status::CommandOk);
                }
                Err(FtpError::UnexpectedResponse(_)) => {}
                Err(err) => panic!("Unexpected error: {}", err),
            }
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_eprt_command() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
            let _ = stream.eprt(addr).await;
        })
    }

    #[test]
    fn test_transfer_type_variants() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(
                stream
                    .transfer_type(FileType::Ascii(FormatControl::NonPrint))
                    .await
                    .is_ok()
            );
            assert!(stream.transfer_type(FileType::Image).await.is_ok());
            let _ = stream.transfer_type(FileType::Local(8)).await;
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_cwd_error() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            match stream.cwd("/nonexistent/directory/path").await {
                Err(FtpError::UnexpectedResponse(response)) => {
                    assert_eq!(response.status, Status::FileUnavailable);
                }
                _ => panic!("Expected UnexpectedResponse for nonexistent directory"),
            }
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_rm_nonexistent_file() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            match stream.rm("nonexistent_file.txt").await {
                Err(FtpError::UnexpectedResponse(_)) => {}
                _ => panic!("Expected error when removing nonexistent file"),
            }
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_rmdir_nonexistent() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            match stream.rmdir("nonexistent_dir").await {
                Err(FtpError::UnexpectedResponse(_)) => {}
                _ => panic!("Expected error when removing nonexistent directory"),
            }
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_rename_nonexistent() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            match stream.rename("nonexistent.txt", "new_name.txt").await {
                Err(FtpError::UnexpectedResponse(_)) => {}
                _ => panic!("Expected error when renaming nonexistent file"),
            }
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_retr_nonexistent_file() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            match stream.retr_as_stream("nonexistent_file.txt").await {
                Err(FtpError::UnexpectedResponse(_)) => {}
                _ => panic!("Expected error when retrieving nonexistent file"),
            }
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_list_nonexistent_path() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let _ = stream.list(Some("/nonexistent/path")).await;
        })
    }

    #[test]
    fn test_nlst_with_path() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let mut reader = smol::io::Cursor::new("data".as_bytes());
            assert!(stream.put_file("nlst_test.txt", &mut reader).await.is_ok());
            let files = stream.nlst(None).await.unwrap();
            assert!(files.contains(&"nlst_test.txt".to_string()));
            assert!(stream.rm("nlst_test.txt").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn test_list_with_explicit_current_dir() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            let mut reader = smol::io::Cursor::new("data".as_bytes());
            assert!(stream.put_file("list_test.txt", &mut reader).await.is_ok());
            let files = stream.list(Some(".")).await.unwrap();
            assert!(!files.is_empty());
            assert!(stream.rm("list_test.txt").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    /// Test if the stream is Send
    fn is_send<T: Send>(_send: T) {}

    #[test]
    #[ignore = "just needs to compile"]
    fn test_ftp_stream_should_be_send() {
        smol::block_on(async {
            crate::log_init();
            let ftp_stream = AsyncFtpStream::connect("test.rebex.net:21")
                .await
                .unwrap()
                .passive_stream_builder(|addr| {
                    Box::pin(async move {
                        println!("Connecting to {}", addr);
                        smol::Async::<std::net::TcpStream>::connect(addr)
                            .await
                            .map(TcpStream::from)
                            .map_err(FtpError::ConnectionError)
                    })
                });

            is_send::<AsyncFtpStream>(ftp_stream);
        })
    }

    /// Test if the stream is Sync
    fn is_sync<T: Sync>(_send: T) {}

    #[test]
    #[ignore = "just needs to compile"]
    fn test_ftp_stream_should_be_sync() {
        smol::block_on(async {
            crate::log_init();
            let ftp_stream = AsyncFtpStream::connect("test.rebex.net:21")
                .await
                .unwrap()
                .passive_stream_builder(|addr| {
                    Box::pin(async move {
                        println!("Connecting to {}", addr);
                        smol::Async::<std::net::TcpStream>::connect(addr)
                            .await
                            .map(TcpStream::from)
                            .map_err(FtpError::ConnectionError)
                    })
                });

            is_sync::<AsyncFtpStream>(ftp_stream);
        })
    }

    #[test]
    fn should_upload_via_stream_and_finish() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let mut upload = stream.put_with_stream("upload.bin").await.unwrap();
            smol::io::AsyncWriteExt::write_all(&mut upload, b"0123456789")
                .await
                .unwrap();
            upload
                .finish()
                .await
                .expect("finish should read the transfer reply");
            // The control connection is in sync: the next commands work.
            assert_eq!(stream.size("upload.bin").await.unwrap(), 10);
            assert_eq!(stream.nlst(None).await.unwrap().as_slice(), &["upload.bin"]);
            assert!(stream.rm("upload.bin").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_download_via_stream_and_finish() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let mut reader = smol::io::Cursor::new("download me".as_bytes());
            assert!(stream.put_file("download.txt", &mut reader).await.is_ok());
            let mut download = stream.retr_as_stream("download.txt").await.unwrap();
            let mut buffer = Vec::new();
            download.read_to_end(&mut buffer).await.unwrap();
            download
                .finish()
                .await
                .expect("finish should read the transfer reply");
            assert_eq!(buffer, b"download me");
            // The control connection is in sync: the next commands work.
            assert!(stream.pwd().await.is_ok());
            assert_eq!(stream.size("download.txt").await.unwrap(), 11);
            assert!(stream.rm("download.txt").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_drain_reply_of_dropped_stream_on_next_command() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let mut upload = stream.put_with_stream("dropped.bin").await.unwrap();
            smol::io::AsyncWriteExt::write_all(&mut upload, b"dropped")
                .await
                .unwrap();
            smol::io::AsyncWriteExt::flush(&mut upload).await.unwrap();
            // Drop without finish(): the reply is consumed by the next command.
            drop(upload);
            assert_eq!(stream.size("dropped.bin").await.unwrap(), 7);
            let mut download = stream.retr_as_stream("dropped.bin").await.unwrap();
            let mut buffer = Vec::new();
            download.read_to_end(&mut buffer).await.unwrap();
            download.finish().await.unwrap();
            assert_eq!(buffer, b"dropped");
            assert!(stream.rm("dropped.bin").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_read_a_single_reply_on_finish_then_drop() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let mut upload = stream.put_with_stream("single.bin").await.unwrap();
            smol::io::AsyncWriteExt::write_all(&mut upload, b"single")
                .await
                .unwrap();
            // A second (spurious) reply read would block: bound finish() with a timeout.
            let timeout = Duration::from_millis(500);
            let started = Instant::now();
            let finished =
                smol::future::or(async { upload.finish().await.map(|()| true) }, async {
                    smol::Timer::after(timeout).await;
                    Ok(false)
                })
                .await;
            assert!(
                matches!(finished, Ok(true)),
                "finish() blocked: a second reply read was attempted"
            );
            assert!(started.elapsed() < timeout);
            // The control connection is in sync: the next commands work.
            assert!(stream.noop().await.is_ok());
            assert_eq!(stream.size("single.bin").await.unwrap(), 6);
            assert!(stream.rm("single.bin").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_reject_data_commands_while_a_transfer_stream_is_alive() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let mut upload = stream.put_with_stream("alive.bin").await.unwrap();
            smol::io::AsyncWriteExt::write_all(&mut upload, b"alive")
                .await
                .unwrap();
            assert!(matches!(
                stream.list(None).await,
                Err(FtpError::DataConnectionAlreadyOpen)
            ));
            assert!(matches!(
                stream.retr_as_stream("alive.bin").await,
                Err(FtpError::DataConnectionAlreadyOpen)
            ));
            assert!(matches!(
                stream.put_with_stream("other.bin").await,
                Err(FtpError::DataConnectionAlreadyOpen)
            ));
            upload.finish().await.unwrap();
            // Once finished, data commands work again.
            assert_eq!(stream.nlst(None).await.unwrap().as_slice(), &["alive.bin"]);
            assert!(stream.rm("alive.bin").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_finish_transfer_stream_on_another_task() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let mut upload = stream.put_with_stream("spawned.bin").await.unwrap();
            let task = smol::spawn(async move {
                smol::io::AsyncWriteExt::write_all(&mut upload, b"from another task")
                    .await
                    .unwrap();
                upload.finish().await
            });
            task.await.expect("finish should succeed on another task");
            assert_eq!(stream.size("spawned.bin").await.unwrap(), 17);
            assert!(stream.rm("spawned.bin").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    #[test]
    fn should_finalize_transfer_when_retr_callback_fails() {
        smol::block_on(async {
            let (mut stream, _container) = setup_stream().await;
            assert!(stream.transfer_type(FileType::Binary).await.is_ok());
            let mut reader = smol::io::Cursor::new("callback".as_bytes());
            assert!(
                stream
                    .put_file("callback_err.txt", &mut reader)
                    .await
                    .is_ok()
            );
            let result: FtpResult<()> = stream
                .retr("callback_err.txt", |reader| {
                    Box::pin(async move {
                        // Hand the stream back on failure so `retr` can finish it.
                        drop(reader);
                        Err(FtpError::BadResponse)
                    })
                })
                .await;
            assert!(matches!(result, Err(FtpError::BadResponse)));
            // The dropped stream flagged a pending reply, which the next command drains.
            assert_eq!(stream.size("callback_err.txt").await.unwrap(), 8);
            assert!(stream.list(None).await.is_ok());
            assert!(stream.rm("callback_err.txt").await.is_ok());
            finalize_stream(stream).await;
        })
    }

    // -- test utils

    #[cfg(any(
        feature = "smol-async-native-tls",
        feature = "smol-rustls-aws-lc-rs",
        feature = "smol-rustls-ring"
    ))]
    async fn setup_tls_stream() -> (TestTlsFtpStream, SyncTlsFtpRunner) {
        crate::log_init();
        let container = SyncTlsFtpRunner::start();
        let port = container.get_ftp_port();
        let ftp = TestTlsFtpStream::connect(format!("localhost:{port}"))
            .await
            .unwrap();

        #[cfg(feature = "smol-async-native-tls")]
        let mut ftp = {
            let certificate = crate::async_native_tls::Certificate::from_pem(include_bytes!(
                "../test_container/fixtures/ca-cert.pem"
            ))
            .unwrap();
            let connector =
                crate::async_native_tls::TlsConnector::new().add_root_certificate(certificate);
            ftp.into_secure(
                crate::smol::AsyncNativeTlsConnector::from(connector),
                "localhost",
            )
            .await
            .unwrap()
        };

        #[cfg(all(not(feature = "smol-async-native-tls"), feature = "smol-rustls-ring"))]
        let mut ftp = {
            use futures_rustls::rustls;

            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    include_bytes!("../test_container/fixtures/ca-cert.der").to_vec(),
                ))
                .unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = futures_rustls::TlsConnector::from(Arc::new(config));
            ftp.into_secure(
                crate::smol::AsyncRustlsConnector::from(connector),
                "localhost",
            )
            .await
            .unwrap()
        };

        #[cfg(all(
            not(feature = "smol-async-native-tls"),
            not(feature = "smol-rustls-ring"),
            feature = "smol-rustls-aws-lc-rs"
        ))]
        let mut ftp = {
            use futures_rustls::rustls;

            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    include_bytes!("../test_container/fixtures/ca-cert.der").to_vec(),
                ))
                .unwrap();
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = futures_rustls::TlsConnector::from(Arc::new(config));
            ftp.into_secure(
                crate::smol::AsyncRustlsConnector::from(connector),
                "localhost",
            )
            .await
            .unwrap()
        };

        assert!(ftp.login("test", "test").await.is_ok());
        let mut mapped_ports = HashMap::new();
        for port in 30_000..=30_009 {
            mapped_ports.insert(port, container.get_mapped_port(port));
        }
        let ftp = ftp.passive_stream_builder(move |mut addr| {
            addr.set_port(mapped_ports[&addr.port()]);
            addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            Box::pin(async move {
                smol::Async::<std::net::TcpStream>::connect(addr)
                    .await
                    .map(TcpStream::from)
                    .map_err(FtpError::ConnectionError)
            })
        });

        (ftp, container)
    }

    async fn setup_stream() -> (AsyncFtpStream, Arc<SyncPureFtpRunner>) {
        crate::log_init();
        let container = Arc::new(SyncPureFtpRunner::start());

        let port = container.get_ftp_port();
        let url = format!("localhost:{port}");

        let mut ftp_stream = ImplAsyncFtpStream::connect(url).await.unwrap();
        assert!(ftp_stream.login("test", "test").await.is_ok());
        // Create wrkdir
        let tempdir: String = generate_tempdir();
        assert!(ftp_stream.mkdir(tempdir.as_str()).await.is_ok());
        // Change directory
        assert!(ftp_stream.cwd(tempdir.as_str()).await.is_ok());

        let container_t = container.clone();

        let ftp_stream = ftp_stream.passive_stream_builder(move |addr| {
            let container_t = container_t.clone();
            Box::pin(async move {
                let mut addr = addr;
                let port = addr.port();
                let mapped = container_t.get_mapped_port(port);

                addr.set_port(mapped);

                info!("mapped port {port} to {mapped} for PASV");

                // open stream to this address instead
                smol::Async::<std::net::TcpStream>::connect(addr)
                    .await
                    .map(TcpStream::from)
                    .map_err(FtpError::ConnectionError)
            })
        });

        (ftp_stream, container)
    }

    async fn finalize_stream(mut stream: AsyncFtpStream) {
        assert!(stream.quit().await.is_ok());
    }

    fn generate_tempdir() -> String {
        let mut rng = rng();
        let name: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(5)
            .collect();
        format!("temp_{}", name)
    }

    // M-MOCKABLE-SYSCALLS: use a local server for deterministic control-response tests.
    async fn connect_with_control_response(
        expected_command: &'static str,
        response: &'static [u8],
    ) -> (AsyncFtpStream, smol::Task<()>) {
        use smol::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let port = listener.local_addr().expect("missing local address").port();
        let handle = smol::spawn(async move {
            let (stream, _) = listener.accept().await.expect("no incoming connection");
            let mut writer = stream.clone();
            let mut reader = AsyncBufReader::new(stream);

            AsyncWriteExt::write_all(&mut writer, b"220 Welcome\r\n")
                .await
                .unwrap();

            let mut line = String::new();
            AsyncBufReadExt::read_line(&mut reader, &mut line)
                .await
                .unwrap();
            assert_eq!(line, format!("{expected_command}\r\n"));
            AsyncWriteExt::write_all(&mut writer, response)
                .await
                .unwrap();
        });

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("failed to connect");
        let stream = AsyncFtpStream::connect_with_stream(tcp)
            .await
            .expect("failed handshake");
        (stream, handle)
    }

    #[test]
    fn should_accept_mismatched_multiline_terminal_code() {
        smol::block_on(async {
            let response = b"553-\r\n\
553- Directory excluded (precheck).\r\n\
150 Opening BINARY mode data connection.\r\n";
            let (mut stream, handle) =
                connect_with_control_response("STOR upload.bin", response).await;

            let response = stream
                .custom_command("STOR upload.bin", &[Status::AboutToSend])
                .await
                .expect("mismatched terminal code should be accepted");

            assert_eq!(response.status, Status::AboutToSend);
            handle.await;
        })
    }

    #[test]
    fn should_preserve_feat_multiline_handling() {
        smol::block_on(async {
            let response = b"211-Features:\r\n UTF8\r\n211 END\r\n";
            let (mut stream, handle) = connect_with_control_response("FEAT", response).await;

            let features = stream.feat().await.expect("FEAT response should be parsed");

            assert!(features.contains_key("UTF8"));
            handle.await;
        })
    }

    #[test]
    fn should_accept_200_for_file_operations() {
        smol::block_on(async {
            use smol::io::BufReader as AsyncBufReader;
            // Use UFCS below to disambiguate from the in-scope `smol` extension traits.
            use smol::io::{AsyncBufReadExt, AsyncWriteExt};

            crate::log_init();

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to bind");
            let port = listener.local_addr().unwrap().port();

            // Fake FTP server that replies with 200 instead of the spec-mandated
            // 250/257 to file operations, mimicking non-compliant servers such as bftpd.
            let handle = smol::spawn(async move {
                let (stream, _) = listener.accept().await.expect("no incoming connection");
                let mut writer = stream.clone();
                let mut reader = AsyncBufReader::new(stream);

                AsyncWriteExt::write_all(&mut writer, b"220 Welcome\r\n")
                    .await
                    .unwrap();

                let mut line = String::new();
                while AsyncBufReadExt::read_line(&mut reader, &mut line)
                    .await
                    .unwrap()
                    > 0
                {
                    let reply: &[u8] = match line.split_whitespace().next() {
                        // RNFR must be acknowledged with 350 before RNTO is sent.
                        Some("RNFR") => b"350 ready for destination name\r\n",
                        Some("QUIT") => b"221 goodbye\r\n",
                        // Everything else is answered with the non-compliant 200.
                        _ => b"200 ok\r\n",
                    };
                    AsyncWriteExt::write_all(&mut writer, reply).await.unwrap();
                    if line.starts_with("QUIT") {
                        break;
                    }
                    line.clear();
                }
            });

            let tcp = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("failed to connect");
            let mut stream = AsyncFtpStream::connect_with_stream(tcp)
                .await
                .expect("failed handshake");

            assert!(stream.mkdir("dir").await.is_ok());
            assert!(stream.rename("a", "b").await.is_ok());
            assert!(stream.rmdir("dir").await.is_ok());
            assert!(stream.rm("file").await.is_ok());

            assert!(stream.quit().await.is_ok());
            handle.await;
        })
    }

    #[test]
    fn should_reject_command_with_crlf_injection() {
        smol::block_on(async {
            use smol::io::BufReader as AsyncBufReader;
            // Use UFCS below to disambiguate from the in-scope `smol` extension traits.
            use smol::io::{AsyncBufReadExt, AsyncWriteExt};

            crate::log_init();

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to bind");
            let port = listener.local_addr().unwrap().port();

            // Fake FTP server that records every control-channel line it receives.
            let handle = smol::spawn(async move {
                let (stream, _) = listener.accept().await.expect("no incoming connection");
                let mut writer = stream.clone();
                let mut reader = AsyncBufReader::new(stream);

                AsyncWriteExt::write_all(&mut writer, b"220 Welcome\r\n")
                    .await
                    .unwrap();

                let mut seen = Vec::new();
                let mut line = String::new();
                while AsyncBufReadExt::read_line(&mut reader, &mut line)
                    .await
                    .unwrap()
                    > 0
                {
                    let is_quit = line.starts_with("QUIT");
                    seen.push(line.trim_end_matches(['\r', '\n']).to_string());
                    let reply: &[u8] = if is_quit {
                        b"221 goodbye\r\n"
                    } else {
                        b"200 ok\r\n"
                    };
                    AsyncWriteExt::write_all(&mut writer, reply).await.unwrap();
                    if is_quit {
                        break;
                    }
                    line.clear();
                }
                seen
            });

            let tcp = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("failed to connect");
            let mut stream = AsyncFtpStream::connect_with_stream(tcp)
                .await
                .expect("failed handshake");

            let err = stream
                .cwd("dir\r\nDELE secret.txt")
                .await
                .expect_err("command with CRLF must be rejected");
            assert!(
                matches!(err, FtpError::ConnectionError(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
                "unexpected error: {err:?}"
            );
            assert!(stream.cwd("dir\nDELE secret.txt").await.is_err());
            assert!(stream.login("anon\r\nDELE secret.txt", "pw").await.is_err());
            assert!(
                stream
                    .custom_command("NOOP\r\nDELE secret.txt", &[Status::CommandOk])
                    .await
                    .is_err()
            );

            assert!(stream.quit().await.is_ok());
            let seen = handle.await;
            assert_eq!(seen, vec!["QUIT".to_string()]);
        })
    }
}

#[cfg(test)]
mod active_peer_tests {
    use std::time::Duration;

    use crate::ActivePeerCheck;
    use crate::active_mode_fixture::serve_active_nlst;
    use crate::smol::AsyncFtpStream;

    #[test]
    fn should_accept_data_connections_only_from_allowed_peers() {
        smol::block_on(async {
            // The fixture always connects back from 127.0.0.1, which is also the control peer.
            let localhost = "127.0.0.1".parse().unwrap();
            let elsewhere = "192.0.2.1".parse().unwrap();
            for (check, accepted) in [
                (ActivePeerCheck::ControlPeer, true),
                (ActivePeerCheck::Any, true),
                (ActivePeerCheck::Allow(vec![elsewhere, localhost]), true),
                (ActivePeerCheck::Allow(vec![elsewhere]), false),
            ] {
                let address = serve_active_nlst();
                let mut ftp = AsyncFtpStream::connect(address)
                    .await
                    .unwrap()
                    .active_mode(Duration::from_secs(1));
                ftp.set_active_peer_check(check.clone());
                let listing = ftp.nlst(None).await;
                assert_eq!(listing.is_ok(), accepted, "{check:?}: {listing:?}");
            }
        });
    }
}

#[cfg(test)]
mod encoding_tests {
    use pretty_assertions::assert_eq;

    use crate::FtpError;
    use crate::encoding::test_encodings::{DropsLineEnd, Latin1, Smuggler};
    use crate::encoding_fixture::{LATIN1_NAME, serve_latin1, serve_latin1_with_name};
    use crate::smol::AsyncFtpStream;

    #[cfg(feature = "async-secure")]
    #[test]
    fn should_preserve_encoding_across_tls_transitions() {
        smol::block_on(async {
            use crate::encoding_fixture::PassthroughConnector;

            let (address, server) = serve_latin1();
            let mut ftp = crate::smol::ImplAsyncFtpStream::<smol::net::TcpStream>::connect(address)
                .await
                .unwrap();
            ftp.set_encoding(Latin1).await;
            let mut ftp = ftp
                .into_secure(PassthroughConnector, "localhost")
                .await
                .unwrap();
            assert_eq!(ftp.pwd().await.unwrap(), "/café");
            assert_eq!(ftp.nlst(None).await.unwrap(), vec!["café.txt".to_string()]);
            ftp.rm("café.txt").await.unwrap();
            let mut ftp = ftp.clear_command_channel().await.unwrap();
            assert_eq!(ftp.pwd().await.unwrap(), "/café");
            assert_eq!(ftp.nlst(None).await.unwrap(), vec!["café.txt".to_string()]);
            ftp.rm("café.txt").await.unwrap();
            ftp.quit().await.unwrap();
            let received = server.join().unwrap();
            assert_eq!(
                received
                    .iter()
                    .filter(|line| line.as_slice() == b"DELE caf\xE9.txt\r\n")
                    .count(),
                2
            );
            assert!(
                received.iter().any(|line| line == b"AUTH TLS\r\n"),
                "{received:?}"
            );
            assert!(
                received.iter().any(|line| line == b"CCC\r\n"),
                "{received:?}"
            );
        });
    }

    #[test]
    fn should_round_trip_telnet_escaped_names() {
        smol::block_on(async {
            for (name, path, filename, listing, command) in [
                (
                    b"\xFF.txt".as_slice(),
                    "/ÿ",
                    "ÿ.txt",
                    "type=file; ÿ.txt",
                    b"CWD /\xFF\xFF\r\n".as_slice(),
                ),
                (
                    b"\xFF\xFF.txt".as_slice(),
                    "/ÿÿ",
                    "ÿÿ.txt",
                    "type=file; ÿÿ.txt",
                    b"CWD /\xFF\xFF\xFF\xFF\r\n".as_slice(),
                ),
            ] {
                let (address, server) = serve_latin1_with_name(name);
                let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
                ftp.set_encoding(Latin1).await;
                let pwd = ftp.pwd().await.unwrap();
                assert_eq!(pwd, path);
                assert_eq!(ftp.mlst(None).await.unwrap(), listing);
                assert_eq!(ftp.nlst(None).await.unwrap(), vec![filename.to_string()]);
                ftp.cwd(&pwd).await.unwrap();
                ftp.quit().await.unwrap();
                let received = server.join().unwrap();
                assert!(received.iter().any(|line| line == command), "{received:?}");
            }
        });
    }

    #[test]
    fn should_decode_listings_with_custom_encoding() {
        smol::block_on(async {
            let (address, server) = serve_latin1();
            let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
            ftp.set_encoding(Latin1).await;
            assert_eq!(ftp.list(None).await.unwrap(), vec!["café.txt".to_string()]);
            assert_eq!(ftp.nlst(None).await.unwrap(), vec!["café.txt".to_string()]);
            assert_eq!(ftp.mlsd(None).await.unwrap(), vec!["café.txt".to_string()]);
            ftp.quit().await.unwrap();
            server.join().unwrap();
        })
    }

    #[test]
    fn should_decode_mlst_and_pwd_with_custom_encoding() {
        smol::block_on(async {
            let (address, server) = serve_latin1();
            let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
            ftp.set_encoding(Latin1).await;
            assert_eq!(ftp.mlst(None).await.unwrap(), "type=file; café.txt");
            assert_eq!(ftp.pwd().await.unwrap(), "/café");
            ftp.quit().await.unwrap();
            server.join().unwrap();
        })
    }

    #[test]
    fn should_decode_pwd_lossily_by_default() {
        smol::block_on(async {
            let (address, server) = serve_latin1();
            let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
            assert_eq!(ftp.pwd().await.unwrap(), "/caf\u{FFFD}");
            ftp.quit().await.unwrap();
            server.join().unwrap();
        })
    }

    #[test]
    fn should_encode_commands_with_custom_encoding() {
        smol::block_on(async {
            let (address, server) = serve_latin1();
            let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
            ftp.set_encoding(Latin1).await;
            ftp.rm("café.txt").await.unwrap();
            ftp.quit().await.unwrap();
            let received = server.join().unwrap();
            let expected = [b"DELE ".as_slice(), LATIN1_NAME, b"\r\n"].concat();
            assert!(received.contains(&expected), "{received:?}");
        })
    }

    #[test]
    fn should_escape_telnet_iac_in_custom_encoded_commands() {
        smol::block_on(async {
            let (address, server) = serve_latin1();
            let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
            ftp.set_encoding(Latin1).await;
            ftp.rm("ÿ.txt").await.unwrap();
            ftp.rm("ÿÿ.txt").await.unwrap();
            ftp.quit().await.unwrap();
            let received = server.join().unwrap();
            assert!(
                received.contains(&b"DELE \xFF\xFF.txt\r\n".to_vec()),
                "{received:?}"
            );
            assert!(
                received.contains(&b"DELE \xFF\xFF\xFF\xFF.txt\r\n".to_vec()),
                "{received:?}"
            );
        })
    }

    #[test]
    fn should_fail_command_when_name_cannot_be_encoded() {
        smol::block_on(async {
            let (address, server) = serve_latin1();
            let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
            ftp.set_encoding(Latin1).await;
            let err = ftp.rm("€.txt").await.unwrap_err();
            assert!(
                matches!(&err, FtpError::ConnectionError(io) if io.kind() == std::io::ErrorKind::InvalidInput),
                "{err:?}"
            );
            ftp.quit().await.unwrap();
            let received = server.join().unwrap();
            assert!(
                !received.iter().any(|line| line.starts_with(b"DELE")),
                "{received:?}"
            );
        })
    }

    #[test]
    fn should_reject_encoded_command_that_is_not_one_line() {
        smol::block_on(async {
            for smuggle in [true, false] {
                let (address, server) = serve_latin1();
                let mut ftp = AsyncFtpStream::connect(address).await.unwrap();
                if smuggle {
                    ftp.set_encoding(Smuggler).await;
                } else {
                    ftp.set_encoding(DropsLineEnd).await;
                }
                let err = ftp.rm("a.txt").await.unwrap_err();
                assert!(
                    matches!(&err, FtpError::ConnectionError(io) if io.kind() == std::io::ErrorKind::InvalidInput),
                    "{err:?}"
                );
                drop(ftp);
                assert_eq!(server.join().unwrap(), Vec::<Vec<u8>>::new());
            }
        })
    }
}
