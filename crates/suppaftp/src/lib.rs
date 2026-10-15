#![crate_name = "suppaftp"]
#![crate_type = "lib"]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # SuppaFTP
//!
//! SuppaFTP is an FTP client library written in Rust with optional FTPS support.
//! You can choose whether to use **sync** or **async** version of this library using cargo.toml *features*.
//! SuppaFTP is a library derived from [rust-ftp](https://github.com/mattnenterprise/rust-ftp), which has many additional features though, such as:
//!
//! - New methods to work with streams when transferring files, to give you complete freedom when you work with file transfers
//! - Method to retrieve the welcome message
//! - Supports for both sync and **async** rust
//! - Some extra features, such as the parser for the **LIST** command output
//! - Replaced openssl with rustls or native-tls as you prefer
//! - All the old statements have been replaced with modern rust
//! - Better error handling and possibility to retrieve error codes
//! - Test units and high code coverage to provide the community with a reliable library
//!
//! ## Get started
//!
//! To get started, first add **suppaftp** to your dependencies:
//!
//! ```toml
//! suppaftp = "^8"
//! ```
//!
//! ### Features
//!
//! #### SSL/TLS Support
//!
//! If you want to enable **support for FTPS**, you must enable the `native-tls` or `rustls` feature in your cargo dependencies, based on the TLS provider you prefer.
//!
//! ```toml
//! suppaftp = { version = "^8", features = ["native-tls"] }
//! # or
//! suppaftp = { version = "^8", features = ["rustls-aws-lc-rs"] }
//! ```
//!
//! > 💡 If you don't know what to choose, `native-tls` should be preferred for compatibility reasons.
//!
//! #### Async support
//!
//! If you want to enable **async** support, you must enable either `smol` feature,
//! to use [smol](https://crates.io/crates/smol)
//! or `tokio` feature, to use [tokio](https://crates.io/crates/tokio) as backend, in your cargo dependencies.
//!
//! ```toml
//! suppaftp = { version = "8", features = ["tokio"] }
//! ```
//!
//! > ⚠️ If you want to enable both **native-tls** and **smol** you must use the **smol-async-native-tls** feature ⚠️
//! > ⚠️ If you want to enable both **native-tls** and **tokio** you must use the **tokio-async-native-tls** feature ⚠️
//! > ⚠️ If you want to enable both **rustls** and **smol** you must use the **smol-rustls-aws-lc-rs** (or `-ring`) feature ⚠️
//! > ❗ If you want to link libssl statically with `smol`, enable feature `smol-async-native-tls-vendored`
//! > ❗ If you want to link libssl statically with `tokio`, enable feature `tokio-async-native-tls-vendored`
//!
//! #### Deprecated methods
//!
//! If you want to enable deprecated methods of FTPS, please enable the `deprecated` feature in your cargo dependencies.
//!
//! This feature enables these methods:
//!
//! - `connect_secure_implicit()`: used to connect via implicit FTPS
//!
//! ## Usage
//!
//! Here is a basic usage example:
//!
//! ```rust,ignore
//! use suppaftp::FtpStream;
//! let mut ftp_stream = FtpStream::connect("127.0.0.1:10021").unwrap_or_else(|err|
//!     panic!("{}", err)
//! );
//! assert!(ftp_stream.login("test", "test").is_ok());
//!
//! // Disconnect from server
//! assert!(ftp_stream.quit().is_ok());
//! ```
//!
//! ## FTPS
//!
//! The client supports FTPS on demand. To enable it the client should be
//! compiled with feature `secure` enabled which requires
//! [rust-native-tls](https://github.com/sfackler/rust-native-tls).
//!
//! The client uses explicit mode for connecting FTPS what means you should
//! connect the server as usually and then switch to the secure mode (TLS is used).
//! For better security it's the good practice to switch to the secure mode
//! before authentication.
//!
//! ### FTPS Usage
//!
//! ```rust,ignore
//! use suppaftp::{NativeTlsFtpStream, NativeTlsConnector};
//! use suppaftp::native_tls::{TlsConnector, TlsStream};
//!
//! let ftp_stream = NativeTlsFtpStream::connect("test.rebex.net:21").unwrap();
//! // Switch to the secure mode
//! let mut ftp_stream = ftp_stream.into_secure(NativeTlsConnector::from(TlsConnector::new().unwrap()), "test.rebex.net").unwrap();
//! ftp_stream.login("demo", "password").unwrap();
//! // Do other secret stuff
//! assert!(ftp_stream.quit().is_ok());
//! ```
//!
//! ## Going async
//!
//! SuppaFTP also supports **async** execution as said before, through the **async** feature.
//! Basically there's no difference in the function you can use when using the async version of suppaftp.
//! Let's quickly see in the example how it works
//!
//! ```rust,ignore
//! use suppaftp::{AsyncFtpStream, AsyncNativeTlsConnector};
//! use suppaftp::async_native_tls::{TlsConnector, TlsStream};
//!
//! let ftp_stream = AsyncFtpStream::connect("test.rebex.net:21").await.unwrap();
//! // Switch to the secure mode
//! let mut ftp_stream = ftp_stream.into_secure(AsyncNativeTlsConnector::from(TlsConnector::new()), "test.rebex.net").await.unwrap();
//! ftp_stream.login("demo", "password").await.unwrap();
//! // Do other secret stuff
//! assert!(ftp_stream.quit().await.is_ok());
//! ```
//!
//! ## Features
//
// These are all the possible features, by family
//
// - **sync FTP**:
//     - `native-tls`: enable FTPS support using [native-tls](https://crates.io/crates/native-tls) as backend for TLS
//     - `native-tls-vendored`: enable vendored FTPS support using [native-tls](https://crates.io/crates/native-tls)
//     - `rustls-aws-lc-rs`: enable FTPS support using [rustls](https://crates.io/crates/rustls) with aws-lc-rs as TLS
//       backend.
//     - `rustls-ring`: enable FTPS support using [rustls](https://crates.io/crates/rustls) with ring as TLS backend.
// - **Async FTP**:
//     - **Smol**:
//         - `smol`: enable async client using [smol](https://crates.io/crates/smol) as async backend
//         - `smol-async-native-tls`: enable FTPS support
//           using [async-native-tls](https://crates.io/crates/async-native-tls)
//         - `smol-async-native-tls-vendored`: enable vendored FTPS support
//           using [async-native-tls](https://crates.io/crates/async-native-tls)
//         - `smol-rustls-aws-lc-rs`: enable FTPS support
//           using [futures-rustls](https://crates.io/crates/futures-rustls) with aws-lc-rs as TLS backend.
//         - `smol-rustls-ring`: enable FTPS support using [futures-rustls](https://crates.io/crates/futures-rustls)
//           with ring as TLS backend.
//     - **Tokio**:
//         - `tokio`: enable async client using [tokio](https://crates.io/crates/tokio) as async backend
//         - `tokio-async-native-tls`: enable FTPS support
//           using [async-native-tls](https://crates.io/crates/async-native-tls)
//         - `tokio-async-native-tls-vendored`: enable vendored FTPS support
//           using [async-native-tls](https://crates.io/crates/async-native-tls)
//         - `tokio-async-rustls-aws-lc-rs`: enable FTPS support
//           using [async-rustls](https://crates.io/crates/async-rustls)
//           with aws-lc-rs as TLS backend.
//         - `tokio-async-rustls-ring`: enable FTPS support using [async-rustls](https://crates.io/crates/async-rustls)
//           with ring as TLS backend.
// - **Misc**:
//     - `deprecated`: enable deprecated FTP/FTPS methods
//     - `no-log`: disable logging
//!

#![doc(html_playground_url = "https://play.rust-lang.org")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/veeso/suppaftp/main/assets/images/cargo/suppaftp-128.png"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/veeso/suppaftp/main/assets/images/cargo/suppaftp-512.png"
)]

// Give compile error if both `smol-async-native-tls` and `tokio-async-native-tls` are enabled
#[cfg(all(feature = "smol-async-native-tls", feature = "tokio-async-native-tls"))]
compile_error!("smol-async-native-tls and tokio-async-native-tls are mutually exclusive");

// -- common deps
#[macro_use]
extern crate lazy_regex;
#[macro_use]
extern crate log;

// -- private
#[cfg(any(feature = "smol", feature = "tokio"))]
mod async_ftp;

mod ascii;
pub(crate) mod command;
mod encoding;
mod regex;
mod status;
mod sync_ftp;

// -- public
pub mod list;
pub mod types;

#[cfg(test)]
mod test_container;
#[cfg(all(test, any(feature = "secure", feature = "async-secure")))]
pub(crate) mod test_data_command;

// -- secure deps
#[cfg(feature = "native-tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
pub extern crate native_tls_crate as native_tls;
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))
)]
pub extern crate rustls_crate as rustls;
// -- async deps
#[cfg(any(feature = "tokio-async-native-tls", feature = "smol-async-native-tls"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "tokio-async-native-tls", feature = "smol-async-native-tls")))
)]
pub extern crate async_native_tls_crate as async_native_tls;
#[cfg(any(feature = "tokio-rustls-aws-lc-rs", feature = "tokio-rustls-ring"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "tokio-rustls-aws-lc-rs", feature = "tokio-rustls-ring")))
)]
pub extern crate tokio_rustls_crate as tokio_rustls;

// -- export (common)
pub use encoding::{Encoding, Utf8Encoding};
pub use status::Status;
use sync_ftp::NoTlsStream;
// -- export sync
#[cfg(feature = "secure")]
#[cfg_attr(docsrs, doc(cfg(feature = "secure")))]
#[doc(inline)]
pub use sync_ftp::TlsConnector;
pub use sync_ftp::{ImplFtpStream, PassiveStreamBuilder, TlsStream};
pub use types::{ActivePeerCheck, FtpError, FtpResult, Mode, ReplyTooLarge};
pub type FtpStream = ImplFtpStream<NoTlsStream>;
// -- export secure (native-tls)
#[cfg(feature = "native-tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
pub use sync_ftp::NativeTlsConnector;
#[cfg(feature = "native-tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
use sync_ftp::NativeTlsStream;
pub use sync_ftp::{ControlSocket, DataStream, TransferStream};
#[cfg(feature = "native-tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "native-tls")))]
pub type NativeTlsFtpStream = ImplFtpStream<NativeTlsStream>;
// -- export secure (rustls)
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))
)]
pub use sync_ftp::RustlsConnector;
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))
)]
use sync_ftp::RustlsStream;
#[cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "rustls-aws-lc-rs", feature = "rustls-ring")))
)]
pub type RustlsFtpStream = ImplFtpStream<RustlsStream>;

#[cfg(any(feature = "tokio", feature = "smol"))]
pub use crate::async_ftp::*;

// -- test logging
#[cfg(test)]
pub fn log_init() {
    use std::sync::Once;

    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Trace)
            .is_test(true)
            .try_init();
    });
}

/// Fake servers for the active-mode data connection tests of every client.
#[cfg(test)]
pub(crate) mod active_mode_fixture {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{IpAddr, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    /// Control connection addresses to test active mode on, each with the start of the `PORT`
    /// or `EPRT` command the client must announce for it.
    ///
    /// The link-local address uses interface index 1, the loopback interface on macOS, which is
    /// the only platform where loopback has a link-local address by default.
    pub(crate) const CONTROL_ADDRESSES: [(&str, &str); 3] = [
        ("127.0.0.1:0", "PORT 127,0,0,1,"),
        ("[::1]:0", "EPRT |2|::1|"),
        ("[fe80::1%1]:0", "EPRT |2|fe80::1|"),
    ];

    /// Binds a control listener on `address`, or returns `None` if this machine can't bind it.
    pub(crate) fn bind_control(address: &str) -> Option<TcpListener> {
        let address: SocketAddr = address.parse().unwrap();
        match TcpListener::bind(address) {
            Ok(listener) => Some(listener),
            Err(err) => {
                eprintln!("skipping {address}: {err}");
                None
            }
        }
    }

    /// Starts a one-connection server that answers `PORT` and, on `NLST`, connects back from
    /// 127.0.0.1 to the port the client sent and lists a single file, `listed`.
    pub(crate) fn serve_active_nlst() -> SocketAddr {
        serve_active_nlst_on(TcpListener::bind("127.0.0.1:0").unwrap())
    }

    /// Starts a one-connection server on `listener` that answers `PORT` or `EPRT` and, on
    /// `NLST`, connects back to the announced address and lists a single file, `listed`.
    pub(crate) fn serve_active_nlst_on(listener: TcpListener) -> SocketAddr {
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket);
            let _ = reader.get_mut().write_all(b"220 ready\r\n");
            let mut data_address = None;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let reply: &[u8] = if line.starts_with("PORT ") || line.starts_with("EPRT ") {
                    data_address = Some(parse_data_address(line.trim_end(), address));
                    b"200 ok\r\n"
                } else if line.starts_with("NLST") {
                    if let Some(data_address) = data_address
                        && let Ok(mut data) = TcpStream::connect(data_address)
                    {
                        let _ = reader.get_mut().write_all(b"150 here it comes\r\n");
                        let _ = data.write_all(b"listed\r\n");
                    }
                    b"226 done\r\n"
                } else {
                    b"502 not here\r\n"
                };
                if reader.get_mut().write_all(reply).is_err() {
                    break;
                }
                line.clear();
            }
        });
        address
    }

    /// Starts a one-connection server on `listener` that answers one `PORT` or `EPRT` and
    /// returns that command line.
    pub(crate) fn serve_port_command(listener: TcpListener) -> (SocketAddr, JoinHandle<String>) {
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket);
            reader.get_mut().write_all(b"220 ready\r\n").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            reader.get_mut().write_all(b"200 ok\r\n").unwrap();
            line.trim_end().to_string()
        });
        (address, worker)
    }

    /// Parses the data address of a `PORT` or `EPRT` command. An IPv6 address takes the scope of
    /// `control`, which the command can't carry.
    fn parse_data_address(command: &str, control: SocketAddr) -> SocketAddr {
        if let Some(args) = command.strip_prefix("PORT ") {
            let numbers: Vec<u8> = args.split(',').map(|n| n.parse().unwrap()).collect();
            let ip = IpAddr::from([numbers[0], numbers[1], numbers[2], numbers[3]]);
            let port = u16::from(numbers[4]) * 256 + u16::from(numbers[5]);
            return SocketAddr::new(ip, port);
        }
        let args = command.strip_prefix("EPRT ").unwrap();
        let fields: Vec<&str> = args.split('|').collect();
        let ip: IpAddr = fields[2].parse().unwrap();
        let port: u16 = fields[3].parse().unwrap();
        match (ip, control) {
            (IpAddr::V6(ip), SocketAddr::V6(control)) => {
                SocketAddrV6::new(ip, port, 0, control.scope_id()).into()
            }
            (ip, _) => SocketAddr::new(ip, port),
        }
    }
}

/// A fake server with Latin-1 file names, for the encoding tests of every client.
#[cfg(test)]
pub(crate) mod encoding_fixture {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread::{self, JoinHandle};

    /// `café.txt` in Latin-1.
    pub(crate) const LATIN1_NAME: &[u8] = b"caf\xE9.txt";

    /// A connector that exercises control-channel reconstruction without a TLS handshake.
    #[derive(Debug)]
    #[cfg(any(feature = "secure", feature = "async-secure"))]
    pub(crate) struct PassthroughConnector;

    #[cfg(feature = "secure")]
    impl crate::TlsConnector for PassthroughConnector {
        type Stream = std::net::TcpStream;

        fn connect(&self, _: &str, stream: Self::Stream) -> crate::FtpResult<Self::Stream> {
            Ok(stream)
        }
    }

    #[cfg(feature = "secure")]
    impl crate::TlsStream for std::net::TcpStream {
        type InnerStream = Self;

        fn tcp_stream(self) -> crate::FtpResult<Self> {
            Ok(self)
        }

        fn get_ref(&self) -> &Self {
            self
        }

        fn mut_ref(&mut self) -> &mut Self {
            self
        }
    }

    #[cfg(all(feature = "tokio", feature = "async-secure"))]
    #[async_trait::async_trait]
    impl crate::tokio::AsyncTlsConnector for PassthroughConnector {
        type Stream = tokio::net::TcpStream;

        async fn connect(&self, _: &str, stream: Self::Stream) -> crate::FtpResult<Self::Stream> {
            Ok(stream)
        }
    }

    #[cfg(all(feature = "tokio", feature = "async-secure"))]
    impl crate::tokio::TokioTlsStream for tokio::net::TcpStream {
        type InnerStream = Self;

        fn tcp_stream(self) -> crate::FtpResult<Self> {
            Ok(self)
        }

        fn get_ref(&self) -> &Self {
            self
        }

        fn mut_ref(&mut self) -> &mut Self {
            self
        }
    }

    #[cfg(all(feature = "smol", feature = "async-secure"))]
    #[async_trait::async_trait]
    impl crate::smol::AsyncTlsConnector for PassthroughConnector {
        type Stream = smol::net::TcpStream;

        async fn connect(&self, _: &str, stream: Self::Stream) -> crate::FtpResult<Self::Stream> {
            Ok(stream)
        }
    }

    #[cfg(all(feature = "smol", feature = "async-secure"))]
    impl crate::smol::SmolTlsStream for smol::net::TcpStream {
        type InnerStream = Self;

        fn tcp_stream(self) -> crate::FtpResult<Self> {
            Ok(self)
        }

        fn get_ref(&self) -> &Self {
            self
        }

        fn mut_ref(&mut self) -> &mut Self {
            self
        }
    }

    /// Starts a one-connection server for Latin-1 encoding and control-channel transition tests.
    ///
    /// The handle yields every raw command line received, CRLF included, once the client sends
    /// `QUIT` or disconnects.
    pub(crate) fn serve_latin1() -> (SocketAddr, JoinHandle<Vec<Vec<u8>>>) {
        serve_latin1_with_name(LATIN1_NAME)
    }

    /// Starts the encoding fixture with a raw filename and Telnet-escaped control replies.
    pub(crate) fn serve_latin1_with_name(
        name: &'static [u8],
    ) -> (SocketAddr, JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket);
            let control_name: Vec<u8> = name
                .iter()
                .flat_map(|byte| std::iter::once(*byte).chain((*byte == 0xFF).then_some(*byte)))
                .collect();
            let banner = [b"220 ".as_slice(), &control_name, b" ready\r\n"].concat();
            reader.get_mut().write_all(&banner).unwrap();
            let mut data_listener: Option<TcpListener> = None;
            let mut received = Vec::new();
            loop {
                let mut line = Vec::new();
                if reader.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                    break;
                }
                received.push(line.clone());
                let verb: Vec<u8> = line
                    .split(|byte| matches!(byte, b' ' | b'\r' | b'\n'))
                    .next()
                    .unwrap_or_default()
                    .to_vec();
                let reply: Vec<u8> = match verb.as_slice() {
                    b"PWD" => [
                        b"257 \"/".as_slice(),
                        control_name.strip_suffix(b".txt").unwrap_or(&control_name),
                        b"\" is the current directory\r\n",
                    ]
                    .concat(),
                    b"MLST" => [
                        b"250-Listing\r\n type=file; ".as_slice(),
                        &control_name,
                        b"\r\n250 End\r\n",
                    ]
                    .concat(),
                    b"AUTH" => b"234 start TLS\r\n".to_vec(),
                    b"PASV" => {
                        let data = TcpListener::bind("127.0.0.1:0").unwrap();
                        let port = data.local_addr().unwrap().port();
                        data_listener = Some(data);
                        format!(
                            "227 Entering Passive Mode (127,0,0,1,{},{})\r\n",
                            port >> 8,
                            port & 0xFF
                        )
                        .into_bytes()
                    }
                    b"LIST" | b"NLST" | b"MLSD" => {
                        let data = data_listener.take().expect("PASV must precede a listing");
                        reader
                            .get_mut()
                            .write_all(b"150 here it comes\r\n")
                            .unwrap();
                        let (mut socket, _) = data.accept().unwrap();
                        socket.write_all(name).unwrap();
                        socket.write_all(b"\r\n").unwrap();
                        drop(socket);
                        b"226 done\r\n".to_vec()
                    }
                    b"DELE" | b"CWD" => b"250 done\r\n".to_vec(),
                    b"QUIT" => b"221 bye\r\n".to_vec(),
                    _ => b"200 ok\r\n".to_vec(),
                };
                if reader.get_mut().write_all(&reply).is_err() || verb == b"QUIT" {
                    break;
                }
            }
            received
        });
        (address, handle)
    }
}

/// A fake server that records uploads, for the ASCII transfer tests of every client.
#[cfg(test)]
pub(crate) mod upload_fixture {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread::{self, JoinHandle};

    /// Starts a one-connection server that stores the payload of every `STOR` and `APPE`.
    ///
    /// `TYPE E` is refused with `504`; every other `TYPE` is accepted. The handle yields the
    /// payloads in upload order once the client sends `QUIT` or disconnects.
    pub(crate) fn serve_uploads() -> (SocketAddr, JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket);
            reader.get_mut().write_all(b"220 ready\r\n").unwrap();
            let mut data_listener: Option<TcpListener> = None;
            let mut uploads = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let command = line.trim_end();
                let reply = if command.starts_with("TYPE E") {
                    "504 type not implemented\r\n".to_string()
                } else if command == "AUTH TLS" {
                    "234 start TLS\r\n".to_string()
                } else if command == "PASV" {
                    let data = TcpListener::bind("127.0.0.1:0").unwrap();
                    let port = data.local_addr().unwrap().port();
                    data_listener = Some(data);
                    format!(
                        "227 Entering Passive Mode (127,0,0,1,{high},{low})\r\n",
                        high = port >> 8,
                        low = port & 0xFF
                    )
                } else if command.starts_with("STOR ") || command.starts_with("APPE ") {
                    let data = data_listener.take().expect("PASV must precede an upload");
                    reader.get_mut().write_all(b"150 send it\r\n").unwrap();
                    let (mut socket, _) = data.accept().unwrap();
                    let mut payload = Vec::new();
                    socket.read_to_end(&mut payload).unwrap();
                    uploads.push(payload);
                    "226 stored\r\n".to_string()
                } else if command == "QUIT" {
                    "221 bye\r\n".to_string()
                } else {
                    "200 ok\r\n".to_string()
                };
                if reader.get_mut().write_all(reply.as_bytes()).is_err() || command == "QUIT" {
                    break;
                }
            }
            uploads
        });
        (address, handle)
    }
}

/// A fake server that forgets a `REST` offset as soon as another command follows it, for the
/// resumed transfer tests of every client.
#[cfg(test)]
pub(crate) mod restart_fixture {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    /// Content of every file the server sends.
    pub(crate) const CONTENT: &[u8] = b"0123456789abcdef";

    /// File name the server answers `RETR` with `550`.
    pub(crate) const MISSING: &str = "missing";

    /// What the server received during one session.
    pub(crate) struct Session {
        /// Every command line, without the line ending.
        pub(crate) lines: Vec<String>,
        /// The file as left by the last `STOR`: the bytes before the offset followed by the upload.
        pub(crate) stored: Vec<u8>,
    }

    impl Session {
        /// Returns the `REST` and data transfer command lines, in order.
        pub(crate) fn transfer_lines(&self) -> Vec<&str> {
            self.lines
                .iter()
                .map(String::as_str)
                .filter(|line| {
                    ["REST ", "RETR ", "STOR ", "APPE ", "NLST"]
                        .iter()
                        .any(|verb| line.starts_with(verb))
                })
                .collect()
        }
    }

    /// Starts a one-connection server modeled on FileZilla Server, which follows RFC 3659 §5.3
    /// strictly: any command after `REST` drops the offset.
    ///
    /// `REST` beyond [`CONTENT`] is refused with `501`. `RETR` sends [`CONTENT`] from the offset
    /// in effect, except for [`MISSING`]; `STOR` keeps the bytes of [`CONTENT`] before the offset
    /// and appends the upload; `NLST` lists one file. `PASV`, `EPSV`, `PORT` and `EPRT` are
    /// supported. The handle yields the [`Session`] once the client sends `QUIT` or disconnects.
    pub(crate) fn serve_strict_restart() -> (SocketAddr, JoinHandle<Session>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(socket);
            reader.get_mut().write_all(b"220 ready\r\n").unwrap();
            let mut restart = 0;
            let mut passive: Option<TcpListener> = None;
            let mut active: Option<SocketAddr> = None;
            let mut session = Session {
                lines: Vec::new(),
                stored: Vec::new(),
            };
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let command = line.trim_end().to_string();
                session.lines.push(command.clone());
                let (verb, argument) = command.split_once(' ').unwrap_or((&command, ""));
                // Every command drops a pending offset; only REST sets a new one.
                let offset = std::mem::take(&mut restart);
                let reply = match verb {
                    "REST" => match argument.parse() {
                        Ok(value) if value <= CONTENT.len() => {
                            restart = value;
                            format!("350 Restarting at {restart}")
                        }
                        _ => "501 Invalid restart offset".to_string(),
                    },
                    "PASV" => {
                        let data = TcpListener::bind("127.0.0.1:0").unwrap();
                        let port = data.local_addr().unwrap().port();
                        passive = Some(data);
                        format!(
                            "227 Entering Passive Mode (127,0,0,1,{high},{low})",
                            high = port >> 8,
                            low = port & 0xFF
                        )
                    }
                    "EPSV" => {
                        let data = TcpListener::bind("127.0.0.1:0").unwrap();
                        let port = data.local_addr().unwrap().port();
                        passive = Some(data);
                        format!("229 Entering Extended Passive Mode (|||{port}|)")
                    }
                    "PORT" => {
                        let n: Vec<u16> = argument.split(',').map(|v| v.parse().unwrap()).collect();
                        active = Some(SocketAddr::from((
                            [n[0] as u8, n[1] as u8, n[2] as u8, n[3] as u8],
                            n[4] * 256 + n[5],
                        )));
                        "200 PORT command successful".to_string()
                    }
                    "EPRT" => {
                        let fields: Vec<&str> = argument.split('|').collect();
                        let ip: std::net::IpAddr = fields[2].parse().unwrap();
                        active = Some(SocketAddr::new(ip, fields[3].parse().unwrap()));
                        "200 EPRT command successful".to_string()
                    }
                    "RETR" if argument == MISSING => {
                        passive = None;
                        active = None;
                        "550 No such file".to_string()
                    }
                    "RETR" | "STOR" | "NLST" => {
                        reader
                            .get_mut()
                            .write_all(b"150 Opening data connection\r\n")
                            .unwrap();
                        let mut data = match (passive.take(), active.take()) {
                            (Some(data), _) => data.accept().unwrap().0,
                            (None, Some(address)) => TcpStream::connect(address).unwrap(),
                            (None, None) => panic!("no data connection negotiated"),
                        };
                        match verb {
                            "RETR" => data.write_all(&CONTENT[offset..]).unwrap(),
                            "STOR" => {
                                let mut upload = Vec::new();
                                data.read_to_end(&mut upload).unwrap();
                                session.stored = CONTENT[..offset].to_vec();
                                session.stored.extend(upload);
                            }
                            _ => data.write_all(b"file\r\n").unwrap(),
                        }
                        drop(data);
                        "226 Transfer complete".to_string()
                    }
                    "QUIT" => "221 Bye".to_string(),
                    _ => "200 ok".to_string(),
                };
                if reader
                    .get_mut()
                    .write_all(format!("{reply}\r\n").as_bytes())
                    .is_err()
                    || verb == "QUIT"
                {
                    break;
                }
            }
            session
        });
        (address, handle)
    }
}
