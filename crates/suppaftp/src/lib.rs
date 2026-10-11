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

/// A fake server for the active-mode data connection tests of every client.
#[cfg(test)]
pub(crate) mod active_mode_fixture {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;

    /// Starts a one-connection server that answers `PORT` and, on `NLST`, connects back from
    /// 127.0.0.1 to the port the client sent and lists a single file, `listed`.
    pub(crate) fn serve_active_nlst() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket);
            let _ = reader.get_mut().write_all(b"220 ready\r\n");
            let mut data_port = 0;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let reply: &[u8] = if let Some(args) = line.strip_prefix("PORT ") {
                    let numbers: Vec<u16> = args
                        .trim_end()
                        .split(',')
                        .map(|n| n.parse().unwrap())
                        .collect();
                    data_port = numbers[4] * 256 + numbers[5];
                    b"200 ok\r\n"
                } else if line.starts_with("NLST") {
                    if let Ok(mut data) = TcpStream::connect(("127.0.0.1", data_port)) {
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
            reader.get_mut().write_all(b"220 ready\r\n").unwrap();
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
