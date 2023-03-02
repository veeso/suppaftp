#![crate_name = "suppaftp"]
#![crate_type = "lib"]

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
//! suppaftp = "^5.1.0"
//! ```
//!
//! ### Features
//!
//! #### SSL/TLS Support
//!
//! If you want to enable **support for FTPS**, you must enable the `native-tls` or `rustls` feature in your cargo dependencies, based on the TLS provider you prefer.
//!
//! ```toml
//! suppaftp = { version = "^5.1.0", features = ["native-tls"] }
//! # or
//! suppaftp = { version = "^5.1.0", features = ["rustls"] }
//! ```
//!
//! > 💡 If you don't know what to choose, `native-tls` should be preferred for compatibility reasons.
//!
//! #### Async support
//!
//! If you want to enable **async** support, you must enable `async` feature in your cargo dependencies.
//!
//! ```toml
//! suppaftp = { version = "^5.1.0", features = ["async"] }
//! ```
//!
//! > ⚠️ If you want to enable both **native-tls** and **async** you must use the **async-native-tls** feature ⚠️
//! > ⚠️ If you want to enable both **rustls** and **async** you must use the **async-rustls** feature ⚠️
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
//! ```rust
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
//! ```rust
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
//! ```rust
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

#![doc(html_playground_url = "https://play.rust-lang.org")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/veeso/suppaftp/main/assets/images/cargo/suppaftp-128.png"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/veeso/suppaftp/main/assets/images/cargo/suppaftp-512.png"
)]

// -- common deps
#[macro_use]
extern crate lazy_regex;
#[macro_use]
extern crate log;

// -- private
#[cfg(feature = "async")]
mod async_ftp;
pub(crate) mod command;
mod regex;
mod status;
mod sync_ftp;

// -- public
pub mod list;
pub mod types;

// -- secure deps
#[cfg(feature = "native-tls")]
pub extern crate native_tls_crate as native_tls;
#[cfg(feature = "rustls")]
pub extern crate rustls_crate as rustls;
// -- async deps
#[cfg(feature = "async-native-tls")]
pub extern crate async_native_tls_crate as async_native_tls;

// -- export (common)
pub use status::Status;
pub use types::{FtpError, FtpResult, Mode};

// -- export sync
use sync_ftp::{ImplFtpStream, NoTlsStream};
pub type FtpStream = ImplFtpStream<NoTlsStream>;
pub use sync_ftp::DataStream;
// -- export secure (native-tls)
#[cfg(feature = "native-tls")]
pub use sync_ftp::NativeTlsConnector;
#[cfg(feature = "native-tls")]
use sync_ftp::NativeTlsStream;
#[cfg(feature = "native-tls")]
pub type NativeTlsFtpStream = ImplFtpStream<NativeTlsStream>;
// -- export secure (rustls)
#[cfg(feature = "rustls")]
pub use sync_ftp::RustlsConnector;
#[cfg(feature = "rustls")]
use sync_ftp::RustlsStream;
#[cfg(feature = "rustls")]
pub type RustlsFtpStream = ImplFtpStream<RustlsStream>;

// -- export async
#[cfg(feature = "async")]
use async_ftp::AsyncNoTlsStream;
#[cfg(feature = "async")]
use async_ftp::ImplAsyncFtpStream;
#[cfg(feature = "async")]
pub type AsyncFtpStream = ImplAsyncFtpStream<AsyncNoTlsStream>;
#[cfg(feature = "async")]
pub use async_ftp::DataStream as AsyncDataStream;
// -- export async secure (native-tls)
#[cfg(feature = "async-native-tls")]
pub use async_ftp::AsyncNativeTlsConnector;
#[cfg(feature = "async-native-tls")]
use async_ftp::AsyncNativeTlsStream;
#[cfg(feature = "async-native-tls")]
pub type AsyncNativeTlsFtpStream = ImplAsyncFtpStream<AsyncNativeTlsStream>;
// -- export async secure (rustls)
#[cfg(feature = "async-rustls")]
pub use async_ftp::AsyncRustlsConnector;
#[cfg(feature = "async-rustls")]
use async_ftp::AsyncRustlsStream;
#[cfg(feature = "async-rustls")]
pub type AsyncRustlsFtpStream = ImplAsyncFtpStream<AsyncRustlsStream>;

// -- test logging
#[cfg(test)]
pub fn log_init() {
    let _ = env_logger::builder().is_test(true).try_init();
}
