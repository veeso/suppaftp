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
//! - Replaced openssl with [native-tls](https://crates.io/crates/native-tls) to make it compatible with all the operating system (without forcing users to install openssl).
//! - All the old statements have been replaced with modern rust
//! - Better error handling and possibility to retrieve error codes
//! - Test units and high code coverage to provide the community with a reliable library
//!
//! ## Get started
//!
//! First of you need to add **suppaftp** to your project dependencies:
//!
//! ```toml
//! suppaftp = "^4.2.0"
//! ```
//!
//! If you want to enable TLS support to work with **FTPS** you need to enable the **secure** feature in your dependencies:
//!
//! ```toml
//! suppaftp = { version = "^4.2.0", features = ["secure"] }
//! ```
//!
//! While if you want to go async, then you must enable the **async** feature or if you want to mix secure and async then there is the super feature **async-secure**!
//!
//! ```toml
//! suppaftp = { version = "^4.2.0", features = ["async"] }
//! # or
//! suppaftp = { version = "^4.2.0", features = ["async-secure"] }
//! ```
//!
//! Keep in mind that you **can't** use the **sync** and the **async** version of this library at the same time!
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
//! extern crate suppaftp;
//!
//! use suppaftp::FtpStream;
//! use suppaftp::native_tls::{TlsConnector, TlsStream};
//!
//! let ftp_stream = FtpStream::connect("test.rebex.net:21").unwrap();
//! // Switch to the secure mode
//! let mut ftp_stream = ftp_stream.into_secure(TlsConnector::new().unwrap(), "test.rebex.net").unwrap();
//! ftp_stream.login("demo", "password").unwrap();
//! // Do other secret stuff
//! // Switch back to the insecure mode (if required)
//! let mut ftp_stream = ftp_stream.into_insecure().unwrap();
//! // Do all public stuff
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
//! extern crate suppaftp;
//!
//! use suppaftp::FtpStream;
//! use suppaftp::async_native_tls::{TlsConnector, TlsStream};
//!
//! let ftp_stream = FtpStream::connect("test.rebex.net:21").await.unwrap();
//! // Switch to the secure mode
//! let mut ftp_stream = ftp_stream.into_secure(TlsConnector::new(), "test.rebex.net").await.unwrap();
//! ftp_stream.login("demo", "password").await.unwrap();
//! // Do other secret stuff
//! // Do all public stuff
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
extern crate lazy_static;
#[macro_use]
extern crate log;

// -- private
#[cfg(any(feature = "async", feature = "async-secure"))]
mod async_ftp;
pub(crate) mod command;
mod status;
#[cfg(any(test, not(any(feature = "async", feature = "async-secure"))))]
mod sync_ftp;

// -- public
pub mod list;
pub mod types;

// -- secure deps
#[cfg(feature = "secure")]
pub extern crate native_tls;
// -- async deps
#[cfg(feature = "async-secure")]
pub extern crate async_native_tls;

// -- export async
#[cfg(any(feature = "async", feature = "async-secure"))]
pub use async_ftp::FtpStream;
// -- export sync
#[cfg(not(any(feature = "async", feature = "async-secure")))]
pub use sync_ftp::FtpStream;
// -- export (common)
pub use status::Status;
pub use types::{FtpError, FtpResult, Mode};

// -- test logging
#[cfg(test)]
pub fn log_init() {
    let _ = env_logger::builder().is_test(true).try_init();
}
