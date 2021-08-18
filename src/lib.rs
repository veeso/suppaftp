#![crate_name = "ftp4"]
#![crate_type = "lib"]

//! # ftp4
//!
//! ftp4 is an FTP client library written in Rust with optional FTPS support.
//!
//! ### Usage
//!
//! Here is a basic usage example:
//!
//! ```rust,no_run
//! use ftp4::FtpStream;
//! let mut ftp_stream = FtpStream::connect("127.0.0.1:21").unwrap_or_else(|err|
//!     panic!("{}", err)
//! );
//! let _ = ftp_stream.quit();
//! ```
//!
//! ### FTPS
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
//! ```rust,no_run
//! use ftp4::FtpStream;
//! use ftp4::native_tls::{TlsConnector, TlsStream};
//!
//! let ftp_stream = FtpStream::connect("127.0.0.1:21").unwrap();
//! let mut ctx = TlsConnector::new().unwrap();
//! // Switch to the secure mode
//! let mut ftp_stream = ftp_stream.into_secure(ctx, "localhost").unwrap();
//! ftp_stream.login("anonymous", "anonymous").unwrap();
//! // Do other secret stuff
//! // Switch back to the insecure mode (if required)
//! let mut ftp_stream = ftp_stream.into_insecure().unwrap();
//! // Do all public stuff
//! let _ = ftp_stream.quit();
//! ```
//!

#[macro_use]
extern crate lazy_static;
extern crate chrono;
extern crate regex;
extern crate thiserror;

#[cfg(feature = "secure")]
pub extern crate native_tls;

mod data_stream;
mod ftp;
pub mod status;
pub mod types;

pub use self::ftp::FtpStream;
pub use self::types::FtpError;
