//! # Tls
//!
//! Tls wrappers

use std::fmt::Debug;
use std::io::{Read, Write};
use std::net::TcpStream;

#[cfg(feature = "native-tls")]
mod native_tls;
#[cfg(feature = "native-tls")]
pub use self::native_tls::{NativeTlsConnector, NativeTlsStream};

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use self::rustls::{RustlsConnector, RustlsStream};

#[cfg(feature = "secure")]
pub trait TlsConnector: Debug {
    type Stream: TlsStream;

    fn connect(&self, domain: &str, stream: TcpStream) -> crate::FtpResult<Self::Stream>;
}

pub trait TlsStream: Debug {
    type InnerStream: Read + Write;

    /// Get underlying tcp stream
    fn tcp_stream(self) -> TcpStream;

    /// Get ref to underlying tcp stream
    fn get_ref(&self) -> &TcpStream;

    /// Get mutable reference to tls stream
    fn mut_ref(&mut self) -> &mut Self::InnerStream;
}

#[derive(Debug)]
pub struct NoTlsStream;

impl TlsStream for NoTlsStream {
    type InnerStream = TcpStream;

    fn tcp_stream(self) -> TcpStream {
        panic!()
    }

    fn get_ref(&self) -> &TcpStream {
        panic!()
    }

    fn mut_ref(&mut self) -> &mut Self::InnerStream {
        panic!()
    }
}
