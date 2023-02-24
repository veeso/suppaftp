//! # Tls
//!
//! Tls wrappers

use std::io::Write;
use std::net::TcpStream;
use std::{fmt::Debug, io::Read};

#[cfg(feature = "native-tls")]
mod native_tls;
use crate::FtpResult;

#[cfg(feature = "native-tls")]
pub use self::native_tls::{NativeTlsConnector, NativeTlsStream};

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use self::rustls::{RustlsConnector, RustlsStream};

pub trait TlsConnector: Debug {
    type Stream: TlsStream;

    fn connect(&self, domain: &str, stream: TcpStream) -> FtpResult<Self::Stream>;
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
