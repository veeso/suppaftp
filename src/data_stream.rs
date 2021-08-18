//! # Data Stream
//!
//! This module exposes the data stream where bytes must be written to/read from

#[cfg(feature = "secure")]
use native_tls::TlsStream;
use std::io::{Read, Result, Write};
use std::net::TcpStream;

/// ## DataStream
///
/// Data Stream used for communications. It can be both of type Tcp in case of plain communication or Ssl in case of FTPS
#[derive(Debug)]
pub enum DataStream {
    Tcp(TcpStream),
    #[cfg(feature = "secure")]
    Ssl(TlsStream<TcpStream>),
}

#[cfg(feature = "secure")]
impl DataStream {
    /// ### into_tcp_stream
    ///
    /// Unwrap the stream into TcpStream. This method is only used in secure connection.
    pub fn into_tcp_stream(self) -> TcpStream {
        match self {
            DataStream::Tcp(stream) => stream,
            DataStream::Ssl(stream) => stream.get_ref().try_clone().unwrap(),
        }
    }

    /// ### is_ssl
    ///
    /// Test if the stream is secured
    pub fn is_ssl(&self) -> bool {
        matches!(self, DataStream::Ssl(_))
    }
}

impl DataStream {
    /// ### get_ref
    ///
    /// Returns a reference to the underlying TcpStream.
    pub fn get_ref(&self) -> &TcpStream {
        match self {
            DataStream::Tcp(ref stream) => stream,
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref stream) => stream.get_ref(),
        }
    }
}

impl Read for DataStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.read(buf),
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref mut stream) => stream.read(buf),
        }
    }
}

impl Write for DataStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.write(buf),
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref mut stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.flush(),
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref mut stream) => stream.flush(),
        }
    }
}
