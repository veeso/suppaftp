//! # Data Stream
//!
//! This module exposes the data stream where bytes must be written to/read from

use std::io::{Read, Result, Write};
use std::net::TcpStream;

use super::tls::TlsStream;

/// Data Stream used for communications. It can be both of type Tcp in case of plain communication or Ssl in case of FTPS
#[derive(Debug)]
pub enum DataStream<T>
where
    T: TlsStream,
{
    Tcp(TcpStream),
    Ssl(Box<T>),
}

#[cfg(feature = "secure")]
#[cfg_attr(docsrs, doc(cfg(feature = "secure")))]
impl<T> DataStream<T>
where
    T: TlsStream,
{
    /// Unwrap the stream into TcpStream. This method is only used in secure connection.
    pub fn into_tcp_stream(self) -> TcpStream {
        match self {
            DataStream::Tcp(stream) => stream,
            DataStream::Ssl(stream) => stream.tcp_stream(),
        }
    }
}

impl<T> DataStream<T>
where
    T: TlsStream,
{
    /// Returns a reference to the underlying TcpStream.
    pub fn get_ref(&self) -> &TcpStream {
        match self {
            DataStream::Tcp(ref stream) => stream,
            DataStream::Ssl(ref stream) => stream.get_ref(),
        }
    }
}

// -- sync

impl<T> Read for DataStream<T>
where
    T: TlsStream,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.read(buf),
            DataStream::Ssl(ref mut stream) => stream.mut_ref().read(buf),
        }
    }
}

impl<T> Write for DataStream<T>
where
    T: TlsStream,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.write(buf),
            DataStream::Ssl(ref mut stream) => stream.mut_ref().write(buf),
        }
    }

    fn flush(&mut self) -> Result<()>
    where
        T: TlsStream,
    {
        match self {
            DataStream::Tcp(ref mut stream) => stream.flush(),
            DataStream::Ssl(ref mut stream) => stream.mut_ref().flush(),
        }
    }
}
