//! # Data Stream
//!
//! This module exposes the data stream where bytes must be written to/read from

#[cfg(feature = "secure")]
use native_tls::TlsStream;
use std::io::{Read, Result, Write};
use std::net::TcpStream;

/// Data Stream used for communications. It can be both of type Tcp in case of plain communication or Ssl in case of FTPS
#[derive(Debug)]
pub enum DataStream {
    Tcp(TcpStream),
    #[cfg(feature = "secure")]
    Ssl(TlsStreamWrapper),
}

#[cfg(feature = "secure")]
impl DataStream {
    /// Unwrap the stream into TcpStream. This method is only used in secure connection.
    pub fn into_tcp_stream(self) -> TcpStream {
        match self {
            DataStream::Tcp(stream) => stream,
            DataStream::Ssl(stream) => stream.tcp_stream(),
        }
    }
}

impl DataStream {
    /// Returns a reference to the underlying TcpStream.
    pub fn get_ref(&self) -> &TcpStream {
        match self {
            DataStream::Tcp(ref stream) => stream,
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref stream) => stream.get_ref(),
        }
    }
}

// -- sync

impl Read for DataStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.read(buf),
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref mut stream) => stream.mut_ref().read(buf),
        }
    }
}

impl Write for DataStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.write(buf),
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref mut stream) => stream.mut_ref().write(buf),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            DataStream::Tcp(ref mut stream) => stream.flush(),
            #[cfg(feature = "secure")]
            DataStream::Ssl(ref mut stream) => stream.mut_ref().flush(),
        }
    }
}

// -- tls stream wrapper to implement drop...

#[cfg(feature = "secure")]
#[derive(Debug)]
/// Tls stream wrapper. This type is a garbage data type used to impl the drop trait for the tls stream.
/// This allows me to keep returning `Read` and `Write` traits in stream methods
pub struct TlsStreamWrapper {
    stream: TlsStream<TcpStream>,
    ssl_shutdown: bool,
}

#[cfg(feature = "secure")]
impl TlsStreamWrapper {
    /// Get underlying tcp stream
    pub(crate) fn tcp_stream(mut self) -> TcpStream {
        let mut stream = self.stream.get_ref().try_clone().unwrap();
        // Don't perform shutdown later
        self.ssl_shutdown = false;
        // flush stream (otherwise can cause bad chars on channel)
        if let Err(err) = stream.flush() {
            error!("Error in flushing tcp stream: {}", err);
        }
        trace!("TLS stream terminated");
        stream
    }

    /// Get ref to underlying tcp stream
    pub(crate) fn get_ref(&self) -> &TcpStream {
        self.stream.get_ref()
    }

    /// Get mutable reference to tls stream
    pub(crate) fn mut_ref(&mut self) -> &mut TlsStream<TcpStream> {
        &mut self.stream
    }
}

#[cfg(feature = "secure")]
impl From<TlsStream<TcpStream>> for TlsStreamWrapper {
    fn from(stream: TlsStream<TcpStream>) -> Self {
        Self {
            stream,
            ssl_shutdown: true,
        }
    }
}

#[cfg(feature = "secure")]
impl Drop for TlsStreamWrapper {
    fn drop(&mut self) {
        if self.ssl_shutdown {
            if let Err(err) = self.stream.shutdown() {
                error!("Failed to shutdown stream: {}", err);
            } else {
                debug!("TLS Stream shut down");
            }
        }
    }
}
