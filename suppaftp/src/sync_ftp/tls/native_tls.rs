//! # Native tls
//!
//! Native tls implementation of TLS types

use native_tls::{
    HandshakeError, TlsConnector as NativeTlsConnector, TlsStream as NativeTlsStream,
};
use std::io::Write;
use std::net::TcpStream;

#[derive(Debug)]
/// A Wrapper for the tls connector
pub struct TlsConnector {
    connector: NativeTlsConnector,
}

impl From<NativeTlsConnector> for TlsConnector {
    fn from(connector: NativeTlsConnector) -> Self {
        Self { connector }
    }
}

impl TlsConnector {
    pub fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> Result<TlsStream, HandshakeError<TcpStream>> {
        self.connector.connect(domain, stream).map(TlsStream::from)
    }
}

// -- tls stream wrapper to implement drop...

/// Tls stream wrapper. This type is a garbage data type used to impl the drop trait for the tls stream.
/// This allows me to keep returning `Read` and `Write` traits in stream methods
#[derive(Debug)]
pub struct TlsStream {
    stream: NativeTlsStream<TcpStream>,
    ssl_shutdown: bool,
}

impl TlsStream {
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
    pub(crate) fn mut_ref(&mut self) -> &mut NativeTlsStream<TcpStream> {
        &mut self.stream
    }
}

impl From<NativeTlsStream<TcpStream>> for TlsStream {
    fn from(stream: NativeTlsStream<TcpStream>) -> Self {
        Self {
            stream,
            ssl_shutdown: true,
        }
    }
}

impl Drop for TlsStream {
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
