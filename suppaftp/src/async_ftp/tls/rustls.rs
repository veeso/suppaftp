//! # Rustls
//!
//! rustls types for suppaftp

use async_std::io::Error as IoError;
use async_std::net::TcpStream;
use async_tls::{client::TlsStream, TlsConnector as RustlsTlsConnector};

/// A Wrapper for the tls connector
pub struct TlsConnector {
    connector: RustlsTlsConnector,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<?>")
    }
}

impl From<RustlsTlsConnector> for TlsConnector {
    fn from(connector: RustlsTlsConnector) -> Self {
        Self { connector }
    }
}

impl TlsConnector {
    pub async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>, IoError> {
        self.connector.connect(domain, stream).await
    }
}
