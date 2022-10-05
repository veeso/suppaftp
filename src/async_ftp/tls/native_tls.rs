//! # Native TLS
//!
//! Native tls types for suppaftp

use async_native_tls::{Error as TlsError, TlsConnector as NativeTlsConnector, TlsStream};
use async_std::net::TcpStream;

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
    pub async fn connect(
        &self,
        domain: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>, TlsError> {
        self.connector.connect(domain, stream).await
    }
}
