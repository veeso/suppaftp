//! # Rustls
//!
//! rustls types for suppaftp

use async_std::{
    io::{Read, Write},
    net::TcpStream,
};
use async_tls::{client::TlsStream, TlsConnector as RustlsTlsConnector};
use async_trait::async_trait;
use pin_project::pin_project;
use std::pin::Pin;

use super::{AsyncTlsConnector, AsyncTlsStream};
use crate::{FtpError, FtpResult};

/// A Wrapper for the tls connector
pub struct AsyncRustlsConnector {
    connector: RustlsTlsConnector,
}

impl std::fmt::Debug for AsyncRustlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<?>")
    }
}

impl From<RustlsTlsConnector> for AsyncRustlsConnector {
    fn from(connector: RustlsTlsConnector) -> Self {
        Self { connector }
    }
}

#[async_trait]
impl AsyncTlsConnector for AsyncRustlsConnector {
    type Stream = AsyncRustlsStream;

    async fn connect(&self, domain: &str, stream: TcpStream) -> FtpResult<Self::Stream> {
        self.connector
            .connect(domain, stream)
            .await
            .map(AsyncRustlsStream::from)
            .map_err(|e| FtpError::SecureError(e.to_string()))
    }
}

#[derive(Debug)]
#[pin_project(project = AsyncRustlsStreamProj)]
pub struct AsyncRustlsStream {
    #[pin]
    stream: TlsStream<TcpStream>,
}

impl From<TlsStream<TcpStream>> for AsyncRustlsStream {
    fn from(stream: TlsStream<TcpStream>) -> Self {
        Self { stream }
    }
}

impl Read for AsyncRustlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl Write for AsyncRustlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_close(cx)
    }
}

impl AsyncTlsStream for AsyncRustlsStream {
    type InnerStream = TlsStream<TcpStream>;

    fn get_ref(&self) -> &TcpStream {
        self.stream.get_ref()
    }

    fn mut_ref(&mut self) -> &mut Self::InnerStream {
        &mut self.stream
    }

    fn tcp_stream(self) -> TcpStream {
        self.stream.get_ref().clone()
    }
}
