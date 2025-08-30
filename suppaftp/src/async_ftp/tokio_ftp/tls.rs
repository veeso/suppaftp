//! # Tls
//!
//! Tls wrappers

use std::fmt::Debug;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::FtpResult;

#[cfg(feature = "async-native-tls-tokio")]
mod native_tls;
#[cfg(feature = "async-native-tls-tokio")]
pub use self::native_tls::{AsyncNativeTlsConnector, AsyncNativeTlsStream};

#[cfg(feature = "tokio-rustls")]
mod rustls;
#[cfg(feature = "tokio-rustls")]
pub use self::rustls::{AsyncRustlsConnector, AsyncRustlsStream};

#[async_trait]
pub trait AsyncTlsConnector: Debug {
    type Stream: AsyncTlsStream;

    async fn connect(&self, domain: &str, stream: TcpStream) -> FtpResult<Self::Stream>;
}

pub trait AsyncTlsStream: Debug + AsyncRead + AsyncWrite + Unpin {
    type InnerStream: AsyncRead + AsyncWrite;

    /// Get underlying tcp stream
    fn tcp_stream(self) -> TcpStream;

    /// Get ref to underlying tcp stream
    fn get_ref(&self) -> &TcpStream;

    /// Get mutable reference to tls stream
    fn mut_ref(&mut self) -> &mut Self::InnerStream;
}

#[derive(Debug)]
pub struct AsyncNoTlsStream;

impl AsyncRead for AsyncNoTlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        panic!()
    }
}

impl AsyncWrite for AsyncNoTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        panic!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        panic!()
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        panic!()
    }
}

impl AsyncTlsStream for AsyncNoTlsStream {
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
