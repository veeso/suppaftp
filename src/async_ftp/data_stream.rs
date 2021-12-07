//! # Data Stream
//!
//! This module exposes the async data stream implementation where bytes must be written to/read from

#[cfg(feature = "async-secure")]
use async_native_tls::TlsStream;
#[cfg(any(feature = "async", feature = "async-secure"))]
use async_std::io::{Read, Result, Write};
#[cfg(any(feature = "async", feature = "async-secure"))]
use async_std::net::TcpStream;
use pin_project::pin_project;
use std::pin::Pin;

/// Data Stream used for communications. It can be both of type Tcp in case of plain communication or Ssl in case of FTPS
#[pin_project(project = DataStreamProj)]
pub enum DataStream {
    Tcp(#[pin] TcpStream),
    #[cfg(feature = "async-secure")]
    Ssl(#[pin] TlsStream<TcpStream>),
}

#[cfg(feature = "async-secure")]
impl DataStream {
    /// Unwrap the stream into TcpStream. This method is only used in secure connection.
    pub fn into_tcp_stream(self) -> TcpStream {
        match self {
            DataStream::Tcp(stream) => stream,
            DataStream::Ssl(stream) => stream.get_ref().clone(),
        }
    }

    /// Test if the stream is secured
    pub fn is_ssl(&self) -> bool {
        matches!(self, DataStream::Ssl(_))
    }
}

impl DataStream {
    /// Returns a reference to the underlying TcpStream.
    pub fn get_ref(&self) -> &TcpStream {
        match self {
            DataStream::Tcp(ref stream) => stream,
            #[cfg(feature = "async-secure")]
            DataStream::Ssl(ref stream) => stream.get_ref(),
        }
    }
}

// -- async

impl Read for DataStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<usize>> {
        match self.project() {
            DataStreamProj::Tcp(stream) => stream.poll_read(cx, buf),
            #[cfg(feature = "async-secure")]
            DataStreamProj::Ssl(stream) => stream.poll_read(cx, buf),
        }
    }
}

impl Write for DataStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize>> {
        match self.project() {
            DataStreamProj::Tcp(stream) => stream.poll_write(cx, buf),
            #[cfg(feature = "async-secure")]
            DataStreamProj::Ssl(stream) => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        match self.project() {
            DataStreamProj::Tcp(stream) => stream.poll_flush(cx),
            #[cfg(feature = "async-secure")]
            DataStreamProj::Ssl(stream) => stream.poll_flush(cx),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        match self.project() {
            DataStreamProj::Tcp(stream) => stream.poll_close(cx),
            #[cfg(feature = "async-secure")]
            DataStreamProj::Ssl(stream) => stream.poll_close(cx),
        }
    }
}
