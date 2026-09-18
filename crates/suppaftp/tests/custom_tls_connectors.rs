#[cfg(feature = "secure")]
mod sync {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    use suppaftp::{FtpResult, ImplFtpStream, TlsConnector, TlsStream};

    #[derive(Debug)]
    struct CustomTlsConnector;

    impl TlsConnector for CustomTlsConnector {
        type Stream = CustomTlsStream;

        fn connect(&self, _domain: &str, stream: TcpStream) -> FtpResult<Self::Stream> {
            Ok(CustomTlsStream(stream))
        }
    }

    #[derive(Debug)]
    struct CustomTlsStream(TcpStream);

    impl TlsStream for CustomTlsStream {
        type InnerStream = TcpStream;

        fn tcp_stream(self) -> FtpResult<TcpStream> {
            Ok(self.0)
        }

        fn get_ref(&self) -> &TcpStream {
            &self.0
        }

        fn mut_ref(&mut self) -> &mut Self::InnerStream {
            &mut self.0
        }
    }

    impl Read for CustomTlsStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl Write for CustomTlsStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    fn into_secure_accepts_custom_connector(
        stream: ImplFtpStream<CustomTlsStream>,
    ) -> FtpResult<ImplFtpStream<CustomTlsStream>> {
        stream.into_secure(CustomTlsConnector, "example.com")
    }

    #[test]
    fn connector_trait_and_required_types_are_public() {
        fn assert_connector<T>()
        where
            T: TlsConnector<Stream = CustomTlsStream>,
        {
        }

        assert_connector::<CustomTlsConnector>();
        let _ = into_secure_accepts_custom_connector;
    }
}

#[cfg(all(feature = "tokio", feature = "async-secure"))]
mod tokio {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use suppaftp::FtpResult;
    use suppaftp::tokio::{AsyncTlsConnector, ImplAsyncFtpStream, TokioTlsStream};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::TcpStream;

    #[derive(Debug)]
    struct CustomTlsConnector;

    #[async_trait::async_trait]
    impl AsyncTlsConnector for CustomTlsConnector {
        type Stream = CustomTlsStream;

        async fn connect(&self, _domain: &str, stream: TcpStream) -> FtpResult<Self::Stream> {
            Ok(CustomTlsStream(stream))
        }
    }

    #[derive(Debug)]
    struct CustomTlsStream(TcpStream);

    impl AsyncRead for CustomTlsStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for CustomTlsStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }

    impl TokioTlsStream for CustomTlsStream {
        type InnerStream = TcpStream;

        fn tcp_stream(self) -> FtpResult<TcpStream> {
            Ok(self.0)
        }

        fn get_ref(&self) -> &TcpStream {
            &self.0
        }

        fn mut_ref(&mut self) -> &mut Self::InnerStream {
            &mut self.0
        }
    }

    async fn into_secure_accepts_custom_connector(
        stream: ImplAsyncFtpStream<CustomTlsStream>,
    ) -> FtpResult<ImplAsyncFtpStream<CustomTlsStream>> {
        stream.into_secure(CustomTlsConnector, "example.com").await
    }

    #[test]
    fn connector_trait_and_required_types_are_public() {
        fn assert_connector<T>()
        where
            T: AsyncTlsConnector<Stream = CustomTlsStream>,
        {
        }

        assert_connector::<CustomTlsConnector>();
        let _ = into_secure_accepts_custom_connector;
    }
}

#[cfg(all(feature = "smol", feature = "async-secure"))]
mod smol {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use smol::io::{AsyncRead, AsyncWrite};
    use smol::net::TcpStream;
    use suppaftp::FtpResult;
    use suppaftp::smol::{AsyncTlsConnector, ImplAsyncFtpStream, SmolTlsStream};

    #[derive(Debug)]
    struct CustomTlsConnector;

    #[async_trait::async_trait]
    impl AsyncTlsConnector for CustomTlsConnector {
        type Stream = CustomTlsStream;

        async fn connect(&self, _domain: &str, stream: TcpStream) -> FtpResult<Self::Stream> {
            Ok(CustomTlsStream(stream))
        }
    }

    #[derive(Debug)]
    struct CustomTlsStream(TcpStream);

    impl AsyncRead for CustomTlsStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for CustomTlsStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_close(context)
        }
    }

    impl SmolTlsStream for CustomTlsStream {
        type InnerStream = TcpStream;

        fn tcp_stream(self) -> FtpResult<TcpStream> {
            Ok(self.0)
        }

        fn get_ref(&self) -> &TcpStream {
            &self.0
        }

        fn mut_ref(&mut self) -> &mut Self::InnerStream {
            &mut self.0
        }
    }

    async fn into_secure_accepts_custom_connector(
        stream: ImplAsyncFtpStream<CustomTlsStream>,
    ) -> FtpResult<ImplAsyncFtpStream<CustomTlsStream>> {
        stream.into_secure(CustomTlsConnector, "example.com").await
    }

    #[test]
    fn connector_trait_and_required_types_are_public() {
        fn assert_connector<T>()
        where
            T: AsyncTlsConnector<Stream = CustomTlsStream>,
        {
        }

        assert_connector::<CustomTlsConnector>();
        let _ = into_secure_accepts_custom_connector;
    }
}
