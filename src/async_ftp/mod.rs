//! # Async
//!
//! This module contains the definition for all async implementation of suppaftp

mod data_stream;

use super::status;
use super::types::{FileType, FtpError, Mode, Response, Result};
use data_stream::DataStream;

#[cfg(feature = "async-secure")]
use async_native_tls::TlsConnector;
use async_std::io::{copy, BufReader, BufWriter, Read, Write};
use async_std::net::ToSocketAddrs;
use async_std::net::{SocketAddr, TcpListener, TcpStream};
use async_std::prelude::*;
use chrono::offset::TimeZone;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::borrow::Cow;
use std::str::FromStr;
use std::string::String;

lazy_static! {
    // This regex extracts IP and Port details from PASV command response.
    // The regex looks for the pattern (h1,h2,h3,h4,p1,p2).
    static ref PORT_RE: Regex = Regex::new(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)").unwrap();

    // This regex extracts modification time from MDTM command response.
    static ref MDTM_RE: Regex = Regex::new(r"\b(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\b").unwrap();

    // This regex extracts file size from SIZE command response.
    static ref SIZE_RE: Regex = Regex::new(r"\s+(\d+)\s*$").unwrap();
}

/// ## FtpStream
///
/// Stream to interface with the FTP server. This interface is only for the command stream.
pub struct FtpStream {
    reader: BufReader<DataStream>,
    mode: Mode,
    welcome_msg: Option<String>,
    #[cfg(feature = "async-secure")]
    tls_ctx: Option<TlsConnector>,
    #[cfg(feature = "async-secure")]
    domain: Option<String>,
}

impl FtpStream {
    /// ### connect
    ///
    /// Creates an FTP Stream.
    #[cfg(not(feature = "async-secure"))]
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<FtpStream> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;

        let mut ftp_stream = FtpStream {
            reader: BufReader::new(DataStream::Tcp(stream)),
            mode: Mode::Passive,
            welcome_msg: None,
        };

        match ftp_stream.read_response(status::READY).await {
            Ok(response) => {
                ftp_stream.welcome_msg = Some(response.body);
                Ok(ftp_stream)
            }
            Err(err) => Err(err),
        }
    }

    /// ### connect
    ///
    /// Creates an FTP Stream.
    #[cfg(feature = "async-secure")]
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> Result<FtpStream> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(FtpError::ConnectionError)?;

        let mut ftp_stream = FtpStream {
            reader: BufReader::new(DataStream::Tcp(stream)),
            mode: Mode::Passive,
            welcome_msg: None,
            tls_ctx: None,
            domain: None,
        };
        match ftp_stream.read_response(status::READY).await {
            Ok(response) => {
                ftp_stream.welcome_msg = Some(response.body);
                Ok(ftp_stream)
            }
            Err(err) => Err(err),
        }
    }

    /// ### into_secure
    ///
    /// Switch to a secure mode if possible, using a provided SSL configuration.
    /// This method does nothing if the connect is already secured.
    ///
    /// ## Panics
    ///
    /// Panics if the plain TCP connection cannot be switched to TLS mode.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use suppaftp::FtpStream;
    /// use suppaftp::async_native_tls::{TlsConnector, TlsStream};
    /// use std::path::Path;
    ///
    /// // Create a TlsConnector
    /// // NOTE: For custom options see <https://docs.rs/native-tls/0.2.6/native_tls/struct.TlsConnectorBuilder.html>
    /// let mut ctx = TlsConnector::new();
    /// let mut ftp_stream = FtpStream::connect("127.0.0.1:21").await.unwrap();
    /// let mut ftp_stream = ftp_stream.into_secure(ctx, "localhost").await.unwrap();
    /// ```
    #[cfg(feature = "async-secure")]
    pub async fn into_secure(
        mut self,
        tls_connector: TlsConnector,
        domain: &str,
    ) -> Result<FtpStream> {
        // Ask the server to start securing data.
        self.write_str("AUTH TLS\r\n").await?;
        self.read_response(status::AUTH_OK).await?;
        let stream = tls_connector
            .connect(
                domain,
                self.reader.into_inner().into_tcp_stream().to_owned(),
            )
            .await
            .map_err(|e| FtpError::SecureError(format!("{}", e)))?;
        let mut secured_ftp_tream = FtpStream {
            reader: BufReader::new(DataStream::Ssl(stream)),
            mode: self.mode,
            tls_ctx: Some(tls_connector),
            domain: Some(String::from(domain)),
            welcome_msg: self.welcome_msg,
        };
        // Set protection buffer size
        secured_ftp_tream.write_str("PBSZ 0\r\n").await?;
        secured_ftp_tream.read_response(status::COMMAND_OK).await?;
        // Change the level of data protectio to Private
        secured_ftp_tream.write_str("PROT P\r\n").await?;
        secured_ftp_tream.read_response(status::COMMAND_OK).await?;
        Ok(secured_ftp_tream)
    }

    /// ### into_insecure
    ///
    /// Switch to insecure mode. If the connection is already
    /// insecure does nothing.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use suppaftp::FtpStream;
    /// use std::path::Path;
    ///
    /// use suppaftp::async_native_tls::{TlsConnector, TlsStream};
    ///
    /// // Create an TlsConnector
    /// let mut ctx = TlsConnector::new();
    /// let mut ftp_stream = FtpStream::connect("127.0.0.1:21").await.unwrap();
    /// let mut ftp_stream = ftp_stream.into_secure(ctx, "localhost").await.unwrap();
    /// // Do all secret things
    /// // Switch back to the insecure mode
    /// let mut ftp_stream = ftp_stream.into_insecure().await.unwrap();
    /// // Do all public things
    /// let _ = ftp_stream.quit().await;
    /// ```
    #[cfg(feature = "async-secure")]
    pub async fn into_insecure(mut self) -> Result<FtpStream> {
        // Ask the server to stop securing data
        self.write_str("CCC\r\n").await?;
        self.read_response(status::COMMAND_OK).await?;
        let plain_ftp_stream = FtpStream {
            reader: BufReader::new(DataStream::Tcp(self.reader.into_inner().into_tcp_stream())),
            tls_ctx: None,
            mode: self.mode,
            domain: None,
            welcome_msg: self.welcome_msg,
        };
        Ok(plain_ftp_stream)
    }

    /// ### active_mode
    ///
    /// Enable active mode for data channel
    pub fn active_mode(mut self) -> Self {
        self.mode = Mode::Active;
        self
    }

    /// ### get_welcome_msg
    ///
    /// Returns welcome message retrieved from server (if available)
    pub fn get_welcome_msg(&self) -> Option<&str> {
        self.welcome_msg.as_deref()
    }

    /// Set mode
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// ### data_command
    ///
    /// Execute command which send data back in a separate stream
    async fn data_command(&mut self, cmd: &str) -> Result<DataStream> {
        let stream = match self.mode {
            Mode::Passive => {
                let addr = self.pasv().await?;
                self.write_str(cmd).await?;
                TcpStream::connect(addr)
                    .await
                    .map_err(FtpError::ConnectionError)?
            }
            Mode::Active => {
                let listener = self.active().await?;
                self.write_str(cmd).await?;
                listener
                    .accept()
                    .await
                    .map_err(FtpError::ConnectionError)?
                    .0
            }
        };

        #[cfg(not(feature = "async-secure"))]
        {
            Ok(DataStream::Tcp(stream))
        }

        #[cfg(feature = "async-secure")]
        match self.tls_ctx {
            Some(ref tls_ctx) => tls_ctx
                .connect(self.domain.as_ref().unwrap(), stream)
                .await
                .map(DataStream::Ssl)
                .map_err(|e| FtpError::SecureError(format!("{}", e))),
            None => Ok(DataStream::Tcp(stream)),
        }
    }

    /// ### get_ref
    ///
    /// Returns a reference to the underlying TcpStream.
    pub async fn get_ref(&self) -> &TcpStream {
        self.reader.get_ref().get_ref()
    }

    /// ### login
    ///
    /// Log in to the FTP server.
    pub async fn login(&mut self, user: &str, password: &str) -> Result<()> {
        self.write_str(format!("USER {}\r\n", user)).await?;
        let response = self
            .read_response_in(&[status::LOGGED_IN, status::NEED_PASSWORD])
            .await?;
        if response.code == status::NEED_PASSWORD {
            self.write_str(format!("PASS {}\r\n", password)).await?;
            self.read_response(status::LOGGED_IN).await?;
        }
        Ok(())
    }

    /// ### cwd
    ///
    /// Change the current directory to the path specified.
    pub async fn cwd(&mut self, path: &str) -> Result<()> {
        self.write_str(format!("CWD {}\r\n", path)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK)
            .await
            .map(|_| ())
    }

    /// ### cdup
    ///
    /// Move the current directory to the parent directory.
    pub async fn cdup(&mut self) -> Result<()> {
        self.write_str("CDUP\r\n").await?;
        self.read_response_in(&[status::COMMAND_OK, status::REQUESTED_FILE_ACTION_OK])
            .await
            .map(|_| ())
    }

    /// ### pwd
    ///
    /// Gets the current directory
    pub async fn pwd(&mut self) -> Result<String> {
        self.write_str("PWD\r\n").await?;
        self.read_response(status::PATH_CREATED)
            .await
            .and_then(
                |Response { code, body }| match (body.find('"'), body.rfind('"')) {
                    (Some(begin), Some(end)) if begin < end => Ok(body[begin + 1..end].to_string()),
                    _ => Err(FtpError::UnexpectedResponse(Response::new(code, body))),
                },
            )
    }

    /// ### noop
    ///
    /// This does nothing. This is usually just used to keep the connection open.
    pub async fn noop(&mut self) -> Result<()> {
        self.write_str("NOOP\r\n").await?;
        self.read_response(status::COMMAND_OK).await.map(|_| ())
    }

    /// ### mkdir
    ///
    /// This creates a new directory on the server.
    pub async fn mkdir(&mut self, pathname: &str) -> Result<()> {
        self.write_str(format!("MKD {}\r\n", pathname)).await?;
        self.read_response(status::PATH_CREATED).await.map(|_| ())
    }

    /// ### pasv
    ///
    /// Runs the PASV command.
    async fn pasv(&mut self) -> Result<SocketAddr> {
        self.write_str("PASV\r\n").await?;
        // PASV response format : 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
        let response: Response = self.read_response(status::PASSIVE_MODE).await?;
        PORT_RE
            .captures(&response.body)
            .ok_or_else(|| FtpError::UnexpectedResponse(response.clone()))
            .and_then(|caps| {
                // If the regex matches we can be sure groups contains numbers
                let (oct1, oct2, oct3, oct4) = (
                    caps[1].parse::<u8>().unwrap(),
                    caps[2].parse::<u8>().unwrap(),
                    caps[3].parse::<u8>().unwrap(),
                    caps[4].parse::<u8>().unwrap(),
                );
                let (msb, lsb) = (
                    caps[5].parse::<u8>().unwrap(),
                    caps[6].parse::<u8>().unwrap(),
                );
                let port = ((msb as u16) << 8) + lsb as u16;
                let addr = format!("{}.{}.{}.{}:{}", oct1, oct2, oct3, oct4, port);
                SocketAddr::from_str(&addr).map_err(FtpError::InvalidAddress)
            })
    }

    /// ### active
    ///
    /// Create a new tcp listener and send a PORT command for it
    async fn active(&mut self) -> Result<TcpListener> {
        let conn = TcpListener::bind("0.0.0.0:0")
            .await
            .map_err(FtpError::ConnectionError)?;

        let addr = conn.local_addr().map_err(FtpError::ConnectionError)?;

        let ip = match self.reader.get_mut() {
            DataStream::Tcp(stream) => stream.local_addr().unwrap().ip(),

            #[cfg(feature = "async-secure")]
            DataStream::Ssl(stream) => stream.get_mut().local_addr().unwrap().ip(),
        };

        let msb = addr.port() / 256;
        let lsb = addr.port() % 256;
        let ip_port = format!("{},{},{}", ip.to_string().replace(".", ","), msb, lsb);

        if cfg!(feature = "debug_print") {
            println!("Active mode, listening on {}:{}", ip, addr.port());
        }

        self.write_str(format!("PORT {}\r\n", ip_port)).await?;
        self.read_response(status::COMMAND_OK).await?;

        Ok(conn)
    }

    /// ### transfer_type
    ///
    /// Sets the type of file to be transferred. That is the implementation
    /// of `TYPE` command.
    pub async fn transfer_type(&mut self, file_type: FileType) -> Result<()> {
        let type_command = format!("TYPE {}\r\n", file_type.to_string());
        self.write_str(&type_command).await?;
        self.read_response(status::COMMAND_OK).await.map(|_| ())
    }

    /// ### quit
    ///
    /// Quits the current FTP session.
    pub async fn quit(&mut self) -> Result<()> {
        self.write_str("QUIT\r\n").await?;
        self.read_response(status::CLOSING).await.map(|_| ())
    }

    /// ### rename
    ///
    /// Renames the file from_name to to_name
    pub async fn rename(&mut self, from_name: &str, to_name: &str) -> Result<()> {
        self.write_str(format!("RNFR {}\r\n", from_name)).await?;
        self.read_response(status::REQUEST_FILE_PENDING).await?;
        self.write_str(format!("RNTO {}\r\n", to_name)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK)
            .await
            .map(|_| ())
    }

    /// ### retr
    ///
    /// The implementation of `RETR` command where `filename` is the name of the file
    /// to download from FTP and `reader` is the function which operates with the
    /// data stream opened.
    pub async fn retr<F, T>(&mut self, file_name: &str, mut reader: F) -> Result<T>
    where
        F: FnMut(&mut BufReader<DataStream>) -> Result<T>,
    {
        match self.retr_as_stream(file_name).await {
            Ok(mut stream) => {
                let result = reader(&mut stream)?;
                self.finalize_retr_stream(Box::new(stream))
                    .await
                    .map(|_| result)
            }
            Err(err) => Err(err),
        }
    }

    /// ### retr_as_stream
    ///
    /// Retrieves the file name specified from the server as a readable stream.
    /// This method is a more complicated way to retrieve a file.
    /// The reader returned should be dropped.
    /// Also you will have to read the response to make sure it has the correct value.
    /// Once file has been read, call `finalize_retr_stream()`
    pub async fn retr_as_stream(&mut self, file_name: &str) -> Result<BufReader<DataStream>> {
        let retr_command = format!("RETR {}\r\n", file_name);
        let data_stream = BufReader::new(self.data_command(&retr_command).await?);
        self.read_response_in(&[status::ABOUT_TO_SEND, status::ALREADY_OPEN])
            .await?;
        Ok(data_stream)
    }

    /// ### finalize_retr_stream
    ///
    /// Finalize retr stream; must be called once the requested file, got previously with `retr_as_stream()` has been read
    pub async fn finalize_retr_stream(&mut self, reader: Box<dyn Read>) -> Result<()> {
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(reader);
        // Then read response
        match self
            .read_response_in(&[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ])
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// ### rmdir
    ///
    /// Removes the remote pathname from the server.
    pub async fn rmdir(&mut self, pathname: &str) -> Result<()> {
        self.write_str(format!("RMD {}\r\n", pathname)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK)
            .await
            .map(|_| ())
    }

    /// ### rm
    ///
    /// Remove the remote file from the server.
    pub async fn rm(&mut self, filename: &str) -> Result<()> {
        self.write_str(format!("DELE {}\r\n", filename)).await?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK)
            .await
            .map(|_| ())
    }

    /// ### put_file
    ///
    /// This stores a file on the server.
    /// r argument must be any struct which implemenents the Read trait
    pub async fn put_file<R>(&mut self, filename: &str, r: &mut R) -> Result<u64>
    where
        R: Read + std::marker::Unpin,
    {
        // Get stream
        let mut data_stream = self.put_with_stream(filename).await?;
        let bytes = copy(r, &mut data_stream)
            .await
            .map_err(FtpError::ConnectionError)?;
        self.finalize_put_stream(Box::new(data_stream)).await?;
        Ok(bytes)
    }

    /// ### put_with_stream
    ///
    /// Send PUT command and returns a BufWriter, which references the file created on the server
    /// The returned stream must be then correctly manipulated to write the content of the source file to the remote destination
    /// The stream must be then correctly dropped.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub async fn put_with_stream(&mut self, filename: &str) -> Result<BufWriter<DataStream>> {
        let stor_command = format!("STOR {}\r\n", filename);
        let stream = BufWriter::new(self.data_command(&stor_command).await?);
        self.read_response_in(&[status::ALREADY_OPEN, status::ABOUT_TO_SEND])
            .await?;
        Ok(stream)
    }

    /// ### finalize_put_stream
    ///
    /// Finalize put when using stream
    /// This method must be called once the file has been written and
    /// `put_with_stream` has been used to write the file
    pub async fn finalize_put_stream(&mut self, stream: Box<dyn Write>) -> Result<()> {
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(stream);
        // Read response
        match self
            .read_response_in(&[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ])
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// ### list
    ///
    /// Execute `LIST` command which returns the detailed file listing in human readable format.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn list(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("LIST\r\n".into(), |path| {
            format!("LIST {}\r\n", path).into()
        });

        self.stream_lines(
            command,
            status::ABOUT_TO_SEND,
            &[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ],
        )
        .await
    }

    /// ### nlst
    ///
    /// Execute `NLST` command which returns the list of file names only.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub async fn nlst(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("NLST\r\n".into(), |path| {
            format!("NLST {}\r\n", path).into()
        });

        self.stream_lines(
            command,
            status::ABOUT_TO_SEND,
            &[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ],
        )
        .await
    }

    /// ### mdtm
    ///
    /// Retrieves the modification time of the file at `pathname` if it exists.
    pub async fn mdtm(&mut self, pathname: &str) -> Result<DateTime<Utc>> {
        self.write_str(format!("MDTM {}\r\n", pathname)).await?;
        let response: Response = self.read_response(status::FILE).await?;

        match MDTM_RE.captures(&response.body) {
            Some(caps) => {
                let (year, month, day) = (
                    caps[1].parse::<i32>().unwrap(),
                    caps[2].parse::<u32>().unwrap(),
                    caps[3].parse::<u32>().unwrap(),
                );
                let (hour, minute, second) = (
                    caps[4].parse::<u32>().unwrap(),
                    caps[5].parse::<u32>().unwrap(),
                    caps[6].parse::<u32>().unwrap(),
                );
                Ok(Utc.ymd(year, month, day).and_hms(hour, minute, second))
            }
            None => Err(FtpError::BadResponse),
        }
    }

    /// ### size
    ///
    /// Retrieves the size of the file in bytes at `pathname` if it exists.
    pub async fn size(&mut self, pathname: &str) -> Result<usize> {
        self.write_str(format!("SIZE {}\r\n", pathname)).await?;
        let response: Response = self.read_response(status::FILE).await?;

        match SIZE_RE.captures(&response.body) {
            Some(caps) => Ok(caps[1].parse().unwrap()),
            None => Err(FtpError::BadResponse),
        }
    }

    /// ### get_lines_from_stream
    ///
    /// Retrieve stream "message"
    async fn get_lines_from_stream(data_stream: BufReader<DataStream>) -> Result<Vec<String>> {
        let mut lines: Vec<String> = Vec::new();

        let mut lines_stream = data_stream.lines();
        loop {
            let line = lines_stream.next().await;
            match line {
                Some(line) => match line {
                    Ok(l) => {
                        if l.is_empty() {
                            continue;
                        }
                        lines.push(l);
                    }
                    Err(_) => return Err(FtpError::BadResponse),
                },
                None => break Ok(lines),
            }
        }
    }

    /// ### writr_str
    ///
    /// Write data to stream
    async fn write_str<S: AsRef<str>>(&mut self, command: S) -> Result<()> {
        if cfg!(feature = "debug_print") {
            print!("CMD {}", command.as_ref());
        }

        let stream = self.reader.get_mut();
        stream
            .write_all(command.as_ref().as_bytes())
            .await
            .map_err(FtpError::ConnectionError)
    }

    /// ### read_response
    ///
    /// Read response from stream
    pub async fn read_response(&mut self, expected_code: u32) -> Result<Response> {
        self.read_response_in(&[expected_code]).await
    }

    /// ### read_response_in
    ///
    /// Retrieve single line response
    pub async fn read_response_in(&mut self, expected_code: &[u32]) -> Result<Response> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .await
            .map_err(FtpError::ConnectionError)?;

        if cfg!(feature = "debug_print") {
            print!("FTP {}", line);
        }

        if line.len() < 5 {
            return Err(FtpError::BadResponse);
        }

        let code: u32 = line[0..3].parse().map_err(|_| FtpError::BadResponse)?;

        // multiple line reply
        // loop while the line does not begin with the code and a space
        let expected = format!("{} ", &line[0..3]);
        while line.len() < 5 || line[0..4] != expected {
            line.clear();
            if let Err(e) = self.reader.read_line(&mut line).await {
                return Err(FtpError::ConnectionError(e));
            }

            if cfg!(feature = "debug_print") {
                print!("FTP {}", line);
            }
        }

        line = String::from(line.trim());
        let response: Response = Response::new(code, line);
        // Return Ok or error with response
        if expected_code.iter().any(|ec| code == *ec) {
            Ok(response)
        } else {
            Err(FtpError::UnexpectedResponse(response))
        }
    }

    /// ### stream_lines
    ///
    /// Execute a command which returns list of strings in a separate stream
    async fn stream_lines(
        &mut self,
        cmd: Cow<'_, str>,
        open_code: u32,
        close_code: &[u32],
    ) -> Result<Vec<String>> {
        let data_stream = BufReader::new(self.data_command(&cmd).await?);
        self.read_response_in(&[open_code, status::ALREADY_OPEN])
            .await?;
        let lines = Self::get_lines_from_stream(data_stream).await;
        self.read_response_in(close_code).await?;
        lines
    }
}

#[cfg(test)]
mod test {

    use super::*;
    #[cfg(feature = "with-containers")]
    use crate::types::FormatControl;

    #[cfg(any(feature = "with-containers", feature = "async-secure"))]
    use pretty_assertions::assert_eq;
    #[cfg(feature = "with-containers")]
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use serial_test::serial;

    #[cfg(feature = "with-containers")]
    #[async_attributes::test]
    #[serial]
    async fn connect() {
        let stream: FtpStream = setup_stream().await;
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "async-secure")]
    #[serial]
    async fn connect_ssl() {
        let ftp_stream = FtpStream::connect("test.rebex.net:21").await.unwrap();
        let mut ftp_stream = ftp_stream
            .into_secure(TlsConnector::new(), "test.rebex.net")
            .await
            .ok()
            .unwrap();
        // Set timeout (to test ref to ssl)
        assert!(ftp_stream.get_ref().await.set_ttl(255).is_ok());
        // Login
        assert!(ftp_stream.login("demo", "password").await.is_ok());
        // PWD
        assert_eq!(ftp_stream.pwd().await.ok().unwrap().as_str(), "/");
        // Go back to insecure
        let mut ftp_stream = ftp_stream.into_insecure().await.ok().unwrap();
        // Quit
        assert!(ftp_stream.quit().await.is_ok());
    }

    #[async_attributes::test]
    #[serial]
    async fn should_change_mode() {
        let mut ftp_stream = FtpStream::connect("test.rebex.net:21")
            .await
            .map(|x| x.active_mode())
            .unwrap();
        assert_eq!(ftp_stream.mode, Mode::Active);
        ftp_stream.set_mode(Mode::Passive);
        assert_eq!(ftp_stream.mode, Mode::Passive);
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn welcome_message() {
        let stream: FtpStream = setup_stream().await;
        assert_eq!(
            stream.get_welcome_msg().unwrap(),
            "220 You will be disconnected after 15 minutes of inactivity."
        );
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn get_ref() {
        let stream: FtpStream = setup_stream().await;
        assert!(stream.get_ref().await.set_ttl(255).is_ok());
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn change_wrkdir() {
        let mut stream: FtpStream = setup_stream().await;
        let wrkdir: String = stream.pwd().await.ok().unwrap();
        assert!(stream.cwd("/").await.is_ok());
        assert_eq!(stream.pwd().await.ok().unwrap().as_str(), "/");
        assert!(stream.cwd(wrkdir.as_str()).await.is_ok());
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn cd_up() {
        let mut stream: FtpStream = setup_stream().await;
        let wrkdir: String = stream.pwd().await.ok().unwrap();
        assert!(stream.cdup().await.is_ok());
        assert_eq!(stream.pwd().await.ok().unwrap().as_str(), "/");
        assert!(stream.cwd(wrkdir.as_str()).await.is_ok());
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn noop() {
        let mut stream: FtpStream = setup_stream().await;
        assert!(stream.noop().await.is_ok());
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn make_and_remove_dir() {
        let mut stream: FtpStream = setup_stream().await;
        // Make directory
        assert!(stream.mkdir("omar").await.is_ok());
        // It shouldn't allow me to re-create the directory; should return error code 550
        match stream.mkdir("omar").await.err().unwrap() {
            FtpError::UnexpectedResponse(Response { code, body: _ }) => {
                assert_eq!(code, status::FILE_UNAVAILABLE)
            }
            err => panic!("Expected UnexpectedResponse, got {}", err),
        }
        // Remove directory
        assert!(stream.rmdir("omar").await.is_ok());
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn set_transfer_type() {
        let mut stream: FtpStream = setup_stream().await;
        assert!(stream.transfer_type(FileType::Binary).await.is_ok());
        assert!(stream
            .transfer_type(FileType::Ascii(FormatControl::Default))
            .await
            .is_ok());
        finalize_stream(stream).await;
    }

    #[async_attributes::test]
    #[cfg(feature = "with-containers")]
    #[serial]
    async fn transfer_file() {
        use async_std::io::Cursor;

        let mut stream: FtpStream = setup_stream().await;
        // Set transfer type to Binary
        assert!(stream.transfer_type(FileType::Binary).await.is_ok());
        // Write file
        let file_data = "test data\n";
        let mut reader = Cursor::new(file_data.as_bytes());
        assert!(stream.put_file("test.txt", &mut reader).await.is_ok());
        // Read file
        let mut reader = stream.retr_as_stream("test.txt").await.ok().unwrap();
        let mut buffer = Vec::new();
        assert!(reader.read_to_end(&mut buffer).await.is_ok());
        // Verify file matches
        assert_eq!(buffer.as_slice(), file_data.as_bytes());
        // Finalize
        assert!(stream.finalize_retr_stream(Box::new(reader)).await.is_ok());
        // Get size
        assert_eq!(stream.size("test.txt").await.ok().unwrap(), 10);
        // Size of non-existing file
        assert!(stream.size("omarone.txt").await.is_err());
        // List directory
        assert_eq!(stream.list(None).await.ok().unwrap().len(), 1);
        // list names
        assert_eq!(
            stream.nlst(None).await.ok().unwrap().as_slice(),
            &["test.txt"]
        );
        // modification time
        assert!(stream.mdtm("test.txt").await.is_ok());
        // Remove file
        assert!(stream.rm("test.txt").await.is_ok());
        assert!(stream.mdtm("test.txt").await.is_err());
        // Write file, rename and get
        let file_data = "test data\n";
        let mut reader = Cursor::new(file_data.as_bytes());
        assert!(stream.put_file("test.txt", &mut reader).await.is_ok());
        assert!(stream.rename("test.txt", "toast.txt").await.is_ok());
        assert!(stream.rm("toast.txt").await.is_ok());
        // List directory again
        assert_eq!(stream.list(None).await.ok().unwrap().len(), 0);
        finalize_stream(stream).await;
    }

    // -- test utils

    #[cfg(feature = "with-containers")]
    async fn setup_stream() -> FtpStream {
        let mut ftp_stream = FtpStream::connect("127.0.0.1:10021").await.unwrap();
        assert!(ftp_stream.login("test", "test").await.is_ok());
        // Create wrkdir
        let tempdir: String = generate_tempdir();
        assert!(ftp_stream.mkdir(tempdir.as_str()).await.is_ok());
        // Change directory
        assert!(ftp_stream.cwd(tempdir.as_str()).await.is_ok());
        ftp_stream
    }

    #[cfg(feature = "with-containers")]
    async fn finalize_stream(mut stream: FtpStream) {
        // Get working directory
        let wrkdir: String = stream.pwd().await.ok().unwrap();
        // Remove directory
        assert!(stream.rmdir(wrkdir.as_str()).await.is_ok());
        assert!(stream.quit().await.is_ok());
    }

    #[cfg(feature = "with-containers")]
    fn generate_tempdir() -> String {
        let mut rng = thread_rng();
        let name: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(5)
            .collect();
        format!("temp_{}", name)
    }
}
