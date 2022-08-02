//! # Sync
//!
//! This module contains the definition for all Sync implementation of suppaftp

mod data_stream;

use super::types::{FileType, FtpError, FtpResult, Mode, Response};
use super::Status;
use crate::command::Command;
#[cfg(feature = "secure")]
use crate::command::ProtectionLevel;
use data_stream::DataStream;

#[cfg(feature = "secure")]
use data_stream::TlsStreamWrapper;

use chrono::offset::TimeZone;
use chrono::{DateTime, Utc};
use lazy_regex::{Lazy, Regex};
#[cfg(feature = "secure")]
use native_tls::TlsConnector;
use std::io::{copy, BufRead, BufReader, Cursor, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::string::String;

// This regex extracts IP and Port details from PASV command response.
// The regex looks for the pattern (h1,h2,h3,h4,p1,p2).
static PORT_RE: Lazy<Regex> = lazy_regex!(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)");

// This regex extracts modification time from MDTM command response.
static MDTM_RE: Lazy<Regex> = lazy_regex!(r"\b(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\b");

// This regex extracts file size from SIZE command response.
static SIZE_RE: Lazy<Regex> = lazy_regex!(r"\s+(\d+)\s*$");

/// Stream to interface with the FTP server. This interface is only for the command stream.
#[derive(Debug)]
pub struct FtpStream {
    reader: BufReader<DataStream>,
    mode: Mode,
    nat_workaround: bool,
    welcome_msg: Option<String>,
    #[cfg(feature = "secure")]
    tls_ctx: Option<TlsConnector>,
    #[cfg(feature = "secure")]
    domain: Option<String>,
}

impl FtpStream {
    /// Creates an FTP Stream.
    #[cfg(not(feature = "secure"))]
    pub fn connect<A: ToSocketAddrs>(addr: A) -> FtpResult<Self> {
        debug!("Connecting to server");
        TcpStream::connect(addr)
            .map_err(FtpError::ConnectionError)
            .and_then(|stream| {
                debug!("Established connection with server");
                let mut ftp_stream = FtpStream {
                    reader: BufReader::new(DataStream::Tcp(stream)),
                    mode: Mode::Passive,
                    nat_workaround: false,
                    welcome_msg: None,
                };
                debug!("Reading server response...");
                match ftp_stream.read_response(Status::Ready) {
                    Ok(response) => {
                        debug!("Server READY; response: {}", response.body);
                        ftp_stream.welcome_msg = Some(response.body);
                        Ok(ftp_stream)
                    }
                    Err(err) => Err(err),
                }
            })
    }

    /// Creates an FTP Stream.
    #[cfg(feature = "secure")]
    pub fn connect<A: ToSocketAddrs>(addr: A) -> FtpResult<Self> {
        debug!("Connecting to server");
        TcpStream::connect(addr)
            .map_err(FtpError::ConnectionError)
            .and_then(|stream| {
                debug!("Established connection with server");
                let mut ftp_stream = FtpStream {
                    reader: BufReader::new(DataStream::Tcp(stream)),
                    mode: Mode::Passive,
                    nat_workaround: false,
                    welcome_msg: None,
                    tls_ctx: None,
                    domain: None,
                };
                debug!("Reading server response...");
                match ftp_stream.read_response(Status::Ready) {
                    Ok(response) => {
                        debug!("Server READY; response: {}", response.body);
                        ftp_stream.welcome_msg = Some(response.body);
                        Ok(ftp_stream)
                    }
                    Err(err) => Err(err),
                }
            })
    }

    /// Enable active mode for data channel
    pub fn active_mode(mut self) -> Self {
        self.mode = Mode::Active;
        self
    }

    /// Set the data channel transfer mode
    pub fn set_mode(&mut self, mode: Mode) {
        debug!("Changed mode to {:?}", mode);
        self.mode = mode;
    }

    /// Set NAT workaround for passive mode
    pub fn set_nat_workaround(&mut self, nat_workaround: bool) {
        self.nat_workaround = nat_workaround;
    }

    /// Switch to explicit secure mode if possible (FTPS), using a provided SSL configuration.
    /// This method does nothing if the connect is already secured.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use suppaftp::FtpStream;
    /// use suppaftp::native_tls::{TlsConnector, TlsStream};
    /// use std::path::Path;
    ///
    /// // Create a TlsConnector
    /// // NOTE: For custom options see <https://docs.rs/native-tls/0.2.6/native_tls/struct.TlsConnectorBuilder.html>
    /// let mut ctx = TlsConnector::new().unwrap();
    /// let mut ftp_stream = FtpStream::connect("127.0.0.1:21").unwrap();
    /// let mut ftp_stream = ftp_stream.into_secure(ctx, "localhost").unwrap();
    /// ```
    #[cfg(feature = "secure")]
    pub fn into_secure(mut self, tls_connector: TlsConnector, domain: &str) -> FtpResult<Self> {
        // Ask the server to start securing data.
        debug!("Initializing TLS auth");
        self.perform(Command::Auth)?;
        self.read_response(Status::AuthOk)?;
        debug!("TLS OK; initializing ssl stream");
        let stream = tls_connector
            .connect(domain, self.reader.into_inner().into_tcp_stream())
            .map_err(|e| FtpError::SecureError(format!("{}", e)))?;
        debug!("TLS Steam OK");
        let mut secured_ftp_tream = FtpStream {
            reader: BufReader::new(DataStream::Ssl(stream.into())),
            mode: self.mode,
            nat_workaround: self.nat_workaround,
            tls_ctx: Some(tls_connector),
            domain: Some(String::from(domain)),
            welcome_msg: self.welcome_msg,
        };
        // Set protection buffer size
        secured_ftp_tream.perform(Command::Pbsz(0))?;
        secured_ftp_tream.read_response(Status::CommandOk)?;
        // Change the level of data protectio to Private
        secured_ftp_tream.perform(Command::Prot(ProtectionLevel::Private))?;
        secured_ftp_tream.read_response(Status::CommandOk)?;
        Ok(secured_ftp_tream)
    }

    /// Connect to remote ftps server using IMPLICIT secure connection.
    ///
    /// > Warning: mind that implicit ftps should be considered deprecated, if you can use explicit mode with `into_secure()`
    ///
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use suppaftp::FtpStream;
    /// use suppaftp::native_tls::{TlsConnector, TlsStream};
    /// use std::path::Path;
    ///
    /// // Create a TlsConnector
    /// // NOTE: For custom options see <https://docs.rs/native-tls/0.2.6/native_tls/struct.TlsConnectorBuilder.html>
    /// let mut ctx = TlsConnector::new().unwrap();
    /// let mut ftp_stream = FtpStream::connect_secure_implicit("127.0.0.1:990", ctx, "localhost").unwrap();
    /// ```
    #[cfg(all(feature = "secure", feature = "deprecated"))]
    pub fn connect_secure_implicit<A: ToSocketAddrs>(
        addr: A,
        tls_connector: TlsConnector,
        domain: &str,
    ) -> FtpResult<Self> {
        debug!("Connecting to server (secure)");
        let stream = TcpStream::connect(addr)
            .map_err(FtpError::ConnectionError)
            .map(|stream| {
                debug!("Established connection with server");
                FtpStream {
                    reader: BufReader::new(DataStream::Tcp(stream)),
                    mode: Mode::Passive,
                    welcome_msg: None,
                    tls_ctx: None,
                    domain: None,
                }
            })?;
        debug!("Established connection with server");
        debug!("TLS OK; initializing ssl stream");
        let stream = tls_connector
            .connect(domain, stream.reader.into_inner().into_tcp_stream())
            .map_err(|e| FtpError::SecureError(format!("{}", e)))?;
        debug!("TLS Steam OK");
        let mut stream = FtpStream {
            reader: BufReader::new(DataStream::Ssl(stream.into())),
            mode: Mode::Passive,
            tls_ctx: Some(tls_connector),
            domain: Some(String::from(domain)),
            welcome_msg: None,
        };
        debug!("Reading server response...");
        match stream.read_response(Status::Ready) {
            Ok(response) => {
                debug!("Server READY; response: {}", response.body);
                stream.welcome_msg = Some(response.body);
            }
            Err(err) => return Err(err),
        }

        Ok(stream)
    }

    /// Returns welcome message retrieved from server (if available)
    pub fn get_welcome_msg(&self) -> Option<&str> {
        self.welcome_msg.as_deref()
    }

    /// Returns a reference to the underlying TcpStream.
    ///
    /// Example:
    /// ```no_run
    /// use suppaftp::FtpStream;
    /// use std::net::TcpStream;
    /// use std::time::Duration;
    ///
    /// let stream = FtpStream::connect("127.0.0.1:21")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.get_ref().set_read_timeout(Some(Duration::from_secs(10)))
    ///                 .expect("set_read_timeout call failed");
    /// ```
    pub fn get_ref(&self) -> &TcpStream {
        self.reader.get_ref().get_ref()
    }

    /// Log in to the FTP server.
    pub fn login<S: AsRef<str>>(&mut self, user: S, password: S) -> FtpResult<()> {
        debug!("Signin in with user '{}'", user.as_ref());
        self.perform(Command::User(user.as_ref().to_string()))?;
        self.read_response_in(&[Status::LoggedIn, Status::NeedPassword])
            .and_then(|Response { status, body: _ }| {
                if status == Status::NeedPassword {
                    debug!("Password is required");
                    self.perform(Command::Pass(password.as_ref().to_string()))?;
                    self.read_response(Status::LoggedIn)?;
                }
                debug!("Login OK");
                Ok(())
            })
    }

    /// Perform clear command channel (CCC).
    /// Once the command is performed, the command channel will be encrypted no more.
    /// The data stream will still be secure.
    #[cfg(feature = "secure")]
    pub fn clear_command_channel(mut self) -> FtpResult<Self> {
        // Ask the server to stop securing data
        debug!("performing clear command channel");
        self.perform(Command::ClearCommandChannel)?;
        self.read_response(Status::CommandOk)?;
        trace!("CCC OK");
        self.reader = BufReader::new(DataStream::Tcp(self.reader.into_inner().into_tcp_stream()));
        Ok(self)
    }

    /// Change the current directory to the path specified.
    pub fn cwd<S: AsRef<str>>(&mut self, path: S) -> FtpResult<()> {
        debug!("Changing working directory to {}", path.as_ref());
        self.perform(Command::Cwd(path.as_ref().to_string()))?;
        self.read_response(Status::RequestedFileActionOk)
            .map(|_| ())
    }

    /// Move the current directory to the parent directory.
    pub fn cdup(&mut self) -> FtpResult<()> {
        debug!("Going to parent directory");
        self.perform(Command::Cdup)?;
        self.read_response_in(&[Status::CommandOk, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Gets the current directory
    pub fn pwd(&mut self) -> FtpResult<String> {
        debug!("Getting working directory");
        self.perform(Command::Pwd)?;
        self.read_response(Status::PathCreated)
            .and_then(
                |Response { status, body }| match (body.find('"'), body.rfind('"')) {
                    (Some(begin), Some(end)) if begin < end => Ok(body[begin + 1..end].to_string()),
                    _ => Err(FtpError::UnexpectedResponse(Response::new(status, body))),
                },
            )
    }

    /// This does nothing. This is usually just used to keep the connection open.
    pub fn noop(&mut self) -> FtpResult<()> {
        debug!("Pinging server");
        self.perform(Command::Noop)?;
        self.read_response(Status::CommandOk).map(|_| ())
    }

    /// This creates a new directory on the server.
    pub fn mkdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        debug!("Creating directory at {}", pathname.as_ref());
        self.perform(Command::Mkd(pathname.as_ref().to_string()))?;
        self.read_response(Status::PathCreated).map(|_| ())
    }

    /// Sets the type of file to be transferred. That is the implementation
    /// of `TYPE` command.
    pub fn transfer_type(&mut self, file_type: FileType) -> FtpResult<()> {
        debug!("Setting transfer type {}", file_type.to_string());
        self.perform(Command::Type(file_type))?;
        self.read_response(Status::CommandOk).map(|_| ())
    }

    /// Quits the current FTP session.
    pub fn quit(&mut self) -> FtpResult<()> {
        debug!("Quitting stream");
        self.perform(Command::Quit)?;
        self.read_response(Status::Closing).map(|_| ())
    }

    /// Renames the file from_name to to_name
    pub fn rename<S: AsRef<str>>(&mut self, from_name: S, to_name: S) -> FtpResult<()> {
        debug!(
            "Renaming '{}' to '{}'",
            from_name.as_ref(),
            to_name.as_ref()
        );
        self.perform(Command::RenameFrom(from_name.as_ref().to_string()))?;
        self.read_response(Status::RequestFilePending)
            .and_then(|_| {
                self.perform(Command::RenameTo(to_name.as_ref().to_string()))?;
                self.read_response(Status::RequestedFileActionOk)
                    .map(|_| ())
            })
    }

    /// The implementation of `RETR` command where `filename` is the name of the file
    /// to download from FTP and `reader` is the function which operates with the
    /// data stream opened.
    ///
    /// ```
    /// # use suppaftp::{FtpStream, FtpError};
    /// # use std::io::Cursor;
    /// # let mut conn = FtpStream::connect("127.0.0.1:10021").unwrap();
    /// # conn.login("test", "test").and_then(|_| {
    /// #     let mut reader = Cursor::new("hello, world!".as_bytes());
    /// #     conn.put_file("retr.txt", &mut reader)
    /// # }).unwrap();
    /// assert!(conn.retr("retr.txt", |stream| {
    ///     let mut buf = Vec::new();
    ///     stream.read_to_end(&mut buf).map(|_|
    ///         assert_eq!(buf, "hello, world!".as_bytes())
    ///     ).map_err(|e| FtpError::ConnectionError(e))
    /// }).is_ok());
    /// # assert!(conn.rm("retr.txt").is_ok());
    /// ```
    pub fn retr<F, T>(&mut self, file_name: &str, mut reader: F) -> FtpResult<T>
    where
        F: FnMut(&mut dyn Read) -> FtpResult<T>,
    {
        match self.retr_as_stream(file_name) {
            Ok(mut stream) => {
                let result = reader(&mut stream)?;
                self.finalize_retr_stream(stream).map(|_| result)
            }
            Err(err) => Err(err),
        }
    }

    /// Simple way to retr a file from the server. This stores the file in a buffer in memory.
    ///
    /// ```
    /// # use suppaftp::{FtpStream, FtpError};
    /// # use std::io::Cursor;
    /// # let mut conn = FtpStream::connect("127.0.0.1:10021").unwrap();
    /// # conn.login("test", "test").and_then(|_| {
    /// #     let mut reader = Cursor::new("hello, world!".as_bytes());
    /// #     conn.put_file("simple_retr.txt", &mut reader)
    /// # }).unwrap();
    /// let cursor = conn.retr_as_buffer("simple_retr.txt").unwrap();
    /// // do something with bytes
    /// assert_eq!(cursor.into_inner(), "hello, world!".as_bytes());
    /// # assert!(conn.rm("simple_retr.txt").is_ok());
    /// ```
    pub fn retr_as_buffer(&mut self, file_name: &str) -> FtpResult<Cursor<Vec<u8>>> {
        self.retr(file_name, |reader| {
            let mut buffer = Vec::new();
            reader
                .read_to_end(&mut buffer)
                .map(|_| buffer)
                .map_err(FtpError::ConnectionError)
        })
        .map(Cursor::new)
    }

    /// Retrieves the file name specified from the server as a readable stream.
    /// This method is a more complicated way to retrieve a file.
    /// The reader returned should be dropped.
    /// Also you will have to read the response to make sure it has the correct value.
    /// Once file has been read, call `finalize_retr_stream()`
    pub fn retr_as_stream<S: AsRef<str>>(&mut self, file_name: S) -> FtpResult<DataStream> {
        debug!("Retrieving '{}'", file_name.as_ref());
        let data_stream = self.data_command(Command::Retr(file_name.as_ref().to_string()))?;
        self.read_response_in(&[Status::AboutToSend, Status::AlreadyOpen])?;
        Ok(data_stream)
    }

    /// Finalize retr stream; must be called once the requested file, got previously with `retr_as_stream()` has been read
    pub fn finalize_retr_stream(&mut self, stream: impl Read) -> FtpResult<()> {
        debug!("Finalizing retr stream");
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(stream);
        trace!("dropped stream");
        // Then read response
        self.read_response_in(&[Status::ClosingDataConnection, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Removes the remote pathname from the server.
    pub fn rmdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        debug!("Removing directory {}", pathname.as_ref());
        self.perform(Command::Rmd(pathname.as_ref().to_string()))?;
        self.read_response(Status::RequestedFileActionOk)
            .map(|_| ())
    }

    /// Remove the remote file from the server.
    pub fn rm<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<()> {
        debug!("Removing file {}", filename.as_ref());
        self.perform(Command::Dele(filename.as_ref().to_string()))?;
        self.read_response(Status::RequestedFileActionOk)
            .map(|_| ())
    }

    /// This stores a file on the server.
    /// r argument must be any struct which implemenents the Read trait.
    /// Returns amount of written bytes
    pub fn put_file<S: AsRef<str>, R: Read>(&mut self, filename: S, r: &mut R) -> FtpResult<u64> {
        // Get stream
        let mut data_stream = self.put_with_stream(filename.as_ref())?;
        let bytes = copy(r, &mut data_stream).map_err(FtpError::ConnectionError)?;
        self.finalize_put_stream(data_stream)?;
        Ok(bytes)
    }

    /// Send PUT command and returns a BufWriter, which references the file created on the server
    /// The returned stream must be then correctly manipulated to write the content of the source file to the remote destination
    /// The stream must be then correctly dropped.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub fn put_with_stream<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<DataStream> {
        debug!("Put file {}", filename.as_ref());
        let stream = self.data_command(Command::Store(filename.as_ref().to_string()))?;
        self.read_response_in(&[Status::AlreadyOpen, Status::AboutToSend])?;
        Ok(stream)
    }

    /// Finalize put when using stream
    /// This method must be called once the file has been written and
    /// `put_with_stream` has been used to write the file
    pub fn finalize_put_stream(&mut self, stream: impl Write) -> FtpResult<()> {
        debug!("Finalizing put stream");
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(stream);
        trace!("Stream dropped");
        // Read response
        self.read_response_in(&[Status::ClosingDataConnection, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Open specified file for appending data. Returns the stream to append data to specified file.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub fn append_with_stream<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<DataStream> {
        debug!("Appending to file {}", filename.as_ref());
        let stream = self.data_command(Command::Appe(filename.as_ref().to_string()))?;
        self.read_response_in(&[Status::AlreadyOpen, Status::AboutToSend])?;
        Ok(stream)
    }

    /// Append data from reader to file at `filename`
    pub fn append_file<R: Read>(&mut self, filename: &str, r: &mut R) -> FtpResult<u64> {
        // Get stream
        let mut data_stream = self.append_with_stream(filename)?;
        let bytes = copy(r, &mut data_stream).map_err(FtpError::ConnectionError)?;
        self.finalize_put_stream(Box::new(data_stream))?;
        Ok(bytes)
    }

    /// abort the previous FTP service command
    pub fn abort(&mut self, data_stream: impl Read) -> FtpResult<()> {
        debug!("Aborting active file transfer");
        self.perform(Command::Abor)?;
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(data_stream);
        trace!("dropped stream");
        self.read_response_in(&[Status::ClosingDataConnection, Status::TransferAborted])?;
        self.read_response(Status::ClosingDataConnection)?;
        debug!("Transfer aborted");
        Ok(())
    }

    /// Tell the server to resume the transfer from a certain offset. The offset indicates the amount of bytes to skip
    /// from the beginning of the file.
    /// the REST command does not actually initiate the transfer.
    /// After issuing a REST command, the client must send the appropriate FTP command to transfer the file
    ///
    /// It is possible to cancel the REST command, sending a REST command with offset 0
    pub fn resume_transfer(&mut self, offset: usize) -> FtpResult<()> {
        debug!("Requesting to resume transfer at offset {}", offset);
        self.perform(Command::Rest(offset))?;
        self.read_response(Status::RequestFilePending)?;
        debug!("Resume transfer accepted");
        Ok(())
    }

    /// Execute `LIST` command which returns the detailed file listing in human readable format.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    ///
    /// ### Parse result
    ///
    /// You can parse the output of this command with
    ///
    /// ```rust
    ///
    /// use std::str::FromStr;
    /// use suppaftp::list::File;
    ///
    /// let file: File = File::from_str("-rw-rw-r-- 1 0  1  8192 Nov 5 2018 omar.txt")
    ///     .ok()
    ///     .unwrap();
    /// ```
    pub fn list(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        debug!(
            "Reading {} directory content",
            pathname.unwrap_or("working")
        );

        self.stream_lines(
            Command::List(pathname.map(|x| x.to_string())),
            Status::AboutToSend,
        )
    }

    /// Execute `NLST` command which returns the list of file names only.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub fn nlst(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        debug!(
            "Getting file names for {} directory",
            pathname.unwrap_or("working")
        );

        self.stream_lines(
            Command::Nlst(pathname.map(|x| x.to_string())),
            Status::AboutToSend,
        )
    }

    /// Retrieves the modification time of the file at `pathname` if it exists.
    pub fn mdtm<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<DateTime<Utc>> {
        debug!("Getting modification time for {}", pathname.as_ref());
        self.perform(Command::Mdtm(pathname.as_ref().to_string()))?;
        let response: Response = self.read_response(Status::File)?;

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

    /// Retrieves the size of the file in bytes at `pathname` if it exists.
    pub fn size<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<usize> {
        debug!("Getting file size for {}", pathname.as_ref());
        self.perform(Command::Size(pathname.as_ref().to_string()))?;
        let response: Response = self.read_response(Status::File)?;

        match SIZE_RE.captures(&response.body) {
            Some(caps) => Ok(caps[1].parse().unwrap()),
            None => Err(FtpError::BadResponse),
        }
    }

    // -- private

    /// Retrieve stream "message"
    fn get_lines_from_stream(data_stream: &mut BufReader<DataStream>) -> FtpResult<Vec<String>> {
        let mut lines: Vec<String> = Vec::new();

        loop {
            let mut line = String::new();
            match data_stream.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.ends_with('\n') {
                        line.pop();
                        if line.ends_with('\r') {
                            line.pop();
                        }
                    }
                    if line.is_empty() {
                        continue;
                    }
                    lines.push(line);
                }
                Err(_) => return Err(FtpError::BadResponse),
            }
        }
        trace!("Lines from stream {:?}", lines);

        Ok(lines)
    }

    /// Read response from stream
    fn read_response(&mut self, expected_code: Status) -> FtpResult<Response> {
        self.read_response_in(&[expected_code])
    }

    /// Retrieve single line response
    fn read_response_in(&mut self, expected_code: &[Status]) -> FtpResult<Response> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .map_err(FtpError::ConnectionError)?;

        trace!("CC IN: {}", line.trim_end());

        if line.len() < 5 {
            return Err(FtpError::BadResponse);
        }

        let code: u32 = line[0..3].parse().map_err(|_| FtpError::BadResponse)?;
        let code = Status::from(code);

        // multiple line reply
        // loop while the line does not begin with the code and a space
        let expected = format!("{} ", &line[0..3]);
        while line.len() < 5 || line[0..4] != expected {
            line.clear();
            if let Err(e) = self.reader.read_line(&mut line) {
                return Err(FtpError::ConnectionError(e));
            }

            trace!("CC IN: {}", line.trim_end());
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

    /// Write data to stream with command to perform
    fn perform(&mut self, command: Command) -> FtpResult<()> {
        let command = command.to_string();
        trace!("CC OUT: {}", command.trim_end_matches("\r\n"));

        let stream = self.reader.get_mut();
        stream
            .write_all(command.as_bytes())
            .map_err(FtpError::ConnectionError)
    }

    /// Execute command which send data back in a separate stream
    fn data_command(&mut self, cmd: Command) -> FtpResult<DataStream> {
        let stream = match self.mode {
            Mode::Passive => self
                .pasv()
                .and_then(|addr| self.perform(cmd).map(|_| addr))
                .and_then(|addr| TcpStream::connect(addr).map_err(FtpError::ConnectionError))?,

            Mode::Active => self
                .active()
                .and_then(|listener| self.perform(cmd).map(|_| listener))
                .and_then(|listener| listener.accept().map_err(FtpError::ConnectionError))
                .map(|(stream, _)| stream)?,
        };

        #[cfg(not(feature = "secure"))]
        {
            Ok(DataStream::Tcp(stream))
        }

        #[cfg(feature = "secure")]
        match self.tls_ctx {
            Some(ref tls_ctx) => tls_ctx
                .connect(self.domain.as_ref().unwrap(), stream)
                .map(TlsStreamWrapper::from)
                .map(DataStream::Ssl)
                .map_err(|e| FtpError::SecureError(format!("{}", e))),
            None => Ok(DataStream::Tcp(stream)),
        }
    }

    /// Create a new tcp listener and send a PORT command for it
    fn active(&mut self) -> FtpResult<TcpListener> {
        debug!("Starting local tcp listener...");
        let conn = TcpListener::bind("0.0.0.0:0").map_err(FtpError::ConnectionError)?;

        let addr = conn.local_addr().map_err(FtpError::ConnectionError)?;
        trace!("Local address is {}", addr);

        let ip = match self.reader.get_mut() {
            DataStream::Tcp(stream) => stream.local_addr().unwrap().ip(),

            #[cfg(feature = "secure")]
            DataStream::Ssl(stream) => stream.mut_ref().get_mut().local_addr().unwrap().ip(),
        };

        let msb = addr.port() / 256;
        let lsb = addr.port() % 256;
        let ip_port = format!("{},{},{}", ip.to_string().replace('.', ","), msb, lsb);
        debug!("Active mode, listening on {}:{}", ip, addr.port());

        debug!("Running PORT command");
        self.perform(Command::Port(ip_port))?;
        self.read_response(Status::CommandOk)?;

        Ok(conn)
    }

    /// Runs the PASV command.
    fn pasv(&mut self) -> FtpResult<SocketAddr> {
        debug!("PASV command");
        self.perform(Command::Pasv)?;
        // PASV response format : 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
        let response: Response = self.read_response(Status::PassiveMode)?;
        let caps = PORT_RE
            .captures(&response.body)
            .ok_or_else(|| FtpError::UnexpectedResponse(response.clone()))?;
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
        let ip = Ipv4Addr::new(oct1, oct2, oct3, oct4);
        let port = (u16::from(msb) << 8) | u16::from(lsb);
        let addr = SocketAddr::new(ip.into(), port);
        trace!("Passive address: {}", addr);
        if self.nat_workaround && ip.is_private() {
            let mut remote = self
                .reader
                .get_ref()
                .get_ref()
                .peer_addr()
                .map_err(FtpError::ConnectionError)?;
            remote.set_port(port);
            trace!("Replacing site local address {} with {}", addr, remote);
            Ok(remote)
        } else {
            Ok(addr)
        }
    }

    /// Execute a command which returns list of strings in a separate stream
    fn stream_lines(&mut self, cmd: Command, open_code: Status) -> FtpResult<Vec<String>> {
        let mut data_stream = BufReader::new(self.data_command(cmd)?);
        self.read_response_in(&[open_code, Status::AlreadyOpen])?;
        let lines = Self::get_lines_from_stream(&mut data_stream);
        self.finalize_retr_stream(data_stream)?;
        lines
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[cfg(feature = "with-containers")]
    use crate::types::FormatControl;

    #[cfg(any(feature = "with-containers", feature = "secure"))]
    use pretty_assertions::assert_eq;
    #[cfg(feature = "with-containers")]
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    use serial_test::serial;
    use std::time::Duration;

    #[test]
    #[cfg(feature = "with-containers")]
    fn connect() {
        crate::log_init();
        let stream: FtpStream = setup_stream();
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "secure")]
    fn should_connect_ssl() {
        crate::log_init();
        let ftp_stream = FtpStream::connect("test.rebex.net:21").unwrap();
        let mut ftp_stream = ftp_stream
            .into_secure(TlsConnector::new().unwrap(), "test.rebex.net")
            .ok()
            .unwrap();
        // Set timeout (to test ref to ssl)
        assert!(ftp_stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))
            .is_ok());
        // Login
        assert!(ftp_stream.login("demo", "password").is_ok());
        // PWD
        assert_eq!(ftp_stream.pwd().ok().unwrap().as_str(), "/");
        // Quit
        assert!(ftp_stream.quit().is_ok());
    }

    #[test]
    #[serial]
    #[cfg(feature = "secure")]
    fn should_work_after_clear_command_channel() {
        crate::log_init();
        let mut ftp_stream = FtpStream::connect("test.rebex.net:21")
            .unwrap()
            .into_secure(TlsConnector::new().unwrap(), "test.rebex.net")
            .ok()
            .unwrap()
            .clear_command_channel()
            .ok()
            .unwrap();
        // Login
        assert!(ftp_stream.login("demo", "password").is_ok());
        // CCC
        assert!(ftp_stream.pwd().is_ok());
        assert!(ftp_stream.list(None).is_ok());
        assert!(ftp_stream.quit().is_ok());
    }

    #[test]
    #[serial]
    #[cfg(all(feature = "secure", feature = "deprecated"))]
    fn should_connect_ssl_implicit() {
        crate::log_init();
        let mut ftp_stream = FtpStream::connect_secure_implicit(
            "test.rebex.net:990",
            TlsConnector::new().unwrap(),
            "test.rebex.net",
        )
        .ok()
        .unwrap();
        // Set timeout (to test ref to ssl)
        assert!(ftp_stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))
            .is_ok());
        // Login
        assert!(ftp_stream.login("demo", "password").is_ok());
        // PWD
        assert_eq!(ftp_stream.pwd().ok().unwrap().as_str(), "/");
        // Quit
        assert!(ftp_stream.quit().is_ok());
    }

    #[test]
    #[serial]
    fn should_change_mode() {
        crate::log_init();
        let mut ftp_stream = FtpStream::connect("test.rebex.net:21")
            .map(|x| x.active_mode())
            .unwrap();
        assert_eq!(ftp_stream.mode, Mode::Active);
        ftp_stream.set_mode(Mode::Passive);
        assert_eq!(ftp_stream.mode, Mode::Passive);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn welcome_message() {
        crate::log_init();
        let stream: FtpStream = setup_stream();
        assert_eq!(
            stream.get_welcome_msg().unwrap(),
            "220 You will be disconnected after 15 minutes of inactivity."
        );
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn get_ref() {
        crate::log_init();
        let stream: FtpStream = setup_stream();
        assert!(stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))
            .is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn change_wrkdir() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        let wrkdir: String = stream.pwd().ok().unwrap();
        assert!(stream.cwd("/").is_ok());
        assert_eq!(stream.pwd().ok().unwrap().as_str(), "/");
        assert!(stream.cwd(wrkdir.as_str()).is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn cd_up() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        let wrkdir: String = stream.pwd().ok().unwrap();
        assert!(stream.cdup().is_ok());
        assert_eq!(stream.pwd().ok().unwrap().as_str(), "/");
        assert!(stream.cwd(wrkdir.as_str()).is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn noop() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        assert!(stream.noop().is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn make_and_remove_dir() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        // Make directory
        assert!(stream.mkdir("omar").is_ok());
        // It shouldn't allow me to re-create the directory; should return error code 550
        match stream.mkdir("omar").err().unwrap() {
            FtpError::UnexpectedResponse(Response { status, body: _ }) => {
                assert_eq!(status, Status::FileUnavailable)
            }
            err => panic!("Expected UnexpectedResponse, got {}", err),
        }
        // Remove directory
        assert!(stream.rmdir("omar").is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn set_transfer_type() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        assert!(stream.transfer_type(FileType::Binary).is_ok());
        assert!(stream
            .transfer_type(FileType::Ascii(FormatControl::Default))
            .is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn transfer_file() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        // Set transfer type to Binary
        assert!(stream.transfer_type(FileType::Binary).is_ok());
        // Write file
        let file_data = "test data\n";
        let mut reader = Cursor::new(file_data.as_bytes());
        assert!(stream.put_file("test.txt", &mut reader).is_ok());
        // Read file
        assert_eq!(
            stream
                .retr_as_buffer("test.txt")
                .map(|bytes| bytes.into_inner())
                .ok()
                .unwrap(),
            file_data.as_bytes()
        );
        // Get size
        assert_eq!(stream.size("test.txt").ok().unwrap(), 10);
        // Size of non-existing file
        assert!(stream.size("omarone.txt").is_err());
        // List directory
        assert_eq!(stream.list(None).ok().unwrap().len(), 1);
        // list names
        assert_eq!(stream.nlst(None).ok().unwrap().as_slice(), &["test.txt"]);
        // modification time
        assert!(stream.mdtm("test.txt").is_ok());
        // Remove file
        assert!(stream.rm("test.txt").is_ok());
        assert!(stream.mdtm("test.txt").is_err());
        // Write file, rename and get
        let file_data = "test data\n";
        let mut reader = Cursor::new(file_data.as_bytes());
        assert!(stream.put_file("test.txt", &mut reader).is_ok());
        // Append file
        let mut reader = Cursor::new(file_data.as_bytes());
        assert!(stream.append_file("test.txt", &mut reader).is_ok());
        // Read file
        let mut reader = stream.retr_as_stream("test.txt").ok().unwrap();
        let mut buffer = Vec::new();
        assert!(reader.read_to_end(&mut buffer).is_ok());
        // Finalize
        assert!(stream.finalize_retr_stream(Box::new(reader)).is_ok());
        // Verify file matches
        assert_eq!(buffer.as_slice(), "test data\ntest data\n".as_bytes());
        // Rename
        assert!(stream.rename("test.txt", "toast.txt").is_ok());
        assert!(stream.rm("toast.txt").is_ok());
        // List directory again
        assert_eq!(stream.list(None).ok().unwrap().len(), 0);
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    #[serial]
    fn should_abort_transfer() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        // Set transfer type to Binary
        assert!(stream.transfer_type(FileType::Binary).is_ok());
        // put as stream
        let mut transfer_stream = stream.put_with_stream("test.bin").ok().unwrap();
        assert_eq!(
            transfer_stream
                .write(&[0x00, 0x01, 0x02, 0x03, 0x04])
                .ok()
                .unwrap(),
            5
        );
        // Abort
        assert!(stream.abort(transfer_stream).is_ok());
        // Check whether other commands still work after transfer
        assert!(stream.rm("test.bin").is_ok());
        // Check whether data channel still works
        assert!(stream.list(None).is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[serial]
    #[cfg(feature = "with-containers")]
    fn should_resume_transfer() {
        crate::log_init();
        let mut stream: FtpStream = setup_stream();
        // Set transfer type to Binary
        assert!(stream.transfer_type(FileType::Binary).is_ok());
        // get dir
        let wrkdir = stream.pwd().ok().unwrap();
        // put as stream
        let mut transfer_stream = stream.put_with_stream("test.bin").ok().unwrap();
        assert_eq!(
            transfer_stream
                .write(&[0x00, 0x01, 0x02, 0x03, 0x04])
                .ok()
                .unwrap(),
            5
        );
        // Drop stream on purpose to simulate a failed connection
        drop(stream);
        drop(transfer_stream);
        // Re-connect to server
        let mut stream = FtpStream::connect("127.0.0.1:10021").unwrap();
        assert!(stream.login("test", "test").is_ok());
        // Go back to previous dir
        assert!(stream.cwd(wrkdir).is_ok());
        // Set transfer type to Binary
        assert!(stream.transfer_type(FileType::Binary).is_ok());
        // Resume transfer
        assert!(stream.resume_transfer(5).is_ok());
        // Reopen stream
        let mut transfer_stream = stream.put_with_stream("test.bin").ok().unwrap();
        assert_eq!(
            transfer_stream
                .write(&[0x05, 0x06, 0x07, 0x08, 0x09, 0x0a])
                .ok()
                .unwrap(),
            6
        );
        // Finalize
        assert!(stream.finalize_put_stream(transfer_stream).is_ok());
        // Get size
        assert_eq!(stream.size("test.bin").ok().unwrap(), 11);
        // Remove file
        assert!(stream.rm("test.bin").is_ok());
        // Drop stream
        finalize_stream(stream);
    }

    // -- test utils

    #[cfg(feature = "with-containers")]
    fn setup_stream() -> FtpStream {
        let mut ftp_stream = FtpStream::connect("127.0.0.1:10021").unwrap();
        assert!(ftp_stream.login("test", "test").is_ok());
        // Create wrkdir
        let tempdir: String = generate_tempdir();
        assert!(ftp_stream.mkdir(tempdir.as_str()).is_ok());
        // Change directory
        assert!(ftp_stream.cwd(tempdir.as_str()).is_ok());
        ftp_stream
    }

    #[cfg(feature = "with-containers")]
    fn finalize_stream(mut stream: FtpStream) {
        // Get working directory
        let wrkdir: String = stream.pwd().ok().unwrap();
        // Remove directory
        assert!(stream.rmdir(wrkdir.as_str()).is_ok());
        assert!(stream.quit().is_ok());
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
