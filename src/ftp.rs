//! # FTP
//!
//! Main module of the library. This module exposes the real implementation of the ftp client

use super::data_stream::DataStream;
use super::status;
use super::types::{FileType, FtpError, Response, Result};

use chrono::offset::TimeZone;
use chrono::{DateTime, Utc};
#[cfg(feature = "secure")]
use native_tls::TlsConnector;
use regex::Regex;
use std::borrow::Cow;
use std::io::{copy, BufRead, BufReader, BufWriter, Cursor, Read, Write};
use std::net::ToSocketAddrs;
use std::net::{SocketAddr, TcpStream};
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
#[derive(Debug)]
pub struct FtpStream {
    reader: BufReader<DataStream>,
    welcome_msg: Option<String>,
    #[cfg(feature = "secure")]
    tls_ctx: Option<TlsConnector>,
    #[cfg(feature = "secure")]
    domain: Option<String>,
}

impl FtpStream {
    /// ### connect
    ///
    /// Creates an FTP Stream.
    #[cfg(not(feature = "secure"))]
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<FtpStream> {
        TcpStream::connect(addr)
            .map_err(FtpError::ConnectionError)
            .and_then(|stream| {
                let mut ftp_stream = FtpStream {
                    reader: BufReader::new(DataStream::Tcp(stream)),
                    welcome_msg: None,
                };
                match ftp_stream.read_response(status::READY) {
                    Ok(response) => {
                        ftp_stream.welcome_msg = Some(response.body);
                        Ok(ftp_stream)
                    }
                    Err(err) => Err(err),
                }
            })
    }

    /// ### connect
    ///
    /// Creates an FTP Stream.
    #[cfg(feature = "secure")]
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<FtpStream> {
        TcpStream::connect(addr)
            .map_err(FtpError::ConnectionError)
            .and_then(|stream| {
                let mut ftp_stream = FtpStream {
                    reader: BufReader::new(DataStream::Tcp(stream)),
                    welcome_msg: None,
                    tls_ctx: None,
                    domain: None,
                };
                match ftp_stream.read_response(status::READY) {
                    Ok(response) => {
                        ftp_stream.welcome_msg = Some(response.body);
                        Ok(ftp_stream)
                    }
                    Err(err) => Err(err),
                }
            })
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
    /// use ftp4::FtpStream;
    /// use ftp4::native_tls::{TlsConnector, TlsStream};
    /// use std::path::Path;
    ///
    /// // Create a TlsConnector
    /// // NOTE: For custom options see <https://docs.rs/native-tls/0.2.6/native_tls/struct.TlsConnectorBuilder.html>
    /// let mut ctx = TlsConnector::new().unwrap();
    /// let mut ftp_stream = FtpStream::connect("127.0.0.1:21").unwrap();
    /// let mut ftp_stream = ftp_stream.into_secure(ctx, "localhost").unwrap();
    /// ```
    #[cfg(feature = "secure")]
    pub fn into_secure(mut self, tls_connector: TlsConnector, domain: &str) -> Result<FtpStream> {
        // Ask the server to start securing data.
        self.write_str("AUTH TLS\r\n")?;
        self.read_response(status::AUTH_OK)?;
        let stream = tls_connector
            .connect(domain, self.reader.into_inner().into_tcp_stream())
            .map_err(|e| FtpError::SecureError(format!("{}", e)))?;
        let mut secured_ftp_tream = FtpStream {
            reader: BufReader::new(DataStream::Ssl(stream)),
            tls_ctx: Some(tls_connector),
            domain: Some(String::from(domain)),
            welcome_msg: self.welcome_msg,
        };
        // Set protection buffer size
        secured_ftp_tream.write_str("PBSZ 0\r\n")?;
        secured_ftp_tream.read_response(status::COMMAND_OK)?;
        // Change the level of data protectio to Private
        secured_ftp_tream.write_str("PROT P\r\n")?;
        secured_ftp_tream.read_response(status::COMMAND_OK)?;
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
    /// use ftp4::FtpStream;
    /// use std::path::Path;
    ///
    /// use ftp4::native_tls::{TlsConnector, TlsStream};
    ///
    /// // Create an TlsConnector
    /// let mut ctx = TlsConnector::new().unwrap();
    /// let mut ftp_stream = FtpStream::connect("127.0.0.1:21").unwrap();
    /// let mut ftp_stream = ftp_stream.into_secure(ctx, "localhost").unwrap();
    /// // Do all secret things
    /// // Switch back to the insecure mode
    /// let mut ftp_stream = ftp_stream.into_insecure().unwrap();
    /// // Do all public things
    /// let _ = ftp_stream.quit();
    /// ```
    #[cfg(feature = "secure")]
    pub fn into_insecure(mut self) -> Result<FtpStream> {
        // Ask the server to stop securing data
        self.write_str("CCC\r\n")?;
        self.read_response(status::COMMAND_OK)?;
        let plain_ftp_stream = FtpStream {
            reader: BufReader::new(DataStream::Tcp(self.reader.into_inner().into_tcp_stream())),
            tls_ctx: None,
            domain: None,
            welcome_msg: self.welcome_msg,
        };
        Ok(plain_ftp_stream)
    }

    /// ### get_welcome_msg
    ///
    /// Returns welcome message retrieved from server (if available)
    pub fn get_welcome_msg(&self) -> Option<&str> {
        self.welcome_msg.as_deref()
    }

    /// ### data_command
    ///
    /// Execute command which send data back in a separate stream
    #[cfg(not(feature = "secure"))]
    fn data_command(&mut self, cmd: &str) -> Result<DataStream> {
        self.pasv()
            .and_then(|addr| self.write_str(cmd).map(|_| addr))
            .and_then(|addr| TcpStream::connect(addr).map_err(FtpError::ConnectionError))
            .map(DataStream::Tcp)
    }

    /// ### data_command
    ///
    /// Execute command which send data back in a separate stream
    #[cfg(feature = "secure")]
    fn data_command(&mut self, cmd: &str) -> Result<DataStream> {
        self.pasv()
            .and_then(|addr| self.write_str(cmd).map(|_| addr))
            .and_then(|addr| TcpStream::connect(addr).map_err(FtpError::ConnectionError))
            .and_then(|stream| match self.tls_ctx {
                Some(ref tls_ctx) => tls_ctx
                    .connect(self.domain.as_ref().unwrap(), stream)
                    .map(DataStream::Ssl)
                    .map_err(|e| FtpError::SecureError(format!("{}", e))),
                None => Ok(DataStream::Tcp(stream)),
            })
    }

    /// ### get_ref
    ///
    /// Returns a reference to the underlying TcpStream.
    ///
    /// Example:
    /// ```no_run
    /// use ftp4::FtpStream;
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

    /// ### login
    ///
    /// Log in to the FTP server.
    pub fn login(&mut self, user: &str, password: &str) -> Result<()> {
        self.write_str(format!("USER {}\r\n", user))?;
        self.read_response_in(&[status::LOGGED_IN, status::NEED_PASSWORD])
            .and_then(|Response { code, body: _ }| {
                if code == status::NEED_PASSWORD {
                    self.write_str(format!("PASS {}\r\n", password))?;
                    self.read_response(status::LOGGED_IN)?;
                }
                Ok(())
            })
    }

    /// ### cwd
    ///
    /// Change the current directory to the path specified.
    pub fn cwd(&mut self, path: &str) -> Result<()> {
        self.write_str(format!("CWD {}\r\n", path))?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK)
            .map(|_| ())
    }

    /// ### cdup
    ///
    /// Move the current directory to the parent directory.
    pub fn cdup(&mut self) -> Result<()> {
        self.write_str("CDUP\r\n")?;
        self.read_response_in(&[status::COMMAND_OK, status::REQUESTED_FILE_ACTION_OK])
            .map(|_| ())
    }

    /// ### pwd
    ///
    /// Gets the current directory
    pub fn pwd(&mut self) -> Result<String> {
        self.write_str("PWD\r\n")?;
        self.read_response(status::PATH_CREATED)
            .and_then(
                |Response { code, body }| match (body.find('"'), body.rfind('"')) {
                    (Some(begin), Some(end)) if begin < end => Ok(body[begin + 1..end].to_string()),
                    _ => Err(FtpError::InvalidResponse(Response::new(code, body))),
                },
            )
    }

    /// ### noop
    ///
    /// This does nothing. This is usually just used to keep the connection open.
    pub fn noop(&mut self) -> Result<()> {
        self.write_str("NOOP\r\n")?;
        self.read_response(status::COMMAND_OK).map(|_| ())
    }

    /// ### mkdir
    ///
    /// This creates a new directory on the server.
    pub fn mkdir(&mut self, pathname: &str) -> Result<()> {
        self.write_str(format!("MKD {}\r\n", pathname))?;
        self.read_response(status::PATH_CREATED).map(|_| ())
    }

    /// ### pasv
    ///
    /// Runs the PASV command.
    fn pasv(&mut self) -> Result<SocketAddr> {
        self.write_str("PASV\r\n")?;
        // PASV response format : 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
        let response: Response = self.read_response(status::PASSIVE_MODE)?;
        PORT_RE
            .captures(&response.body)
            .ok_or_else(|| FtpError::InvalidResponse(response.clone()))
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

    /// ### transfer_type
    ///
    /// Sets the type of file to be transferred. That is the implementation
    /// of `TYPE` command.
    pub fn transfer_type(&mut self, file_type: FileType) -> Result<()> {
        let type_command = format!("TYPE {}\r\n", file_type.to_string());
        self.write_str(&type_command)?;
        self.read_response(status::COMMAND_OK).map(|_| ())
    }

    /// ### quit
    ///
    /// Quits the current FTP session.
    pub fn quit(&mut self) -> Result<()> {
        self.write_str("QUIT\r\n")?;
        self.read_response(status::CLOSING).map(|_| ())
    }

    /// ### rename
    ///
    /// Renames the file from_name to to_name
    pub fn rename(&mut self, from_name: &str, to_name: &str) -> Result<()> {
        self.write_str(format!("RNFR {}\r\n", from_name))?;
        self.read_response(status::REQUEST_FILE_PENDING)
            .and_then(|_| {
                self.write_str(format!("RNTO {}\r\n", to_name))?;
                self.read_response(status::REQUESTED_FILE_ACTION_OK)
                    .map(|_| ())
            })
    }

    /// ### retr
    ///
    /// The implementation of `RETR` command where `filename` is the name of the file
    /// to download from FTP and `reader` is the function which operates with the
    /// data stream opened.
    ///
    /// ```
    /// # use ftp4::{FtpStream, FtpError};
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
    pub fn retr<F, T>(&mut self, file_name: &str, reader: F) -> Result<T>
    where
        F: Fn(&mut dyn Read) -> Result<T>,
    {
        match self.retr_as_stream(file_name) {
            Ok(mut stream) => {
                let result = reader(&mut stream)?;
                self.finalize_retr_stream(Box::new(stream)).map(|_| result)
            }
            Err(err) => Err(err),
        }
    }

    /// ### retr_as_buffer
    ///
    /// Simple way to retr a file from the server. This stores the file in a buffer in memory.
    ///
    /// ```
    /// # use ftp4::{FtpStream, FtpError};
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
    pub fn retr_as_buffer(&mut self, file_name: &str) -> Result<Cursor<Vec<u8>>> {
        self.retr(file_name, |reader| {
            let mut buffer = Vec::new();
            reader
                .read_to_end(&mut buffer)
                .map(|_| buffer)
                .map_err(FtpError::ConnectionError)
        })
        .map(Cursor::new)
    }

    /// ### retr_as_stream
    ///
    /// Retrieves the file name specified from the server as a readable stream.
    /// This method is a more complicated way to retrieve a file.
    /// The reader returned should be dropped.
    /// Also you will have to read the response to make sure it has the correct value.
    /// Once file has been read, call `finalize_retr_stream()`
    pub fn retr_as_stream(&mut self, file_name: &str) -> Result<BufReader<DataStream>> {
        let retr_command = format!("RETR {}\r\n", file_name);
        let data_stream = BufReader::new(self.data_command(&retr_command)?);
        self.read_response_in(&[status::ABOUT_TO_SEND, status::ALREADY_OPEN])?;
        Ok(data_stream)
    }

    /// ### finalize_retr_stream
    ///
    /// Finalize retr stream; must be called once the requested file, got previously with `retr_as_stream()` has been read
    pub fn finalize_retr_stream(&mut self, reader: Box<dyn Read>) -> Result<()> {
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(reader);
        // Then read response
        match self.read_response_in(&[
            status::CLOSING_DATA_CONNECTION,
            status::REQUESTED_FILE_ACTION_OK,
        ]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// ### rmdir
    ///
    /// Removes the remote pathname from the server.
    pub fn rmdir(&mut self, pathname: &str) -> Result<()> {
        self.write_str(format!("RMD {}\r\n", pathname))?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK)
            .map(|_| ())
    }

    /// ### rm
    ///
    /// Remove the remote file from the server.
    pub fn rm(&mut self, filename: &str) -> Result<()> {
        self.write_str(format!("DELE {}\r\n", filename))?;
        self.read_response(status::REQUESTED_FILE_ACTION_OK)
            .map(|_| ())
    }

    /// ### put_file
    ///
    /// This stores a file on the server.
    /// r argument must be any struct which implemenents the Read trait
    pub fn put_file<R: Read>(&mut self, filename: &str, r: &mut R) -> Result<()> {
        // Get stream
        let mut data_stream = self.put_with_stream(filename)?;
        copy(r, &mut data_stream)
            .map_err(FtpError::ConnectionError)
            .and_then(|_| self.finalize_put_stream(Box::new(data_stream)))
    }

    /// ### put_with_stream
    ///
    /// Send PUT command and returns a BufWriter, which references the file created on the server
    /// The returned stream must be then correctly manipulated to write the content of the source file to the remote destination
    /// The stream must be then correctly dropped.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub fn put_with_stream(&mut self, filename: &str) -> Result<BufWriter<DataStream>> {
        let stor_command = format!("STOR {}\r\n", filename);
        let stream = BufWriter::new(self.data_command(&stor_command)?);
        self.read_response_in(&[status::ALREADY_OPEN, status::ABOUT_TO_SEND])?;
        Ok(stream)
    }

    /// ### finalize_put_stream
    ///
    /// Finalize put when using stream
    /// This method must be called once the file has been written and
    /// `put_with_stream` has been used to write the file
    pub fn finalize_put_stream(&mut self, stream: Box<dyn Write>) -> Result<()> {
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(stream);
        // Read response
        match self.read_response_in(&[
            status::CLOSING_DATA_CONNECTION,
            status::REQUESTED_FILE_ACTION_OK,
        ]) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// ### list_command
    ///
    /// Execute a command which returns list of strings in a separate stream
    fn list_command(
        &mut self,
        cmd: Cow<'static, str>,
        open_code: u32,
        close_code: &[u32],
    ) -> Result<Vec<String>> {
        let data_stream = BufReader::new(self.data_command(&cmd)?);
        self.read_response_in(&[open_code, status::ALREADY_OPEN])?;
        let lines = Self::get_lines_from_stream(data_stream);
        self.read_response_in(close_code)?;
        lines
    }

    /// ### list
    ///
    /// Execute `LIST` command which returns the detailed file listing in human readable format.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub fn list(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("LIST\r\n".into(), |path| {
            format!("LIST {}\r\n", path).into()
        });

        self.list_command(
            command,
            status::ABOUT_TO_SEND,
            &[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ],
        )
    }

    /// ### nlst
    ///
    /// Execute `NLST` command which returns the list of file names only.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub fn nlst(&mut self, pathname: Option<&str>) -> Result<Vec<String>> {
        let command = pathname.map_or("NLST\r\n".into(), |path| {
            format!("NLST {}\r\n", path).into()
        });

        self.list_command(
            command,
            status::ABOUT_TO_SEND,
            &[
                status::CLOSING_DATA_CONNECTION,
                status::REQUESTED_FILE_ACTION_OK,
            ],
        )
    }

    /// ### mdtm
    ///
    /// Retrieves the modification time of the file at `pathname` if it exists.
    pub fn mdtm(&mut self, pathname: &str) -> Result<DateTime<Utc>> {
        self.write_str(format!("MDTM {}\r\n", pathname))?;
        let response: Response = self.read_response(status::FILE)?;

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
    pub fn size(&mut self, pathname: &str) -> Result<usize> {
        self.write_str(format!("SIZE {}\r\n", pathname))?;
        let response: Response = self.read_response(status::FILE)?;

        match SIZE_RE.captures(&response.body) {
            Some(caps) => Ok(caps[1].parse().unwrap()),
            None => Err(FtpError::BadResponse),
        }
    }

    /// ### get_lines_from_stream
    ///
    /// Retrieve stream "message"
    fn get_lines_from_stream(data_stream: BufReader<DataStream>) -> Result<Vec<String>> {
        let mut lines: Vec<String> = Vec::new();

        let mut lines_stream = data_stream.lines();
        loop {
            let line = lines_stream.next();
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
    fn write_str<S: AsRef<str>>(&mut self, command: S) -> Result<()> {
        if cfg!(feature = "debug_print") {
            print!("CMD {}", command.as_ref());
        }

        let stream = self.reader.get_mut();
        stream
            .write_all(command.as_ref().as_bytes())
            .map_err(FtpError::ConnectionError)
    }

    /// ### read_response
    ///
    /// Read response from stream
    pub fn read_response(&mut self, expected_code: u32) -> Result<Response> {
        self.read_response_in(&[expected_code])
    }

    /// ### read_response_in
    ///
    /// Retrieve single line response
    pub fn read_response_in(&mut self, expected_code: &[u32]) -> Result<Response> {
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
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
            if let Err(e) = self.reader.read_line(&mut line) {
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
            Err(FtpError::InvalidResponse(response))
        }
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
    #[cfg(feature = "with-containers")]
    use std::time::Duration;

    #[test]
    #[cfg(feature = "with-containers")]
    fn connect() {
        let stream: FtpStream = setup_stream();
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "secure")]
    fn connect_ssl() {
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
        // Go back to insecure
        let mut ftp_stream = ftp_stream.into_insecure().ok().unwrap();
        // Quit
        assert!(ftp_stream.quit().is_ok());
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn welcome_message() {
        let stream: FtpStream = setup_stream();
        assert_eq!(
            stream.get_welcome_msg().unwrap(),
            "220 You will be disconnected after 15 minutes of inactivity."
        );
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn get_ref() {
        let stream: FtpStream = setup_stream();
        assert!(stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))
            .is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn change_wrkdir() {
        let mut stream: FtpStream = setup_stream();
        let wrkdir: String = stream.pwd().ok().unwrap();
        assert!(stream.cwd("/").is_ok());
        assert_eq!(stream.pwd().ok().unwrap().as_str(), "/");
        assert!(stream.cwd(wrkdir.as_str()).is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn cd_up() {
        let mut stream: FtpStream = setup_stream();
        let wrkdir: String = stream.pwd().ok().unwrap();
        assert!(stream.cdup().is_ok());
        assert_eq!(stream.pwd().ok().unwrap().as_str(), "/");
        assert!(stream.cwd(wrkdir.as_str()).is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn noop() {
        let mut stream: FtpStream = setup_stream();
        assert!(stream.noop().is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn make_and_remove_dir() {
        let mut stream: FtpStream = setup_stream();
        // Make directory
        assert!(stream.mkdir("omar").is_ok());
        // It shouldn't allow me to re-create the directory; should return error code 550
        match stream.mkdir("omar").err().unwrap() {
            FtpError::InvalidResponse(Response { code, body: _ }) => {
                assert_eq!(code, status::FILE_UNAVAILABLE)
            }
            err => panic!("Expected InvalidResponse, got {}", err),
        }
        // Remove directory
        assert!(stream.rmdir("omar").is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn set_transfer_type() {
        let mut stream: FtpStream = setup_stream();
        assert!(stream.transfer_type(FileType::Binary).is_ok());
        assert!(stream
            .transfer_type(FileType::Ascii(FormatControl::Default))
            .is_ok());
        finalize_stream(stream);
    }

    #[test]
    #[cfg(feature = "with-containers")]
    fn transfer_file() {
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
        assert!(stream.rename("test.txt", "toast.txt").is_ok());
        assert!(stream.rm("toast.txt").is_ok());
        // List directory again
        assert_eq!(stream.list(None).ok().unwrap().len(), 0);
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
