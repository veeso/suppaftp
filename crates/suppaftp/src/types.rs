//! # Types
//!
//! The set of valid values for FTP commands

use std::collections::HashMap;
use std::convert::From;
use std::fmt;
use std::net::IpAddr;
use std::string::FromUtf8Error;

use thiserror::Error;

use super::Status;

/// A shorthand for a Result whose error type is always an FtpError.
pub type FtpResult<T> = std::result::Result<T, FtpError>;

/// `FtpError` is a library-global error type to describe the different kinds of
/// errors that might occur while using FTP.
#[derive(Debug, Error)]
pub enum FtpError {
    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(std::io::Error),
    /// There was an error with the secure stream
    #[cfg(any(feature = "secure", feature = "async-secure"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "secure", feature = "async-secure"))))]
    #[error("Secure error: {0}")]
    SecureError(String),
    /// Unexpected response from remote. The command expected a certain response, but got another one.
    /// This means the ftp server refused to perform your request or there was an error while processing it.
    /// Contains the response data.
    #[error("Invalid response: {0}")]
    UnexpectedResponse(Response),
    /// The response syntax is invalid
    #[error("Response contains an invalid syntax")]
    BadResponse,
    /// The address provided was invalid
    #[error("Invalid address: {0}")]
    InvalidAddress(std::net::AddrParseError),
    /// Data connection is already open. You can't open more than one data connection at a time.
    #[error("Data connection is already open")]
    DataConnectionAlreadyOpen,
}

/// Defines a response from the ftp server
#[derive(Clone, Debug, Error)]
pub struct Response {
    pub status: Status,
    pub body: Vec<u8>,
}

/// Text Format Control used in `TYPE` command
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FormatControl {
    /// Default text format control (is NonPrint)
    Default,
    /// Non-print (not destined for printing)
    NonPrint,
    /// Telnet format control (\<CR\>, \<FF\>, etc.)
    Telnet,
    /// ASA (Fortran) Carriage Control
    Asa,
}

/// File Type used in `TYPE` command
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileType {
    /// ASCII text (the argument is the text format control)
    Ascii(FormatControl),
    /// EBCDIC text (the argument is the text format control)
    Ebcdic(FormatControl),
    /// Image,
    Image,
    /// Binary (the synonym to Image)
    Binary,
    /// Local format (the argument is the number of bits in one byte on local machine)
    Local(u8),
}

/// Connection mode for data channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Active,
    /// Required by some servers (ipv6); defined in rfc 2428 <https://www.rfc-editor.org/rfc/rfc2428#section-3>
    ExtendedPassive,
    Passive,
}

/// Which addresses an active-mode data connection is accepted from.
///
/// In active mode the client listens for the server to connect back, and anyone who can reach
/// the listener may connect first. Connections from addresses that are not allowed are ignored
/// until an allowed one arrives or the active timeout expires. Addresses are compared after
/// [`IpAddr::to_canonical`], so an IPv4-mapped IPv6 address matches its IPv4 form.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum ActivePeerCheck {
    /// Accept only the address of the server on the control connection.
    #[default]
    ControlPeer,
    /// Accept any address, as before this check existed.
    Any,
    /// Accept only the addresses on the list, e.g. when the server connects back from another
    /// address behind NAT, or the control connection goes through a relay or proxy.
    Allow(Vec<IpAddr>),
}

impl ActivePeerCheck {
    /// Whether a data connection from `peer` is accepted, given the control connection's peer.
    pub(crate) fn allows(&self, peer: IpAddr, control_peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        match self {
            Self::ControlPeer => peer == control_peer.to_canonical(),
            Self::Any => true,
            Self::Allow(allowed) => allowed.iter().any(|ip| ip.to_canonical() == peer),
        }
    }
}

/// Features returned by FEAT command (key, maybe value)
pub type Features = HashMap<String, Option<String>>;

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}",
            self.status.code(),
            self.as_string().ok().unwrap_or_default()
        )
    }
}

impl Response {
    /// Instantiates a new `Response`
    pub fn new(status: Status, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// Get response as string
    pub fn as_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.body.clone()).map(|x| x.trim_end().to_string())
    }
}

/// Most bytes one control-connection reply may take, every line of a multiline reply included.
///
/// Legitimate replies stay far below it; the largest ones in practice are `FEAT` lists and
/// multiline welcome banners of a few KiB.
pub(crate) const MAX_REPLY_SIZE: usize = 256 * 1024;

/// The error inside [`FtpError::ConnectionError`], with [`std::io::ErrorKind::InvalidData`],
/// when the server sends a control-connection reply larger than 256 KiB.
///
/// Without a bound, a server answering with an endless line or an endless multiline reply
/// (including the greeting, before any authentication) would make the client buffer it without
/// limit. The reply is abandoned half-read, so the connection cannot be used afterwards.
///
/// ```rust
/// use suppaftp::{FtpError, ReplyTooLarge};
///
/// fn is_reply_too_large(err: &FtpError) -> bool {
///     matches!(err, FtpError::ConnectionError(io)
///         if io.get_ref().is_some_and(|inner| inner.is::<ReplyTooLarge>()))
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the server sent a reply larger than {} bytes", MAX_REPLY_SIZE)]
pub struct ReplyTooLarge;

impl From<ReplyTooLarge> for FtpError {
    fn from(err: ReplyTooLarge) -> Self {
        FtpError::ConnectionError(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }
}

/// A fake server shared by the reply size tests of every client.
#[cfg(test)]
pub(crate) mod reply_size_fixture {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;

    use super::{FtpError, MAX_REPLY_SIZE, ReplyTooLarge};

    /// Starts a one-connection server that sends `greeting`, then, when `command_reply` is set,
    /// reads one command and sends `command_reply`. After that it repeats `endless` until the
    /// client hangs up, or just waits for the client to hang up when `endless` is empty.
    pub(crate) fn serve(
        greeting: Vec<u8>,
        command_reply: Option<&'static [u8]>,
        endless: Vec<u8>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket);
            let _ = reader.get_mut().write_all(&greeting);
            if let Some(reply) = command_reply {
                let _ = reader.read_line(&mut String::new());
                let _ = reader.get_mut().write_all(reply);
            }
            if endless.is_empty() {
                let _ = reader.read_to_end(&mut Vec::new());
            } else {
                while reader.get_mut().write_all(&endless).is_ok() {}
            }
        });
        address
    }

    /// Starts a one-connection server that closes the connection without sending anything.
    pub(crate) fn serve_and_hang_up() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || drop(listener.accept()));
        address
    }

    /// Panics unless `result` failed with an `UnexpectedEof` connection error.
    pub(crate) fn assert_connection_closed(result: Result<(), FtpError>) {
        match result {
            Err(FtpError::ConnectionError(err))
                if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    /// A greeting of exactly [`MAX_REPLY_SIZE`] bytes.
    pub(crate) fn greeting_of_max_size() -> Vec<u8> {
        let last = b"220 ready\r\n";
        let mut greeting = b"220-".to_vec();
        greeting.resize(MAX_REPLY_SIZE - last.len() - 2, b'a');
        greeting.extend_from_slice(b"\r\n");
        greeting.extend_from_slice(last);
        assert_eq!(greeting.len(), MAX_REPLY_SIZE);
        greeting
    }

    /// Panics unless `result` failed with [`ReplyTooLarge`].
    pub(crate) fn assert_reply_too_large(result: Result<(), FtpError>) {
        match result {
            Err(FtpError::ConnectionError(err))
                if err
                    .get_ref()
                    .is_some_and(|inner| inner.is::<ReplyTooLarge>()) => {}
            other => panic!("expected ReplyTooLarge, got {other:?}"),
        }
    }
}

impl fmt::Display for FormatControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FormatControl::Default | FormatControl::NonPrint => String::from("N"),
                FormatControl::Telnet => String::from("T"),
                FormatControl::Asa => String::from("C"),
            }
        )
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FileType::Ascii(fc) => format!("A {}", fc),
                FileType::Ebcdic(fc) => format!("E {}", fc),
                FileType::Image | FileType::Binary => String::from("I"),
                FileType::Local(bits) => format!("L {bits}"),
            }
        )
    }
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn should_check_active_peers() {
        let server: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();

        assert!(ActivePeerCheck::ControlPeer.allows(server, server));
        assert!(ActivePeerCheck::ControlPeer.allows(mapped, server));
        assert!(ActivePeerCheck::ControlPeer.allows(server, mapped));
        assert!(!ActivePeerCheck::ControlPeer.allows(other, server));

        assert!(ActivePeerCheck::Any.allows(other, server));

        let allow = ActivePeerCheck::Allow(vec![other]);
        assert!(allow.allows(other, server));
        assert!(!allow.allows(server, server));
        assert!(!ActivePeerCheck::Allow(Vec::new()).allows(server, server));
    }

    #[test]
    fn fmt_error() {
        assert_eq!(
            FtpError::ConnectionError(std::io::Error::new(std::io::ErrorKind::NotFound, "omar"))
                .to_string()
                .as_str(),
            "Connection error: omar"
        );
        #[cfg(feature = "secure")]
        assert_eq!(
            FtpError::SecureError("omar".to_string())
                .to_string()
                .as_str(),
            "Secure error: omar"
        );
        assert_eq!(
            FtpError::UnexpectedResponse(Response::new(
                Status::ExceededStorage,
                "error".as_bytes().to_vec()
            ))
            .to_string()
            .as_str(),
            "Invalid response: [552] error"
        );
        assert_eq!(
            FtpError::BadResponse.to_string().as_str(),
            "Response contains an invalid syntax"
        );
        assert_eq!(
            FtpError::InvalidAddress("127.0.0.1:abc".parse::<std::net::SocketAddr>().unwrap_err())
                .to_string()
                .as_str(),
            "Invalid address: invalid socket address syntax"
        );
        assert_eq!(
            FtpError::DataConnectionAlreadyOpen.to_string().as_str(),
            "Data connection is already open"
        );
    }

    #[test]
    fn response() {
        let response: Response = Response::new(Status::AboutToSend, "error".as_bytes().to_vec());
        assert_eq!(response.status, Status::AboutToSend);
        assert_eq!(response.as_string().unwrap(), "error");
    }

    #[test]
    fn fmt_response() {
        let response: Response = Response::new(
            Status::FileUnavailable,
            "Can't create directory: File exists".as_bytes().to_vec(),
        );
        assert_eq!(
            response.to_string().as_str(),
            "[550] Can't create directory: File exists"
        );
    }

    #[test]
    fn response_as_string_with_invalid_utf8() {
        let response = Response::new(Status::CommandOk, vec![0xff, 0xfe, 0xfd]);
        assert!(response.as_string().is_err());
    }

    #[test]
    fn response_as_string_trims_trailing_whitespace() {
        let response = Response::new(Status::CommandOk, "hello world  \r\n".as_bytes().to_vec());
        assert_eq!(response.as_string().unwrap(), "hello world");
    }

    #[test]
    fn response_empty_body() {
        let response = Response::new(Status::CommandOk, vec![]);
        assert_eq!(response.as_string().unwrap(), "");
        assert_eq!(response.to_string(), "[200] ");
    }

    #[test]
    fn mode_debug() {
        assert_eq!(format!("{:?}", Mode::Active), "Active");
        assert_eq!(format!("{:?}", Mode::Passive), "Passive");
        assert_eq!(format!("{:?}", Mode::ExtendedPassive), "ExtendedPassive");
    }

    #[test]
    fn mode_clone_and_eq() {
        let mode = Mode::Passive;
        let cloned = mode;
        assert_eq!(mode, cloned);
        assert_ne!(Mode::Active, Mode::Passive);
        assert_ne!(Mode::ExtendedPassive, Mode::Passive);
    }

    #[test]
    fn file_type_clone_and_eq() {
        let ft = FileType::Binary;
        let cloned = ft.clone();
        assert_eq!(ft, cloned);
        assert_ne!(FileType::Binary, FileType::Ascii(FormatControl::Default));
        assert_ne!(FileType::Image, FileType::Local(8));
    }

    #[test]
    fn format_control_ordering() {
        assert!(FormatControl::Default < FormatControl::NonPrint);
        assert!(FormatControl::NonPrint < FormatControl::Telnet);
        assert!(FormatControl::Telnet < FormatControl::Asa);
    }

    #[test]
    fn fmt_format_control() {
        assert_eq!(FormatControl::Asa.to_string().as_str(), "C");
        assert_eq!(FormatControl::Telnet.to_string().as_str(), "T");
        assert_eq!(FormatControl::Default.to_string().as_str(), "N");
        assert_eq!(FormatControl::NonPrint.to_string().as_str(), "N");
    }

    #[test]
    fn fmt_file_type() {
        assert_eq!(
            FileType::Ascii(FormatControl::Telnet).to_string().as_str(),
            "A T"
        );
        assert_eq!(FileType::Binary.to_string().as_str(), "I");
        assert_eq!(FileType::Image.to_string().as_str(), "I");
        assert_eq!(
            FileType::Ebcdic(FormatControl::Telnet).to_string().as_str(),
            "E T"
        );
        assert_eq!(FileType::Local(2).to_string().as_str(), "L 2");
    }
}
