//! # Types
//!
//! The set of valid values for FTP commands

use std::convert::From;
use thiserror::Error;

/// ## Result
///
/// A shorthand for a Result whose error type is always an FtpError.
pub type Result<T> = std::result::Result<T, FtpError>;

/// ## FtpError
///
/// `FtpError` is a library-global error type to describe the different kinds of
/// errors that might occur while using FTP.
#[derive(Debug, Error)]
pub enum FtpError {
    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(std::io::Error),
    /// There was an error with the secure stream
    #[cfg(feature = "secure")]
    #[error("Secure error: {0}")]
    SecureError(String),
    /// Invalid response from remote. Contains the response data
    #[error("Invalid response: {0}")]
    InvalidResponse(Response),
    /// The response syntax is invalid
    #[error("Response contains an invalid syntax")]
    BadResponse,
    /// The address provided was invalid
    #[error("Invalid address: {0}")]
    InvalidAddress(std::net::AddrParseError),
}

/// ## Response
///
/// Defines a response from the ftp server
#[derive(Clone, Debug, Error)]
#[error("[{code}] {body}")]
pub struct Response {
    pub code: u32,
    pub body: String,
}

/// ## FormatControl
///
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

/// ## FileType
///
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

impl Response {
    /// ### new
    ///
    /// Instantiates a new `Response`
    pub fn new<S: AsRef<str>>(code: u32, body: S) -> Self {
        Self {
            code,
            body: body.as_ref().to_string(),
        }
    }
}

impl ToString for FormatControl {
    fn to_string(&self) -> String {
        match self {
            FormatControl::Default | FormatControl::NonPrint => String::from("N"),
            FormatControl::Telnet => String::from("T"),
            FormatControl::Asa => String::from("C"),
        }
    }
}

impl ToString for FileType {
    fn to_string(&self) -> String {
        match self {
            FileType::Ascii(fc) => format!("A {}", fc.to_string()),
            FileType::Ebcdic(fc) => format!("E {}", fc.to_string()),
            FileType::Image | FileType::Binary => String::from("I"),
            FileType::Local(bits) => format!("L {}", bits),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn fmt_error() {
        assert_eq!(
            FtpError::ConnectionError(std::io::Error::new(std::io::ErrorKind::NotFound, "omar"))
                .to_string()
                .as_str(),
            "Connection error: NotFound (omar)"
        );
        #[cfg(feature = "secure")]
        assert_eq!(
            FtpError::SecureError("omar".to_string())
                .to_string()
                .as_str(),
            "Secure error: omar"
        );
        assert_eq!(
            FtpError::InvalidResponse(Response::new(0, "error"))
                .to_string()
                .as_str(),
            "Invalid response: [0] error"
        );
        assert_eq!(
            FtpError::BadResponse.to_string().as_str(),
            "Response contains an invalid syntax"
        );
    }

    #[test]
    fn response() {
        let response: Response = Response::new(0, "error");
        assert_eq!(response.code, 0);
        assert_eq!(response.body.as_str(), "error");
    }

    #[test]
    fn fmt_response() {
        let response: Response = Response::new(550, "Can't create directory: File exists");
        assert_eq!(
            response.to_string().as_str(),
            "[550] Can't create directory: File exists"
        );
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
