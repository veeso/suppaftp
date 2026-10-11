//! Character encoding of file names and other text on the control and data connections.
//!
//! FTP sends file names as raw bytes. Modern servers use UTF-8, but older ones often use
//! Latin-1, Windows-1252, Shift-JIS and so on. An [`Encoding`] turns those bytes into
//! [`String`]s and back, so such names can be listed and addressed.

use std::{fmt, io};

/// Converts text exchanged with the server between bytes and [`String`]s.
///
/// The client encodes every command line it sends (verb, arguments and the trailing CRLF) and
/// decodes listing lines (`LIST`, `NLST`, `MLSD`), the `MLST` and `PWD` replies and the welcome
/// message.
///
/// The encoding must be ASCII-compatible: command verbs, spaces and CRLF must encode to the
/// same bytes as in ASCII. Latin-1, Windows-1252, Shift-JIS and UTF-8 all are. A command whose
/// encoded form contains CR or LF anywhere but at its end is rejected before it is sent.
/// Literal `0xFF` bytes in commands are escaped for the FTP control connection's Telnet framing.
/// Doubled `0xFF` bytes in `MLST` and `PWD` replies and in the welcome message are unescaped
/// before decoding.
///
/// The default is [`Utf8Encoding`].
///
/// # Examples
///
/// A Latin-1 (ISO-8859-1) encoding:
///
/// ```rust
/// use std::io;
///
/// use suppaftp::Encoding;
///
/// #[derive(Debug)]
/// struct Latin1;
///
/// impl Encoding for Latin1 {
///     fn decode(&self, bytes: &[u8]) -> String {
///         bytes.iter().map(|byte| char::from(*byte)).collect()
///     }
///
///     fn encode(&self, text: &str) -> io::Result<Vec<u8>> {
///         text.chars()
///             .map(|c| {
///                 u8::try_from(u32::from(c)).map_err(|_| {
///                     io::Error::new(io::ErrorKind::InvalidInput, "not representable in Latin-1")
///                 })
///             })
///             .collect()
///     }
/// }
///
/// assert_eq!(Latin1.decode(b"caf\xE9.txt"), "café.txt");
/// assert_eq!(Latin1.encode("café.txt").unwrap(), b"caf\xE9.txt");
/// ```
pub trait Encoding: fmt::Debug + Send + Sync {
    /// Decodes `bytes` received from the server into text.
    ///
    /// Decoding never fails: bytes that the encoding cannot map should be replaced, for example
    /// with U+FFFD.
    fn decode(&self, bytes: &[u8]) -> String;

    /// Encodes `text` into the bytes sent to the server.
    ///
    /// # Errors
    ///
    /// Returns an error, preferably with [`io::ErrorKind::InvalidInput`], if `text` contains a
    /// character the encoding cannot represent. The command is then not sent.
    fn encode(&self, text: &str) -> io::Result<Vec<u8>>;
}

/// UTF-8 [`Encoding`], the default.
///
/// Decoding is lossy: invalid UTF-8 sequences become U+FFFD. Encoding never fails.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Utf8Encoding;

impl Encoding for Utf8Encoding {
    fn decode(&self, bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn encode(&self, text: &str) -> io::Result<Vec<u8>> {
        Ok(text.as_bytes().to_vec())
    }
}

/// The server's welcome banner.
///
/// The banner is read while connecting, before the caller can choose an [`Encoding`], so the raw
/// bytes are kept and decoded again whenever the encoding changes.
#[derive(Debug, Clone)]
pub(crate) struct WelcomeMessage {
    /// Reply body with doubled Telnet IAC bytes unescaped.
    raw: Vec<u8>,
    /// `raw` decoded with the current encoding, trailing whitespace trimmed.
    text: String,
}

impl WelcomeMessage {
    /// Keeps the reply `body` and decodes it with `encoding`.
    pub(crate) fn new(body: &[u8], encoding: &dyn Encoding) -> Self {
        let raw = crate::command::unescape_telnet_iac(body).into_owned();
        let text = Self::decode(&raw, encoding);
        Self { raw, text }
    }

    /// Decodes the banner again with `encoding`.
    pub(crate) fn redecode(&mut self, encoding: &dyn Encoding) {
        self.text = Self::decode(&self.raw, encoding);
    }

    /// Returns the decoded banner.
    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }

    fn decode(raw: &[u8], encoding: &dyn Encoding) -> String {
        encoding.decode(raw).trim_end().to_string()
    }
}

/// Encodings shared by the encoding tests of every client.
#[cfg(test)]
pub(crate) mod test_encodings {
    use std::io;

    use super::Encoding;

    /// Latin-1 (ISO-8859-1): every byte is the code point of the same value.
    #[derive(Debug)]
    pub(crate) struct Latin1;

    impl Encoding for Latin1 {
        fn decode(&self, bytes: &[u8]) -> String {
            bytes.iter().map(|byte| char::from(*byte)).collect()
        }

        fn encode(&self, text: &str) -> io::Result<Vec<u8>> {
            text.chars()
                .map(|c| {
                    u8::try_from(u32::from(c)).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, format!("{c:?} is not Latin-1"))
                    })
                })
                .collect()
        }
    }

    /// Encodes every space as LF, so an encoded command would carry a second line.
    #[derive(Debug)]
    pub(crate) struct Smuggler;

    impl Encoding for Smuggler {
        fn decode(&self, bytes: &[u8]) -> String {
            String::from_utf8_lossy(bytes).into_owned()
        }

        fn encode(&self, text: &str) -> io::Result<Vec<u8>> {
            Ok(text.replace(' ', "\n").into_bytes())
        }
    }

    /// Drops the trailing CRLF of every command.
    #[derive(Debug)]
    pub(crate) struct DropsLineEnd;

    impl Encoding for DropsLineEnd {
        fn decode(&self, bytes: &[u8]) -> String {
            String::from_utf8_lossy(bytes).into_owned()
        }

        fn encode(&self, text: &str) -> io::Result<Vec<u8>> {
            Ok(text.trim_end_matches("\r\n").as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn utf8_should_decode_valid_utf8() {
        assert_eq!(Utf8Encoding.decode("café.txt".as_bytes()), "café.txt");
    }

    #[test]
    fn utf8_should_decode_invalid_utf8_lossily() {
        assert_eq!(Utf8Encoding.decode(b"caf\xE9.txt"), "caf\u{FFFD}.txt");
    }

    #[test]
    fn utf8_should_encode_as_utf8() {
        assert_eq!(
            Utf8Encoding.encode("RETR café.txt\r\n").unwrap(),
            "RETR café.txt\r\n".as_bytes()
        );
    }
}
