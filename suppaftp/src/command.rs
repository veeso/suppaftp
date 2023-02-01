//! # Command
//!
//! The set of FTP commands

use crate::types::FileType;

use std::string::ToString;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Ftp commands with their arguments
pub enum Command {
    /// Abort an active file transfer
    Abor,
    /// Append to file
    Appe(String),
    /// Set auth to TLS
    #[cfg(any(feature = "secure", feature = "async-secure"))]
    Auth,
    /// Ask server not to encrypt command channel
    #[cfg(any(feature = "secure", feature = "async-secure"))]
    ClearCommandChannel,
    /// Change directory to parent directory
    Cdup,
    /// Change working directory
    Cwd(String),
    /// Remove file at specified path
    Dele(String),
    /// Extended passive mode <https://www.rfc-editor.org/rfc/rfc2428#section-3>
    Epsv,
    /// List entries at specified path. If path is not provided list entries at current working directory
    List(Option<String>),
    /// Get modification time for file at specified path
    Mdtm(String),
    /// Make directory
    Mkd(String),
    /// Get the list of file names at specified path. If path is not provided list entries at current working directory
    Nlst(Option<String>),
    /// Ping server
    Noop,
    /// Provide login password
    Pass(String),
    /// Passive mode
    Pasv,
    /// Protection buffer size
    #[cfg(any(feature = "secure", feature = "async-secure"))]
    Pbsz(usize),
    /// Specifies an address and port to which the server should connect (active mode)
    Port(String),
    /// Set protection level for protocol
    #[cfg(any(feature = "secure", feature = "async-secure"))]
    Prot(ProtectionLevel),
    /// Print working directory
    Pwd,
    /// Quit
    Quit,
    /// Select file to rename
    RenameFrom(String),
    /// Rename selected file to
    RenameTo(String),
    /// Resume transfer from offset
    Rest(usize),
    /// Retrieve file
    Retr(String),
    /// Remove directory
    Rmd(String),
    /// Get file size of specified path
    Size(String),
    /// Put file at specified path
    Store(String),
    /// Set transfer type
    Type(FileType),
    /// Provide user to login as
    User(String),
}

#[cfg(any(feature = "secure", feature = "async-secure"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(unused)]
/// Protection level; argument for `Prot` command
pub enum ProtectionLevel {
    Clear,
    Private,
}

// -- stringify

impl ToString for Command {
    fn to_string(&self) -> String {
        let mut s = match self {
            Self::Abor => "ABOR".to_string(),
            Self::Appe(f) => format!("APPE {}", f),
            #[cfg(any(feature = "secure", feature = "async-secure"))]
            Self::Auth => "AUTH TLS".to_string(),
            Self::Cdup => "CDUP".to_string(),
            #[cfg(any(feature = "secure", feature = "async-secure"))]
            Self::ClearCommandChannel => "CCC".to_string(),
            Self::Cwd(d) => format!("CWD {}", d),
            Self::Dele(f) => format!("DELE {}", f),
            Self::Epsv => "EPSV".to_string(),
            Self::List(p) => p
                .as_deref()
                .map(|x| format!("LIST {}", x))
                .unwrap_or_else(|| "LIST".to_string()),
            Self::Mdtm(p) => format!("MDTM {}", p),
            Self::Mkd(p) => format!("MKD {}", p),
            Self::Nlst(p) => p
                .as_deref()
                .map(|x| format!("NLST {}", x))
                .unwrap_or_else(|| "NLST".to_string()),
            Self::Noop => "NOOP".to_string(),
            Self::Pass(p) => format!("PASS {}", p),
            Self::Pasv => "PASV".to_string(),
            #[cfg(any(feature = "secure", feature = "async-secure"))]
            Self::Pbsz(sz) => format!("PBSZ {}", sz),
            Self::Port(p) => format!("PORT {}", p),
            #[cfg(any(feature = "secure", feature = "async-secure"))]
            Self::Prot(l) => format!("PROT {}", l.to_string()),
            Self::Pwd => "PWD".to_string(),
            Self::Quit => "QUIT".to_string(),
            Self::RenameFrom(p) => format!("RNFR {}", p),
            Self::RenameTo(p) => format!("RNTO {}", p),
            Self::Rest(offset) => format!("REST {}", offset),
            Self::Retr(p) => format!("RETR {}", p),
            Self::Rmd(p) => format!("RMD {}", p),
            Self::Size(p) => format!("SIZE {}", p),
            Self::Store(p) => format!("STOR {}", p),
            Self::Type(t) => format!("TYPE {}", t.to_string()),
            Self::User(u) => format!("USER {}", u),
        };
        s.push_str("\r\n");
        s
    }
}

#[cfg(any(feature = "secure", feature = "async-secure"))]
impl ToString for ProtectionLevel {
    fn to_string(&self) -> String {
        match self {
            Self::Clear => "C",
            Self::Private => "P",
        }
        .to_string()
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_stringify_command() {
        assert_eq!(Command::Abor.to_string().as_str(), "ABOR\r\n");
        assert_eq!(
            Command::Appe(String::from("foobar.txt"))
                .to_string()
                .as_str(),
            "APPE foobar.txt\r\n"
        );
        #[cfg(any(feature = "secure", feature = "async-secure"))]
        assert_eq!(Command::Auth.to_string().as_str(), "AUTH TLS\r\n");
        #[cfg(any(feature = "secure", feature = "async-secure"))]
        assert_eq!(Command::ClearCommandChannel.to_string().as_str(), "CCC\r\n");
        assert_eq!(Command::Cdup.to_string().as_str(), "CDUP\r\n");
        assert_eq!(
            Command::Cwd(String::from("/tmp")).to_string().as_str(),
            "CWD /tmp\r\n"
        );
        assert_eq!(
            Command::Dele(String::from("a.txt")).to_string().as_str(),
            "DELE a.txt\r\n"
        );
        assert_eq!(Command::Epsv.to_string().as_str(), "EPSV\r\n");
        assert_eq!(
            Command::List(Some(String::from("/tmp")))
                .to_string()
                .as_str(),
            "LIST /tmp\r\n"
        );
        assert_eq!(Command::List(None).to_string().as_str(), "LIST\r\n");
        assert_eq!(
            Command::Mdtm(String::from("a.txt")).to_string().as_str(),
            "MDTM a.txt\r\n"
        );
        assert_eq!(
            Command::Mkd(String::from("/tmp")).to_string().as_str(),
            "MKD /tmp\r\n"
        );
        assert_eq!(
            Command::Nlst(Some(String::from("/tmp")))
                .to_string()
                .as_str(),
            "NLST /tmp\r\n"
        );
        assert_eq!(Command::Nlst(None).to_string().as_str(), "NLST\r\n");
        assert_eq!(Command::Noop.to_string().as_str(), "NOOP\r\n");
        assert_eq!(
            Command::Pass(String::from("qwerty123"))
                .to_string()
                .as_str(),
            "PASS qwerty123\r\n"
        );
        assert_eq!(Command::Pasv.to_string().as_str(), "PASV\r\n");
        #[cfg(any(feature = "secure", feature = "async-secure"))]
        assert_eq!(Command::Pbsz(0).to_string().as_str(), "PBSZ 0\r\n");
        assert_eq!(
            Command::Port(String::from("0.0.0.0:21"))
                .to_string()
                .as_str(),
            "PORT 0.0.0.0:21\r\n"
        );
        #[cfg(any(feature = "secure", feature = "async-secure"))]
        assert_eq!(
            Command::Prot(ProtectionLevel::Clear).to_string().as_str(),
            "PROT C\r\n"
        );
        assert_eq!(Command::Pwd.to_string().as_str(), "PWD\r\n");
        assert_eq!(Command::Quit.to_string().as_str(), "QUIT\r\n");
        assert_eq!(
            Command::RenameFrom(String::from("a.txt"))
                .to_string()
                .as_str(),
            "RNFR a.txt\r\n"
        );
        assert_eq!(
            Command::RenameTo(String::from("b.txt"))
                .to_string()
                .as_str(),
            "RNTO b.txt\r\n"
        );
        assert_eq!(Command::Rest(123).to_string().as_str(), "REST 123\r\n");
        assert_eq!(
            Command::Retr(String::from("a.txt")).to_string().as_str(),
            "RETR a.txt\r\n"
        );
        assert_eq!(
            Command::Rmd(String::from("/tmp")).to_string().as_str(),
            "RMD /tmp\r\n"
        );
        assert_eq!(
            Command::Size(String::from("a.txt")).to_string().as_str(),
            "SIZE a.txt\r\n"
        );
        assert_eq!(
            Command::Store(String::from("a.txt")).to_string().as_str(),
            "STOR a.txt\r\n"
        );
        assert_eq!(
            Command::Type(FileType::Binary).to_string().as_str(),
            "TYPE I\r\n"
        );
        assert_eq!(
            Command::User(String::from("omar")).to_string().as_str(),
            "USER omar\r\n"
        );
    }

    #[cfg(any(feature = "secure", feature = "async-secure"))]
    #[test]
    fn should_stringify_protection_level() {
        assert_eq!(ProtectionLevel::Clear.to_string().as_str(), "C");
        assert_eq!(ProtectionLevel::Private.to_string().as_str(), "P");
    }
}
