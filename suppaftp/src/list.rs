//! # List
//!
//! This module exposes the parser for the LIST command.
//! Please note that there's no guarantee this parser works and the reason is quite simple.
//! There's no specification regarding the LIST command output, so it basically depends on the implementation of the
//! remote FTP server. Despite this though, this parser, has worked on all the ftp server I've used.
//! If you find a variant which doesn't work with this parser,
//! please feel free to report an issue to <https://github.com/veeso/suppaftp>.
//!
//! ## Get started
//!
//! Whenever you receive the output for your LIST command, all you have to do is to iterate over lines and
//! call `File::from_line()` function as shown in the example.
//!
//! ```rust
//! use std::convert::TryFrom;
//! use suppaftp::{FtpStream, list::File};
//!
//! // Connect to the server
//! let mut ftp_stream = FtpStream::connect("127.0.0.1:10021").unwrap_or_else(|err|
//!     panic!("{}", err)
//! );
//!
//! // Authenticate
//! assert!(ftp_stream.login("test", "test").is_ok());
//!
//! // List current directory
//! let files: Vec<File> = ftp_stream.list(None).ok().unwrap().iter().map(|x| File::try_from(x.as_str()).ok().unwrap()).collect();
//!
//! // Disconnect from server
//! assert!(ftp_stream.quit().is_ok());
//!
//! ```

use std::convert::TryFrom;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use chrono::prelude::{NaiveDate, NaiveDateTime, Utc};
use chrono::Datelike;
use lazy_regex::{Lazy, Regex};
use thiserror::Error;

// -- Regex

/// POSIX system regex to parse list output
static POSIX_LS_RE: Lazy<Regex> = lazy_regex!(
    r#"^([\-ld])([\-rwxsStT]{9})\s+(\d+)\s+([^ ]+)\s+([^ ]+)\s+(\d+)\s+([^ ]+\s+\d{1,2}\s+(?:\d{1,2}:\d{1,2}|\d{4}))\s+(.+)$"#
);
/// DOS system regex to parse list output
static DOS_LS_RE: Lazy<Regex> =
    lazy_regex!(r#"^(\d{2}\-\d{2}\-\d{2}\s+\d{2}:\d{2}\s*[AP]M)\s+(<DIR>)?([\d,]*)\s+(.+)$"#);

// -- File entry

/// Describes a file entry on the remote system.
/// This data type is returned in a collection after parsing a LIST output
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct File {
    /// File name
    name: String,
    /// File type describes whether it is a directory, a file or a symlink
    file_type: FileType,
    /// File size in bytes
    size: usize,
    /// Last time the file was modified
    modified: SystemTime,
    /// User id (POSIX only)
    uid: Option<u32>,
    /// Group id (POSIX only)
    gid: Option<u32>,
    /// POSIX permissions
    posix_pex: (PosixPex, PosixPex, PosixPex),
}

/// Describes the kind of file. Can be `Directory`, `File` or `Symlink`. If `Symlink` the path to the pointed file must be provided
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum FileType {
    Directory,
    File,
    Symlink(PathBuf),
}

/// ### PosixPexQuery
///
/// This enum is used to query about posix permissions on a file
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PosixPexQuery {
    Owner,
    Group,
    Others,
}

/// Describes the permissions on POSIX system.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct PosixPex {
    read: bool,
    write: bool,
    execute: bool,
}

// -- Error

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ParseError {
    #[error("Syntax error: invalid line")]
    SyntaxError,
    #[error("Invalid date")]
    InvalidDate,
    #[error("Bad file size")]
    BadSize,
}

impl File {
    // -- getters

    /// Get file name
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Get whether file is a directory
    pub fn is_directory(&self) -> bool {
        self.file_type.is_directory()
    }

    /// Get whether file is a file
    pub fn is_file(&self) -> bool {
        self.file_type.is_file()
    }

    /// Get whether file is a symlink
    pub fn is_symlink(&self) -> bool {
        self.file_type.is_symlink()
    }

    /// Returns, if available, the file the symlink is pointing to
    pub fn symlink(&self) -> Option<&Path> {
        self.file_type.symlink()
    }

    /// Returned file size in bytes
    pub fn size(&self) -> usize {
        self.size
    }

    //// Returns the last time the file was modified
    pub fn modified(&self) -> SystemTime {
        self.modified
    }

    /// Returns when available the owner user of the file. (POSIX only)
    pub fn uid(&self) -> Option<u32> {
        self.uid.to_owned()
    }

    /// Returns when available the owner group of the file. (POSIX only)
    pub fn gid(&self) -> Option<u32> {
        self.gid.to_owned()
    }

    /// Returns whether `who` can read file
    pub fn can_read(&self, who: PosixPexQuery) -> bool {
        self.query_pex(who).can_read()
    }

    /// Returns whether `who` can write file
    pub fn can_write(&self, who: PosixPexQuery) -> bool {
        self.query_pex(who).can_write()
    }

    /// Returns whether `who` can execute file
    pub fn can_execute(&self, who: PosixPexQuery) -> bool {
        self.query_pex(who).can_execute()
    }

    /// Returns the pex structure for selected query
    fn query_pex(&self, who: PosixPexQuery) -> &PosixPex {
        match who {
            PosixPexQuery::Group => &self.posix_pex.1,
            PosixPexQuery::Others => &self.posix_pex.2,
            PosixPexQuery::Owner => &self.posix_pex.0,
        }
    }

    // -- parsers

    /// Parse an output line from a MLSD or MLST command
    pub fn from_mlsx_line(line: &str) -> Result<Self, ParseError> {
        let tokens = line.split(';').collect::<Vec<&str>>();
        if tokens.is_empty() {
            return Err(ParseError::SyntaxError);
        }
        let mut f = File {
            name: String::default(),
            file_type: FileType::File,
            size: 0,
            modified: SystemTime::UNIX_EPOCH,
            uid: None,
            gid: None,
            posix_pex: (
                PosixPex::from(0o7),
                PosixPex::from(0o7),
                PosixPex::from(0o7),
            ),
        };
        for token in tokens.iter() {
            let mut parts = token.split('=');
            let key = match parts.next() {
                Some(k) => k,
                None => continue,
            };
            let value = match parts.next() {
                Some(v) => v,
                None => continue,
            };
            match key.to_lowercase().as_str() {
                "type" => {
                    f.file_type = match value.to_lowercase().as_str() {
                        "dir" => FileType::Directory,
                        "file" => FileType::File,
                        "link" => FileType::Symlink(PathBuf::default()),
                        _ => return Err(ParseError::SyntaxError),
                    };
                }
                "size" => {
                    f.size = value.parse::<usize>().map_err(|_| ParseError::BadSize)?;
                }
                "modify" => {
                    f.modified = Self::parse_mlsx_time(value)?;
                }
                "unix.uid" => {
                    f.uid = value.parse::<u32>().ok();
                }
                "unix.gid" => {
                    f.gid = value.parse::<u32>().ok();
                }
                "unix.mode" => {
                    if value.len() != 3 {
                        return Err(ParseError::SyntaxError);
                    }
                    let chars = value.chars().collect::<Vec<char>>();
                    // convert to nums
                    let modes = chars
                        .iter()
                        .map(|c| c.to_digit(8).unwrap_or(0))
                        .collect::<Vec<u32>>();

                    f.posix_pex = (
                        PosixPex::from(modes[0] as u8),
                        PosixPex::from(modes[1] as u8),
                        PosixPex::from(modes[2] as u8),
                    );
                }
                _ => continue,
            }
        }

        // get name
        f.name = tokens.last().unwrap().trim_start().to_string();

        Ok(f)
    }

    /// Parse a POSIX LIST output line and if it is valid, return a `File` instance.
    /// In case of error a `ParseError` is returned
    pub fn from_posix_line(line: &str) -> Result<Self, ParseError> {
        // Apply regex to result
        match POSIX_LS_RE.captures(line) {
            // String matches regex
            Some(metadata) => {
                trace!("Parsed POSIX line {}", line);
                // NOTE: metadata fmt: (regex, file_type, permissions, link_count, uid, gid, filesize, mtime, filename)
                // Expected 7 + 1 (8) values: + 1 cause regex is repeated at 0
                if metadata.len() < 8 {
                    trace!("Bad syntax for posix line");
                    return Err(ParseError::SyntaxError);
                }
                // Collect metadata
                // Get if is directory and if is symlink
                let file_type: FileType = match metadata.get(1).unwrap().as_str() {
                    "-" => FileType::File,
                    "d" => FileType::Directory,
                    "l" => FileType::Symlink(PathBuf::default()),
                    _ => return Err(ParseError::SyntaxError), // This case is actually already covered by the regex
                };

                let pex = |range: Range<usize>| {
                    let mut count: u8 = 0;
                    for (i, c) in metadata.get(2).unwrap().as_str()[range].chars().enumerate() {
                        match c {
                            '-' | 'S' | 'T' => {}
                            _ => {
                                count += match i {
                                    0 => 4,
                                    1 => 2,
                                    2 => 1,
                                    _ => 0,
                                }
                            }
                        }
                    }
                    count
                };

                // Get posix pex
                let posix_pex: (PosixPex, PosixPex, PosixPex) = (
                    PosixPex::from(pex(0..3)),
                    PosixPex::from(pex(3..6)),
                    PosixPex::from(pex(6..9)),
                );

                // Parse mtime and convert to SystemTime
                let modified: SystemTime = Self::parse_lstime(
                    metadata.get(7).unwrap().as_str().trim(),
                    "%b %d %Y",
                    "%b %d %H:%M",
                )?;
                // Get gid
                let gid: Option<u32> = metadata.get(5).unwrap().as_str().trim().parse::<u32>().ok();
                // Get uid
                let uid: Option<u32> = metadata.get(4).unwrap().as_str().trim().parse::<u32>().ok();
                // Get filesize
                let size: usize = metadata
                    .get(6)
                    .unwrap()
                    .as_str()
                    .parse::<usize>()
                    .map_err(|_| ParseError::BadSize)?;
                // Split filename if required
                let (name, symlink_path): (String, Option<PathBuf>) = match file_type.is_symlink() {
                    true => Self::get_name_and_link(metadata.get(8).unwrap().as_str()),
                    false => (String::from(metadata.get(8).unwrap().as_str()), None),
                };
                // If symlink path is Some, assign symlink path to file_type
                let file_type: FileType = match symlink_path {
                    Some(p) => FileType::Symlink(p),
                    None => file_type,
                };
                trace!(
                    "Found file with name {}, type: {:?}, size: {}, uid: {:?}, gid: {:?}, pex: {:?}",
                    name,
                    file_type,
                    size,
                    uid,
                    gid,
                    posix_pex
                );
                Ok(File {
                    name,
                    file_type,
                    size,
                    modified,
                    uid,
                    gid,
                    posix_pex,
                })
            }
            None => Err(ParseError::SyntaxError),
        }
    }

    /// Try to parse a "LIST" output command line in DOS format.
    /// Returns error if syntax is not DOS compliant.
    /// DOS syntax has the following syntax:
    ///
    /// ```text
    /// {DATE} {TIME} {<DIR> | SIZE} {FILENAME}
    /// 10-19-20  03:19PM <DIR> pub
    /// 04-08-14  03:09PM 403   readme.txt
    /// ```
    pub fn from_dos_line(line: &str) -> Result<Self, ParseError> {
        // Apply regex to result
        match DOS_LS_RE.captures(line) {
            // String matches regex
            Some(metadata) => {
                trace!("Parsed DOS line {}", line);
                // NOTE: metadata fmt: (regex, date_time, is_dir?, file_size?, file_name)
                // Expected 4 + 1 (5) values: + 1 cause regex is repeated at 0
                if metadata.len() < 5 {
                    return Err(ParseError::SyntaxError);
                }
                // Parse date time
                let modified: SystemTime = Self::parse_dostime(metadata.get(1).unwrap().as_str())?;
                // Get if is a directory
                let file_type: FileType = match metadata.get(2).is_some() {
                    true => FileType::Directory,
                    false => FileType::File,
                };
                // Get file size
                let size: usize = match file_type.is_directory() {
                    true => 0, // If is directory, filesize is 0
                    false => match metadata.get(3) {
                        // If is file, parse arg 3
                        Some(val) => val
                            .as_str()
                            .parse::<usize>()
                            .map_err(|_| ParseError::BadSize)?,
                        None => 0,
                    },
                };
                // Get file name
                let name: String = String::from(metadata.get(4).unwrap().as_str());
                trace!(
                    "Found file with name {}, type: {:?}, size: {}",
                    name,
                    file_type,
                    size,
                );
                // Return entry
                Ok(File {
                    name,
                    file_type,
                    size,
                    modified,
                    uid: None,
                    gid: None,
                    posix_pex: (
                        PosixPex::default(),
                        PosixPex::default(),
                        PosixPex::default(),
                    ),
                })
            }
            None => Err(ParseError::SyntaxError), // Invalid syntax
        }
    }

    /// Returns from a `ls -l` command output file name token, the name of the file and the symbolic link (if there is any)
    fn get_name_and_link(token: &str) -> (String, Option<PathBuf>) {
        let tokens: Vec<&str> = token.split(" -> ").collect();
        let filename: String = String::from(*tokens.first().unwrap());
        let symlink: Option<PathBuf> = tokens.get(1).map(PathBuf::from);
        (filename, symlink)
    }

    /// Convert MLSD time to System Time
    fn parse_mlsx_time(tm: &str) -> Result<SystemTime, ParseError> {
        NaiveDateTime::parse_from_str(tm, "%Y%m%d%H%M%S")
            .map(|dt| {
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(dt.and_utc().timestamp() as u64))
                    .unwrap_or(SystemTime::UNIX_EPOCH)
            })
            .map_err(|_| ParseError::InvalidDate)
    }

    /// Convert ls syntax time to System Time
    /// ls time has two possible syntax:
    /// 1. if year is current: %b %d %H:%M (e.g. Nov 5 13:46)
    /// 2. else: %b %d %Y (e.g. Nov 5 2019)
    fn parse_lstime(tm: &str, fmt_year: &str, fmt_hours: &str) -> Result<SystemTime, ParseError> {
        let datetime: NaiveDateTime = match NaiveDate::parse_from_str(tm, fmt_year) {
            Ok(date) => {
                // Case 2.
                // Return NaiveDateTime from NaiveDate with time 00:00:00
                date.and_hms_opt(0, 0, 0).unwrap()
            }
            Err(_) => {
                // Might be case 1.
                // We need to add Current Year at the end of the string
                let this_year: i32 = Utc::now().year();
                let date_time_str: String = format!("{tm} {this_year}");
                // Now parse
                NaiveDateTime::parse_from_str(
                    date_time_str.as_ref(),
                    format!("{fmt_hours} %Y").as_ref(),
                )
                .map_err(|_| ParseError::InvalidDate)?
            }
        };
        // Convert datetime to system time
        let sys_time: SystemTime = SystemTime::UNIX_EPOCH;
        Ok(sys_time
            .checked_add(Duration::from_secs(datetime.and_utc().timestamp() as u64))
            .unwrap_or(SystemTime::UNIX_EPOCH))
    }

    /// Parse date time string in DOS representation ("%m-%d-%y %I:%M%p")
    fn parse_dostime(tm: &str) -> Result<SystemTime, ParseError> {
        NaiveDateTime::parse_from_str(tm, "%m-%d-%y %I:%M%p")
            .map(|dt| {
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(dt.and_utc().timestamp() as u64))
                    .unwrap_or(SystemTime::UNIX_EPOCH)
            })
            .map_err(|_| ParseError::InvalidDate)
    }
}

impl FromStr for File {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for File {
    type Error = ParseError;

    fn try_from(line: &str) -> Result<Self, Self::Error> {
        // First try to parse the line in POSIX format (vast majority case).
        match Self::from_posix_line(line) {
            Ok(entry) => Ok(entry),
            // If POSIX parsing fails, try with DOS parser.
            Err(_) => match Self::from_dos_line(line) {
                Ok(entry) => Ok(entry),
                Err(err) => Err(err),
            },
        }
    }
}

impl TryFrom<String> for File {
    type Error = ParseError;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        File::try_from(line.as_str())
    }
}

impl FileType {
    /// Returns whether the file is a directory
    fn is_directory(&self) -> bool {
        matches!(self, &FileType::Directory)
    }

    /// Returns whether the file is a file
    fn is_file(&self) -> bool {
        matches!(self, &FileType::File)
    }

    /// Returns whether the file is a symlink
    fn is_symlink(&self) -> bool {
        matches!(self, &FileType::Symlink(_))
    }

    /// get symlink if any
    fn symlink(&self) -> Option<&Path> {
        match self {
            FileType::Symlink(p) => Some(p.as_path()),
            _ => None,
        }
    }
}

impl PosixPex {
    /// Returns whether read permission is true
    fn can_read(&self) -> bool {
        self.read
    }

    /// Returns whether write permission is true
    fn can_write(&self) -> bool {
        self.write
    }

    /// Returns whether execute permission is true
    fn can_execute(&self) -> bool {
        self.execute
    }
}

impl Default for PosixPex {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }
}

impl From<u8> for PosixPex {
    fn from(bits: u8) -> Self {
        Self {
            read: ((bits >> 2) & 0x01) != 0,
            write: ((bits >> 1) & 0x01) != 0,
            execute: (bits & 0x01) != 0,
        }
    }
}

#[cfg(test)]
mod test {

    use chrono::DateTime;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn file_getters() {
        let file: File = File {
            name: String::from("provola.txt"),
            file_type: FileType::File,
            size: 2048,
            modified: SystemTime::UNIX_EPOCH,
            gid: Some(0),
            uid: Some(0),
            posix_pex: (PosixPex::from(7), PosixPex::from(5), PosixPex::from(4)),
        };
        assert_eq!(file.name(), "provola.txt");
        assert_eq!(file.is_directory(), false);
        assert_eq!(file.is_file(), true);
        assert_eq!(file.is_symlink(), false);
        assert_eq!(file.symlink(), None);
        assert_eq!(file.size(), 2048);
        assert_eq!(file.gid(), Some(0));
        assert_eq!(file.uid(), Some(0));
        assert_eq!(file.modified(), SystemTime::UNIX_EPOCH);
        // -- posix pex
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), true);
        assert_eq!(file.can_write(PosixPexQuery::Group), false);
        assert_eq!(file.can_execute(PosixPexQuery::Group), true);
        assert_eq!(file.can_read(PosixPexQuery::Others), true);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), false);
    }

    #[test]
    fn parse_posix_line() {
        let file: File = File::from_str("-rw-rw-r-- 1 0  1  8192 Nov 5 2018 omar.txt")
            .ok()
            .unwrap();
        assert_eq!(file.name(), "omar.txt");
        assert_eq!(file.size, 8192);
        assert_eq!(file.is_file(), true);
        assert_eq!(file.uid, Some(0));
        assert_eq!(file.gid, Some(1));
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), false);
        assert_eq!(file.can_read(PosixPexQuery::Group), true);
        assert_eq!(file.can_write(PosixPexQuery::Group), true);
        assert_eq!(file.can_execute(PosixPexQuery::Group), false);
        assert_eq!(file.can_read(PosixPexQuery::Others), true);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), false);
        assert_eq!(
            file.modified()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(1541376000)
        );
        // Group and user as strings; directory
        let file: File = File::from_str("drwxrwxr-x 1 root  dialout  4096 Nov 5 2018 provola")
            .ok()
            .unwrap();
        assert_eq!(file.name(), "provola");
        assert_eq!(file.size, 4096);
        assert_eq!(file.is_directory(), true);
        assert_eq!(file.uid, None);
        assert_eq!(file.gid, None);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), true);
        assert_eq!(file.can_write(PosixPexQuery::Group), true);
        assert_eq!(file.can_execute(PosixPexQuery::Group), true);
        assert_eq!(file.can_read(PosixPexQuery::Others), true);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), true);
        assert_eq!(
            file.modified()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(1541376000)
        );
        // Setuid bit
        let file: File =
            File::from_str("drws------    2 u-redacted g-redacted      3864 Feb 17  2023 sas")
                .ok()
                .unwrap();
        assert_eq!(file.is_directory(), true);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), false);
        assert_eq!(file.can_write(PosixPexQuery::Group), false);
        assert_eq!(file.can_execute(PosixPexQuery::Group), false);
        assert_eq!(file.can_read(PosixPexQuery::Others), false);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), false);
        let file: File =
            File::from_str("drwS------    2 u-redacted g-redacted      3864 Feb 17  2023 sas")
                .ok()
                .unwrap();
        assert_eq!(file.is_directory(), true);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), false);
        assert_eq!(file.can_read(PosixPexQuery::Group), false);
        assert_eq!(file.can_write(PosixPexQuery::Group), false);
        assert_eq!(file.can_execute(PosixPexQuery::Group), false);
        assert_eq!(file.can_read(PosixPexQuery::Others), false);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), false);
        // Setgid bit
        let file: File =
            File::from_str("drwx--s---    2 u-redacted g-redacted      3864 Feb 17  2023 sas")
                .ok()
                .unwrap();
        assert_eq!(file.is_directory(), true);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), false);
        assert_eq!(file.can_write(PosixPexQuery::Group), false);
        assert_eq!(file.can_execute(PosixPexQuery::Group), true);
        assert_eq!(file.can_read(PosixPexQuery::Others), false);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), false);
        let file: File =
            File::from_str("drwx--S---    2 u-redacted g-redacted      3864 Feb 17  2023 sas")
                .ok()
                .unwrap();
        assert_eq!(file.is_directory(), true);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), false);
        assert_eq!(file.can_write(PosixPexQuery::Group), false);
        assert_eq!(file.can_execute(PosixPexQuery::Group), false);
        assert_eq!(file.can_read(PosixPexQuery::Others), false);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), false);
        // Sticky bit
        let file: File =
            File::from_str("drwx-----t    2 u-redacted g-redacted      3864 Feb 17  2023 sas")
                .ok()
                .unwrap();
        assert_eq!(file.is_directory(), true);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), false);
        assert_eq!(file.can_write(PosixPexQuery::Group), false);
        assert_eq!(file.can_execute(PosixPexQuery::Group), false);
        assert_eq!(file.can_read(PosixPexQuery::Others), false);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), true);
        let file: File =
            File::from_str("drwx--S--T    2 u-redacted g-redacted      3864 Feb 17  2023 sas")
                .ok()
                .unwrap();
        assert_eq!(file.is_directory(), true);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), false);
        assert_eq!(file.can_write(PosixPexQuery::Group), false);
        assert_eq!(file.can_execute(PosixPexQuery::Group), false);
        assert_eq!(file.can_read(PosixPexQuery::Others), false);
        assert_eq!(file.can_write(PosixPexQuery::Others), false);
        assert_eq!(file.can_execute(PosixPexQuery::Others), false);

        // Error
        assert_eq!(
            File::from_posix_line("drwxrwxr-x 1 0  9  Nov 5 2018 docs")
                .err()
                .unwrap(),
            ParseError::SyntaxError
        );
        assert_eq!(
            File::from_posix_line("drwxrwxr-x 1 root  dialout  4096 Nov 31 2018 provola")
                .err()
                .unwrap(),
            ParseError::InvalidDate
        );
    }

    #[test]
    fn should_parse_utf8_names_in_ls_output() {
        assert!(File::try_from(
            "-rw-rw-r-- 1 омар  www-data  8192 Nov 5 2018 фообар.txt".to_string()
        )
        .is_ok());
    }

    #[test]
    fn parse_dos_line() {
        let file: File = File::try_from("04-08-14  03:09PM  8192 omar.txt".to_string())
            .ok()
            .unwrap();
        assert_eq!(file.name(), "omar.txt");
        assert_eq!(file.size, 8192);
        assert!(file.is_file());
        assert_eq!(file.gid, None);
        assert_eq!(file.uid, None);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), true);
        assert_eq!(file.can_write(PosixPexQuery::Group), true);
        assert_eq!(file.can_execute(PosixPexQuery::Group), true);
        assert_eq!(file.can_read(PosixPexQuery::Others), true);
        assert_eq!(file.can_write(PosixPexQuery::Others), true);
        assert_eq!(file.can_execute(PosixPexQuery::Others), true);
        assert_eq!(
            file.modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(1396969740)
        );
        // Parse directory
        let dir: File = File::try_from("04-08-14  03:09PM  <DIR> docs")
            .ok()
            .unwrap();
        assert_eq!(dir.name(), "docs");
        assert!(dir.is_directory());
        assert_eq!(dir.uid, None);
        assert_eq!(dir.gid, None);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), true);
        assert_eq!(file.can_write(PosixPexQuery::Group), true);
        assert_eq!(file.can_execute(PosixPexQuery::Group), true);
        assert_eq!(file.can_read(PosixPexQuery::Others), true);
        assert_eq!(file.can_write(PosixPexQuery::Others), true);
        assert_eq!(file.can_execute(PosixPexQuery::Others), true);
        assert_eq!(
            dir.modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(1396969740)
        );
        // Error
        assert_eq!(
            File::from_dos_line("-08-14  03:09PM  <DIR> docs")
                .err()
                .unwrap(),
            ParseError::SyntaxError
        );
        assert_eq!(
            File::from_dos_line("34-08-14  03:09PM  <DIR> docs")
                .err()
                .unwrap(),
            ParseError::InvalidDate
        );
        assert_eq!(
            File::from_dos_line("04-08-14  03:09PM  OMAR docs")
                .err()
                .unwrap(),
            ParseError::BadSize
        );
    }

    #[test]
    fn test_should_parse_name_starting_with_tricky_numbers() {
        let file = File::from_posix_line(
            "-r--r--r--    1 23        23         1234567 Jan 1  2000 01 1234 foo.mp3",
        )
        .unwrap();
        assert_eq!(file.name(), "01 1234 foo.mp3");
        assert_eq!(file.size, 1234567);
        assert_eq!(
            file.modified
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(946684800)
        );
    }

    #[test]
    fn get_name_and_link() {
        assert_eq!(
            File::get_name_and_link("Cargo.toml"),
            (String::from("Cargo.toml"), None)
        );
        assert_eq!(
            File::get_name_and_link("Cargo -> Cargo.toml"),
            (String::from("Cargo"), Some(PathBuf::from("Cargo.toml")))
        );
    }

    #[test]
    fn parse_lstime() {
        // Good cases
        assert_eq!(
            fmt_time(
                File::parse_lstime("Nov 5 16:32", "%b %d %Y", "%b %d %H:%M")
                    .ok()
                    .unwrap(),
                "%m %d %M"
            )
            .as_str(),
            "11 05 32"
        );
        assert_eq!(
            fmt_time(
                File::parse_lstime("Dec 2 21:32", "%b %d %Y", "%b %d %H:%M")
                    .ok()
                    .unwrap(),
                "%m %d %M"
            )
            .as_str(),
            "12 02 32"
        );
        assert_eq!(
            File::parse_lstime("Nov 5 2018", "%b %d %Y", "%b %d %H:%M")
                .ok()
                .unwrap()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(1541376000)
        );
        assert_eq!(
            File::parse_lstime("Mar 18 2018", "%b %d %Y", "%b %d %H:%M")
                .ok()
                .unwrap()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(1521331200)
        );
        // bad cases
        assert!(File::parse_lstime("Oma 31 2018", "%b %d %Y", "%b %d %H:%M").is_err());
        assert!(File::parse_lstime("Feb 31 2018", "%b %d %Y", "%b %d %H:%M").is_err());
        assert!(File::parse_lstime("Feb 15 25:32", "%b %d %Y", "%b %d %H:%M").is_err());
    }

    #[test]
    fn parse_dostime() {
        assert_eq!(
            File::parse_dostime("04-08-14  03:09PM")
                .ok()
                .unwrap()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .unwrap(),
            Duration::from_secs(1396969740)
        );
        // Not enough argument for datetime
        assert!(File::parse_dostime("04-08-14").is_err());
    }

    #[test]
    fn test_parse_mlsx_line() {
        let file = File::from_mlsx_line("type=file;size=8192;modify=20181105163248; omar.txt")
            .ok()
            .unwrap();

        assert_eq!(file.name(), "omar.txt");
        assert_eq!(file.size, 8192);
        assert!(file.is_file());
        assert_eq!(file.gid, None);
        assert_eq!(file.uid, None);
        assert_eq!(file.can_read(PosixPexQuery::Owner), true);
        assert_eq!(file.can_write(PosixPexQuery::Owner), true);
        assert_eq!(file.can_execute(PosixPexQuery::Owner), true);
        assert_eq!(file.can_read(PosixPexQuery::Group), true);
        assert_eq!(file.can_write(PosixPexQuery::Group), true);
        assert_eq!(file.can_execute(PosixPexQuery::Group), true);
        assert_eq!(file.can_read(PosixPexQuery::Others), true);
        assert_eq!(file.can_write(PosixPexQuery::Others), true);
        assert_eq!(file.can_execute(PosixPexQuery::Others), true);

        let file = File::from_mlsx_line("type=dir;size=4096;modify=20181105163248; docs")
            .ok()
            .unwrap();

        assert_eq!(file.name(), "docs");
        assert!(file.is_directory());

        let file = File::from_mlsx_line(
            "type=file;size=4096;modify=20181105163248;unix.mode=644; omar.txt",
        )
        .ok()
        .unwrap();
        assert_eq!(
            file.posix_pex,
            (PosixPex::from(6), PosixPex::from(4), PosixPex::from(4))
        );
    }

    #[test]
    fn file_type() {
        assert_eq!(FileType::Directory.is_directory(), true);
        assert_eq!(FileType::Directory.is_file(), false);
        assert_eq!(FileType::Directory.is_symlink(), false);
        assert_eq!(FileType::Directory.symlink(), None);
        assert_eq!(FileType::File.is_directory(), false);
        assert_eq!(FileType::File.is_file(), true);
        assert_eq!(FileType::File.is_symlink(), false);
        assert_eq!(FileType::File.symlink(), None);
        assert_eq!(FileType::Symlink(PathBuf::default()).is_directory(), false);
        assert_eq!(FileType::Symlink(PathBuf::default()).is_file(), false);
        assert_eq!(FileType::Symlink(PathBuf::default()).is_symlink(), true);
        assert_eq!(
            FileType::Symlink(PathBuf::default()).symlink(),
            Some(PathBuf::default().as_path())
        );
    }

    #[test]
    fn posix_pex_from_bits() {
        let pex: PosixPex = PosixPex::from(4);
        assert_eq!(pex.can_read(), true);
        assert_eq!(pex.can_write(), false);
        assert_eq!(pex.can_execute(), false);
        let pex: PosixPex = PosixPex::from(0);
        assert_eq!(pex.can_read(), false);
        assert_eq!(pex.can_write(), false);
        assert_eq!(pex.can_execute(), false);
        let pex: PosixPex = PosixPex::from(3);
        assert_eq!(pex.can_read(), false);
        assert_eq!(pex.can_write(), true);
        assert_eq!(pex.can_execute(), true);
        let pex: PosixPex = PosixPex::from(7);
        assert_eq!(pex.can_read(), true);
        assert_eq!(pex.can_write(), true);
        assert_eq!(pex.can_execute(), true);
    }

    // -- utils

    fn fmt_time(time: SystemTime, fmt: &str) -> String {
        let datetime: DateTime<Utc> = time.into();
        format!("{}", datetime.format(fmt))
    }
}
