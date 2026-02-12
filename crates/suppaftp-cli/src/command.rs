use std::path::PathBuf;
use std::str::FromStr;

use suppaftp::Mode;

pub enum Command {
    Appe(PathBuf, String),
    Cdup,
    Connect(String, bool),
    Cwd(String),
    Feat,
    Help,
    List(Option<String>),
    Login,
    Mdtm(String),
    Mlsd(Option<String>),
    Mlst(Option<String>),
    Mkdir(String),
    Mode(Mode),
    Noop,
    Opts(String, Option<String>),
    Put(PathBuf, String),
    Pwd,
    Quit,
    Rename(String, String),
    Retr(String, PathBuf),
    Rm(String),
    Rmdir(String),
    Size(String),
}

impl FromStr for Command {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split string by space
        let mut args = s.split_ascii_whitespace();
        // Match args
        match args.next() {
            Some(cmd) => match cmd.to_ascii_uppercase().as_str() {
                "APPE" => {
                    let local: PathBuf = match args.next() {
                        Some(l) => PathBuf::from(l),
                        None => return Err("Missing `source` field"),
                    };
                    match args.next() {
                        Some(d) => Ok(Self::Appe(local, d.to_string())),
                        None => Err("Missing `dest` field"),
                    }
                }
                "CDUP" => Ok(Self::Cdup),
                "CONNECT" => match args.next() {
                    Some(addr) => Ok(Self::Connect(addr.to_string(), false)),
                    None => Err("Missing `addr` field"),
                },
                "CONNECT+S" => match args.next() {
                    Some(addr) => Ok(Self::Connect(addr.to_string(), true)),
                    None => Err("Missing `addr` field"),
                },
                "CWD" => match args.next() {
                    Some(p) => Ok(Self::Cwd(p.to_string())),
                    None => Err("Missing `dir` field"),
                },
                "FEAT" => Ok(Self::Feat),
                "HELP" => Ok(Self::Help),
                "LIST" => match args.next() {
                    Some(dir) => Ok(Self::List(Some(dir.to_string()))),
                    None => Ok(Self::List(None)),
                },
                "LOGIN" => Ok(Self::Login),
                "MDTM" => match args.next() {
                    Some(file) => Ok(Self::Mdtm(file.to_string())),
                    None => Err("Missing `file` field"),
                },
                "MKDIR" => match args.next() {
                    Some(file) => Ok(Self::Mkdir(file.to_string())),
                    None => Err("Missing `file` field"),
                },
                "MLSD" => match args.next() {
                    Some(dir) => Ok(Self::Mlsd(Some(dir.to_string()))),
                    None => Ok(Self::Mlsd(None)),
                },
                "MLST" => match args.next() {
                    Some(dir) => Ok(Self::Mlst(Some(dir.to_string()))),
                    None => Ok(Self::Mlst(None)),
                },
                "MODE" => match args.next() {
                    Some("ACTIVE") => Ok(Self::Mode(Mode::Active)),
                    Some("EXTPASSIVE") => Ok(Self::Mode(Mode::ExtendedPassive)),
                    Some("PASSIVE") => Ok(Self::Mode(Mode::Passive)),
                    Some(_) => Err("Invalid mode"),
                    None => Err("Missing `mode` field"),
                },
                "NOOP" => Ok(Self::Noop),
                "OPTS" => {
                    let feature_name = match args.next() {
                        Some(s) => s.to_string(),
                        None => return Err("Missing `feature-name` field"),
                    };
                    match args.collect::<Vec<&str>>().join(" ") {
                        s if s.is_empty() => Ok(Self::Opts(feature_name, None)),
                        s => Ok(Self::Opts(feature_name, Some(s.to_string()))),
                    }
                }
                "PUT" => {
                    let local: PathBuf = match args.next() {
                        Some(l) => PathBuf::from(l),
                        None => return Err("Missing `source` field"),
                    };
                    match args.next() {
                        Some(d) => Ok(Self::Put(local, d.to_string())),
                        None => Err("Missing `dest` field"),
                    }
                }
                "PWD" => Ok(Self::Pwd),
                "QUIT" => Ok(Self::Quit),
                "RENAME" => {
                    let src: String = match args.next() {
                        Some(s) => s.to_string(),
                        None => return Err("Missing `src` field"),
                    };
                    match args.next() {
                        Some(d) => Ok(Self::Rename(src, d.to_string())),
                        None => Err("Missing `dest` field"),
                    }
                }
                "RETR" => {
                    let file: String = match args.next() {
                        Some(f) => f.to_string(),
                        None => return Err("Missing `file` field"),
                    };
                    match args.next() {
                        Some(d) => Ok(Self::Retr(file, PathBuf::from(d))),
                        None => Err("Missing `dest` field"),
                    }
                }
                "RM" => match args.next() {
                    Some(file) => Ok(Self::Rm(file.to_string())),
                    None => Err("Missing `file` field"),
                },
                "RMDIR" => match args.next() {
                    Some(dir) => Ok(Self::Rmdir(dir.to_string())),
                    None => Err("Missing `file` field"),
                },
                "SIZE" => match args.next() {
                    Some(dir) => Ok(Self::Size(dir.to_string())),
                    None => Err("Missing `file` field"),
                },
                _ => Err("Unknown command"),
            },
            None => Err("Unknown command"),
        }
    }
}
