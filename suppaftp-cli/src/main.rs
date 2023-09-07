//! # SuppaFTP Client
//!
//! This is a client you can install via `cargo install suppaftp` on your system to connect and work with FTP servers
//!

// -- mods
mod actions;
mod args;
mod command;

use actions::*;
use args::Args;
use command::Command;

use env_logger::Builder as LogBuilder;
use log::LevelFilter;
use std::io;
use std::io::Write;
use std::str::FromStr;
use suppaftp::{FtpError, NativeTlsFtpStream as FtpStream};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

fn usage() {
    println!("Available commands:");
    println!("APPE <file> <dest>                  Append content of local file `file` to `dest`");
    println!("CDUP                                Go to parent directory");
    println!("CONNECT <addr:port>                 Connect to remote host");
    println!("CONNECT+S <addr:port>               Connect to remote host using FTPS");
    println!("CWD <dir>                           Change working directory");
    println!("FEAT                                Get supported features on the server");
    println!("HELP                                Print this help");
    println!("LIST [dir]                          List files. If directory is not provided, current directory is used");
    println!("LOGIN                               Login to remote");
    println!("MDTM <file>                         Get modification time for `file`");
    println!("MODE <PASSIVE|EXTPASSIVE|ACTIVE>    Set mode");
    println!("NOOP                                Ping server");
    println!("OPTS <feature-name> [feature-value] Set a feature on the server (e.g. OPTS UTF8 ON)");
    println!("PUT <file> <dest>                   Upload local file `file` to `dest`");
    println!("PWD                                 Print working directory");
    println!("QUIT                                Quit suppaftp");
    println!("RENAME <source> <dest>              Rename file `source` to `dest`");
    println!("RETR <file> <dest>                  Download `file` to `dest`");
    println!("RM <file>                           Remove file");
    println!("RMDIR <dir>                         Remove directory");
    println!("SIZE <file>                         Get `file` size");
}

fn input() -> Command {
    loop {
        print!(">> ");
        let _ = io::stdout().flush();
        let mut input: String = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read stdin");
        // Try to create command
        if let Ok(cmd) = Command::from_str(input.as_str()) {
            return cmd;
        }
        println!("Unknown command");
    }
}

fn main() {
    let args: Args = argh::from_env();
    // print version
    if args.version {
        println!("suppaftp {APP_VERSION} - developed by {APP_AUTHORS}")
    }
    // init logger
    LogBuilder::new()
        .filter_level(if args.debug {
            LevelFilter::Trace
        } else if args.verbose {
            LevelFilter::Info
        } else {
            LevelFilter::Off
        })
        .init();
    // Main loop
    let mut ftp: Option<FtpStream> = None;

    // connect if host is specified
    if let Some(host) = args.host {
        perform(&mut ftp, Command::Connect(host, false));
    }

    loop {
        match input() {
            Command::Quit => {
                // Break if quit
                quit(ftp);
                break;
            }
            Command::Help => usage(),
            cmd => perform(&mut ftp, cmd),
        }
    }
}

fn perform(ftp: &mut Option<FtpStream>, command: Command) {
    match ftp {
        Some(ftp) => perform_connected(ftp, command),
        None => {
            if let Some(stream) = perform_uninitialized(command) {
                *ftp = Some(stream);
            }
        }
    }
}

fn perform_uninitialized(command: Command) -> Option<FtpStream> {
    match command {
        Command::Connect(remote, secure) => connect(remote.as_str(), secure),
        _ => {
            eprintln!("Can't perform command: you must connect to remote first");
            None
        }
    }
}

fn perform_connected(ftp: &mut FtpStream, command: Command) {
    match command {
        Command::Appe(src, dest) => appe(ftp, src.as_path(), dest.as_str()),
        Command::Cdup => cdup(ftp),
        Command::Connect(remote, secure) => {
            if let Some(stream) = connect(remote.as_str(), secure) {
                *ftp = stream;
            }
        }
        Command::Cwd(dir) => cwd(ftp, dir.as_str()),
        Command::List(p) => list(ftp, p.as_deref()),
        Command::Feat => feat(ftp),
        Command::Login => login(ftp),
        Command::Mdtm(p) => mdtm(ftp, p.as_str()),
        Command::Mkdir(p) => mkdir(ftp, p.as_str()),
        Command::Mode(m) => set_mode(ftp, m),
        Command::Noop => noop(ftp),
        Command::Opts(feature, values) => opts(ftp, feature, values),
        Command::Put(src, dest) => put(ftp, src.as_path(), dest.as_str()),
        Command::Pwd => pwd(ftp),
        Command::Rename(src, dest) => rename(ftp, src.as_str(), dest.as_str()),
        Command::Retr(file, dest) => retr(ftp, file.as_str(), dest.as_path()),
        Command::Rm(file) => rm(ftp, file.as_str()),
        Command::Rmdir(file) => rmdir(ftp, file.as_str()),
        Command::Size(file) => size(ftp, file.as_str()),
        Command::Help | Command::Quit => {
            panic!("Something unexpected happened")
        }
    }
}
