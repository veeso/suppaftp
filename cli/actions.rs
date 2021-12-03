use super::{FtpError, FtpStream};

use std::fs::File;
use std::io;
use std::path::Path;
use suppaftp::native_tls::TlsConnector;
use suppaftp::types::FileType;
use suppaftp::Mode;

pub fn quit(mut ftp: Option<FtpStream>) {
    if let Some(mut ftp) = ftp.take() {
        match ftp.quit() {
            Ok(_) => println!("OK"),
            Err(err) => eprintln!("Failed to disconnect from remote: {}", err),
        }
    }
}

pub fn cdup(ftp: &mut FtpStream) {
    match ftp.cdup() {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("CDUP error: {}", err),
    }
}

pub fn connect(remote: &str, secure: bool) -> Option<FtpStream> {
    let mut stream: FtpStream = match FtpStream::connect(remote) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Failed to connect to remote: {}", err);
            return None;
        }
    };
    // if secure, enable TLS
    if secure {
        let ctx = match TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
        {
            Ok(tls) => tls,
            Err(err) => {
                eprintln!("Failed to setup TLS stream: {}", err);
                return None;
            }
        };
        // Get address without port
        let address: &str = remote.split(':').next().unwrap();
        stream = match stream.into_secure(ctx, address) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("Failed to setup TLS stream: {}", err);
                return None;
            }
        };
    }
    // Set transfer type to binary
    if let Err(err) = stream.transfer_type(FileType::Binary) {
        eprintln!("Failed to set transfer type to binary: {}", err);
    }
    println!("OK");
    Some(stream)
}

pub fn cwd(ftp: &mut FtpStream, dir: &str) {
    match ftp.cwd(dir) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("CWD error: {}", err),
    }
}

pub fn list(ftp: &mut FtpStream, p: Option<&str>) {
    match ftp.list(p) {
        Ok(files) => {
            files.iter().for_each(|f| println!("{}", f));
        }
        Err(err) => eprintln!("LIST error: {}", err),
    }
}

pub fn login(ftp: &mut FtpStream) {
    // Read username
    let username: String = match rpassword::read_password_from_tty(Some("Username: ")) {
        Ok(u) => u,
        Err(err) => {
            eprintln!("Could not read username: {}", err);
            return;
        }
    };
    println!();
    // Read password
    let password: String = match rpassword::read_password_from_tty(Some("Password: ")) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("Could not read password: {}", err);
            return;
        }
    };
    println!();
    // Login
    match ftp.login(username.as_str(), password.as_str()) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("LOGIN error: {}", err),
    }
}

pub fn mdtm(ftp: &mut FtpStream, f: &str) {
    match ftp.mdtm(f) {
        Ok(time) => println!("OK: {}", time),
        Err(err) => eprintln!("MDTM error: {}", err),
    }
}

pub fn mkdir(ftp: &mut FtpStream, f: &str) {
    match ftp.mkdir(f) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("MDTM error: {}", err),
    }
}

pub fn set_mode(ftp: &mut FtpStream, mode: Mode) {
    ftp.set_mode(mode);
    println!("OK");
}

pub fn noop(ftp: &mut FtpStream) {
    match ftp.noop() {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("NOOP error: {}", err),
    }
}

pub fn put(ftp: &mut FtpStream, local: &Path, dest: &str) {
    let mut reader = match File::open(local) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("Failed to open local file for read: {}", err);
            return;
        }
    };
    match ftp.put_file(dest, &mut reader) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("PUT error: {}", err),
    }
}

pub fn pwd(ftp: &mut FtpStream) {
    match ftp.pwd() {
        Ok(p) => println!("OK: {}", p),
        Err(err) => eprintln!("PWD error: {}", err),
    }
}

pub fn rename(ftp: &mut FtpStream, src: &str, dest: &str) {
    match ftp.rename(src, dest) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("RENAME error: {}", err),
    }
}

pub fn retr(ftp: &mut FtpStream, file: &str, dest: &Path) {
    let mut dest: File = match File::create(dest) {
        Ok(d) => d,
        Err(err) => {
            eprintln!("Failed to open destination file: {}", err);
            return;
        }
    };
    match ftp.retr(file, move |reader| {
        io::copy(reader, &mut dest)
            .map(|_| ())
            .map_err(FtpError::ConnectionError)
    }) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("RETR error: {}", err),
    }
}

pub fn rm(ftp: &mut FtpStream, file: &str) {
    match ftp.rm(file) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("RM error: {}", err),
    }
}

pub fn rmdir(ftp: &mut FtpStream, dir: &str) {
    match ftp.rmdir(dir) {
        Ok(_) => println!("OK"),
        Err(err) => eprintln!("RMDIR error: {}", err),
    }
}

pub fn size(ftp: &mut FtpStream, file: &str) {
    match ftp.size(file) {
        Ok(size) => println!("OK: {}", size),
        Err(err) => eprintln!("SIZE error: {}", err),
    }
}
