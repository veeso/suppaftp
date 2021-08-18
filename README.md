# rust-ftp

<p align="center">~ An FTP/FTPS client library for Rust ~</p>
<p align="center">
  <a href="https://docs.rs/ftp4" target="_blank">Documentation</a>
  ·
  <a href="https://crates.io/crates/ftp4" target="_blank">Crates.io</a>
</p>

<p align="center">Developed by <a href="https://veeso.github.io/">veeso</a> and <a href="https://github.com/mattnenterprise">Matt McCoy</a></p>
<p align="center">Current version: 4.1.0 (FIXME: 23/07/2021)</p>

[![Number of Crate Downloads](https://img.shields.io/crates/d/ftp4.svg)](https://crates.io/crates/ftp4)
[![Crate Version](https://img.shields.io/crates/v/ftp4.svg)](https://crates.io/crates/ftp4)
[![Crate License](https://img.shields.io/crates/l/ftp4.svg)](https://crates.io/crates/ftp4)
[![Docs](https://docs.rs/ftp4/badge.svg)](https://docs.rs/ftp4)  

[![Build](https://github.com/veeso/rust-ftp4/workflows/Build/badge.svg)](https://github.com/veeso/rust-ftp4/actions) [![Coverage](https://github.com/veeso/rust-ftp4/workflows/Coverage/badge.svg)](https://github.com/veeso/rust-ftp4/actions) [![Coverage Status](https://coveralls.io/repos/github/veeso/rust-ftp4/badge.svg)](https://coveralls.io/github/veeso/rust-ftp4)

---

- [rust-ftp](#rust-ftp)
  - [Introduction 👋](#introduction-)
    - [Main differences between ftp4 and rust-ftp 🤔](#main-differences-between-ftp4-and-rust-ftp-)
  - [Get started 🏁](#get-started-)
    - [Usage 📚](#usage-)
  - [Changelog](#changelog)
  - [License 📜](#license-)
    - [Contribution 🤝](#contribution-)

---

## Introduction 👋

ftp4 is a FTP/FTPS client library written in Rust. It is a fork of the original ftp library "[rust-ftp](https://github.com/mattnenterprise/rust-ftp)", but since this library is unmaintened, I decided to keep working on this library by myself since I needed to add some features for [termscp](https://github.com/veeso/termscp). Sometimes, when I need to I add some features, so feel free to use this library if you want.

### Main differences between ftp4 and rust-ftp 🤔

- Added methods to work with streams (e.g. `put_with_stream`) ⬇️
- Added `get_welcome_msg` method 👋
- Replaced openssl with native-tls 🔒
- Removed deprecated statements 👴
- Better error handling 🐛
- Added test units keeping an eye on code coverage 👀

---

## Get started 🏁

To get started, first add **ftp4** to your dependencies:

```toml
ftp4 = "4.1.0"
```

or if you want to enable **TLS support for FTPS**. FTPS support is achieved through [rust-native-tls](https://github.com/sfackler/rust-native-tls), so check if your target systems are compatible.

```toml
ftp4 = { version = "4.1.0", features = ["secure"] }
```

### Usage 📚

```rust
extern crate ftp4;

use std::str;
use std::io::Cursor;
use ftp4::FtpStream;

fn main() {
    // Create a connection to an FTP server and authenticate to it.
    let mut ftp_stream = FtpStream::connect("127.0.0.1:21").unwrap();
    let _ = ftp_stream.login("username", "password").unwrap();

    // Get the current directory that the client will be reading from and writing to.
    println!("Current directory: {}", ftp_stream.pwd().unwrap());

    // Change into a new directory, relative to the one we are currently in.
    let _ = ftp_stream.cwd("test_data").unwrap();

    // Retrieve (GET) a file from the FTP server in the current working directory.
    let remote_file = ftp_stream.simple_retr("ftpext-charter.txt").unwrap();
    println!("Read file with contents\n{}\n", str::from_utf8(&remote_file.into_inner()).unwrap());

    // Store (PUT) a file from the client to the current working directory of the server.
    let mut reader = Cursor::new("Hello from the Rust \"ftp\" crate!".as_bytes());
    let _ = ftp_stream.put("greeting.txt", &mut reader);
    println!("Successfully wrote greeting.txt");

    // Terminate the connection to the server.
    let _ = ftp_stream.quit();
}

```

## Changelog

View Changelog [here](CHANGELOG.md)

## License 📜

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution 🤝

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
