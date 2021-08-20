# SuppaFTP

<p align="center">
  <img src="/assets/images/suppaftp.svg" width="256" height="256" />
</p>
<p align="center">~ A super FTP/FTPS client library for Rust ~</p>
<p align="center">
  <a href="https://docs.rs/suppaftp" target="_blank">Documentation</a>
  ·
  <a href="https://crates.io/crates/suppaftp" target="_blank">Crates.io</a>
</p>

<p align="center">Developed by <a href="https://veeso.github.io/">veeso</a> and <a href="https://github.com/mattnenterprise">Matt McCoy</a></p>
<p align="center">Current version: 4.1.0 (20/08/2021)</p>

[![Number of Crate Downloads](https://img.shields.io/crates/d/suppaftp.svg)](https://crates.io/crates/suppaftp)
[![Crate Version](https://img.shields.io/crates/v/suppaftp.svg)](https://crates.io/crates/suppaftp)
[![Crate License](https://img.shields.io/crates/l/suppaftp.svg)](https://crates.io/crates/suppaftp)
[![Docs](https://docs.rs/suppaftp/badge.svg)](https://docs.rs/suppaftp)  

[![Build](https://github.com/veeso/rust-suppaftp/workflows/Build/badge.svg)](https://github.com/veeso/rust-suppaftp/actions) [![Coverage](https://github.com/veeso/rust-suppaftp/workflows/Coverage/badge.svg)](https://github.com/veeso/rust-suppaftp/actions) [![Coverage Status](https://coveralls.io/repos/github/veeso/rust-suppaftp/badge.svg)](https://coveralls.io/github/veeso/rust-suppaftp)

---

- [SuppaFTP](#suppaftp)
  - [Introduction 👋](#introduction-)
    - [Main differences between SuppaFTP and rust-ftp 🤔](#main-differences-between-suppaftp-and-rust-ftp-)
  - [Get started 🏁](#get-started-)
    - [Features](#features)
      - [SSL/TLS Support](#ssltls-support)
      - [Async support](#async-support)
    - [Example 📚](#example-)
  - [Changelog](#changelog)
  - [License 📜](#license-)
    - [Contribution 🤝](#contribution-)

---

## Introduction 👋

SuppaFTP is a FTP/FTPS client library written in Rust. It is a fork of the original ftp library "[rust-ftp](https://github.com/mattnenterprise/rust-ftp)", but since the original library is currently unmaintened, I decided to keep working on this library by myself. Currently, I consider myself as the only maintainer of this project, indeed I've already added some features to the library and improved it with better error handling and test units. Then, feel free to use this library instead of the classic *rust-ftp* if you want, and if you have any feature request or issue to report, please open an issue on this repository; I will answer you as soon as possible.

### Main differences between SuppaFTP and rust-ftp 🤔

- Added methods to work with streams (e.g. `put_with_stream`) ⬇️
- Added `get_welcome_msg` method 👋
- Supports for both sync/async rust
- Some extra features, such as the **LIST** command output parser
- Replaced openssl with native-tls 🔒
- Removed deprecated statements 👴
- Better error handling 🐛
- Added test units keeping an eye on code coverage 👀

---

## Get started 🏁

To get started, first add **suppaftp** to your dependencies:

```toml
suppaftp = "4.1.0"
```

### Features

#### SSL/TLS Support

If you want to enable **support for FTPS**, you must enable the `secure` feature in your cargo dependencies. FTPS support is achieved through [rust-native-tls](https://github.com/sfackler/rust-native-tls), so check if your target systems are compatible.

```toml
suppaftp = { version = "4.1.0", features = ["secure"] }
```

#### Async support

If you want to enable **async** support, you must enable `async` feature in your cargo dependencies.

```toml
suppaftp = { version = "4.1.0", features = ["async"] }
```

⚠️ If you want to enable both **secure** and **async** you must use the **async-secure** feature ⚠️

### Example 📚

```rust
extern crate suppaftp;

use std::str;
use std::io::Cursor;
use suppaftp::FtpStream;

fn main() {
    // Create a connection to an FTP server and authenticate to it.
    let mut ftp_stream = FtpStream::connect("127.0.0.1:21").unwrap();
    let _ = ftp_stream.login("username", "password").unwrap();

    // Get the current directory that the client will be reading from and writing to.
    println!("Current directory: {}", ftp_stream.pwd().unwrap());

    // Change into a new directory, relative to the one we are currently in.
    let _ = ftp_stream.cwd("test_data").unwrap();

    // Retrieve (GET) a file from the FTP server in the current working directory.
    let data = ftp_stream.retr_as_buffer("ftpext-charter.txt").unwrap();
    println!("Read file with contents\n{}\n", str::from_utf8(&data.into_inner()).unwrap());

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
