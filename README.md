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
<p align="center">Current version: 4.4.0 (02/08/2022)</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"
    ><img
      src="https://img.shields.io/crates/l/suppaftp.svg"
      alt="License-Apache-2.0/MIT"
  /></a>
  <a href="https://github.com/veeso/suppaftp/stargazers"
    ><img
      src="https://img.shields.io/github/stars/veeso/suppaftp.svg"
      alt="Repo stars"
  /></a>
  <a href="https://crates.io/crates/suppaftp"
    ><img
      src="https://img.shields.io/crates/d/suppaftp.svg"
      alt="Downloads counter"
  /></a>
  <a href="https://crates.io/crates/suppaftp"
    ><img
      src="https://img.shields.io/crates/v/suppaftp.svg"
      alt="Latest version"
  /></a>
  <a href="https://ko-fi.com/veeso">
    <img
      src="https://img.shields.io/badge/donate-ko--fi-red"
      alt="Ko-fi"
  /></a>
</p>
<p align="center">
  <a href="https://github.com/veeso/suppaftp/actions"
    ><img
      src="https://github.com/veeso/suppaftp/workflows/Build/badge.svg"
      alt="Linux CI"
  /></a>
  <a href="https://coveralls.io/github/veeso/suppaftp"
    ><img
      src="https://coveralls.io/repos/github/veeso/suppaftp/badge.svg"
      alt="Coveralls"
  /></a>
  <a href="https://docs.rs/suppaftp"
    ><img
      src="https://docs.rs/suppaftp/badge.svg"
      alt="Docs"
  /></a>
</p>

---

- [SuppaFTP](#suppaftp)
  - [Introduction 👋](#introduction-)
    - [Main differences between SuppaFTP and rust-ftp 🤔](#main-differences-between-suppaftp-and-rust-ftp-)
  - [Get started 🏁](#get-started-)
    - [Features](#features)
      - [SSL/TLS Support](#ssltls-support)
      - [Async support](#async-support)
      - [Deprecated methods](#deprecated-methods)
      - [Logging](#logging)
    - [Examples 📚](#examples-)
      - [Ftp with TLS (native-tls)](#ftp-with-tls-native-tls)
      - [Ftp with TLS (rustls)](#ftp-with-tls-rustls)
      - [Going Async](#going-async)
  - [Built-in CLI client 🖥️](#built-in-cli-client-️)
  - [Support the developer ☕](#support-the-developer-)
  - [Changelog ⌛](#changelog-)
  - [License 📜](#license-)
    - [Contribution 🤝](#contribution-)

---

## Introduction 👋

SuppaFTP is a FTP/FTPS client library written in Rust, with both support for sync/async programming. It is a fork of the original ftp library "[rust-ftp](https://github.com/mattnenterprise/rust-ftp)", but since the original library is currently unmaintained, I decided to keep working on this library by myself. Currently, I consider myself as the only maintainer of this project, indeed I've already added some features to the library and improved it with better error handling and test units. Then, feel free to use this library instead of the classic *rust-ftp* if you want, and if you have any feature request or issue to report, please open an issue on this repository; I will answer you as soon as possible.

### Main differences between SuppaFTP and rust-ftp 🤔

- Added methods to work with streams (e.g. `put_with_stream`) ⬇️
- suppaftp supports **Active mode**
- Added `get_welcome_msg` method 👋
- Supports for both **sync/async** rust 🕙
- Supports for more commands 🌟
  - ABOR
  - APPE
  - REST
- Some extra features, such as the **LIST** command output parser
- Replaced OpenSSL with native-tls 🔒
- Removed deprecated statements ⚰️
- Better error handling 🐛
- Added test units keeping an eye on code coverage 👀

---

## Get started 🏁

To get started, first add **suppaftp** to your dependencies:

```toml
suppaftp = "^4.4.0"
```

### Features

#### SSL/TLS Support

If you want to enable **support for FTPS**, you must enable the `native-tls` or `rustls` feature in your cargo dependencies, based on the TLS provider you prefer.

```toml
suppaftp = { version = "^4.4.0", features = ["native-tls"] }
# or
suppaftp = { version = "^4.4.0", features = ["rustls"] }
```

> 💡 If you don't know what to choose, `native-tls` should be preferred for compatibility reasons.

#### Async support

If you want to enable **async** support, you must enable `async` feature in your cargo dependencies.

```toml
suppaftp = { version = "^4.4.0", features = ["async"] }
```

> ⚠️ If you want to enable both **native-tls** and **async** you must use the **async-native-tls** feature ⚠️
> ⚠️ If you want to enable both **rustls** and **async** you must use the **async-rustls** feature ⚠️

#### Deprecated methods

If you want to enable deprecated methods of FTPS, please enable the `deprecated` feature in your cargo dependencies.

This feature enables these methods:

- `connect_secure_implicit()`: used to connect via implicit FTPS

#### Logging

By default, the library will log if there is any `log` crate consumer on the user implementation.
Logging can be if preferred, disabled via the `no-log` feature.

### Examples 📚

```rust
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

#### Ftp with TLS (native-tls)

```rust
use std::str;
use std::io::Cursor;
use suppaftp::{FtpStream};
use suppaftp::native_tls::TlsConnector;

fn main() {
    // Create a connection to an FTP server and authenticate to it.
    let mut ftp_stream = FtpStream::connect("127.0.0.1:21")
        .into_secure(NativeTlsConnector::new().unwrap().into(), "domain-name")
        .unwrap();
    // Terminate the connection to the server.
    let _ = ftp_stream.quit();
}
```

#### Ftp with TLS (rustls)

```rust
use std::str;
use std::io::Cursor;
use std::sync::Arc;
use suppaftp::{FtpStream};
use suppaftp::rustls::ClientConfig;

fn main() {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    // Create a connection to an FTP server and authenticate to it.
    let config = Arc::new(rustls_config());
    let mut ftp_stream = FtpStream::connect("test.rebex.net:21")
        .unwrap()
        .into_secure(Arc::clone(&config).into(), "test.rebex.net")
        .unwrap();
    // Terminate the connection to the server.
    let _ = ftp_stream.quit();
}
```

#### Going Async

```rust
use suppaftp::FtpStream;
use suppaftp::async_native_tls::{TlsConnector, TlsStream};
let ftp_stream = FtpStream::connect("test.rebex.net:21").await.unwrap();
// Switch to the secure mode
let mut ftp_stream = ftp_stream.into_secure(TlsConnector::new().into(), "test.rebex.net").await.unwrap();
ftp_stream.login("demo", "password").await.unwrap();
// Do other secret stuff
// Do all public stuff
assert!(ftp_stream.quit().await.is_ok());
```

## Built-in CLI client 🖥️

SuppaFTP comes also with a built-in command-line FTP client. This CLI application provides all the commands to interact with a remote FTP server and supports FTPS too. You can also use it as a reference to implement your project. You can find it in the `cli/` directory.

You can simply install as any other rust application via **Cargo**:

```sh
cargo install suppaftp --features="secure cli-bin"
```

---

## Support the developer ☕

If you like **SuppaFTP**, please consider a little donation 🥳

[![ko-fi](https://img.shields.io/badge/Ko--fi-F16061?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/veeso)
[![PayPal](https://img.shields.io/badge/PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white)](https://www.paypal.me/chrisintin)
[![bitcoin](https://img.shields.io/badge/Bitcoin-ff9416?style=for-the-badge&logo=bitcoin&logoColor=white)](https://btc.com/bc1qvlmykjn7htz0vuprmjrlkwtv9m9pan6kylsr8w)
[![litecoin](https://img.shields.io/badge/Litecoin-345d9d?style=for-the-badge&logo=Litecoin&logoColor=white)](https://blockchair.com/litecoin/address/ltc1q89a7f859gt7nuekvnuuc25wapkq2f8ny78mp8l)

---

## Changelog ⌛

View Changelog [here](CHANGELOG.md)

---

## License 📜

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

---

### Contribution 🤝

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

If you want to contribute to this project, please read the [Contributing guide](CONTRIBUTING.md) first 🙂.
