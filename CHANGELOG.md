# Changelog

- [Changelog](#changelog)
  - [6.3.0](#630)
  - [6.2.1](#621)
  - [6.2.0](#620)
  - [6.1.1](#611)
  - [6.1.0](#610)
  - [6.0.7](#607)
  - [6.0.6](#606)
  - [6.0.5](#605)
  - [6.0.4](#604)
  - [6.0.3](#603)
  - [6.0.2](#602)
  - [6.0.1](#601)
  - [6.0.0](#600)
  - [5.4.0](#540)
  - [5.3.1](#531)
  - [5.3.0](#530)
  - [5.2.2](#522)
  - [5.2.1](#521)
  - [5.2.0](#520)
  - [5.1.2](#512)
  - [5.1.1](#511)
  - [5.1.0](#510)
  - [5.0.1](#501)
  - [5.0.0](#500)
  - [4.7.0](#470)
  - [4.6.1](#461)
  - [4.6.0](#460)
  - [4.5.3](#453)
  - [4.5.2](#452)
  - [4.5.1](#451)
  - [4.5.0](#450)
  - [4.4.0](#440)
  - [4.3.0](#430)
  - [4.2.0](#420)
  - [4.1.3](#413)
  - [4.1.2](#412)
  - [4.1.1](#411)
  - [4.1.0](#410)
  - [4.0.2](#402)
  - [4.0.1](#401)
  - [4.0.0](#400)

---

## 6.3.0

Released on 05/06/2025

- [Issue 85](https://github.com/veeso/suppaftp/issues/85): Fixed `retr` method signature on the `AsyncFtpStream` to allow passing a closure taking the stream reader.

    ```rust
    stream
      .retr("test.txt", |mut reader| {
            Box::pin(async move {
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).await.expect("failed to read stream");
                Ok((buf, reader))
            })
        })
        .await
    ```

- [Issue 108](https://github.com/veeso/suppaftp/issues/108): fixed FEAT command response parser

## 6.2.1

Released on 13/05/2025

- [Issue 106](https://github.com/veeso/suppaftp/issues/106): Fixed `list` related commands which failed if the file name contained non UTF-8 characters.
- MSRV updated to 1.80.1

## 6.2.0

Released on 14/04/2025

- [feat (BREAKING): `get_ref` for async tls stream was unnecessarily async](https://github.com/veeso/suppaftp/pull/103)

## 6.1.1

Released on 17/03/2025

- added a couple of logs to debug streams.

## 6.1.0

Released on 10/03/2025

- [Issue 100](https://github.com/veeso/suppaftp/issues/100): Migrated away from unmaintained `async-tls` to `futures-rustls`
- [Issue 98](https://github.com/veeso/suppaftp/issues/98): doc: fixed minor typos that referenced `termscp`

## 6.0.7

- [Issue 88](https://github.com/veeso/suppaftp/issues/88): Removed `ip.is_private()` check on NAT workaround, which prevented public IPs to be used for Natting.

## 6.0.6

Released on 17/01/2025

- [Issue 95](https://github.com/veeso/suppaftp/issues/95): Fixed TLS Stream not properly closed when using rustls.

## 6.0.5

Released on 27/11/2024

- [Force rustls to use ring](https://github.com/veeso/suppaftp/issues/94)

## 6.0.4

Released on 26/10/2024

- Added `Sync` to client.
- Added unit test to guarantee that sync FtpStream stays `Sync`

## 6.0.3

Released on 15/10/2024

- Added `Send` marker to the Closure: `dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = FtpResult<TcpStream>> + Send>> + Send;`
- Added unit test to guarantee that FtpStream stays `Send`

## 6.0.2

Released on 14/10/2024

- [Issue 89](https://github.com/veeso/suppaftp/issues/89): added new `FtpStream::passive_stream_builder` to provide a function to build the Passive mode `TcpStream` with a custom builder. This is useful if you need to use some proxy.

## 6.0.1

Released on 24/05/2024

- [PR 84](https://github.com/veeso/suppaftp/pull/84): LIST with DOS lines parsed `%d-%m` but the correct syntax is `%m-%d`

## 6.0.0

Released on 20/05/2024

- feat!: `Response.body` now contains the entire response
- feat!: `site()` and `custom_command` now return `FtpResult<Response>`

## 5.4.0

Released on 18/05/2024

- [Issue 70](https://github.com/veeso/suppaftp/issues/70): **SITE** Command
- [Issue 75](https://github.com/veeso/suppaftp/issues/75): Public access to `connect_with_stream`
- [Issue 76](https://github.com/veeso/suppaftp/issues/76): Support for **MLST** and **MLSD**
- [PR 78](https://github.com/veeso/suppaftp/pull/78): Async SSL file uploads not properly closing
- `custom_command`: added `custom_command` function to perform custom commands

## 5.3.1

Released on 28/01/2024

- Fixed [issue #69](https://github.com/veeso/suppaftp/issues/69): SyntaxError on name that starts with 2 numbers

## 5.3.0

Released on 06/01/2024

- Fix [issue #64](https://github.com/veeso/suppaftp/issues/64): added active mode listener timeout
- Fix [issue #66](https://github.com/veeso/suppaftp/issues/66): abort can be called without passing ownership to data_stream

## 5.2.2

Released on 14/11/2023

- Fix issue #61: Send + Sync trait to AsyncFtpStream/FtpStream
- Fix issue #63: FEAT function hangs on async

## 5.2.1

Released on 16/10/2023

- Add POSIX setgid/setuid/sticky bit support: [PR59](https://github.com/veeso/suppaftp/pull/59)

Thanks to [@rye](https://github.com/rye)

## 5.2.0

Released on 07/09/2023

- Implemented [RFC 2389](https://www.rfc-editor.org/rfc/rfc2389)
  - Added `FEAT` command
  - Added `OPTS` command

## 5.1.2

Released on 14/06/2023

- Added `clock` feature to chrono to overcome security issue with `time` <https://github.com/veeso/suppaftp/issues/46>

## 5.1.1

Released on 03/04/2023

- `ImplFtpStream` and `ImplAsyncFtpStream` are now public

## 5.1.0

Released on 02/03/2023

- Implemented new connection method `connect_timeout` with the possibility to specify a timeout on connect

## 5.0.1

Released on 26/02/2023

- Exposed publicly `DataStream` and `AsyncDataStream`

## 5.0.0

Released on 24/02/2023

- [Issue 33](https://github.com/veeso/suppaftp/issues/33) **‼️ BREAKING CHANGES ‼️**
  - Features are now additive. This means that you can successfully build suppaftp with all the features enabled at the same time.
  - Ftp stream has now been split into different types:
    - `FtpStream`: sync no-tls stream
    - `NativeTlsFtpStream`: ftp stream with TLS with native-tls
    - `RustlsFtpStream`: ftp stream with TLS with rustls
    - `AsyncFtpStream`: async no-tls stream
    - `AsyncNativeTlsFtpStream`: async ftp stream with TLS with async-native-tls
    - `AsyncRustlsFtpStream`: async ftp stream with TLS with async-rustls

## 4.7.0

Released on 01/02/2023

- [RFC 2428](https://www.rfc-editor.org/rfc/rfc2428) implementation
  - [Issue 28](https://github.com/veeso/suppaftp/issues/28): Implemented Extended Passive mode (**EPSV**)
  - [Issue 30](https://github.com/veeso/suppaftp/issues/30): Implemented EPRT
- Updated suppaftp-cli to suppaftp 4.7.0

## 4.6.1

Released on 26/01/2023

- `suppaftp::list::File` now derives the `core::hash::Hash` trait

## 4.6.0

Released on 09/01/2023

- `MDTM` now returns `NaiveDateTime` since the command won't provide timezone

## 4.5.3

Released on 27/12/2022

- Don't use read to string from stream, but read line
- Response body is now bytes
- Fixed [issue 24](https://github.com/veeso/suppaftp/issues/24)

## 4.5.2

Released on 10/10/2022

- Fixed missing export of tls stream

## 4.5.1

Released on 08/10/2022

- Export `TlsStream` when async secure

## 4.5.0

Released on 08/10/2022

- Added `native-tls-vendored` and `async-native-tls-vendored` features to link OpenSSL statically
- suppaftp-cli as a separate package.
- Rustls support
- **‼️ BREAKING CHANGE**: refactored secure features:
  - **REMOVED** `secure`/`async-secure` feature
  - Use `native-tls` to enable TLS support with native-tls crate
  - Use `async-native-tls` to enable async TLS support with async-native-tls crate
  - Use `rustls` to enable TLS support with rustls crate
  - Use `async-rustls` to enable TLS support with async-tls crate

## 4.4.0

Released on 02/08/2022

- Added `set_passive_nat_workaround()` method to allow PASV with server behind NAT/proxy

## 4.3.0

Released on 27/06/2022

- Added implicit FTPS support
  - Added `connect_secure_implicit()` method
  - Added `deprecated` feature to enable deprecated methods (required for implicit FTPS)

## 4.2.0

Released on 07/12/2021

- **Active mode**
  - suppaftp now supports Active-mode (credit [@devbydav](https://github.com/devbydav))
  - You can change mode with `set_mode(Mode::Passive) or set_mode(Mode::Active)` whenever you want
- **New commands**
  - **Abort command**: implemented the `ABOR` FTP command
  - **Append command**: implemented the `APPE` FTP command
  - **Resume transfer command**: implemented the `REST` FTP command
- **Logging**: `log` crate has been implemented for debugging. You can disable logging with `no-log` feature
- Security
  - **TlsStream shutdown**: fixed [issue 5](https://github.com/veeso/suppaftp/issues/5) (credit [@devbydav](https://github.com/devbydav))
- ❗ Breaking changes:
  - `Response.code` renamed to `status`.
  - status is no more a `u32`: from now on it will be an enum named `Status`.
    - The status enum implements the `code()` method which will return the `u32` representation
    - The status enum can be displayed and converted to string: this will return the description of the error code
  - Changed `into_insecure()` to `clear_command_channel()`: the implementation of into_insecure was wrong and inconsistent. What it actually does is to make the server not to encrypt the communication on the command channel.
  - Removed `File::from_line`; use `File::try_from()` or `File::from_str()`

## 4.1.3

Released on 01/12/2021

- UNIX file parser:
  - Fixed file parsing, which didn't allow any other characters than alphanumerics for groups, users and dates
- `put_file()` will now return the amount of bytes written
- Updated dependencies

## 4.1.2

Released on 23/08/2021

- Renamed `InvalidResponse` to `UnexpectedResponse`, which makes more sense
- Renamed `File::from_unix_line` to `File::from_posix_line`
- Renamed `UnixPexQuery` to `PosixPexQuery`
- Made `parse_dostime` private

## 4.1.1

Released on 22/08/2021

- Fixed missing `cli/` directory on Cargo registry.

## 4.1.0

Released on 22/08/2021

- Added `Response` struct, which will be returned in case of `InvalidResponse` error.
  - This adds the possibility to get the exact error code and the message
- Added **async** support
- **API** changes
  - renamed `simple_retr` to `retr_as_buffer`
  - renamed `get` to `retr_as_stream`
  - renamed `finalize_get_stream` to `finalize_retr_stream`
- **LIST** command output parser
  - Read more on [docs.rs](https://docs.rs/suppaftp/4.1.0/suppaftp/list/index.html)
- Optimized code to reuse stream functions as much as possible
- `size()` and `mdtm()` methods will return an option no more.
- Improved code with linter
- Added CI tests

## 4.0.2

Released on 09/01/2020

- Fixed `finalize_get` and `finalize_put_stream`. Stream must be dropped before waiting for response.

## 4.0.1

Released on 10/12/2020

- Added `finalize_get` method to terminate reader and `RETR` command

## 4.0.0

Released on 06/12/2020

- Removed deprecated statements
- Replaced openssl with native-tls
- Added `put_with_stream` method
- Added `get_welcome_msg` method
