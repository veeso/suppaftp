# Changelog

All notable changes to this project are documented in this file.

## 12.0.0

Released on 2026-09-08

### Breaking changes

- make data streams finalize themselves

> finalize_put_stream, finalize_retr_stream and
> close_data_connection are removed; put_with_stream, append_with_stream,
> retr_as_stream and custom_data_command return TransferStream, whose
> finish() replaces them; abort takes a TransferStream; the async retr
> callbacks receive and return a TransferStream; get_ref returns a locked
> ControlSocket (async: through an async fn); get_lines_from_stream is
> generic over BufRead readers.

### Added

- Breaking: make data streams finalize themselves

> Move the control connection (reply reader and data-connection flag) of
> every client behind an Arc<Mutex<..>> shared with a new TransferStream
> returned by put_with_stream, append_with_stream, retr_as_stream and
> custom_data_command. The stream closes its data socket and reads the
> 226/250 reply itself through finish(); a dropped stream does the same
> (sync) or defers the reply to the next command (tokio, smol), so the
> control connection can no longer desynchronize because a caller forgot
> to finalize.

### Fixed

- preserve transfer cleanup across cancellation and locking

> Retain pending replies and partial response buffers when async finalization is cancelled. Record dropped transfers without locking the control channel and reject TLS mode changes before sending commands while a transfer is alive.
>
> Add regression coverage for cancellation, control socket contention, and TLS transitions. Document the breaking stream API migration and cleanup limitations, and resolve test helper lint warnings.

## 11.0.0

Released on 2026-08-31

### Breaking changes

- **tokio:** send close_notify on finalize_retr_stream

> tokio finalize_retr_stream now requires streams to implement AsyncWrite and Unpin.

- **smol:** close retrieval streams gracefully

> smol finalize_retr_stream now requires streams to implement AsyncWrite and Unpin.

### Fixed

- Breaking: **tokio:** send close_notify on finalize_retr_stream

> finalize_retr_stream() (used by retr()/list()/nlst()/mlsd() on the tokio
> backend) dropped the data-connection stream without a graceful shutdown,
> unlike finalize_put_stream() which already calls stream.shutdown().
>
> For a plain TCP data stream this is harmless, but for a TLS-secured FTPS
> data channel it means no close_notify is sent. TLS 1.2 servers tolerate
> the abrupt close (session-ID based resumption apparently masks it), but
> TLS-1.3-strict servers reply "426 Transfer failed (unable to close data
> connection gracefully)" even though the transfer already completed —
> reproduced live against test.rebex.net (public FTPS server, TLS 1.3) with
> RUST_LOG=trace: rustls confirms `Resuming using PSK` and the full LIST
> payload is read before the 426 appears, ruling out a session-resumption
> mismatch. The 426 only goes away when the data stream shuts down cleanly.
>
> This widens finalize_retr_stream()'s bound from `impl AsyncRead` to
> `impl AsyncRead + AsyncWriteExt + Unpin` (matching finalize_put_stream's
> existing bound) and sends the close_notify before dropping. Shutdown
> errors are ignored, mirroring the fact that the data has already been
> fully read by this point — a failed shutdown must not fail an
> otherwise-successful transfer (finalize_put_stream is stricter here since
> for uploads the write isn't confirmed complete until shutdown succeeds).
>
> Verified with a small standalone client exercising both an unrestricted
> rustls config (negotiates TLS 1.3) and one capped at TLS 1.2 against
> test.rebex.net: before this fix, only the TLS-1.2-capped path completed
> LIST; after, both do.

- Breaking: **smol:** close retrieval streams gracefully

> Mirror Tokio retrieval finalization by closing smol data streams before reading the final control response. Add deterministic coverage for both runtimes and document the response-authority policy.

## 10.0.2

Released on 2026-08-18

### Fixed

- reject FTP commands carrying CR or LF to prevent command injection (#172)

> - fix: reject FTP commands carrying CR or LF to prevent command injection
>
> An argument containing CR or LF ended the intended command line and let a
> second command be smuggled onto the control channel. Every rendered command
> is now validated before it is written to the wire, in the sync, tokio and
> smol implementations alike, and rejected with an InvalidInput connection
> error.
>
> As a consequence custom_command no longer accepts several commands joined by
> CRLF in a single call.

## 10.0.1

Released on 2026-07-13

### Fixed

- **parser:** accept mismatched terminal codes (#169)

> Accept non-standard multiline replies that finish with a different status code while preserving FEAT continuation handling.

## 10.0.0

Released on 2026-06-29

### Breaking changes

- replace panics with errors across library and CLI (#166)

> the `tcp_stream` method of the `TlsStream`, `TokioTlsStream` and
> `SmolTlsStream` traits now returns `FtpResult<TcpStream>` instead of `TcpStream`,
> and `DataStream::into_tcp_stream` now returns `FtpResult<TcpStream>`.

### Changed

- Breaking: replace panics with errors across library and CLI (#166)

> Convert unwrap/expect/panic patterns in production code paths to proper
> FtpError/ParseError results, so malformed server responses (e.g. an out-of-range
> PASV octet or unparsable LIST/MLSx line) and socket-clone failures no longer abort
> the program. Placeholder no-TLS streams now return io errors or unreachable! for
> truly unreachable accessors.

### Fixed

- `tcp_stream()` Windows compatibility with tokio + native-tls (#164)

> Add a branch on windows that uses `as_socket` instead of `as_fd` to get
> a reference to the underlying system socket before cloning.

## 9.0.0

Released on 2026-06-20

### Breaking changes

- replace async-std runtime with smol (#162)

> the async-std runtime and all async-std* cargo features are
> removed; use the smol runtime and the equivalent smol* features instead. The

### Added

- Breaking: replace async-std runtime with smol (#162)

> async-std is unmaintained upstream (RUSTSEC-2025-0052). Drop it as an async
> backend and replace it with smol, an equivalent lightweight runtime.
>
> The TLS backends are unchanged: futures-rustls and async-native-tls are
> runtime-agnostic, so only the runtime glue (TcpStream/TcpListener, timers,
> spawn, task) moved from async-std to smol. async-native-tls already ran on its
> runtime-smol backend. The direct futures-lite dependency is gone too: smol
> re-exports it and nothing else used it, so it is no longer compiled for
> sync/tokio builds.
>
> This commit also centralizes dependencies into [workspace.dependencies], applies
> Cargo.toml conventions across all manifests, and renames mod.rs files to the
> module_name.rs style.
>
> Migrating from async-std:
>
> - Cargo features: rename every async-std* feature to its smol* counterpart.
>   - async-std -> smol
>   - async-std-async-native-tls -> smol-async-native-tls
>   - async-std-async-native-tls-vendored -> smol-async-native-tls-vendored
>   - async-std-rustls-aws-lc-rs -> smol-rustls-aws-lc-rs
>   - async-std-rustls-ring -> smol-rustls-ring
> - Module path: the async module is now suppaftp::smol instead of
>   suppaftp::async_std. The stream type aliases are unchanged: AsyncFtpStream,
>   AsyncNativeTlsFtpStream, AsyncRustlsFtpStream.
> - Helper types: AsyncStdTlsStream is now SmolTlsStream, and
>   AsyncStdPassiveStreamBuilder is now SmolPassiveStreamBuilder.
> - Runtime: drive the client on a smol executor (e.g. smol::block_on) instead of
>   async_std::task::block_on or #[async_std::main].

## 8.0.5

Released on 2026-06-20

### Fixed

- accept 200 as a valid response for file operations (#158)

> Some non-compliant FTP servers (e.g. bftpd) reply with 200 instead of
> the spec-mandated 250/257 to file operations such as DELE, RMD, RNTO and
> MKD. Tolerate 200 alongside the expected code in rm, rmdir, rename and
> mkdir, across the sync, tokio and async-std implementations.

## 8.0.4

Released on 2026-06-08

### Fixed

- reset data_connection_open flag when a data command fails

> Data commands set `data_connection_open = true` once the data stream is
> opened, but the follow-up `read_response_in` could still fail (e.g. the
> server returns 550 for a missing file). On that error the flag stayed
> true, so every subsequent data command wrongly failed with
> `DataConnectionAlreadyOpen`.
>
> Introduce a `data_command_with_response` wrapper that runs the data
> command and reads its preliminary response, dropping the stream and
> resetting the flag on error. Route every data-command caller
> (`retr_as_stream`, `put_with_stream`, `append_with_stream`,
> `custom_data_command`, `stream_lines`) through it, in the sync, tokio
> and async-std implementations.
>
> Add tests in all three implementations verifying that every kind of
> data command remains usable after a failed one.

### Build

- bump rand 0.10
- upgrade async-native-tls to 0.6

> The crate dropped its runtime-async-std feature in 0.6, so the
> async-std FTPS backend now enables runtime-smol instead, which uses
> the futures-util IO traits compatible with async-std's TcpStream.

## 8.0.3

Released on 2026-04-23

### Fixed

- handle 200 (command OK) as success in cwd()

> RFC 959 specifies 250 as the standard response code when changing
> the working directory successfully, but some FTP servers return
> 200 instead.

## 8.0.2

Released on 2026-02-12

### Changed

- Moved crates to crates/ folder (#133)

### Fixed

- reader does not need to be mutable
- replace unsafe UB in tokio AsyncNativeTlsStream::tcp_stream() (#135)

> The previous implementation used Box::from_raw on a pointer obtained from
> get_ref(), which points into the interior of a TlsStream allocation, not
> a Box allocation. This caused heap corruption / undefined behavior.
>
> Replace with safe fd cloning via BorrowedFd::try_clone_to_owned().

- data_connection_open flag now only set on successful data_command (#136)

> The data_connection_open flag was being set before the data stream was
> actually created, causing it to remain true even when connection failed.

- add EOF check to async feat() to prevent infinite loop (#137)

> The async implementations of feat() were missing an EOF check in their
> read loop, causing an infinite loop if the server disconnected mid-response.

- add EOF check to read_response_in multiline loop (#138)

> The multiline response reader could loop infinitely if the server
> disconnected mid-response. Now returns ConnectionError on unexpected EOF.

- MLSX parser now accepts cdir and pdir type values (#139)

> RFC 3659 defines cdir (current directory) and pdir (parent directory)
> as standard MLSX type values. Most FTP servers include these in MLSD
> output for . and .. entries.

- MLSX unix.mode accepts 4-digit octal modes (#140)

> - fix: MLSX unix.mode now accepts 4-digit octal modes
>
> Some FTP servers return 4-digit octal modes (e.g. 0755) in MLSX responses.
> The parser now accepts both 3 and 4 digit modes by taking the last 3 chars.

- abort() only reads second response when server sends 426 (#141)

> Previously abort() always tried to read two responses, which could hang
> if the server only sends one response (226). Now conditionally reads the
> second response only when the first is 426 (TransferAborted).

- DOS LIST parser handles comma-separated file sizes (#142)

> - fix: DOS LIST parser now handles comma-separated file sizes
>
> Some FTP servers return file sizes with comma separators (e.g. 1,234,567).
> The parser now strips commas before parsing the size.

- remove redundant feature = "async-std" in cfg gate (#147)
- correct doc(cfg) attribute on SecureError (#148)
- parse_lstime adjusts year for future dates (#143)

> - fix: parse_lstime now adjusts year for future dates
>
> When a LIST response contains a date more than 6 months in the future
> (no year specified), it almost certainly refers to the previous year.
> The parser now adjusts accordingly, matching the behavior of GNU ls.

- DOS time parser handles space before AM/PM (#144)

> - fix: DOS time parser now handles space before AM/PM
>
> Some FTP servers format DOS timestamps with a space before AM/PM
> (e.g. '01:30 PM' vs '01:30PM'). The parser now tries both formats.

- replace unwrap() panics on server-controlled data (#146)

> - fix: replace unwrap() with error handling on server-controlled data
>
> Server responses parsed via unwrap() (EPSV port, SIZE value, MDTM
> timestamp) could panic on malformed data. Now returns FtpError::BadResponse.

- active mode uses EPRT for IPv6 connections (#145)

> - fix: active mode uses EPRT for IPv6, fix unwrap panics
>
> The PORT command only supports IPv4. When connected via IPv6, the client
> now uses EPRT instead. Also replaces unwrap() on local_addr() with
> proper error handling.

## 8.0.1

Released on 2026-01-18

### Fixed

- Fixed docs.rs build

## 8.0.0

Released on 2026-01-18

### Breaking changes

- **deps:** Added new features to choose the backend for `rustls` (#132)

> Update your Cargo.toml if you're using `rustls` to explicitly set the Rustls backend to use

### Build

- Breaking: **deps:** Added new features to choose the backend for `rustls` (#132)

> - build(deps)!: Added new features to choose the backend for `rustls`
>
> Added `-aws-lc-rs` and `-ring` to all `rustls` features to allow choosing the backend. Removed all the `async-std-rustls`, `rustls`, and `tokio-rustls` features to prevent ambiguity.

## 7.1.0

Released on 2026-01-07

### Added

- **list:** FileType enum is now public; deprecated File::from...line in favour of `LineParser` (#129)

> It is now possible to retrieve the `FileType` from a file using `File::file_type()`.
>
> [Issue 128](https://github.com/veeso/suppaftp/issues/128)
>
> - Made `FileType` enum public
> - Added `File::file_type()` method to retrieve the file type
> - Deprecated `File::from_dos_line`, `File::from_mlsx_line`, and `File::from_posix_line` methods in favor of `ListParser::parse_dos`, `ListParser::parse_mlst`, `ListParser::parse_mlsd`, and `ListParser::parse_posix` respectively.

### Fixed

- Prevent commands which require a data connection to be executed if there is already a data connection open (#130)

> - fix: Prevent commands which require a data connection from being executed if there is already a data connection open
>
> ftp should never allow this. Indeed, it currently causes the code to hang

## 7.0.7

Released on 2025-11-05

### Fix

- re-export tls streams when using tokio (#126)

## 7.0.6

Released on 2025-10-07

### Fixed

- Allow to access async_native_tls when using tokio (#125)
- 7.0.6

## 7.0.5

Released on 2025-10-03

### Build

- Update chrono version (#124)

> - update chrono version
> - docs: 7.0.5
>
> ---

## 7.0.4

Released on 2025-09-22

### Fixed

- docs.rs build
- Exported `TlsStream` types for implementing functions that use the retrieved stream. (#122)

> - fix: Exported `TlsStream` types for implementing functions that use the retrieved stream.
>
> `TlsStream` for sync ftp.
> `AsyncStdTlsStream` for async-std ftp.

## 7.0.0

Released on 2025-08-31

### Breaking changes

- Tokio for a new async backend of suppaftp (#116)

> Tokio for a new async backend of suppaftp (#116)

### Added

- Breaking: Tokio for a new async backend of suppaftp (#116)

> - feat: add tokio for a new backend of suppaftp
> - feat: make async-std and tokio backend parallel existed.
> - fix: conflicting with tokio async backend and test container environment.
> - fix: mismatched feature gates of async-native-tls-std, async-std; fix wrong ref.
> - fix: Exports for async and features
> - fix: fail-fast
> - ci: Workflow
> - test: tests
> - docs: Features docs
> - ci: Merged coverage workflow into tests
> - ci: coverage
>
> ---

- Custom Data commands (#117)

> Added `custom_data_command` to perform the execution of custom data commands.
> Added `close_data_connection` to close the `DataStream` once consumed after executing custom data commands.
> Made `get_lines_from_stream` public to easily read String lines from the `DataStream`.

## 6.3.0

Released on 2025-06-05

### Fixed

- FEAT command response parser (#109)

> The parser didn't fully respect the RFC 2389

- **async:** Fixed `retr` method signature on the `AsyncFtpStream` to allow passing a closure taking the stream reader. (#110)

> The signature of the `retr` method was not allowing any argument, because the dyn Read needs to be Unpin, but it's a mutable reference at the same time and this with Async causes several issues. The mutable reference is required by the finalize_retr_stream which is called immediately after calling the closure. Because of this, the signature has been changed to return both the result and the stream back to be able to finalize it.

- 6.3.0

## 6.2.1

Released on 2025-05-13

### Fixed

- **chore:** Update/fix rustls example in readme (#104)
- Fixed `list` related commands which failed if the file name contained non UTF8 characters (#107)

> Changed the logic of get stream lines: use read_until and then convert to UTF8 lossy

### Build

- Updated dev-dependencies

## 6.2.0

Released on 2025-04-14

### Breaking changes

- `get_ref` for async tls stream was unnecessarily async

> get_ref calls must remove await

### Added

- Breaking: `get_ref` for async tls stream was unnecessarily async

> it was an async function, but it didn't make sense to be async and created issues when dealing with pooling

### Fixed

- set `get_ref` to sync, to acquire reference to internal tls stream. (#103)
- unnecessary to_string
- lint

## 6.1.1

Released on 2025-03-17

### Changed

- **log:** added better logs for tracing streams

### Fixed

- **chore:** readme styles

## 6.1.0

Released on 2025-03-10

### Added

- **deps:** migrated from async-tls to futures-rustls (#101)

> async-tls is unmaintained and rustls has actually released an official version for async tls, so we should use that instead

### Fixed

- **ci:** coverage
- doc: fix minor typos referencing 'termscp' in CONTRIBUTING.md (#98) (#99)

## 6.0.7

Released on 2025-01-18

### Fixed

- remove is_private check for nat workaround (#97)
- 6.0.7

## 6.0.6

Released on 2025-01-17

### Fixed

- msrv
- close rustls stream on drop (#96)
- suppaftp 6.0.6

## 6.0.5

Released on 2024-11-27

### Fixed

- **deps:** force rustls to use ring
- ci
- testcontainers for tests

## 6.0.4

Released on 2024-10-26

### Fixed

- FtpStream should be Sync

## 6.0.3

Released on 2024-10-15

### Fixed

- Added `Send` marker to the Closure: `dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = FtpResult<TcpStream>> + Send>> + Send;`

## 6.0.2

Released on 2024-10-14

### Fixed

- Passive mode with custom provided TcpStream (#91)

> - fix: Passive mode with custom provided TcpStream
> - fix: ci
> - fix: ci

## 6.0.1

Released on 2024-05-24

### Fixed

- docs
- docs
- ms-dos date format (#84)

> - fix:ms-dos date format
> - fix:ms-dos date format
>
> ---

## 6.0.0

Released on 2024-05-20

### Breaking changes

- `Response.body` now contains the entire response

> `Response.body` now contains the entire response

- `site()` and `custom_command` now return `FtpResult<Response>`

> `site()` and `custom_command` now return `FtpResult<Response>`

- 6.0.0

> 6.0.0

### Added

- Breaking: `Response.body` now contains the entire response
- Breaking: `site()` and `custom_command` now return `FtpResult<Response>`
- Breaking: 6.0.0

### Fixed

- style flat stars badge
- unique manifest
- deps
- lint
- test
- test

## 5.4.0

Released on 2024-05-18

### Added

- custom_command
- SITE command
- Support MLST and MLSD

### Fixed

- #75 Make function connect_with_stream public
- lint
- async
- async
- lint

## 5.3.1

Released on 2024-01-28

### Added

- suppaftp 5.3.1

### Fixed

- issue #69 Syntax error on name that staqrts with 2 number

## 5.3.0

Released on 2024-01-06

### Added

- active mode socket timeout (#68)

> - feat: active mode socket timeout
> - fix: build

- release

## 5.2.2

Released on 2023-11-14

### Added

- Send + Sync trait to AsyncFtpStream/FtpStream (#61)

> - feat: Send trait to AsyncFtpStream/FtpStream
> - fix: ci failing

### Fixed

- async feat function hang (#63)
- format

## 5.2.1

Released on 2023-10-16

### Added

- deps
- changelog
- removed broken tests

### Fixed

- removed test

## 5.2.0

Released on 2023-09-07

### Added

- FEAT and OPTS commands (#51)

## 5.1.1

Released on 2023-04-03

### Added

- `ImplFtpStream` and `ImplAsyncFtpStream` are now public

## 4.5.2

Released on 2022-10-10

### Fixed

- tls::TlsConnector should be pub use

## 4.5.1

Released on 2022-10-08

### Fixed

- async TlsConnector not exported

## 4.4.0

Released on 2022-08-02

### FtpStream

- :set_nat_workaround() instead of feature flag "nat".

## 4.1.1

Released on 2021-08-22

### README

- syntax highlighting fix

> This fixes the syntax highlighting for the Rust code by using the `rust` language for the fenced code block.
