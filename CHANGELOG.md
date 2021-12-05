# Changelog

- [Changelog](#changelog)
  - [4.2.0](#420)
  - [4.1.3](#413)
  - [4.1.2](#412)
  - [4.1.1](#411)
  - [4.1.0](#410)
  - [4.0.2](#402)
  - [4.0.1](#401)
  - [4.0.0](#400)

## 4.2.0

Released on ??

- **Active mode**
  - suppaftp now supports Active-mode (credit [@devbydav](https://github.com/devbydav))
  - You can change mode with `set_mode(Mode::Passive) or set_mode(Mode::Active)` whenever you want

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
