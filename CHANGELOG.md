# Changelog

- [Changelog](#changelog)
  - [4.1.0](#410)
  - [4.0.2](#402)
  - [4.0.1](#401)
  - [4.0.0](#400)

## 4.1.0

Released on ??

- Improved code with linter

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
