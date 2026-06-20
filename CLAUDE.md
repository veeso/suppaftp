# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SuppaFTP is a sync/async FTP/FTPS client library for Rust (crate: `suppaftp`), with an optional CLI binary (
`suppaftp-cli`).
It supports multiple TLS backends (native-tls, rustls) and async runtimes (tokio, async-std).

## Repository Layout

- **Workspace root**: `Cargo.toml` — two members under `crates/`
- **`crates/suppaftp/`**: Main library crate
- **`crates/suppaftp-cli/`**: CLI binary crate
- **Edition**: 2024, **MSRV**: 1.85.1

## Build & Development Commands

This repo uses [`just`](https://github.com/casey/just) as its command runner. Run `just` (or `just --list`) to see all
recipes. Formatting is handled by [`dprint`](https://dprint.dev/) (Markdown/TOML/YAML + Rust via nightly rustfmt) and
dependency policy by [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny). The `CHANGELOG.md` is generated from
conventional commits with [`git-cliff`](https://git-cliff.org) (config in `cliff.toml`).

```bash
# Build the library for a single feature set
just build native-tls

# Build across every supported feature combination
just build_all

# Lint a single feature set
just clippy native-tls "-- -D warnings"

# Lint across every supported feature combination (denies warnings)
just clippy_all

# Format all sources (write) / check only
just fmt
just fmt_check

# Run tests for a specific feature set (optionally a single test)
just test native-tls [TEST_NAME]

# Run tests across every supported feature combination
just test_all [TEST_NAME]

# Check dependencies (advisories, licenses, bans, sources)
just deny

# Generate docs (denies warnings)
just doc

# Run all code checks at once (fmt_check, clippy, doc, deny)
just check_code

# Add a new CHANGELOG.md entry from conventional commits (git-cliff), e.g. for a release
just changelog 8.1.0
just changelog_preview 8.1.0  # preview to stdout only

# Install the git pre-commit hook (trufflehog + dprint + cargo-deny)
just setup_githooks
```

## Feature Flags

Features are **not default** — you must enable at least one for TLS or async support. Many features are **mutually
exclusive** (enforced via `compile_error!`).

**Sync TLS** (pick one or none):

- `native-tls` / `native-tls-vendored` — OS-native TLS
- `rustls-aws-lc-rs` / `rustls-ring` — pure-Rust TLS

**Async runtimes** (pick one or none):

- `async-std` — plain async-std (no TLS)
- `tokio` — plain tokio (no TLS)

**Async + TLS** (combined features, pick one):

- `async-std-async-native-tls`, `async-std-rustls-aws-lc-rs`, `async-std-rustls-ring`
- `tokio-async-native-tls`, `tokio-rustls-aws-lc-rs`, `tokio-rustls-ring`

**Misc**: `deprecated` (enables implicit FTPS), `no-log` (disables logging)

## Architecture

### Generic TLS Abstraction

The core type is `ImplFtpStream<T>` where `T: TlsStream`. Concrete type aliases simplify usage:

- `FtpStream` = `ImplFtpStream<NoTlsStream>` (plain FTP)
- `NativeTlsFtpStream` = `ImplFtpStream<NativeTlsStream>` (native-tls FTPS)
- `RustlsFtpStream` = `ImplFtpStream<RustlsStream>` (rustls FTPS)

TLS pluggability is via two traits in `sync_ftp/tls.rs`:

- `TlsStream` — wraps a TLS-encrypted TCP stream
- `TlsConnector` — creates TLS connections (only available with `secure` feature)

### Sync vs Async

The sync implementation lives in `src/sync_ftp/mod.rs`. Async implementations mirror the same API with `async`/`await`:

- `src/async_ftp/tokio_ftp/` — tokio-based
- `src/async_ftp/async_std_ftp/` — async-std-based

### Key Modules

- `command.rs` — Strongly-typed `Command` enum for all FTP commands with `Display` formatting
- `types.rs` — `FtpError` (using thiserror), `FtpResult`, `Mode`, `Response`, `Features`
- `status.rs` — `Status` enum for FTP response codes
- `list.rs` — Parser for LIST output (POSIX and DOS formats) into structured `File` objects
- `regex.rs` — Lazy-compiled regexes for parsing PASV, EPSV, MDTM, SIZE responses
- `sync_ftp/data_stream.rs` — `DataStream<T>` enum wrapping TCP or TLS data connections

## Testing

Integration tests use **testcontainers** with the `delfer/alpine-ftp-server` Docker image (requires Docker running).
Test configuration is in `src/test_container.rs` (user: `test`, password: `test`, passive ports: 30000-30009).

CI runs tests across 11 feature combinations in parallel with coverage via `cargo-llvm-cov`.

## Code Style

- **rustfmt**: `group_imports = "StdExternalCrate"`, `imports_granularity = "Module"`
- **Clippy**: treat warnings as errors (`-Dwarnings`)
- **Commits**: conventional commit format (`feat:`, `fix:`, `refactor:`, `test:`, `ci:`, `docs:`, `build:`, `chore:`)
- **Dependencies**: minimize external deps, avoid C-bindings where possible (prefer pure Rust)

## PR Checklist (from CONTRIBUTING.md)

1. Rustdoc documentation for public API
2. Tests for new code
3. `cargo clippy` passes
4. CI green
5. Update `CHANGELOG.md` under `PR{NUMBER}` section
