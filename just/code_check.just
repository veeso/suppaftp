# Format all sources (Markdown, TOML, YAML and Rust via nightly rustfmt) with dprint
[group('code_check')]
fmt args="":
    dprint fmt {{ args }}

# Check formatting of all sources with dprint (no writes)
[group('code_check')]
fmt_check args="":
    dprint check {{ args }}

# Run clippy for a single feature set, e.g. `just clippy native-tls "-- -D warnings"`
[group('code_check')]
clippy feature args="":
    cargo clippy -p suppaftp --features {{ feature }} {{ args }}

# Run clippy across every supported feature combination, denying warnings
[group('code_check')]
clippy_all:
    #!/usr/bin/env bash
    set -euo pipefail
    for feature in {{ FEATURES }}; do
        echo "::group::clippy $feature"
        cargo clippy -p suppaftp --features "$feature" -- -D warnings
        echo "::endgroup::"
    done

# Run clippy on the CLI binary, denying warnings
[group('code_check')]
clippy_cli args="":
    cargo clippy -p suppaftp-cli {{ args }} -- -D warnings

# Build the crate documentation, denying warnings
[group('code_check')]
doc args="":
    RUSTDOCFLAGS="-D warnings" cargo doc -p suppaftp --no-deps --features {{ DOC_FEATURES }} {{ args }}

# Check dependencies for advisories, licenses, bans and sources (cargo-deny)
[group('code_check')]
deny args="":
    cargo deny check {{ args }}

# Scan for secrets with trufflehog (defaults to the whole working tree)
[group('code_check')]
scan_secrets *args=".":
    trufflehog filesystem {{ args }} --results=verified,unknown --fail --no-update

# Point git at the tracked .githooks directory (installs the pre-commit hook)
[group('code_check')]
setup_githooks:
    git config core.hooksPath .githooks
    @echo "git hooks installed: core.hooksPath = .githooks"

# Run all code checks. Fails if any check fails
[group('code_check')]
check_code:
    just fmt_check
    just clippy_all
    just clippy_cli
    just doc
    just deny
