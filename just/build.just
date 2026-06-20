# Build the library for a single feature set, e.g. `just build native-tls`
[group('build')]
build feature args="":
    cargo build -p suppaftp --features {{ feature }} {{ args }}

# Build the library across every supported feature combination
[group('build')]
build_all:
    #!/usr/bin/env bash
    set -euo pipefail
    for feature in {{ FEATURES }}; do
        echo "::group::build $feature"
        cargo build -p suppaftp --features "$feature"
        echo "::endgroup::"
    done

# Build the CLI binary
[group('build')]
build_cli args="":
    cargo build -p suppaftp-cli {{ args }}

# Clean build artifacts
[group('build')]
[confirm("Are you sure you want to clean the build artifacts?")]
clean:
    cargo clean
