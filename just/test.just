# Run tests for a single feature set, e.g. `just test native-tls test_name`
[group('test')]
test feature test_name="":
    cargo test -p suppaftp --features {{ feature }} {{ test_name }}

# Run tests across every supported feature combination
[group('test')]
test_all test_name="":
    #!/usr/bin/env bash
    set -euo pipefail
    for feature in {{ FEATURES }}; do
        echo "::group::test $feature"
        cargo test -p suppaftp --features "$feature" {{ test_name }}
        echo "::endgroup::"
    done

# Run tests with coverage for a single feature set (writes lcov-<feature>.info)
[group('test')]
coverage feature:
    cargo llvm-cov --no-fail-fast --no-default-features --features {{ feature }} --workspace --lcov --output-path lcov-{{ feature }}.info
