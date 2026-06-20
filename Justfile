import "./just/build.just"
import "./just/changelog.just"
import "./just/code_check.just"
import "./just/publish.just"
import "./just/test.just"

# Every feature combination the library is built, linted and tested against.
# These are mutually exclusive in many cases, so they must be exercised one at a
# time. Keep in sync with the matrix in .github/workflows/ci.yml.
FEATURES := "native-tls rustls-aws-lc-rs rustls-ring smol tokio smol-async-native-tls tokio-async-native-tls smol-rustls-aws-lc-rs smol-rustls-ring tokio-rustls-aws-lc-rs tokio-rustls-ring"

# The feature set documented on docs.rs; these coexist, so docs build in one pass.
DOC_FEATURES := "native-tls,rustls-aws-lc-rs,smol,tokio,tokio-async-native-tls,smol-rustls-aws-lc-rs,tokio-rustls-aws-lc-rs"

# Lists all the available commands
default:
    @just --list
