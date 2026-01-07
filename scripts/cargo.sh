#!/usr/bin/env bash

FEATURES="native-tls
rustls
async-std
tokio
tokio-async-native-tls
async-std-rustls
tokio-rustls"

set -euox pipefail

build_all() {
  for feature in $FEATURES; do
    cargo build -p suppaftp --features $feature
  done
}

clippy_all() {
  for feature in $FEATURES; do
    cargo clippy -p suppaftp --features $feature -- -D warnings
  done
}

test_all() {
  local test_name
  test_name="${1:-}"
  for feature in $FEATURES; do
    cargo test -p suppaftp --features $feature $test_name
  done
}

COMMAND=${1:-x}
shift

case "$COMMAND" in

  "lint")
    clippy_all
    ;;
  
  "test")
    test_all "$@"
    ;;

  "build")
    build_all
    ;;

  *)
    echo "Unknown command: $COMMAND"
    exit 1
    ;;

esac