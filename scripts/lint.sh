#!/usr/bin/env bash

FEATURES="native-tls
rustls
async-std
tokio
tokio-async-native-tls
async-std-rustls
tokio-rustls"

set -euox pipefail

for feature in $FEATURES; do
  cargo clippy -p suppaftp --features $feature -- -D warnings
done
