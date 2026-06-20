# Publish all crates in dependency order (library first, then the CLI)
[group('publish')]
publish_all: publish_lib publish_cli

# Publish the library crate
[group('publish')]
publish_lib:
    cargo publish -p suppaftp

# Publish the CLI crate
[group('publish')]
publish_cli:
    cargo publish -p suppaftp-cli
