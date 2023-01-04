# rscrypt

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![License][license-badge]

**rscrypt** ([`scryptenc-cli`][version-url]) is a command-line utility for
encrypt and decrypt files.

This is a Rust implementation of `scrypt(1)`.

## Installation

### From source

```sh
cargo install scryptenc-cli
```

### From binaries

The [release page][release-page-url] contains pre-built binaries for Linux,
macOS and Windows.

### How to build

Please see [BUILD.adoc](BUILD.adoc).

## Usage

### Basic usage

Encrypt a file:

```sh
rscrypt enc file file.enc
```

Decrypt a file:

```sh
rscrypt dec file.enc file
```

### Generate shell completion

`--generate-completion` option generates shell completions to stdout.

The following shells are supported:

- `bash`
- `elvish`
- `fish`
- `powershell`
- `zsh`

Example:

```sh
rscrypt --generate-completion bash > rscrypt.bash
```

## Command-line options

Please see the following:

- [`rscrypt(1)`](doc/man/man1/rscrypt.1.adoc)
- [`rscrypt-enc(1)`](doc/man/man1/rscrypt-enc.1.adoc)
- [`rscrypt-dec(1)`](doc/man/man1/rscrypt-dec.1.adoc)
- [`rscrypt-info(1)`](doc/man/man1/rscrypt-info.1.adoc)

## Changelog

Please see [CHANGELOG.adoc](CHANGELOG.adoc).

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## License

Copyright &copy; 2022&ndash;2023 Shun Sakai (see [AUTHORS.adoc](AUTHORS.adoc))

This program is distributed under the terms of the _GNU General Public License
v3.0 or later_.

See [COPYING](COPYING) for more details.

[ci-badge]: https://github.com/sorairolake/rscrypt/workflows/CI/badge.svg
[ci-url]: https://github.com/sorairolake/rscrypt/actions?query=workflow%3ACI
[version-badge]: https://img.shields.io/crates/v/scryptenc-cli
[version-url]: https://crates.io/crates/scryptenc-cli
[license-badge]: https://img.shields.io/crates/l/scryptenc-cli
[release-page-url]: https://github.com/sorairolake/rscrypt/releases
