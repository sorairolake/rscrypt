# SPDX-FileCopyrightText: 2022 Shun Sakai
#
# SPDX-License-Identifier: GPL-3.0-or-later

alias all := default
alias lint := clippy

# Run default recipe
default: build

# Build a package
@build:
    cargo build

# Remove generated artifacts
@clean:
    cargo clean

# Check a package
@check:
    cargo check

# Run tests
@test:
    cargo test

# Run the formatter
@fmt:
    cargo fmt

# Run the formatter with options
@fmt-with-options:
    cargo fmt -- --config "format_code_in_doc_comments=true,wrap_comments=true"

# Run the linter
@clippy:
    cargo clippy -- -D warnings

# Apply lint suggestions
@clippy-fix:
    cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs -- -D warnings

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint

# Run the formatter for the README
@fmt-readme:
    npx prettier -w README.md

# Build the book
build-book:
    #!/usr/bin/env bash
    sed -i -E -e '/^:includedir: \.\.\//s/\.\.\//\.\//' -e '/ifdef::|endif::/d' doc/book/man/man1/*.1.adoc
    npx honkit build
