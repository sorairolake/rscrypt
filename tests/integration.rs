//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]
#![allow(clippy::multiple_crate_versions)]

use assert_cmd::Command;
use predicates::prelude::predicate;

fn command() -> Command {
    let mut command = Command::cargo_bin("rscrypt").unwrap();
    command.current_dir("tests");
    command
}

#[test]
fn generate_completion_conflicts_with_subcommands() {
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("enc")
        .assert()
        .failure()
        .code(2);
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("dec")
        .assert()
        .failure()
        .code(2);
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("info")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn basic_encrypt() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .success();
}

#[test]
fn encrypt_verbose() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: N = 1024; r = 8; p = 1;",
        ));
}

#[test]
fn validate_work_parameter_ranges_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("9")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid value '9' for '--log-n <VALUE>': 9 is not in 10..=40",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("41")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid value '41' for '--log-n <VALUE>': 41 is not in 10..=40",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("0")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid value '0' for '-r <VALUE>': 0 is not in 1..=32",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("33")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid value '33' for '-r <VALUE>': 33 is not in 1..=32",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("0")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid value '0' for '-p <VALUE>': 0 is not in 1..=32",
        ));
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("33")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Invalid value '33' for '-p <VALUE>': 33 is not in 1..=32",
        ));
}

#[test]
fn validate_conflicts_if_reading_from_stdin_for_encrypt_command() {
    command()
        .arg("enc")
        .arg("--log-n")
        .arg("10")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("-")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both password and input data from stdin\n",
        ));
}

#[test]
fn basic_decrypt() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.enc")
        .write_stdin("password")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
}

#[test]
fn decrypt_verbose() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.enc")
        .write_stdin("password")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: N = 1024; r = 8; p = 1;",
        ));
}

#[test]
fn validate_conflicts_if_reading_from_stdin_for_decrypt_command() {
    command()
        .arg("dec")
        .arg("--passphrase-from-stdin")
        .arg("-")
        .write_stdin("password")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both password and input data from stdin\n",
        ));
}

#[test]
fn basic_information() {
    command()
        .arg("info")
        .arg("data/data.txt.enc")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: N = 1024; r = 8; p = 1;",
        ));
}

#[cfg(feature = "cbor")]
#[test]
fn information_as_cbor() {
    command()
        .arg("info")
        .arg("-f")
        .arg("cbor")
        .arg("data/data.txt.enc")
        .assert()
        .success()
        .stdout(predicate::eq(
            [
                0xa3, 0x61, 0x4e, 0x19, 0x04, 0x00, 0x61, 0x72, 0x08, 0x61, 0x70, 0x01,
            ]
            .as_slice(),
        ));
}

#[cfg(feature = "json")]
#[test]
fn information_as_json() {
    command()
        .arg("info")
        .arg("-f")
        .arg("json")
        .arg("data/data.txt.enc")
        .assert()
        .success()
        .stdout(predicate::eq(concat!(r#"{"N":1024,"r":8,"p":1}"#, '\n')));
}

#[cfg(feature = "toml")]
#[test]
fn information_as_toml() {
    command()
        .arg("info")
        .arg("-f")
        .arg("toml")
        .arg("data/data.txt.enc")
        .assert()
        .success()
        .stdout(predicate::eq("N = 1024\nr = 8\np = 1\n"));
}

#[cfg(feature = "yaml")]
#[test]
fn information_as_yaml() {
    command()
        .arg("info")
        .arg("-f")
        .arg("yaml")
        .arg("data/data.txt.enc")
        .assert()
        .success()
        .stdout(predicate::eq("N: 1024\nr: 8\np: 1\n"));
}
