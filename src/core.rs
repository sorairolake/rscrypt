//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

use std::{
    env, fs,
    io::{self, Read, Write},
    path::Path,
};

use anyhow::Context;
use byte_unit::Byte;
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Password};
use scryptenc::{scrypt, Decryptor, Encryptor, Error as ScryptencError};

use crate::cli::{Command, Opt};

/// Runs the program and returns the result.
#[allow(clippy::too_many_lines)]
pub fn run() -> anyhow::Result<()> {
    let opt = Opt::parse();

    if let Some(shell) = opt.generate_completion {
        Opt::print_completion(shell);
        return Ok(());
    }

    if let Some(command) = opt.command {
        match command {
            Command::Encrypt(arg) => {
                let input = if arg.input == Path::new("-") {
                    let mut buf = Vec::new();
                    io::stdin()
                        .read_to_end(&mut buf)
                        .context("could not read data from stdin")?;
                    buf
                } else {
                    fs::read(&arg.input).with_context(|| {
                        format!("could not read data from {}", arg.input.display())
                    })?
                };

                let password = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_tty_once,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => {
                        let mut buf = String::new();
                        io::stdin()
                            .read_to_string(&mut buf)
                            .context("could not read password from stdin")?;
                        buf
                    }
                    (_, _, true, ..) => Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter password")
                        .interact()
                        .context("could not read password")?,
                    (.., Some(env), _) => env::var(env)
                        .context("could not read password from environment variable")?,
                    (.., Some(file)) => fs::read_to_string(&file).with_context(|| {
                        format!("could not read password from {}", file.display())
                    })?,
                    _ => Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter password")
                        .with_confirmation("Confirm password", "Passwords mismatch, try again")
                        .interact()
                        .context("could not read password")?,
                };

                if arg.verbose {
                    let n: u64 = 1 << arg.log_n;
                    let mem_usage = Byte::from_bytes(128 * u128::from(n) * u128::from(arg.r))
                        .get_appropriate_unit(true);
                    eprintln!("Parameters used: N = {}; r = {}; p = {};", n, arg.r, arg.p);
                    eprintln!(
                        "Decrypting this file requires at least {} of memory",
                        mem_usage.format(1)
                    );
                }

                let params = scrypt::Params::new(arg.log_n, arg.r, arg.p)
                    .expect("encryption parameters should be valid");
                let cipher = Encryptor::with_params(input, password, params);
                let encrypted = cipher.encrypt_to_vec();

                if let Some(file) = arg.output {
                    fs::write(&file, encrypted)
                        .with_context(|| format!("could not write data to {}", file.display()))?;
                } else {
                    io::stdout()
                        .write_all(&encrypted)
                        .context("could not write data to stdout")?;
                }
            }
            Command::Decrypt(arg) => {
                let input = if arg.input == Path::new("-") {
                    let mut buf = Vec::new();
                    io::stdin()
                        .read_to_end(&mut buf)
                        .context("could not read data from stdin")?;
                    buf
                } else {
                    fs::read(&arg.input).with_context(|| {
                        format!("could not read data from {}", arg.input.display())
                    })?
                };

                let password = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => {
                        let mut buf = String::new();
                        io::stdin()
                            .read_to_string(&mut buf)
                            .context("could not read password from stdin")?;
                        buf
                    }
                    (.., Some(env), _) => env::var(env)
                        .context("could not read password from environment variable")?,
                    (.., Some(file)) => fs::read_to_string(&file).with_context(|| {
                        format!("could not read password from {}", file.display())
                    })?,
                    _ => Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter password")
                        .interact()
                        .context("could not read password")?,
                };

                if arg.verbose {
                    let params = scryptenc::Params::new(&input).with_context(|| {
                        format!(
                            "{} is not a valid scrypt encrypted file",
                            arg.input.display()
                        )
                    })?;
                    let mem_usage =
                        Byte::from_bytes(128 * u128::from(params.n()) * u128::from(params.r()))
                            .get_appropriate_unit(true);
                    eprintln!(
                        "Parameters used: N = {}; r = {}; p = {};",
                        params.n(),
                        params.r(),
                        params.p()
                    );
                    eprintln!(
                        "Decrypting this file requires at least {} of memory",
                        mem_usage.format(1)
                    );
                }

                let cipher = match Decryptor::new(input, password) {
                    c @ Err(ScryptencError::InvalidSignature(_)) => {
                        c.context("password is incorrect")
                    }
                    c => c.with_context(|| {
                        format!("the header in {} is invalid", arg.input.display())
                    }),
                }?;
                let decrypted = cipher
                    .decrypt_to_vec()
                    .with_context(|| format!("{} is corrupted", arg.input.display()))?;

                if let Some(file) = arg.output {
                    fs::write(&file, decrypted)
                        .with_context(|| format!("could not write data to {}", file.display()))?;
                } else {
                    io::stdout()
                        .write_all(&decrypted)
                        .context("could not write data to stdout")?;
                }
            }
            Command::Information(arg) => {
                let input = if arg.input == Path::new("-") {
                    let mut buf = Vec::new();
                    io::stdin()
                        .read_to_end(&mut buf)
                        .context("could not read data from stdin")?;
                    buf
                } else {
                    fs::read(&arg.input).with_context(|| {
                        format!("could not read data from {}", arg.input.display())
                    })?
                };

                let params = scryptenc::Params::new(input).with_context(|| {
                    format!(
                        "{} is not a valid scrypt encrypted file",
                        arg.input.display()
                    )
                })?;
                let mem_usage =
                    Byte::from_bytes(128 * u128::from(params.n()) * u128::from(params.r()))
                        .get_appropriate_unit(true);
                eprintln!(
                    "Parameters used: N = {}; r = {}; p = {};",
                    params.n(),
                    params.r(),
                    params.p()
                );
                eprintln!(
                    "Decrypting this file requires at least {} of memory",
                    mem_usage.format(1)
                );
            }
        }
    } else {
        unreachable!();
    }
    Ok(())
}
