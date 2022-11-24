//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, Read},
    path::Path,
};

use anyhow::Context;
use dialoguer::{theme::ColorfulTheme, Password};

/// Reads the passphrase from /dev/tty.
pub fn read_passphrase_from_tty() -> anyhow::Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter password")
        .with_confirmation("Confirm password", "Passwords mismatch, try again")
        .interact()
        .context("could not read password")
}

/// Reads the passphrase from stdin.
pub fn read_passphrase_from_stdin() -> anyhow::Result<String> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .context("could not read password from stdin")?;
    Ok(buf)
}

/// Reads the passphrase from /dev/tty only once.
pub fn read_passphrase_from_tty_once() -> anyhow::Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter password")
        .interact()
        .context("could not read password")
}

/// Reads the passphrase from the environment variable.
pub fn read_passphrase_from_env(key: &OsStr) -> anyhow::Result<String> {
    env::var(key).context("could not read password from environment variable")
}

/// Reads the passphrase from the file.
pub fn read_passphrase_from_file(path: &Path) -> anyhow::Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("could not read password from {}", path.display()))
}
