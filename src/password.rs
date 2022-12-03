//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

use std::{
    env,
    ffi::OsStr,
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

use anyhow::Context;
use dialoguer::{theme::ColorfulTheme, Password};

/// Removes trailing newline.
fn remove_newline(password: &str) -> String {
    password.trim_end_matches(&['\r', '\n'][..]).to_string()
}

/// Reads the password from /dev/tty.
pub fn read_password_from_tty() -> anyhow::Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter password")
        .with_confirmation("Confirm password", "Passwords mismatch, try again")
        .interact()
        .context("could not read password")
}

/// Reads the password from stdin.
pub fn read_password_from_stdin() -> anyhow::Result<String> {
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .context("could not read password from stdin")?;
    let password = remove_newline(&buf);
    Ok(password)
}

/// Reads the password from /dev/tty only once.
pub fn read_password_from_tty_once() -> anyhow::Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter password")
        .interact()
        .context("could not read password")
}

/// Reads the password from the environment variable.
pub fn read_password_from_env(key: &OsStr) -> anyhow::Result<String> {
    env::var(key).context("could not read password from environment variable")
}

/// Reads the password from the file.
pub fn read_password_from_file(path: &Path) -> anyhow::Result<String> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut buf = String::new();
    reader
        .read_line(&mut buf)
        .with_context(|| format!("could not read password from {}", path.display()))?;
    let password = remove_newline(&buf);
    Ok(password)
}
