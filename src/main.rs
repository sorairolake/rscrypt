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

mod cli;
mod core;
mod input;
mod output;
mod params;
mod password;
mod utils;

use std::{
    io,
    process::{self, Termination},
};

use scryptenc::Error as ScryptencError;

/// The system exit code of this package.
#[derive(Debug)]
enum ExitCode {
    /// The successful exit.
    Success,

    /// An error occurred.
    Failure,

    /// Data was not a valid scrypt-encrypted block.
    InvalidFormat,

    /// The version was the unrecognized scrypt version number.
    UnknownVersion,

    /// Decrypting files takes too much memory.
    LackOfMemory,

    /// Decrypting files takes too much CPU time.
    LackOfCpuTime,

    /// Password is incorrect.
    InvalidPassword,

    /// The scrypt parameters were invalid.
    InvalidParams,

    /// Decrypting files takes too much resources.
    LackOfResources,

    /// Error defined by `<sysexits.h>`.
    Other(sysexits::ExitCode),
}

impl From<sysexits::ExitCode> for ExitCode {
    fn from(code: sysexits::ExitCode) -> Self {
        Self::Other(code)
    }
}

impl Termination for ExitCode {
    fn report(self) -> process::ExitCode {
        match self {
            Self::Success => process::ExitCode::SUCCESS,
            Self::Failure => process::ExitCode::FAILURE,
            Self::InvalidFormat => process::ExitCode::from(7),
            Self::UnknownVersion => process::ExitCode::from(8),
            Self::LackOfMemory => process::ExitCode::from(9),
            Self::LackOfCpuTime => process::ExitCode::from(10),
            Self::InvalidPassword => process::ExitCode::from(11),
            Self::InvalidParams => process::ExitCode::from(14),
            Self::LackOfResources => process::ExitCode::from(15),
            Self::Other(code) => process::ExitCode::from(code),
        }
    }
}

fn main() -> ExitCode {
    match core::run() {
        Ok(()) => ExitCode::Success,
        Err(err) => {
            eprintln!("Error: {err:?}");
            #[allow(clippy::option_if_let_else)]
            if let Some(e) = err.downcast_ref::<io::Error>() {
                match e.kind() {
                    io::ErrorKind::NotFound => sysexits::ExitCode::NoInput.into(),
                    io::ErrorKind::PermissionDenied => sysexits::ExitCode::NoPerm.into(),
                    _ => ExitCode::Failure,
                }
            } else if let Some(e) = err.downcast_ref::<ScryptencError>() {
                match e {
                    ScryptencError::InvalidLength
                    | ScryptencError::InvalidMagicNumber
                    | ScryptencError::InvalidChecksum => ExitCode::InvalidFormat,
                    ScryptencError::UnknownVersion(_) => ExitCode::UnknownVersion,
                    ScryptencError::InvalidParams(_) => ExitCode::InvalidParams,
                    ScryptencError::InvalidSignature(_) => ExitCode::InvalidPassword,
                }
            } else if let Some(e) = err.downcast_ref::<params::Error>() {
                match e {
                    params::Error::Memory => ExitCode::LackOfMemory,
                    params::Error::CpuTime => ExitCode::LackOfCpuTime,
                    params::Error::Resources => ExitCode::LackOfResources,
                }
            } else {
                ExitCode::Failure
            }
        }
    }
}
