//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

use std::{ffi::OsString, io, path::PathBuf, str::FromStr, time::Duration};

use anyhow::anyhow;
use byte_unit::{n_eib_bytes, n_mib_bytes};
use clap::{value_parser, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{Generator, Shell};
use fraction::{Fraction, Zero};

#[derive(Debug, Parser)]
#[command(
    name("rscrypt"),
    version,
    about,
    max_term_width(100),
    propagate_version(true),
    arg_required_else_help(true),
    args_conflicts_with_subcommands(true)
)]
pub struct Opt {
    /// Generate shell completion.
    ///
    /// The completion is output to stdout.
    #[arg(long, value_enum, value_name("SHELL"))]
    pub generate_completion: Option<Shell>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt files.
    #[command(name("enc"))]
    Encrypt(Encrypt),

    /// Decrypt files.
    #[command(name("dec"))]
    Decrypt(Decrypt),

    /// Provides information about the encryption parameters.
    #[command(name("info"))]
    Information(Information),
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
#[command(
    group(ArgGroup::new("password")),
    group(
        ArgGroup::new("resources")
            .multiple(true)
            .conflicts_with("force")
            .conflicts_with("parameters")
    ),
    group(ArgGroup::new("parameters").multiple(true))
)]
pub struct Encrypt {
    /// Force the encryption to proceed even if it requires an excessive amount
    /// of resources.
    #[arg(short, long, requires("parameters"))]
    pub force: bool,

    /// Use at most the specified bytes of RAM to compute the derived key.
    #[arg(short('M'), long, value_name("BYTES"), group("resources"))]
    pub max_memory: Option<Byte>,

    /// Use at most the specified fraction of the available RAM to compute the
    /// derived key.
    #[arg(
        short,
        long,
        default_value("0.125"),
        value_name("RATE"),
        group("resources")
    )]
    pub max_memory_fraction: Rate,

    /// Use at most the specified seconds of CPU time to compute the derived
    /// key.
    #[arg(
        short('t'),
        long,
        default_value("5"),
        value_name("SECONDS"),
        group("resources")
    )]
    pub max_time: Time,

    /// Set the work parameter N.
    #[arg(
        value_parser(value_parser!(u8).range(10..=40)),
        long,
        requires("r"),
        requires("p"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub log_n: Option<u8>,

    /// Set the work parameter r.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        requires("log_n"),
        requires("p"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub r: Option<u32>,

    /// Set the work parameter p.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        requires("log_n"),
        requires("r"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub p: Option<u32>,

    /// Read the password from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("password"))]
    pub passphrase_from_tty: bool,

    /// Read the password from stdin.
    #[arg(long, group("password"))]
    pub passphrase_from_stdin: bool,

    /// Read the password from /dev/tty only once.
    #[arg(long, group("password"))]
    pub passphrase_from_tty_once: bool,

    /// Read the password from the environment variable.
    ///
    /// Note that storing a password in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("password"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the password from the file.
    ///
    /// Note that storing a password in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("password")
    )]
    pub passphrase_from_file: Option<PathBuf>,

    /// Print encryption parameters and resource limits.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from stdin.
    #[arg(value_name("INFILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,

    /// Output file.
    ///
    /// If it is not specified, the result will be write to stdout.
    #[arg(value_name("OUTFILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
#[command(
    group(ArgGroup::new("password")),
    group(ArgGroup::new("resources").multiple(true).conflicts_with("force"))
)]
pub struct Decrypt {
    /// Force the decryption to proceed even if it requires an excessive amount
    /// of resources.
    #[arg(short, long)]
    pub force: bool,

    /// Use at most the specified bytes of RAM to compute the derived key.
    #[arg(short('M'), long, value_name("BYTES"), group("resources"))]
    pub max_memory: Option<Byte>,

    /// Use at most the specified fraction of the available RAM to compute the
    /// derived key.
    #[arg(
        short,
        long,
        default_value("0.5"),
        value_name("RATE"),
        group("resources")
    )]
    pub max_memory_fraction: Rate,

    /// Use at most the specified seconds of CPU time to compute the derived
    /// key.
    #[arg(
        short('t'),
        long,
        default_value("300"),
        value_name("SECONDS"),
        group("resources")
    )]
    pub max_time: Time,

    /// Read the password from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("password"))]
    pub passphrase_from_tty: bool,

    /// Read the password from stdin.
    #[arg(long, group("password"))]
    pub passphrase_from_stdin: bool,

    /// Read the password from the environment variable.
    ///
    /// Note that storing a password in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("password"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the password from the file.
    ///
    /// Note that storing a password in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("password")
    )]
    pub passphrase_from_file: Option<PathBuf>,

    /// Print encryption parameters and resource limits.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from stdin.
    #[arg(value_name("INFILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,

    /// Output file.
    ///
    /// If it is not specified, the result will be write to stdout.
    #[arg(value_name("OUTFILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Information {
    /// Output format.
    #[cfg(any(feature = "cbor", feature = "json", feature = "toml", feature = "yaml"))]
    #[arg(short, long, value_enum, value_name("FORMAT"), ignore_case(true))]
    pub format: Option<Format>,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from stdin.
    #[arg(value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,
}

impl Opt {
    /// Generates shell completion and print it.
    pub fn print_completion(gen: impl Generator) {
        clap_complete::generate(
            gen,
            &mut Self::command(),
            Self::command().get_name(),
            &mut io::stdout(),
        );
    }
}

/// Amount of RAM.
#[derive(Clone, Copy, Debug)]
pub struct Byte(byte_unit::Byte);

impl Byte {
    /// Returns `byte_unit::Byte`.
    pub const fn as_byte(&self) -> byte_unit::Byte {
        self.0
    }
}

impl FromStr for Byte {
    type Err = anyhow::Error;

    fn from_str(bytes: &str) -> anyhow::Result<Self> {
        match byte_unit::Byte::from_str(bytes) {
            Ok(b) if b.get_bytes() < n_mib_bytes!(1) => {
                Err(anyhow!("amount of RAM is less than 1 MiB"))
            }
            Ok(b) if b.get_bytes() > n_eib_bytes!(16) => {
                Err(anyhow!("amount of RAM is more than 16 EiB"))
            }
            Err(err) => Err(anyhow!("amount of RAM is not a valid value: {err}")),
            Ok(b) => Ok(Self(b)),
        }
    }
}

/// Fraction of the available RAM.
#[derive(Clone, Copy, Debug)]
pub struct Rate(Fraction);

impl Rate {
    /// Returns `Fraction`.
    pub const fn as_fraction(&self) -> Fraction {
        self.0
    }
}

impl FromStr for Rate {
    type Err = anyhow::Error;

    fn from_str(rate: &str) -> anyhow::Result<Self> {
        match Fraction::from_str(rate) {
            Ok(r) if r == Fraction::zero() => Err(anyhow!("fraction is 0")),
            Ok(r) if r > Fraction::from(0.5) => Err(anyhow!("fraction is more than 0.5")),
            Err(err) => Err(anyhow!("fraction is not a valid number: {err}")),
            Ok(r) => Ok(Self(r)),
        }
    }
}

/// CPU time.
#[derive(Clone, Copy, Debug)]
pub struct Time(Duration);

impl Time {
    /// Returns `Duration`.
    pub const fn as_duration(&self) -> Duration {
        self.0
    }
}

impl FromStr for Time {
    type Err = anyhow::Error;

    fn from_str(seconds: &str) -> anyhow::Result<Self> {
        match f64::from_str(seconds) {
            Ok(s) if s.is_nan() => Err(anyhow!("time is NaN")),
            Ok(s) if s.is_sign_negative() => Err(anyhow!("time is negative")),
            Ok(s) if s.is_infinite() => Err(anyhow!("time is infinite")),
            Ok(s) if s >= Duration::MAX.as_secs_f64() => Err(anyhow!("time is too big")),
            Err(err) => Err(anyhow!("time is not a valid number: {err}")),
            Ok(s) => Ok(Self(Duration::from_secs_f64(s))),
        }
    }
}

#[cfg(any(feature = "cbor", feature = "json", feature = "toml", feature = "yaml"))]
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Format {
    /// CBOR.
    #[cfg(feature = "cbor")]
    Cbor,

    /// JSON.
    #[cfg(feature = "json")]
    Json,

    /// TOML.
    #[cfg(feature = "toml")]
    Toml,

    /// YAML.
    #[cfg(feature = "yaml")]
    Yaml,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        Opt::command().debug_assert();
    }
}
