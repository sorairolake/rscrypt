//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

use std::{ffi::OsString, io, path::PathBuf, str::FromStr, time::Duration};

use anyhow::anyhow;
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
    group(ArgGroup::new("passphrase")),
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

    /// Read the passphrase from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from stdin.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from /dev/tty only once.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty_once: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("passphrase"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("passphrase")
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
    group(ArgGroup::new("passphrase")),
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

    /// Read the passphrase from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from stdin.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("passphrase"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("passphrase")
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
        let bytes = byte_unit::Byte::from_str(bytes)?;
        if bytes.get_bytes() > u128::from(u64::MAX) {
            Err(anyhow!("maximum amount of RAM should be 16 EiB or less"))
        } else {
            Ok(Self(bytes))
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
        let rate = Fraction::from_str(rate)?;
        match rate {
            r if (Fraction::new(1_u64, u64::MAX)..=Fraction::new(1_u64, 2_u64)).contains(&r) => {
                Ok(Self(r))
            }
            r if r == Fraction::zero() => Err(anyhow!(
                "fraction of the available RAM should be greater than 0.0"
            )),
            r => Err(anyhow!("{r} is not in 0.0..=0.5")),
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
        let secs = f64::from_str(seconds)?;
        if secs.is_sign_negative() {
            Err(anyhow!("time is negative"))
        } else if secs >= Duration::MAX.as_secs_f64() {
            Err(anyhow!("time is too big"))
        } else if !secs.is_finite() {
            Err(anyhow!("time is not finite"))
        } else {
            Ok(Self(Duration::from_secs_f64(secs)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        Opt::command().debug_assert();
    }
}
