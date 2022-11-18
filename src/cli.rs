//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

use std::{ffi::OsString, io, path::PathBuf};

use clap::{value_parser, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{Generator, Shell};

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
    group(
        ArgGroup::new("passphrase")
            .arg("passphrase_from_tty")
            .arg("passphrase_from_stdin")
            .arg("passphrase_from_tty_once")
            .arg("passphrase_from_env")
            .arg("passphrase_from_file")
    )
)]
pub struct Encrypt {
    /// Set the work parameter N.
    #[arg(
        value_parser(value_parser!(u8).range(10..=40)),
        long,
        default_value("15"),
        value_name("VALUE")
    )]
    pub log_n: u8,

    /// Set the work parameter r.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        default_value("8"),
        value_name("VALUE")
    )]
    pub r: u32,

    /// Set the work parameter p.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        default_value("1"),
        value_name("VALUE")
    )]
    pub p: u32,

    /// Read the passphrase from /dev/tty.
    #[arg(long)]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from stdin.
    #[arg(long)]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from /dev/tty only once.
    #[arg(long)]
    pub passphrase_from_tty_once: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(long, value_name("FILE"), value_hint(ValueHint::FilePath))]
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
    group(
        ArgGroup::new("passphrase")
            .arg("passphrase_from_tty")
            .arg("passphrase_from_stdin")
            .arg("passphrase_from_env")
            .arg("passphrase_from_file")
    )
)]
pub struct Decrypt {
    /// Read the passphrase from /dev/tty.
    #[arg(long)]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from stdin.
    #[arg(long)]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(long, value_name("FILE"), value_hint(ValueHint::FilePath))]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        Opt::command().debug_assert();
    }
}
