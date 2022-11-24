//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

use std::path::Path;

use anyhow::Context;
use byte_unit::Byte;

/// Gets the encryption parameters.
pub fn get(data: &[u8], path: &Path) -> anyhow::Result<scryptenc::Params> {
    scryptenc::Params::new(data)
        .with_context(|| format!("{} is not a valid scrypt encrypted file", path.display()))
}

/// Prints the encryption parameters.
pub fn print(n: u64, r: u32, p: u32) {
    let mem_usage =
        Byte::from_bytes(128 * u128::from(n) * u128::from(r)).get_appropriate_unit(true);
    eprintln!("Parameters used: N = {}; r = {}; p = {};", n, r, p);
    eprintln!(
        "Decrypting this file requires at least {} of memory",
        mem_usage.format(1)
    );
}
