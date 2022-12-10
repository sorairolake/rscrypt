//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Copyright (C) 2022 Shun Sakai
//

/// Removes trailing newline.
pub fn remove_newline(string: &str) -> String {
    string.trim_end_matches(&['\r', '\n'][..]).to_string()
}
