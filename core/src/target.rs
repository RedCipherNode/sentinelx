//! Inspection targets.
//!
//! This module defines the types of targets supported by SentinelX.
//! It is responsible only for representing inspection targets.
//! It does not perform inspection or analysis.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum Target {
    File(PathBuf),
    Directory(PathBuf),
    Url(String),
    Command(String),
}

impl Target {
    pub fn resolve(input: &str) -> Self {
        if input.starts_with("http://") || input.starts_with("https://") {
            return Self::Url(input.to_owned());
        }

        let path = Path::new(input);

        if path.exists() {
            if path.is_dir() {
                return Self::Directory(path.to_path_buf());
            }

            return Self::File(path.to_path_buf());
        }

        // Temporary fallback.
        //
        // Unknown inputs are currently treated as files.
        // Future versions will distinguish commands and
        // unsupported targets.
        Self::File(path.to_path_buf())
    }
}
