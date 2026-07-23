//! Inspection orchestrator (Dispatcher).
//!
//! This module coordinates the inspection pipeline.
//!
//! It performs general inspection, identifies target types,
//! and dispatches targets to the appropriate inspectors.
//!
//! The orchestrator never interprets format-specific structures.
//! The orchestrator never performs threat assessment.
//! The orchestrator never generates user-facing reports.

use crate::analysis::analyze;
use crate::assessment::Assessment;
use crate::file_type::FileType;
use crate::inspection::inspect_pe;
use crate::observation::Observation;
use crate::target::Target;

use md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub fn inspect(target: Target) -> Assessment {
    let observations = inspect_target(target);
    let findings = analyze(&observations);

    Assessment {
        summary: String::from("Inspection completed."),
        observations,
        findings,
    }
}

fn inspect_target(target: Target) -> Vec<Observation> {
    match target {
        Target::File(path) => inspect_file(&path),
        Target::Directory(path) => inspect_directory(&path),
        Target::Url(url) => inspect_url(&url),
        Target::Command(command) => inspect_command(&command),
    }
}

fn inspect_file(path: &Path) -> Vec<Observation> {
    let mut observations = Vec::new();

    observations.push(Observation::new("Target", path.display().to_string()));

    if let Some(ext) = path.extension() {
        observations.push(Observation::new(
            "Extension",
            format!(".{}", ext.to_string_lossy()),
        ));
    }

    if let Ok(metadata) = fs::metadata(path) {
        observations.push(Observation::new(
            "Size",
            format!("{} bytes", metadata.len()),
        ));
    }

    if let Some(file_type) = detect_file_type(path) {
        observations.push(Observation::new("Detected Type", file_type.display()));
    }

    inspect_hashes(path, &mut observations);

    dispatch(path, &mut observations);

    observations
}

fn dispatch(path: &Path, observations: &mut Vec<Observation>) {
    if let Some(file_type) = detect_file_type(path) {
        match file_type {
            FileType::PE => inspect_pe(path, observations),

            _ => {}
        }
    }
}

fn detect_file_type(path: &Path) -> Option<FileType> {
    let mut file = File::open(path).ok()?;

    let mut buffer = [0u8; 16];
    let bytes_read = file.read(&mut buffer).ok()?;

    let data = &buffer[..bytes_read];

    if data.starts_with(b"MZ") {
        return Some(FileType::PE);
    }

    if data.starts_with(b"%PDF") {
        return Some(FileType::PDF);
    }

    if data.starts_with(b"PK\x03\x04") {
        return Some(FileType::ZIP);
    }

    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(FileType::PNG);
    }

    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(FileType::JPEG);
    }

    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some(FileType::GIF);
    }

    None
}

//==================================
//Hash
//===============================

fn inspect_hashes(path: &Path, observations: &mut Vec<Observation>) {
    let Ok(bytes) = fs::read(path) else {
        return;
    };

    //
    // MD5
    //

    let md5 = md5::compute(&bytes);

    observations.push(Observation::new("MD5", format!("{:x}", md5)));

    //
    // SHA-1
    //

    let mut sha1 = Sha1::new();

    sha1.update(&bytes);

    observations.push(Observation::new("SHA-1", format!("{:x}", sha1.finalize())));

    //
    // SHA-256
    //

    let mut sha256 = Sha256::new();

    sha256.update(&bytes);

    observations.push(Observation::new(
        "SHA-256",
        format!("{:x}", sha256.finalize()),
    ));
}
