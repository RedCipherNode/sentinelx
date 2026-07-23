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

//=====================================================
// Public API
//=====================================================

pub fn inspect(target: Target) -> Assessment {
    let observations = inspect_target(target);
    let findings = analyze(&observations);

    Assessment {
        summary: String::from("Inspection completed."),
        observations,
        findings,
    }
}

//=====================================================
// Main Pipeline
//=====================================================

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

    inspect_metadata(path, &mut observations);

    let file_type = detect_file_type(path);

    if let Some(file_type) = file_type {
        observations.push(Observation::new("Detected Type", file_type.display()));
    }

    inspect_hashes(path, &mut observations);

    if let Some(file_type) = file_type {
        dispatch_file(path, file_type, &mut observations);
    }

    observations
}

fn inspect_directory(path: &Path) -> Vec<Observation> {
    let mut observations = Vec::new();

    observations.push(Observation::new("Target", path.display().to_string()));

    observations
}

fn inspect_url(url: &str) -> Vec<Observation> {
    let mut observations = Vec::new();

    observations.push(Observation::new("Target", url));

    observations
}

fn inspect_command(command: &str) -> Vec<Observation> {
    let mut observations = Vec::new();

    observations.push(Observation::new("Target", command));

    observations
}

//=====================================================
// Discovery Pipeline
//=====================================================

//
// Reserved.
//
// This pipeline is executed when an inspector discovers
// additional inspection targets during investigation.
//
// Examples:
//
// ZIP  -> extracted executable
// PDF  -> embedded file
// PDF  -> URI
// DOCX -> embedded object
// PNG  -> extracted payload
//
// Future:
//
// fn inspect_discovered_target(...)
//
// fn inspect_child_target(...)
//

//=====================================================
// Orchestration Support
//=====================================================

//
// --------------------------------------------------------
// Identification
// --------------------------------------------------------
//

fn detect_file_type(path: &Path) -> Option<FileType> {
    let mut file = File::open(path).ok()?;

    let mut header = [0u8; 32];

    let bytes_read = file.read(&mut header).ok()?;

    FileType::detect(&header[..bytes_read])
}

//
// --------------------------------------------------------
// Dispatching
// --------------------------------------------------------
//

fn dispatch_file(path: &Path, file_type: FileType, observations: &mut Vec<Observation>) {
    match file_type {
        FileType::PE => inspect_pe(path, observations),

        _ => {}
    }
}

//
// --------------------------------------------------------
// General Inspection
// --------------------------------------------------------
//

fn inspect_metadata(path: &Path, observations: &mut Vec<Observation>) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };

    observations.push(Observation::new("File Size", metadata.len().to_string()));

    observations.push(Observation::new(
        "Read Only",
        metadata.permissions().readonly().to_string(),
    ));
}

fn inspect_hashes(path: &Path, observations: &mut Vec<Observation>) {
    let Ok(mut file) = File::open(path) else {
        return;
    };

    let mut buffer = Vec::new();

    if file.read_to_end(&mut buffer).is_err() {
        return;
    }

    let md5 = format!("{:x}", md5::compute(&buffer));

    let sha1 = format!("{:x}", Sha1::digest(&buffer));

    let sha256 = format!("{:x}", Sha256::digest(&buffer));

    observations.push(Observation::new("MD5", md5));

    observations.push(Observation::new("SHA1", sha1));

    observations.push(Observation::new("SHA256", sha256));
}
