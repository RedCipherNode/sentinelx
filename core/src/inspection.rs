//! Inspection pipeline.
//!
//! This module is responsible for inspecting supported targets and
//! collecting observable facts.
//!
//! Inspection never performs threat assessment.
//! Inspection never generates user-facing reports.

use crate::analysis::analyze;
use crate::assessment::Assessment;
use crate::file_type::FileType;
use crate::observation::Observation;
use crate::target::Target;
use md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub fn inspect(target: Target) -> Assessment {
    let observations = match target {
        Target::File(path) => inspect_file(&path),

        Target::Directory(path) => {
            vec![Observation::new("Target", path.display().to_string())]
        }

        Target::Url(url) => {
            vec![Observation::new("Target", url)]
        }

        Target::Command(command) => {
            vec![Observation::new("Target", command)]
        }
    };

    let findings = analyze(&observations);

    Assessment {
        summary: String::from("Inspection completed."),
        observations,
        findings,
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

    inspect_pe(path, &mut observations);

    observations
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

fn inspect_pe(path: &Path, observations: &mut Vec<Observation>) {
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    if bytes.len() < 0x40 {
        return;
    }
    if !bytes.starts_with(b"MZ") {
        return;
    }

    let pe_offset =
        u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;

    if pe_offset + 24 > bytes.len() {
        return;
    }

    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return;
    }

    let machine_code = u16::from_le_bytes([bytes[pe_offset + 4], bytes[pe_offset + 5]]);

    let machine = match machine_code {
        0x014c => "Intel 386 (0x014C)",
        0x8664 => "AMD64 (0x8664)",
        0xAA64 => "ARM64 (0xAA64)",
        _ => "Unknown",
    };

    let sections = u16::from_le_bytes([bytes[pe_offset + 6], bytes[pe_offset + 7]]);

    let timestamp = u32::from_le_bytes([
        bytes[pe_offset + 8],
        bytes[pe_offset + 9],
        bytes[pe_offset + 10],
        bytes[pe_offset + 11],
    ]);
    observations.push(Observation::new("PE Machine", machine));
    observations.push(Observation::new("PE Sections", sections.to_string()));
    observations.push(Observation::new(
        "PE Timestamp",
        format_pe_timestamp(timestamp),
    ));
}

use chrono::{DateTime, Utc};

fn format_pe_timestamp(timestamp: u32) -> String {
    let Some(datetime) = DateTime::<Utc>::from_timestamp(timestamp as i64, 0) else {
        return String::from("Invalid");
    };

    datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}
