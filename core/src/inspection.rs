//! Inspection pipeline.
//!
//! This module is responsible for inspecting supported targets and
//! collecting observable facts.
//!
//! Inspection never performs threat assessment.
//! Inspection never generates user-facing reports.

use crate::assessment::Assessment;
use crate::observation::Observation;
use crate::target::Target;
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

    Assessment {
        summary: String::from("Inspection completed."),
        observations,
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
        observations.push(Observation::new("Detected Type", file_type));

        if !extension_matches(path, file_type) {
            observations.push(Observation::with_description(
                "Extension Mismatch",
                "Yes",
                "The file extension does not match the detected file format.",
            ));
        }
    }

    observations
}

fn detect_file_type(path: &Path) -> Option<&'static str> {
    let mut file = File::open(path).ok()?;

    let mut buffer = [0u8; 16];
    let bytes_read = file.read(&mut buffer).ok()?;

    let data = &buffer[..bytes_read];

    if data.starts_with(b"MZ") {
        return Some("PE Executable");
    }

    if data.starts_with(b"%PDF") {
        return Some("PDF Document");
    }

    if data.starts_with(b"PK\x03\x04") {
        return Some("ZIP Archive");
    }

    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("PNG Image");
    }

    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("JPEG Image");
    }

    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("GIF Image");
    }

    None
}

fn extension_matches(path: &Path, detected_type: &str) -> bool {
    let Some(ext) = path.extension() else {
        return true;
    };

    let ext = ext.to_string_lossy().to_ascii_lowercase();

    match detected_type {
        "PE Executable" => ext == "exe",
        "PDF Document" => ext == "pdf",
        "ZIP Archive" => ext == "zip",
        "PNG Image" => ext == "png",
        "JPEG Image" => ext == "jpg" || ext == "jpeg",
        "GIF Image" => ext == "gif",
        _ => true,
    }
}
