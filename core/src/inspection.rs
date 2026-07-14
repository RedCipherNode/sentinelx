//! Inspection pipeline.
//!
//! This module is responsible for inspecting supported targets and
//! collecting observable facts.
//!
//! Inspection never performs threat assessment.
//! Inspection never generates user-facing reports.

use crate::assessment::Assessment;
use crate::file_type::FileType;
use crate::observation::Observation;
use crate::severity::Severity;
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
        observations.push(Observation::new("Detected Type", file_type.display()));

        inspect_extension_mismatch(path, file_type, &mut observations);
    }

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

fn inspect_extension_mismatch(
    path: &Path,
    file_type: FileType,
    observations: &mut Vec<Observation>,
) {
    let expected = file_type.expected_extension();

    let Some(extension) = path.extension() else {
        return;
    };

    let actual = extension.to_string_lossy().to_ascii_lowercase();

    let matches = match expected {
        "jpg" => actual == "jpg" || actual == "jpeg",
        _ => actual == expected,
    };

    if !matches {
        observations.push(Observation::with_severity(
            "Extension Mismatch",
            "Yes",
            Severity::Warning,
            Some(format!(
                "Expected extension .{} based on detected {}, but found .{}.",
                expected,
                file_type.display(),
                actual,
            )),
        ));
    }
}
