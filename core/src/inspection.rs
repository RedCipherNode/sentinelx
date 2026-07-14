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

//=====================================
// PE (Portable Executable)
//===========================================

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

    //
    // ========================================================
    // COFF Header
    // ========================================================
    //

    let Some(machine_code) = read_u16(&bytes, pe_offset + 4) else {
        return;
    };

    let machine = match machine_code {
        0x014C => "Intel 386 (0x014C)",
        0x8664 => "AMD64 (0x8664)",
        0xAA64 => "ARM64 (0xAA64)",
        _ => "Unknown",
    };

    let Some(sections) = read_u16(&bytes, pe_offset + 6) else {
        return;
    };

    let Some(timestamp) = read_u32(&bytes, pe_offset + 8) else {
        return;
    };

    // Observation COFF Header

    observations.push(Observation::new("PE Machine", machine));
    observations.push(Observation::new("PE Sections", sections.to_string()));
    observations.push(Observation::new(
        "PE Timestamp",
        format_pe_timestamp(timestamp),
    ));
    use chrono::{DateTime, Utc};

    fn format_pe_timestamp(timestamp: u32) -> String {
        let Some(datetime) = DateTime::<Utc>::from_timestamp(timestamp as i64, 0) else {
            return String::from("Invalid");
        };

        datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    //
    // ========================================================
    // Optional Header
    // ========================================================
    //
    let optional_header_offset = pe_offset + 24;
    if optional_header_offset + 2 > bytes.len() {
        return;
    }

    //
    // --------------------------------------------------------
    // Format
    // --------------------------------------------------------
    //
    let Some(magic) = read_u16(&bytes, optional_header_offset) else {
        return;
    };

    let format = match magic {
        0x10B => "PE32",
        0x20B => "PE32+",
        _ => "Unknown",
    };

    let Some(entry_point) = read_u32(&bytes, optional_header_offset + 16) else {
        return;
    };

    observations.push(Observation::new("PE Format", format));

    //Image Base

    let image_base = match magic {
        // PE32
        0x10B => {
            let Some(value) = read_u32(&bytes, optional_header_offset + 28) else {
                return;
            };

            format!("0x{:08X}", value)
        }

        // PE32+
        0x20B => {
            let Some(value) = read_u64(&bytes, optional_header_offset + 24) else {
                return;
            };

            format!("0x{:016X}", value)
        }

        _ => String::from("Unknown"),
    };

    //Observation Optional Header - Format
    observations.push(Observation::new(
        "PE Entry Point",
        format!("0x{:08X}", entry_point),
    ));

    observations.push(Observation::new("PE Image Base", image_base));

    //
    // --------------------------------------------------------
    // Memory Layout
    // --------------------------------------------------------
    //

    let Some(section_alignment) = read_u32(&bytes, optional_header_offset + 32) else {
        return;
    };

    let Some(file_alignment) = read_u32(&bytes, optional_header_offset + 36) else {
        return;
    };

    let Some(image_size) = read_u32(&bytes, optional_header_offset + 56) else {
        return;
    };

    let Some(header_size) = read_u32(&bytes, optional_header_offset + 60) else {
        return;
    };

    //
    // Observation
    //

    observations.push(Observation::new(
        "PE Section Alignment",
        format!("{section_alignment} bytes"),
    ));

    observations.push(Observation::new(
        "PE File Alignment",
        format!("{file_alignment} bytes"),
    ));

    observations.push(Observation::new(
        "PE Image Size",
        format!("{image_size} bytes"),
    ));

    observations.push(Observation::new(
        "PE Header Size",
        format!("{header_size} bytes"),
    ));
    observations.push(Observation::new(
        "PE File Alignment Raw",
        format!("0x{:08X}", file_alignment),
    ));

    //
    // --------------------------------------------------------
    // Integrity
    // --------------------------------------------------------
    //

    let Some(checksum) = read_u32(&bytes, optional_header_offset + 64) else {
        return;
    };

    for offset in (64..=80).step_by(2) {
        let value = read_u16(&bytes, optional_header_offset + offset).unwrap_or(0);

        observations.push(Observation::new(
            format!("OH +{offset}"),
            format!("0x{:04X}", value),
        ));
    }

    //
    // Observation
    //

    observations.push(Observation::new(
        "PE Checksum",
        format!("0x{:08X}", checksum),
    ));

    observations.push(Observation::new(
        "OH +68",
        format!(
            "0x{:04X}",
            read_u16(&bytes, optional_header_offset + 68).unwrap_or(0)
        ),
    ));

    observations.push(Observation::new(
        "OH +70",
        format!(
            "0x{:04X}",
            read_u16(&bytes, optional_header_offset + 70).unwrap_or(0)
        ),
    ));

    observations.push(Observation::new(
        "OH +72",
        format!(
            "0x{:04X}",
            read_u16(&bytes, optional_header_offset + 72).unwrap_or(0)
        ),
    ));
    //
    // --------------------------------------------------------
    // Execution
    // --------------------------------------------------------
    //

    let subsystem_offset = optional_header_offset + 68;

    let Some(subsystem_code) = read_u16(&bytes, subsystem_offset) else {
        return;
    };
    let subsystem = match subsystem_code {
        1 => "Native (1)",
        2 => "Windows GUI (2)",
        3 => "Windows Console (3)",
        5 => "OS/2 Console (5)",
        7 => "POSIX Console (7)",
        9 => "Windows CE (9)",
        10 => "EFI Application (10)",
        11 => "EFI Boot Service Driver (11)",
        12 => "EFI Runtime Driver (12)",
        13 => "EFI ROM (13)",
        14 => "Xbox (14)",
        16 => "Windows Boot Application (16)",
        _ => "Unknown",
    };

    // Observation

    observations.push(Observation::new("PE Subsystem", subsystem));

    //
    // --------------------------------------------------------
    // Security
    // --------------------------------------------------------
    //

    let Some(dll_characteristics) = read_u16(&bytes, optional_header_offset + 70) else {
        return;
    };
    const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
    const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
    const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
    const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
    const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
    const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
    const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
    const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
    const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
    const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
    const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

    //
    // Observation
    //

    observations.push(Observation::new(
        "PE DLL Characteristics",
        format!("0x{:04X}", dll_characteristics),
    ));

    observations.push(Observation::new(
        "PE High Entropy VA",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE Dynamic Base",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE Force Integrity",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE NX Compatible",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE No Isolation",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE No SEH",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE No Bind",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE AppContainer",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE WDM Driver",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE Control Flow Guard",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));

    observations.push(Observation::new(
        "PE Terminal Server Aware",
        if dll_characteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 {
            "Enabled"
        } else {
            "Disabled"
        },
    ));
}

//==============================
// Binary Reader Helpers
//===========================

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > bytes.len() {
        return None;
    }

    Some(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > bytes.len() {
        return None;
    }

    Some(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > bytes.len() {
        return None;
    }

    Some(u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]))
}
