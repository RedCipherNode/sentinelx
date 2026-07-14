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

#[allow(dead_code)]
struct PeSection {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
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

    let Some(optional_header_size) = read_u16(&bytes, pe_offset + 20) else {
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

    observations.push(Observation::new(
        "PE Optional Header Size",
        format!("{} bytes", optional_header_size),
    ));

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

    observations.push(Observation::new(
        "PE Checksum",
        format!("0x{:08X}", checksum),
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

    //
    // ========================================================
    // Section Table
    // ========================================================
    //

    let section_table_offset = optional_header_offset + optional_header_size as usize;

    observations.push(Observation::new(
        "PE Section Table Offset",
        format!("0x{:X}", section_table_offset),
    ));
    let mut pe_sections = Vec::new();

    for index in 0..sections {
        let offset = section_table_offset + index as usize * 40;

        if offset + 40 > bytes.len() {
            break;
        }

        // Name
        let name_bytes = &bytes[offset..offset + 8];

        let section_name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches('\0')
            .to_string();

        // IMAGE_SECTION_HEADER

        let Some(virtual_size) = read_u32(&bytes, offset + 8) else {
            continue;
        };

        let Some(virtual_address) = read_u32(&bytes, offset + 12) else {
            continue;
        };

        let Some(size_of_raw_data) = read_u32(&bytes, offset + 16) else {
            continue;
        };

        let Some(pointer_to_raw_data) = read_u32(&bytes, offset + 20) else {
            continue;
        };

        let Some(pointer_to_relocations) = read_u32(&bytes, offset + 24) else {
            continue;
        };

        let Some(pointer_to_linenumbers) = read_u32(&bytes, offset + 28) else {
            continue;
        };

        let Some(number_of_relocations) = read_u16(&bytes, offset + 32) else {
            continue;
        };

        let Some(number_of_linenumbers) = read_u16(&bytes, offset + 34) else {
            continue;
        };

        let Some(characteristics) = read_u32(&bytes, offset + 36) else {
            continue;
        };

        pe_sections.push(PeSection {
            name: section_name.clone(),
            virtual_size,
            virtual_address,
            raw_size: size_of_raw_data,
            raw_offset: pointer_to_raw_data,
            characteristics,
        });

        observations.push(Observation::new(
            format!("Section[{}] Name", index + 1),
            section_name,
        ));

        observations.push(Observation::new(
            format!("Section[{}] Virtual Size", index + 1),
            format!("0x{:08X}", virtual_size),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Virtual Address", index + 1),
            format!("0x{:08X}", virtual_address),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Raw Size", index + 1),
            format!("0x{:08X}", size_of_raw_data),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Raw Offset", index + 1),
            format!("0x{:08X}", pointer_to_raw_data),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Relocation Offset", index + 1),
            format!("0x{:08X}", pointer_to_relocations),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Line Number Offset", index + 1),
            format!("0x{:08X}", pointer_to_linenumbers),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Relocations", index + 1),
            number_of_relocations.to_string(),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Line Numbers", index + 1),
            number_of_linenumbers.to_string(),
        ));

        observations.push(Observation::new(
            format!("Section[{}] Characteristics", index + 1),
            format!("0x{:08X}", characteristics),
        ));
    }

    //
    // -----------------------------------------------
    // Data Directories
    // ------------------------------------------------
    //

    let data_directory_offset = match magic {
        // PE32
        0x10B => optional_header_offset + 96,

        // PE32+
        0x20B => optional_header_offset + 112,

        _ => return,
    };

    let number_of_directories = match magic {
        0x10B => read_u32(&bytes, optional_header_offset + 92),
        0x20B => read_u32(&bytes, optional_header_offset + 108),
        _ => None,
    };

    let Some(number_of_directories) = number_of_directories else {
        return;
    };

    observations.push(Observation::new(
        "PE Data Directories",
        number_of_directories.to_string(),
    ));

    const DATA_DIRECTORY_NAMES: [&str; 16] = [
        "Export",
        "Import",
        "Resource",
        "Exception",
        "Certificate",
        "Base Relocation",
        "Debug",
        "Architecture",
        "Global Ptr",
        "TLS",
        "Load Config",
        "Bound Import",
        "IAT",
        "Delay Import",
        "CLR",
        "Reserved",
    ];

    for index in 0..number_of_directories.min(16) {
        let offset = data_directory_offset + index as usize * 8;

        if offset + 8 > bytes.len() {
            break;
        }

        let Some(rva) = read_u32(&bytes, offset) else {
            continue;
        };

        let Some(size) = read_u32(&bytes, offset + 4) else {
            continue;
        };

        let name = DATA_DIRECTORY_NAMES[index as usize];

        if name == "Import" {
            if let Some(import_offset) = rva_to_file_offset(rva, &pe_sections) {
                observations.push(Observation::new(
                    "PE Import Directory Offset",
                    format!("0x{:08X}", import_offset),
                ));

                let mut descriptor_offset = import_offset;

                loop {
                    let Some(original_first_thunk) = read_u32(&bytes, descriptor_offset) else {
                        break;
                    };

                    let Some(time_date_stamp) = read_u32(&bytes, descriptor_offset + 4) else {
                        break;
                    };

                    let Some(forwarder_chain) = read_u32(&bytes, descriptor_offset + 8) else {
                        break;
                    };

                    let Some(name_rva) = read_u32(&bytes, descriptor_offset + 12) else {
                        break;
                    };

                    let Some(first_thunk) = read_u32(&bytes, descriptor_offset + 16) else {
                        break;
                    };

                    // Null descriptor = selesai
                    if original_first_thunk == 0
                        && time_date_stamp == 0
                        && forwarder_chain == 0
                        && name_rva == 0
                        && first_thunk == 0
                    {
                        break;
                    }

                    if let Some(name_offset) = rva_to_file_offset(name_rva, &pe_sections) {
                        if let Some(dll_name) = read_c_string(&bytes, name_offset) {
                            observations.push(Observation::new("PE Import DLL", dll_name));
                        }
                    }

                    observations.push(Observation::new(
                        "PE Import Original First Thunk",
                        format!("0x{:08X}", original_first_thunk),
                    ));

                    observations.push(Observation::new(
                        "PE Import First Thunk",
                        format!("0x{:08X}", first_thunk),
                    ));

                    if let Some(thunk_offset) =
                        rva_to_file_offset(original_first_thunk, &pe_sections)
                    {
                        let mut current_thunk = thunk_offset;

                        loop {
                            let Some(thunk_data) = read_u64(&bytes, current_thunk) else {
                                break;
                            };

                            if thunk_data == 0 {
                                break;
                            }

                            let hint_name_rva = thunk_data as u32;

                            if let Some(hint_name_offset) =
                                rva_to_file_offset(hint_name_rva, &pe_sections)
                            {
                                if let Some(function_name) =
                                    read_c_string(&bytes, hint_name_offset + 2)
                                {
                                    observations.push(Observation::new(
                                        "PE Import Function",
                                        function_name,
                                    ));
                                }
                            }

                            current_thunk += 8;
                        }
                    }

                    descriptor_offset += 20;
                }
            }
        }

        observations.push(Observation::new(
            format!("PE {} Directory Size", name),
            format!("0x{:08X}", size),
        ));
    }
}

//
//==============================
// Helpers
//===========================
//
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

fn rva_to_file_offset(rva: u32, sections: &[PeSection]) -> Option<usize> {
    for section in sections {
        let section_start = section.virtual_address;
        let section_end = section.virtual_address + section.virtual_size;

        if rva >= section_start && rva < section_end {
            let section_offset = rva - section.virtual_address;
            let file_offset = section.raw_offset + section_offset;

            return Some(file_offset as usize);
        }
    }

    None
}

fn read_c_string(bytes: &[u8], offset: usize) -> Option<String> {
    if offset >= bytes.len() {
        return None;
    }

    let mut end = offset;

    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }

    Some(String::from_utf8_lossy(&bytes[offset..end]).to_string())
}
