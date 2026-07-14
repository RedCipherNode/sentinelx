//! Threat analysis.
//!
//! This module evaluates observations collected during inspection
//! and identifies suspicious behaviors, techniques, and attack patterns.
//!
//! Analysis should always be explainable and evidence-driven.

use crate::{Finding, Observation, Severity};

pub fn analyze(observations: &[Observation]) -> Vec<Finding> {
    let mut findings = Vec::new();

    analyze_extension_mismatch(observations, &mut findings);

    fn analyze_extension_mismatch(observations: &[Observation], findings: &mut Vec<Finding>) {
        let mut extension = None;
        let mut detected = None;

        for observation in observations {
            match observation.title.as_str() {
                "Extension" => {
                    extension = Some(observation.value.clone());
                }

                "Detected Type" => {
                    detected = Some(observation.value.clone());
                }

                _ => {}
            }
        }

        let (Some(extension), Some(detected)) = (extension, detected) else {
            return;
        };

        let expected = match detected.as_str() {
            "PE Executable" => ".exe",

            "PDF Document" => ".pdf",

            "ZIP Archive" => ".zip",

            "PNG Image" => ".png",

            "JPEG Image" => ".jpg",

            "GIF Image" => ".gif",

            _ => return,
        };

        let matches = match expected {
            ".jpg" => extension == ".jpg" || extension == ".jpeg",

            _ => extension == expected,
        };

        if !matches {
            findings.push(Finding::with_description(
                "Extension Mismatch",
                "Yes",
                Severity::Warning,
                format!(
                    "Detected {}, but file extension is {}.",
                    detected, extension,
                ),
            ));
        }
    }

    findings
}
