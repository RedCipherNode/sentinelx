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

pub fn inspect(target: Target) -> Assessment {
    let observation = match target {
        Target::File(path) => Observation {
            title: "Target".into(),
            value: path.display().to_string(),
            description: Some("File target resolved successfully.".into()),
        },

        Target::Directory(path) => Observation {
            title: "Target".into(),
            value: path.display().to_string(),
            description: Some("Directory target resolved successfully.".into()),
        },

        Target::Url(url) => Observation {
            title: "Target".into(),
            value: url,
            description: Some("URL target resolved successfully.".into()),
        },

        Target::Command(command) => Observation {
            title: "Target".into(),
            value: command,
            description: Some("Command target resolved successfully.".into()),
        },
    };

    Assessment {
        summary: "Inspection pipeline initialized.".into(),
        observations: vec![observation],
    }
}
