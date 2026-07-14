use crate::Severity;

#[derive(Debug, Clone)]
pub struct Observation {
    pub title: String,
    pub value: String,
    pub severity: Severity,
    pub description: Option<String>,
}

impl Observation {
    pub fn new(title: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            value: value.into(),
            severity: Severity::Info,
            description: None,
        }
    }

    pub fn with_description(
        title: impl Into<String>,
        value: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            value: value.into(),
            severity: Severity::Info,
            description: Some(description.into()),
        }
    }

    pub fn with_severity(
        title: impl Into<String>,
        value: impl Into<String>,
        severity: Severity,
        description: Option<String>,
    ) -> Self {
        Self {
            title: title.into(),
            value: value.into(),
            severity,
            description,
        }
    }
}
