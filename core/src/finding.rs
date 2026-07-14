use crate::Severity;

#[derive(Debug, Clone)]
pub struct Finding {
    pub title: String,
    pub value: String,
    pub severity: Severity,
    pub description: Option<String>,
}

impl Finding {
    pub fn new(title: impl Into<String>, value: impl Into<String>, severity: Severity) -> Self {
        Self {
            title: title.into(),
            value: value.into(),
            severity,
            description: None,
        }
    }

    pub fn with_description(
        title: impl Into<String>,
        value: impl Into<String>,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            value: value.into(),
            severity,
            description: Some(description.into()),
        }
    }
}
