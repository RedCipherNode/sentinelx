#[derive(Debug, Clone)]
pub struct Observation {
    pub title: String,
    pub value: String,
    pub description: Option<String>,
}

impl Observation {
    pub fn new(title: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            value: value.into(),
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
            description: Some(description.into()),
        }
    }
}
