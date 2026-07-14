#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    PE,
    PDF,
    ZIP,
    PNG,
    JPEG,
    GIF,
}

impl FileType {
    pub fn display(&self) -> &'static str {
        match self {
            Self::PE => "PE Executable",
            Self::PDF => "PDF Document",
            Self::ZIP => "ZIP Archive",
            Self::PNG => "PNG Image",
            Self::JPEG => "JPEG Image",
            Self::GIF => "GIF Image",
        }
    }

    pub fn expected_extension(&self) -> &'static str {
        match self {
            Self::PE => "exe",
            Self::PDF => "pdf",
            Self::ZIP => "zip",
            Self::PNG => "png",
            Self::JPEG => "jpg",
            Self::GIF => "gif",
        }
    }
}
