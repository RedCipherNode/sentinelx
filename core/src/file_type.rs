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
    pub fn detect(header: &[u8]) -> Option<Self> {
        if header.starts_with(b"MZ") {
            return Some(Self::PE);
        }

        if header.starts_with(b"%PDF-") {
            return Some(Self::PDF);
        }

        if header.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            return Some(Self::ZIP);
        }

        if header.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
            return Some(Self::PNG);
        }

        if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some(Self::JPEG);
        }

        if header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a") {
            return Some(Self::GIF);
        }

        None
    }

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
            Self::JPEG => "jpeg",
            Self::GIF => "gif",
        }
    }
}
