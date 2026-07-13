use std::fs;
use std::path::PathBuf;

pub struct ScanRequest {
    pub path: PathBuf,
}

pub struct ScanResult {
    pub path: PathBuf,
    pub exists: bool,
    pub is_file: bool,
    pub is_directory: bool,
    pub size: Option<u64>,
    pub extension: Option<String>,
}

pub fn scan(request: ScanRequest) -> ScanResult {
    let metadata = fs::metadata(&request.path);

    let exists = metadata.is_ok();

    let size = metadata.as_ref().ok().map(|m| m.len());

    let extension = request
        .path
        .extension()
        .map(|e| e.to_string_lossy().to_string());

    ScanResult {
        path: request.path.clone(),

        exists,

        is_file: request.path.is_file(),

        is_directory: request.path.is_dir(),

        size,

        extension,
    }
}
