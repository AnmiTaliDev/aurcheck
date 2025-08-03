use thiserror::Error;

#[derive(Error, Debug)]
pub enum AurCheckError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Package '{0}' not found in AUR")]
    PackageNotFound(String),

    #[error("Failed to parse PKGBUILD: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),


    #[error("Security check error: {0}")]
    Security(String),
}

pub type Result<T> = std::result::Result<T, AurCheckError>;