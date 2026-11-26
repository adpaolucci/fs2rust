use thiserror::Error;

/// Unified error type for `fs2rust-data` parsers, evaluators, and providers.
#[derive(Debug, Error)]
pub enum DataError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV parse error: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("table error: {0}")]
    Table(#[from] guap_table::TableError),
    #[error("export error: {0}")]
    Export(#[from] guap_export::ExportError),
    #[error("invalid EXIF/TIFF data: {0}")]
    InvalidExif(String),
    #[error("template error: {0}")]
    Template(String),
    #[error("contact parse error: {0}")]
    ContactParse(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<DataError> for guap_table::TableError {
    fn from(err: DataError) -> Self {
        match err {
            DataError::Table(te) => te,
            other => guap_table::TableError::Provider(other.to_string()),
        }
    }
}
