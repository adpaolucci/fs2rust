use std::io::ErrorKind;
use std::path::Path;
use thiserror::Error;

/// Unified error type across `fs2rust` crates.
#[derive(Debug, Error)]
pub enum FsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("source unavailable: {0}")]
    SourceUnavailable(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("time conversion error: {0}")]
    TimeConversion(String),
    #[error("table error: {0}")]
    Table(#[from] guap_table::TableError),
}

impl FsError {
    /// Convert an `std::io::Error` paired with its target path into a semantic `FsError`.
    pub fn from_io(path: &Path, err: std::io::Error) -> Self {
        match err.kind() {
            ErrorKind::PermissionDenied => Self::PermissionDenied(format!("{}: {err}", path.display())),
            ErrorKind::NotFound => Self::SourceUnavailable(format!("{}: {err}", path.display())),
            ErrorKind::InvalidInput => Self::InvalidPath(format!("{}: {err}", path.display())),
            _ => Self::Io(std::io::Error::new(err.kind(), format!("{}: {err}", path.display()))),
        }
    }
}

impl From<FsError> for guap_table::TableError {
    fn from(err: FsError) -> Self {
        match err {
            FsError::Table(te) => te,
            other => guap_table::TableError::Provider(other.to_string()),
        }
    }
}

impl From<FsError> for guap_mcp::McpToolError {
    fn from(err: FsError) -> Self {
        match err {
            FsError::PolicyDenied(msg) => guap_mcp::McpToolError::PolicyDenied(msg),
            FsError::InvalidPath(msg) | FsError::InvalidArgument(msg) | FsError::InvalidConfig(msg) => {
                guap_mcp::McpToolError::InvalidParams(msg)
            }
            FsError::SourceUnavailable(msg) => guap_mcp::McpToolError::NotFound(msg),
            FsError::Table(te) => guap_mcp::McpToolError::Table(te),
            other => guap_mcp::McpToolError::ExecutionFailed(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_io_maps_permission_and_not_found() {
        let p = Path::new("C:\\nonexistent\\file.txt");
        let e1 = FsError::from_io(p, std::io::Error::new(ErrorKind::PermissionDenied, "denied"));
        assert!(matches!(e1, FsError::PermissionDenied(_)));

        let e2 = FsError::from_io(p, std::io::Error::new(ErrorKind::NotFound, "missing"));
        assert!(matches!(e2, FsError::SourceUnavailable(_)));
    }

    #[test]
    fn converts_to_table_and_mcp_errors() {
        let te: guap_table::TableError = FsError::SourceUnavailable("missing".into()).into();
        assert!(matches!(te, guap_table::TableError::Provider(_)));

        let me: guap_mcp::McpToolError = FsError::PolicyDenied("blocked".into()).into();
        assert!(matches!(me, guap_mcp::McpToolError::PolicyDenied(_)));

        let me2: guap_mcp::McpToolError = FsError::InvalidArgument("bad".into()).into();
        assert!(matches!(me2, guap_mcp::McpToolError::InvalidParams(_)));

        let me3: guap_mcp::McpToolError = FsError::SourceUnavailable("gone".into()).into();
        assert!(matches!(me3, guap_mcp::McpToolError::NotFound(_)));
    }
}
