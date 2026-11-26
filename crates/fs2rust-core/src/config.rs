use crate::error::FsError;
use crate::types::PolicyContext;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Shared configuration baseline for `fs2rust` traversal and execution engines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsConfig {
    pub root_paths: Vec<PathBuf>,
    pub follow_symlinks: bool,
    pub include_hidden: bool,
    pub include_system: bool,
    pub max_depth: Option<usize>,
    pub max_results: Option<usize>,
    pub threads: usize,
    pub hash_buffer_bytes: usize,
    pub policy: PolicyContext,
}

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            root_paths: Vec::new(),
            follow_symlinks: false,
            include_hidden: true,
            include_system: true,
            max_depth: None,
            max_results: None,
            threads: 0,
            hash_buffer_bytes: 65_536,
            policy: PolicyContext::read_only(),
        }
    }
}

impl FsConfig {
    /// Resolve effective worker thread count (`>= 1`).
    pub fn effective_threads(&self) -> usize {
        if self.threads > 0 {
            return self.threads.min(64);
        }
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 16))
            .unwrap_or(4)
    }

    /// Validate configuration invariants.
    pub fn validate(&self) -> Result<(), FsError> {
        if self.hash_buffer_bytes == 0 {
            return Err(FsError::InvalidConfig(
                "hash_buffer_bytes must be greater than zero".to_string(),
            ));
        }
        if matches!(self.max_results, Some(0)) {
            return Err(FsError::InvalidConfig(
                "max_results cannot be zero when specified".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_effective_threads_and_validation() {
        let mut cfg = FsConfig::default();
        assert!(cfg.effective_threads() >= 1);
        assert!(cfg.validate().is_ok());

        cfg.threads = 3;
        assert_eq!(cfg.effective_threads(), 3);

        cfg.hash_buffer_bytes = 0;
        assert!(matches!(cfg.validate(), Err(FsError::InvalidConfig(_))));
    }
}
