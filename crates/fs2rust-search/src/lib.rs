#![forbid(unsafe_code)]

pub mod bulk_file_time;
pub mod folder_time_update;
pub mod folders_report;
pub mod hash_files;
pub mod search_files;
pub mod shortcuts;

use fs2rust_core::{FileSystemOps, OsFileSystem};
use guap_mcp::McpServerRegistry;
use std::sync::Arc;

pub use bulk_file_time::{
    BulkChangeSpec, BulkFileTimeAction, BulkFileTimePreviewProvider, TimestampChange, TimestampField,
};
pub use folder_time_update::{
    FolderTimeSource, FolderTimeUpdateAction, FolderTimeUpdateConfig, FolderTimeUpdatePreviewProvider,
};
pub use folders_report::{FoldersReportConfig, FoldersReportProvider};
pub use hash_files::{HashAlgorithmSet, HashFilesConfig, HashFilesProvider};
pub use search_files::{ContentSearchMode, SearchFilesConfig, SearchFilesProvider};
pub use shortcuts::{
    ExtraDataBlock, LinkInfo, LinkTargetIdList, ShellLinkFile, ShellLinkHeader, ShortcutsConfig, ShortcutsDeleteAction,
    ShortcutsFixAction, ShortcutsProvider, ShowCommand, StringData,
};

/// Register all 6 `fs2rust-search` read-only `TableProvider`s and 4 mutating `ActionCommand`s
/// on the given `McpServerRegistry`.
pub fn register_search_tools(
    registry: &mut McpServerRegistry,
    search_cfg: SearchFilesConfig,
    bulk_spec: BulkChangeSpec,
    folder_time_cfg: FolderTimeUpdateConfig,
    folders_report_cfg: FoldersReportConfig,
    shortcuts_cfg: ShortcutsConfig,
    hash_cfg: HashFilesConfig,
) {
    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    register_search_tools_with_backend(
        registry,
        os_fs,
        search_cfg,
        bulk_spec,
        folder_time_cfg,
        folders_report_cfg,
        shortcuts_cfg,
        hash_cfg,
    );
}

/// Register all 6 `fs2rust-search` tools with a caller-supplied `FileSystemOps` backend.
#[allow(clippy::too_many_arguments)]
pub fn register_search_tools_with_backend(
    registry: &mut McpServerRegistry,
    backend: Arc<dyn FileSystemOps>,
    search_cfg: SearchFilesConfig,
    bulk_spec: BulkChangeSpec,
    folder_time_cfg: FolderTimeUpdateConfig,
    folders_report_cfg: FoldersReportConfig,
    shortcuts_cfg: ShortcutsConfig,
    hash_cfg: HashFilesConfig,
) {
    registry.register_table(Arc::new(SearchFilesProvider::new(search_cfg)));
    registry.register_table(Arc::new(BulkFileTimePreviewProvider::new(
        bulk_spec,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(FolderTimeUpdatePreviewProvider::new(
        folder_time_cfg,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(FoldersReportProvider::new(
        folders_report_cfg,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(ShortcutsProvider::with_backend(
        shortcuts_cfg,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(HashFilesProvider::new(hash_cfg)));

    registry.register_action(Arc::new(BulkFileTimeAction::new(Arc::clone(&backend))));
    registry.register_action(Arc::new(FolderTimeUpdateAction::new(Arc::clone(&backend))));
    registry.register_action(Arc::new(ShortcutsFixAction::new(Arc::clone(&backend))));
    registry.register_action(Arc::new(ShortcutsDeleteAction::new(backend)));
}
