#![deny(unsafe_op_in_unsafe_fn)]

pub mod app_io;
pub mod backend;
pub mod bin_util;
pub mod disk_counters;
pub mod disk_smart;
pub mod drive_letter;
pub mod etw_file;
pub mod folder_changes;
#[cfg(windows)]
mod live_win32;
pub mod mft_ads;
pub mod ntstatus;
pub mod property_system;
pub mod reparse;
pub mod usn_journal;

pub use app_io::{
    AppReadWriteConfig, AppReadWriteCounterProvider, IoCounters, ProcessIoRateEntry, ProcessIoSnapshot,
    compute_io_rates, parse_io_counters,
};
pub use backend::{LiveNtfsBackend, NtfsBackend};
pub use disk_counters::{DiskCountersConfig, DiskCountersProvider, DiskPerformanceRecord, parse_disk_performance};
pub use disk_smart::{
    AtaSmartPage, DiskSmartConfig, DiskSmartRecord, DiskSmartViewProvider, NvmeHealthLog, SmartAttribute,
    ata_attribute_name, ata_checksum_valid, ata_page_to_records, nvme_log_to_records, parse_ata_smart_attributes,
    parse_ata_smart_thresholds, parse_nvme_health_log,
};
pub use drive_letter::{
    DriveLetterAssignAction, DriveLetterConfig, DriveLetterEntry, DriveLetterProvider, DriveLetterRemoveAction,
    MountedDeviceTarget, parse_mounted_device_value, parse_mounted_devices_map,
};
pub use etw_file::{
    FileAccessErrorConfig, FileAccessErrorEntry, FileAccessErrorViewProvider, FileActivityConfig, FileActivityEntry,
    FileActivityWatchProvider, KERNEL_FILE_MAGIC, KERNEL_FILE_PROVIDER_GUID, KernelFileRawEvent,
    correlate_file_access_errors, correlate_file_activity, encode_kernel_file_wire_record, kernel_file_operation_name,
    parse_kernel_file_wire_record, parse_kernel_file_wire_stream,
};
pub use folder_changes::{
    FolderChangeAction, FolderChangeEntry, FolderChangesConfig, FolderChangesViewProvider, FolderSnapshot,
    parse_file_notify_buffer,
};
pub use mft_ads::{
    AdsEntry, AlternateStreamConfig, AlternateStreamDeleteAction, AlternateStreamViewProvider, apply_mft_usa_fixup,
    normalize_ads_target, parse_mft_ads_records, parse_mft_file_record_ads,
};
pub use ntstatus::{NtStatusInfo, decode_ntstatus};
pub use property_system::{
    FilePropertyEntry, PropertySystemConfig, PropertySystemSetAction, PropertySystemViewProvider,
    SerializedPropertyEntry, SerializedPropertyStorageBlock, lookup_canonical_property_name,
    parse_serialized_property_storage,
};
pub use reparse::{
    IO_REPARSE_TAG_APPEXECLINK, IO_REPARSE_TAG_LX_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK,
    NtfsLinkEntry, NtfsLinksConfig, NtfsLinksViewProvider, ParsedReparsePoint, ReparseKind, parse_reparse_data_buffer,
};
pub use usn_journal::{
    UsnJournalConfig, UsnJournalInfo, UsnJournalViewProvider, UsnQueryMode, UsnRecord, decode_usn_reasons,
    decode_usn_source_info, parse_usn_ioctl_buffer, parse_usn_journal_stream,
};

use fs2rust_core::PolicyContext;
use guap_mcp::McpServerRegistry;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct NtfsToolsConfig {
    pub drive_letter: DriveLetterConfig,
    pub disk_counters: DiskCountersConfig,
    pub file_activity: FileActivityConfig,
    pub folder_changes: FolderChangesConfig,
    pub file_access_error: FileAccessErrorConfig,
    pub app_read_write: AppReadWriteConfig,
    pub disk_smart: DiskSmartConfig,
    pub alternate_stream: AlternateStreamConfig,
    pub ntfs_links: NtfsLinksConfig,
    pub property_system: PropertySystemConfig,
    pub usn_journal: UsnJournalConfig,
    pub action_policy: PolicyContext,
}

/// Register all 11 `fs2rust-ntfs` read-only `TableProvider`s and 4 mutating `ActionCommand`s
/// using the live Windows OS backend.
pub fn register_ntfs_tools(registry: &mut McpServerRegistry, cfg: NtfsToolsConfig) {
    let backend: Arc<dyn NtfsBackend> = Arc::new(LiveNtfsBackend);
    register_ntfs_tools_with_backend(registry, backend, cfg);
}

/// Register all 11 `fs2rust-ntfs` `TableProvider`s and 4 mutating `ActionCommand`s
/// using a caller-supplied `NtfsBackend`.
pub fn register_ntfs_tools_with_backend(
    registry: &mut McpServerRegistry,
    backend: Arc<dyn NtfsBackend>,
    cfg: NtfsToolsConfig,
) {
    registry.register_table(Arc::new(DriveLetterProvider::new(
        cfg.drive_letter,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(DiskCountersProvider::new(
        cfg.disk_counters,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(FileActivityWatchProvider::new(
        cfg.file_activity,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(FolderChangesViewProvider::new(
        cfg.folder_changes,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(FileAccessErrorViewProvider::new(
        cfg.file_access_error,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(AppReadWriteCounterProvider::new(
        cfg.app_read_write,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(DiskSmartViewProvider::new(
        cfg.disk_smart,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(AlternateStreamViewProvider::new(
        cfg.alternate_stream,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(NtfsLinksViewProvider::new(
        cfg.ntfs_links,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(PropertySystemViewProvider::new(
        cfg.property_system,
        Arc::clone(&backend),
    )));
    registry.register_table(Arc::new(UsnJournalViewProvider::new(
        cfg.usn_journal,
        Arc::clone(&backend),
    )));

    let policy = cfg.action_policy;
    registry.register_action(Arc::new(
        DriveLetterAssignAction::new(Arc::clone(&backend)).with_policy(policy.clone()),
    ));
    registry.register_action(Arc::new(
        DriveLetterRemoveAction::new(Arc::clone(&backend)).with_policy(policy.clone()),
    ));
    registry.register_action(Arc::new(
        AlternateStreamDeleteAction::new(Arc::clone(&backend)).with_policy(policy.clone()),
    ));
    registry.register_action(Arc::new(PropertySystemSetAction::new(backend).with_policy(policy)));
}
