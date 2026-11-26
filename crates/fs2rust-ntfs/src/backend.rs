#![forbid(unsafe_code)]

use crate::app_io::ProcessIoSnapshot;
use crate::disk_counters::DiskPerformanceRecord;
use crate::disk_smart::DiskSmartRecord;
use crate::drive_letter::DriveLetterEntry;
use crate::etw_file::KernelFileRawEvent;
use crate::folder_changes::FolderChangeEntry;
use crate::mft_ads::AdsEntry;
use crate::property_system::FilePropertyEntry;
use crate::reparse::NtfsLinkEntry;
use crate::usn_journal::{UsnQueryMode, UsnRecord};
use fs2rust_core::FsError;
use std::collections::HashMap;
use std::path::Path;

pub trait NtfsBackend: Send + Sync {
    fn list_drive_letters(&self) -> Result<Vec<DriveLetterEntry>, FsError>;
    fn set_volume_mount_point(&self, mount_point: &str, volume_guid: &str) -> Result<(), FsError>;
    fn delete_volume_mount_point(&self, mount_point: &str) -> Result<(), FsError>;
    fn query_disk_counters(&self, device_paths: &[String]) -> Result<Vec<DiskPerformanceRecord>, FsError>;
    fn capture_kernel_file_events(
        &self,
        duration_ms: u64,
        max_events: usize,
        include_op_end: bool,
    ) -> Result<Vec<KernelFileRawEvent>, FsError>;
    fn watch_folder_changes(
        &self,
        watch_dir: &Path,
        recursive: bool,
        duration_ms: u64,
        max_events: usize,
    ) -> Result<Vec<FolderChangeEntry>, FsError>;
    fn snapshot_process_io(&self) -> Result<Vec<ProcessIoSnapshot>, FsError>;
    fn list_process_names(&self) -> Result<HashMap<u32, String>, FsError>;
    fn query_disk_smart(&self, disk_indices: &[u32]) -> Result<Vec<DiskSmartRecord>, FsError>;
    fn enumerate_ads(
        &self,
        target_paths: &[PathBufAlias],
        recursive: bool,
        include_default_data: bool,
    ) -> Result<Vec<AdsEntry>, FsError>;
    fn delete_ads(&self, full_stream_path: &str) -> Result<(), FsError>;
    fn inspect_ntfs_links(
        &self,
        target_paths: &[PathBufAlias],
        recursive: bool,
        include_hardlinks: bool,
    ) -> Result<Vec<NtfsLinkEntry>, FsError>;
    fn read_file_properties(&self, file_path: &Path) -> Result<Vec<FilePropertyEntry>, FsError>;
    fn set_file_property(
        &self,
        file_path: &Path,
        canonical_name: &str,
        value: &str,
    ) -> Result<FilePropertyEntry, FsError>;
    fn read_usn_journal(
        &self,
        device_path: &str,
        start_usn: i64,
        reason_mask: u32,
        max_records: usize,
        mode: UsnQueryMode,
    ) -> Result<Vec<UsnRecord>, FsError>;
}

pub type PathBufAlias = std::path::PathBuf;

#[derive(Debug, Default, Clone, Copy)]
pub struct LiveNtfsBackend;

impl NtfsBackend for LiveNtfsBackend {
    fn list_drive_letters(&self) -> Result<Vec<DriveLetterEntry>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::list_drive_letters()
        }
        #[cfg(not(windows))]
        {
            Err(FsError::Unsupported(
                "DriveLetterView live enumeration requires Windows".to_string(),
            ))
        }
    }

    fn set_volume_mount_point(&self, mount_point: &str, volume_guid: &str) -> Result<(), FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::set_volume_mount_point(mount_point, volume_guid)
        }
        #[cfg(not(windows))]
        {
            let _ = (mount_point, volume_guid);
            Err(FsError::Unsupported(
                "SetVolumeMountPointW requires Windows".to_string(),
            ))
        }
    }

    fn delete_volume_mount_point(&self, mount_point: &str) -> Result<(), FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::delete_volume_mount_point(mount_point)
        }
        #[cfg(not(windows))]
        {
            let _ = mount_point;
            Err(FsError::Unsupported(
                "DeleteVolumeMountPointW requires Windows".to_string(),
            ))
        }
    }

    fn query_disk_counters(&self, device_paths: &[String]) -> Result<Vec<DiskPerformanceRecord>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::query_disk_counters(device_paths)
        }
        #[cfg(not(windows))]
        {
            let _ = device_paths;
            Err(FsError::Unsupported(
                "IOCTL_DISK_PERFORMANCE requires Windows".to_string(),
            ))
        }
    }

    fn capture_kernel_file_events(
        &self,
        duration_ms: u64,
        max_events: usize,
        include_op_end: bool,
    ) -> Result<Vec<KernelFileRawEvent>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::capture_kernel_file_events(duration_ms, max_events, include_op_end)
        }
        #[cfg(not(windows))]
        {
            let _ = (duration_ms, max_events, include_op_end);
            Err(FsError::Unsupported("ETW Kernel-File requires Windows".to_string()))
        }
    }

    fn watch_folder_changes(
        &self,
        watch_dir: &Path,
        recursive: bool,
        duration_ms: u64,
        max_events: usize,
    ) -> Result<Vec<FolderChangeEntry>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::watch_folder_changes(watch_dir, recursive, duration_ms, max_events)
        }
        #[cfg(not(windows))]
        {
            let _ = (watch_dir, recursive, duration_ms, max_events);
            Err(FsError::Unsupported(
                "ReadDirectoryChangesW requires Windows".to_string(),
            ))
        }
    }

    fn snapshot_process_io(&self) -> Result<Vec<ProcessIoSnapshot>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::snapshot_process_io()
        }
        #[cfg(not(windows))]
        {
            Err(FsError::Unsupported(
                "GetProcessIoCounters requires Windows".to_string(),
            ))
        }
    }

    fn list_process_names(&self) -> Result<HashMap<u32, String>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::list_process_names()
        }
        #[cfg(not(windows))]
        {
            Ok(HashMap::new())
        }
    }

    fn query_disk_smart(&self, disk_indices: &[u32]) -> Result<Vec<DiskSmartRecord>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::query_disk_smart(disk_indices)
        }
        #[cfg(not(windows))]
        {
            let _ = disk_indices;
            Err(FsError::Unsupported(
                "PhysicalDrive S.M.A.R.T. IOCTLs require Windows".to_string(),
            ))
        }
    }

    fn enumerate_ads(
        &self,
        target_paths: &[PathBufAlias],
        recursive: bool,
        include_default_data: bool,
    ) -> Result<Vec<AdsEntry>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::enumerate_ads(target_paths, recursive, include_default_data)
        }
        #[cfg(not(windows))]
        {
            let _ = (target_paths, recursive, include_default_data);
            Err(FsError::Unsupported("FindFirstStreamW requires Windows".to_string()))
        }
    }

    fn delete_ads(&self, full_stream_path: &str) -> Result<(), FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::delete_ads(full_stream_path)
        }
        #[cfg(not(windows))]
        {
            let _ = full_stream_path;
            Err(FsError::Unsupported("ADS DeleteFileW requires Windows".to_string()))
        }
    }

    fn inspect_ntfs_links(
        &self,
        target_paths: &[PathBufAlias],
        recursive: bool,
        include_hardlinks: bool,
    ) -> Result<Vec<NtfsLinkEntry>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::inspect_ntfs_links(target_paths, recursive, include_hardlinks)
        }
        #[cfg(not(windows))]
        {
            let _ = (target_paths, recursive, include_hardlinks);
            Err(FsError::Unsupported(
                "FSCTL_GET_REPARSE_POINT / FindFirstFileNameW requires Windows".to_string(),
            ))
        }
    }

    fn read_file_properties(&self, file_path: &Path) -> Result<Vec<FilePropertyEntry>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::read_file_properties(file_path)
        }
        #[cfg(not(windows))]
        {
            let _ = file_path;
            Err(FsError::Unsupported(
                "Windows Property System requires Windows".to_string(),
            ))
        }
    }

    fn set_file_property(
        &self,
        file_path: &Path,
        canonical_name: &str,
        value: &str,
    ) -> Result<FilePropertyEntry, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::set_file_property(file_path, canonical_name, value)
        }
        #[cfg(not(windows))]
        {
            let _ = (file_path, canonical_name, value);
            Err(FsError::Unsupported(
                "Windows Property System requires Windows".to_string(),
            ))
        }
    }

    fn read_usn_journal(
        &self,
        device_path: &str,
        start_usn: i64,
        reason_mask: u32,
        max_records: usize,
        mode: UsnQueryMode,
    ) -> Result<Vec<UsnRecord>, FsError> {
        #[cfg(windows)]
        {
            crate::live_win32::read_usn_journal(device_path, start_usn, reason_mask, max_records, mode)
        }
        #[cfg(not(windows))]
        {
            let _ = (device_path, start_usn, reason_mask, max_records, mode);
            Err(FsError::Unsupported(
                "FSCTL_READ_USN_JOURNAL requires Windows".to_string(),
            ))
        }
    }
}
