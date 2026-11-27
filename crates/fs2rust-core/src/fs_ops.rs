use crate::config::FsConfig;
use crate::error::FsError;
use crate::types::{FileAttributes, FileEntry, FileTimestamps};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Clock abstraction enabling deterministic timestamp tests.
pub trait ClockOps: Send + Sync {
    fn now_utc(&self) -> DateTime<Utc>;
}

/// Real wall-clock UTC time provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl ClockOps for SystemClock {
    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Deterministic fixed clock for unit and integration tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub DateTime<Utc>);

impl ClockOps for FixedClock {
    fn now_utc(&self) -> DateTime<Utc> {
        self.0
    }
}

/// Abstracted filesystem operations enabling both real Win32/OS execution and deterministic in-memory mocks.
pub trait FileSystemOps: Send + Sync {
    fn exists(&self, path: &Path) -> bool;
    fn metadata(&self, path: &Path) -> Result<FileEntry, FsError>;
    fn read_dir(&self, path: &Path) -> Result<Vec<FileEntry>, FsError>;
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, FsError>;
    fn read_range(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, FsError>;
    fn write_bytes(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError>;
    fn compressed_size(&self, path: &Path) -> Result<u64, FsError>;
    fn set_timestamps(&self, path: &Path, timestamps: &FileTimestamps) -> Result<(), FsError>;
    fn set_attributes(&self, path: &Path, attrs: &FileAttributes) -> Result<(), FsError>;
    fn remove_file(&self, path: &Path) -> Result<(), FsError>;
}

/// Real OS filesystem implementation using `std::fs` and native Win32 APIs on Windows.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsFileSystem;

impl FileSystemOps for OsFileSystem {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn metadata(&self, path: &Path) -> Result<FileEntry, FsError> {
        let meta = std::fs::symlink_metadata(path).map_err(|e| FsError::from_io(path, e))?;
        let target_is_dir = meta.is_dir()
            || (meta.file_type().is_symlink() && std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false));
        let compressed = if !target_is_dir && meta.is_file() {
            self.compressed_size(path).ok()
        } else {
            None
        };
        let mut entry = FileEntry::from_metadata(path.to_path_buf(), &meta, compressed);
        if target_is_dir {
            entry.is_dir = true;
            entry.size = 0;
            entry.extension.clear();
        }
        Ok(entry)
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<FileEntry>, FsError> {
        let rd = std::fs::read_dir(path).map_err(|e| FsError::from_io(path, e))?;
        let mut entries = Vec::new();
        for item in rd {
            let dir_entry = item.map_err(|e| FsError::from_io(path, e))?;
            let child_path = dir_entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&child_path) {
                let target_is_dir = meta.is_dir()
                    || (meta.file_type().is_symlink()
                        && std::fs::metadata(&child_path).map(|m| m.is_dir()).unwrap_or(false));
                let compressed = if !target_is_dir && meta.is_file() {
                    self.compressed_size(&child_path).ok()
                } else {
                    None
                };
                let mut entry = FileEntry::from_metadata(child_path, &meta, compressed);
                if target_is_dir {
                    entry.is_dir = true;
                    entry.size = 0;
                    entry.extension.clear();
                }
                entries.push(entry);
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        std::fs::read(path).map_err(|e| FsError::from_io(path, e))
    }

    fn read_range(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        let mut file = File::open(path).map_err(|e| FsError::from_io(path, e))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| FsError::from_io(path, e))?;
        let mut buf = vec![0u8; len];
        let mut total = 0usize;
        while total < len {
            let n = file.read(&mut buf[total..]).map_err(|e| FsError::from_io(path, e))?;
            if n == 0 {
                break;
            }
            total += n;
        }
        buf.truncate(total);
        Ok(buf)
    }

    fn write_bytes(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        std::fs::write(path, bytes).map_err(|e| FsError::from_io(path, e))
    }

    fn compressed_size(&self, path: &Path) -> Result<u64, FsError> {
        #[cfg(windows)]
        {
            os_win32::get_compressed_file_size(path)
        }
        #[cfg(not(windows))]
        {
            let meta = std::fs::symlink_metadata(path).map_err(|e| FsError::from_io(path, e))?;
            Ok(meta.len())
        }
    }

    fn set_timestamps(&self, path: &Path, timestamps: &FileTimestamps) -> Result<(), FsError> {
        if timestamps.created.is_none() && timestamps.modified.is_none() && timestamps.accessed.is_none() {
            return Ok(());
        }
        #[cfg(windows)]
        {
            os_win32::set_file_timestamps(path, timestamps)
        }
        #[cfg(not(windows))]
        {
            let file = if path.is_dir() {
                File::open(path).map_err(|e| FsError::from_io(path, e))?
            } else {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(|e| FsError::from_io(path, e))?
            };
            let mut times = std::fs::FileTimes::new();
            if let Some(m) = timestamps.modified {
                times = times.set_modified(std::time::SystemTime::from(m));
            }
            if let Some(a) = timestamps.accessed {
                times = times.set_accessed(std::time::SystemTime::from(a));
            }
            file.set_times(times).map_err(|e| FsError::from_io(path, e))
        }
    }

    fn set_attributes(&self, path: &Path, attrs: &FileAttributes) -> Result<(), FsError> {
        #[cfg(windows)]
        {
            os_win32::set_file_attributes(path, attrs)
        }
        #[cfg(not(windows))]
        {
            let meta = std::fs::symlink_metadata(path).map_err(|e| FsError::from_io(path, e))?;
            let mut perms = meta.permissions();
            perms.set_readonly(attrs.read_only);
            std::fs::set_permissions(path, perms).map_err(|e| FsError::from_io(path, e))
        }
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        std::fs::remove_file(path).map_err(|e| FsError::from_io(path, e))
    }
}

/// Validate and normalize an effective thread count from config.
pub fn resolve_thread_count(cfg: &FsConfig) -> usize {
    cfg.effective_threads()
}

#[cfg(windows)]
#[deny(unsafe_op_in_unsafe_fn)]
mod os_win32 {
    use crate::error::FsError;
    use crate::types::{FileAttributes, FileTimestamps, datetime_to_windows_filetime_parts};
    use chrono::{DateTime, Utc};
    use std::path::Path;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION,
        FILETIME, GetLastError, HANDLE, NO_ERROR, SetLastError, WIN32_ERROR,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, GetCompressedFileSizeW, GetFileAttributesW,
        INVALID_FILE_ATTRIBUTES, INVALID_FILE_SIZE, OPEN_EXISTING, SetFileAttributesW, SetFileTime,
    };
    use windows::core::HSTRING;

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // SAFETY: `self.0` was returned by a successful `CreateFileW` call and is closed once on drop.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn map_win32_code(path: &Path, code: u32, detail: &str) -> FsError {
        if code == ERROR_ACCESS_DENIED.0 || code == ERROR_SHARING_VIOLATION.0 {
            FsError::PermissionDenied(format!("{}: {detail} (win32 {code})", path.display()))
        } else if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PATH_NOT_FOUND.0 {
            FsError::SourceUnavailable(format!("{}: {detail} (win32 {code})", path.display()))
        } else {
            FsError::Io(std::io::Error::from_raw_os_error(code as i32))
        }
    }

    fn map_windows_err(path: &Path, err: windows::core::Error) -> FsError {
        let code = (err.code().0 as u32) & 0xFFFF;
        map_win32_code(path, code, &err.to_string())
    }

    fn to_filetime(dt: DateTime<Utc>) -> Result<FILETIME, FsError> {
        let (low, high) = datetime_to_windows_filetime_parts(dt)?;
        Ok(FILETIME {
            dwLowDateTime: low,
            dwHighDateTime: high,
        })
    }

    pub(super) fn set_file_timestamps(path: &Path, timestamps: &FileTimestamps) -> Result<(), FsError> {
        let ct = timestamps.created.map(to_filetime).transpose()?;
        let at = timestamps.accessed.map(to_filetime).transpose()?;
        let mt = timestamps.modified.map(to_filetime).transpose()?;

        let hpath = HSTRING::from(path);
        // SAFETY: `hpath` is a valid null-terminated UTF-16 string; `CreateFileW` returns an owned handle or error.
        let raw_handle = unsafe {
            CreateFileW(
                &hpath,
                FILE_WRITE_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }
        .map_err(|e| map_windows_err(path, e))?;
        let handle = OwnedHandle(raw_handle);

        let ct_ptr = ct.as_ref().map(|v| v as *const FILETIME);
        let at_ptr = at.as_ref().map(|v| v as *const FILETIME);
        let mt_ptr = mt.as_ref().map(|v| v as *const FILETIME);

        // SAFETY: `handle.0` is an open handle with `FILE_WRITE_ATTRIBUTES`; pointers point to stack `FILETIME` values.
        unsafe { SetFileTime(handle.0, ct_ptr, at_ptr, mt_ptr) }.map_err(|e| map_windows_err(path, e))
    }

    pub(super) fn set_file_attributes(path: &Path, attrs: &FileAttributes) -> Result<(), FsError> {
        let hpath = HSTRING::from(path);
        // SAFETY: `hpath` is a valid null-terminated UTF-16 string.
        let current = unsafe { GetFileAttributesW(&hpath) };
        if current == INVALID_FILE_ATTRIBUTES {
            // SAFETY: `GetLastError` reads the thread-local Win32 error code immediately after failure.
            let err: WIN32_ERROR = unsafe { GetLastError() };
            return Err(map_win32_code(path, err.0, "GetFileAttributesW failed"));
        }

        let preserved = current & !FileAttributes::USER_MUTABLE_MASK;
        let requested = attrs.to_raw() & FileAttributes::USER_MUTABLE_MASK;
        let mut merged = preserved | requested;
        if merged == 0 {
            merged = FILE_ATTRIBUTE_NORMAL.0;
        }

        // SAFETY: `hpath` is a valid null-terminated UTF-16 string and `merged` is a valid attribute mask.
        unsafe { SetFileAttributesW(&hpath, FILE_FLAGS_AND_ATTRIBUTES(merged)) }.map_err(|e| map_windows_err(path, e))
    }

    pub(super) fn get_compressed_file_size(path: &Path) -> Result<u64, FsError> {
        let hpath = HSTRING::from(path);
        let mut high: u32 = 0;
        // SAFETY: Clear thread-local last error so `NO_ERROR` vs actual failure is unambiguous on 4 GiB-1 low word.
        unsafe { SetLastError(NO_ERROR) };
        // SAFETY: `hpath` is a valid null-terminated UTF-16 string and `high` is a valid mutable `u32`.
        let low = unsafe { GetCompressedFileSizeW(&hpath, Some(&mut high)) };
        if low == INVALID_FILE_SIZE {
            // SAFETY: `GetLastError` checks whether `INVALID_FILE_SIZE` is an actual error vs exact `0xFFFF_FFFF` low word.
            let err: WIN32_ERROR = unsafe { GetLastError() };
            if err != NO_ERROR {
                return Err(map_win32_code(path, err.0, "GetCompressedFileSizeW failed"));
            }
        }
        Ok(((high as u64) << 32) | (low as u64))
    }
}

#[derive(Debug, Clone)]
struct MockNode {
    entry: FileEntry,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct MockState {
    nodes: BTreeMap<PathBuf, MockNode>,
    denied_paths: BTreeMap<PathBuf, String>,
}

/// Thread-safe in-memory filesystem mock for deterministic offline unit and integration tests.
#[derive(Debug, Default)]
pub struct MockFileSystem {
    state: Mutex<MockState>,
}

impl MockFileSystem {
    pub fn new() -> Self {
        Self::default()
    }

    fn norm_key(path: &Path) -> PathBuf {
        let sep = std::path::MAIN_SEPARATOR;
        let s = path
            .to_string_lossy()
            .replace(['/', '\\'], std::path::MAIN_SEPARATOR_STR);
        let trimmed = s.trim_end_matches(sep);
        if trimmed.is_empty() {
            PathBuf::from(s)
        } else {
            PathBuf::from(trimmed)
        }
    }

    /// Insert or replace a mock file entry.
    pub fn insert_file(
        &self,
        path: impl AsRef<Path>,
        bytes: Vec<u8>,
        timestamps: FileTimestamps,
        attributes: FileAttributes,
    ) {
        self.insert_file_with_compressed(path, bytes, None, timestamps, attributes);
    }

    /// Insert or replace a mock file entry with an explicit compressed-on-disk size.
    pub fn insert_file_with_compressed(
        &self,
        path: impl AsRef<Path>,
        bytes: Vec<u8>,
        compressed_size: Option<u64>,
        timestamps: FileTimestamps,
        mut attributes: FileAttributes,
    ) {
        let key = Self::norm_key(path.as_ref());
        let name = key
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| key.to_string_lossy().into_owned());
        let extension = key
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        attributes.directory = false;
        let len = bytes.len() as u64;
        let entry = FileEntry {
            path: key.clone(),
            name,
            extension,
            size: len,
            compressed_size: Some(compressed_size.unwrap_or(len)),
            is_dir: false,
            is_symlink: false,
            timestamps,
            attributes,
        };
        let mut guard = self.state.lock().expect("mock fs lock poisoned");
        guard.nodes.insert(key, MockNode { entry, bytes });
    }

    /// Insert or replace a mock directory entry.
    pub fn insert_dir(&self, path: impl AsRef<Path>, timestamps: FileTimestamps, mut attributes: FileAttributes) {
        let key = Self::norm_key(path.as_ref());
        let name = key
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| key.to_string_lossy().into_owned());
        attributes.directory = true;
        let entry = FileEntry {
            path: key.clone(),
            name,
            extension: String::new(),
            size: 0,
            compressed_size: Some(0),
            is_dir: true,
            is_symlink: false,
            timestamps,
            attributes,
        };
        let mut guard = self.state.lock().expect("mock fs lock poisoned");
        guard.nodes.insert(
            key,
            MockNode {
                entry,
                bytes: Vec::new(),
            },
        );
    }

    /// Mark a path as returning `FsError::PermissionDenied`.
    pub fn deny_path(&self, path: impl AsRef<Path>, reason: impl Into<String>) {
        let mut guard = self.state.lock().expect("mock fs lock poisoned");
        guard.denied_paths.insert(Self::norm_key(path.as_ref()), reason.into());
    }

    fn check_denied(guard: &MockState, key: &Path) -> Result<(), FsError> {
        if let Some(reason) = guard.denied_paths.get(key) {
            return Err(FsError::PermissionDenied(format!("{}: {reason}", key.display())));
        }
        Ok(())
    }
}

impl FileSystemOps for MockFileSystem {
    fn exists(&self, path: &Path) -> bool {
        let key = Self::norm_key(path);
        let guard = self.state.lock().expect("mock fs lock poisoned");
        guard.nodes.contains_key(&key)
    }

    fn metadata(&self, path: &Path) -> Result<FileEntry, FsError> {
        let key = Self::norm_key(path);
        let guard = self.state.lock().expect("mock fs lock poisoned");
        Self::check_denied(&guard, &key)?;
        guard
            .nodes
            .get(&key)
            .map(|n| n.entry.clone())
            .ok_or_else(|| FsError::SourceUnavailable(format!("mock path not found: {}", path.display())))
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<FileEntry>, FsError> {
        let key = Self::norm_key(path);
        let guard = self.state.lock().expect("mock fs lock poisoned");
        Self::check_denied(&guard, &key)?;
        let parent = guard
            .nodes
            .get(&key)
            .ok_or_else(|| FsError::SourceUnavailable(format!("mock dir not found: {}", path.display())))?;
        if !parent.entry.is_dir {
            return Err(FsError::InvalidPath(format!("not a directory: {}", path.display())));
        }
        let mut out = Vec::new();
        for (child_key, node) in &guard.nodes {
            if child_key != &key && child_key.parent() == Some(key.as_path()) {
                out.push(node.entry.clone());
            }
        }
        Ok(out)
    }

    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        let key = Self::norm_key(path);
        let guard = self.state.lock().expect("mock fs lock poisoned");
        Self::check_denied(&guard, &key)?;
        let node = guard
            .nodes
            .get(&key)
            .ok_or_else(|| FsError::SourceUnavailable(format!("mock file not found: {}", path.display())))?;
        if node.entry.is_dir {
            return Err(FsError::InvalidPath(format!(
                "cannot read dir bytes: {}",
                path.display()
            )));
        }
        Ok(node.bytes.clone())
    }

    fn read_range(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        let bytes = self.read_bytes(path)?;
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }

    fn write_bytes(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let key = Self::norm_key(path);
        let mut guard = self.state.lock().expect("mock fs lock poisoned");
        Self::check_denied(&guard, &key)?;
        let now = Utc::now();
        if let Some(existing) = guard.nodes.get_mut(&key) {
            if existing.entry.is_dir {
                return Err(FsError::InvalidPath(format!(
                    "cannot write bytes to directory: {}",
                    path.display()
                )));
            }
            if existing.entry.attributes.read_only {
                return Err(FsError::PermissionDenied(format!(
                    "cannot write bytes to read-only file: {}",
                    path.display()
                )));
            }
            let len = bytes.len() as u64;
            existing.bytes = bytes.to_vec();
            existing.entry.size = len;
            existing.entry.compressed_size = Some(len);
            existing.entry.timestamps.modified = Some(now);
            return Ok(());
        }

        let name = key
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| key.to_string_lossy().into_owned());
        let extension = key
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let len = bytes.len() as u64;
        let entry = FileEntry {
            path: key.clone(),
            name,
            extension,
            size: len,
            compressed_size: Some(len),
            is_dir: false,
            is_symlink: false,
            timestamps: FileTimestamps {
                created: Some(now),
                modified: Some(now),
                accessed: Some(now),
            },
            attributes: FileAttributes::default(),
        };
        guard.nodes.insert(
            key,
            MockNode {
                entry,
                bytes: bytes.to_vec(),
            },
        );
        Ok(())
    }

    fn compressed_size(&self, path: &Path) -> Result<u64, FsError> {
        let entry = self.metadata(path)?;
        Ok(entry.compressed_size.unwrap_or(entry.size))
    }

    fn set_timestamps(&self, path: &Path, timestamps: &FileTimestamps) -> Result<(), FsError> {
        let key = Self::norm_key(path);
        let mut guard = self.state.lock().expect("mock fs lock poisoned");
        Self::check_denied(&guard, &key)?;
        let node = guard
            .nodes
            .get_mut(&key)
            .ok_or_else(|| FsError::SourceUnavailable(format!("mock path not found: {}", path.display())))?;
        if node.entry.attributes.read_only && !node.entry.is_dir {
            return Err(FsError::PermissionDenied(format!(
                "cannot modify timestamps on read-only file: {}",
                path.display()
            )));
        }
        if let Some(c) = timestamps.created {
            node.entry.timestamps.created = Some(c);
        }
        if let Some(m) = timestamps.modified {
            node.entry.timestamps.modified = Some(m);
        }
        if let Some(a) = timestamps.accessed {
            node.entry.timestamps.accessed = Some(a);
        }
        Ok(())
    }

    fn set_attributes(&self, path: &Path, attrs: &FileAttributes) -> Result<(), FsError> {
        let key = Self::norm_key(path);
        let mut guard = self.state.lock().expect("mock fs lock poisoned");
        Self::check_denied(&guard, &key)?;
        let node = guard
            .nodes
            .get_mut(&key)
            .ok_or_else(|| FsError::SourceUnavailable(format!("mock path not found: {}", path.display())))?;
        let preserved = node.entry.attributes.to_raw() & !FileAttributes::USER_MUTABLE_MASK;
        let requested = attrs.to_raw() & FileAttributes::USER_MUTABLE_MASK;
        node.entry.attributes = FileAttributes::from_raw(preserved | requested);
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        let key = Self::norm_key(path);
        let mut guard = self.state.lock().expect("mock fs lock poisoned");
        Self::check_denied(&guard, &key)?;
        let node = guard
            .nodes
            .get(&key)
            .ok_or_else(|| FsError::SourceUnavailable(format!("mock file not found: {}", path.display())))?;
        if node.entry.is_dir {
            return Err(FsError::InvalidPath(format!(
                "cannot remove dir via remove_file: {}",
                path.display()
            )));
        }
        if node.entry.attributes.read_only {
            return Err(FsError::PermissionDenied(format!(
                "cannot remove read-only file: {}",
                path.display()
            )));
        }
        guard.nodes.remove(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn mock_fs_supports_metadata_read_dir_range_and_mutations() {
        let mock = MockFileSystem::new();
        let dir = Path::new("C:\\mock_root");
        let file = Path::new("C:\\mock_root\\sample.bin");
        let ts = FileTimestamps {
            created: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            modified: Some(Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap()),
            accessed: Some(Utc.with_ymd_and_hms(2024, 1, 3, 0, 0, 0).unwrap()),
        };

        mock.insert_dir(dir, ts, FileAttributes::default());
        mock.insert_file_with_compressed(
            file,
            b"0123456789abcdef".to_vec(),
            Some(8),
            ts,
            FileAttributes::from_raw(FileAttributes::ARCHIVE | FileAttributes::READONLY),
        );

        assert!(mock.exists(file));
        assert_eq!(mock.read_dir(dir).unwrap().len(), 1);
        assert_eq!(mock.read_range(file, 4, 6).unwrap(), b"456789");
        assert_eq!(mock.compressed_size(file).unwrap(), 8);

        // Read-only blocks timestamp change until READONLY is cleared.
        let new_ts = FileTimestamps {
            created: None,
            modified: Some(Utc.with_ymd_and_hms(2025, 5, 5, 5, 5, 5).unwrap()),
            accessed: None,
        };
        assert!(matches!(
            mock.set_timestamps(file, &new_ts),
            Err(FsError::PermissionDenied(_))
        ));

        mock.set_attributes(file, &FileAttributes::from_raw(FileAttributes::ARCHIVE))
            .unwrap();
        mock.set_timestamps(file, &new_ts).unwrap();
        assert_eq!(mock.metadata(file).unwrap().timestamps.modified, new_ts.modified);
    }

    #[test]
    fn os_fs_sets_timestamps_attributes_and_reads_compressed_size() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("win_probe.txt");
        let subdir = tmp.path().join("sub_folder");
        std::fs::write(&file, b"hello win32 fs_ops").unwrap();
        std::fs::create_dir(&subdir).unwrap();

        let fs = OsFileSystem;
        let entry = fs.metadata(&file).unwrap();
        assert_eq!(entry.size, 18);
        assert!(fs.compressed_size(&file).unwrap() > 0);
        assert_eq!(fs.read_range(&file, 6, 5).unwrap(), b"win32");

        let target_dt = Utc.with_ymd_and_hms(2023, 7, 14, 9, 30, 0).unwrap();
        let target_ts = FileTimestamps {
            created: Some(target_dt),
            modified: Some(target_dt),
            accessed: Some(target_dt),
        };

        // Set timestamps on both file and directory (exercises FILE_FLAG_BACKUP_SEMANTICS on Windows).
        fs.set_timestamps(&file, &target_ts).unwrap();
        fs.set_timestamps(&subdir, &target_ts).unwrap();

        let after_file = fs.metadata(&file).unwrap();
        let after_dir = fs.metadata(&subdir).unwrap();
        assert_eq!(after_file.timestamps.modified, Some(target_dt));
        assert_eq!(after_dir.timestamps.modified, Some(target_dt));

        // Toggle Hidden + ReadOnly, verify, and clear before tempdir cleanup.
        let attrs = FileAttributes::parse_flags("RH").unwrap();
        fs.set_attributes(&file, &attrs).unwrap();
        let updated = fs.metadata(&file).unwrap();
        assert!(updated.attributes.read_only);
        #[cfg(windows)]
        assert!(updated.attributes.hidden);

        fs.set_attributes(&file, &FileAttributes::default()).unwrap();
        let cleared = fs.metadata(&file).unwrap();
        assert!(!cleared.attributes.read_only);
        assert!(!cleared.attributes.hidden);
    }

    #[test]
    fn write_bytes_works_on_mock_and_os_filesystems() {
        let mock = MockFileSystem::new();
        let mock_file = Path::new("C:\\mock_root\\written.bin");
        mock.insert_dir(
            Path::new("C:\\mock_root"),
            FileTimestamps::default(),
            FileAttributes::default(),
        );
        mock.write_bytes(mock_file, b"hello mock").unwrap();
        assert_eq!(mock.read_bytes(mock_file).unwrap(), b"hello mock");
        assert_eq!(mock.metadata(mock_file).unwrap().size, 10);

        mock.write_bytes(mock_file, b"updated bytes!").unwrap();
        assert_eq!(mock.read_bytes(mock_file).unwrap(), b"updated bytes!");
        assert_eq!(mock.metadata(mock_file).unwrap().size, 14);
        assert!(mock.metadata(mock_file).unwrap().timestamps.modified.is_some());

        mock.set_attributes(mock_file, &FileAttributes::from_raw(FileAttributes::READONLY))
            .unwrap();
        assert!(matches!(
            mock.write_bytes(mock_file, b"blocked"),
            Err(FsError::PermissionDenied(_))
        ));

        let tmp = tempfile::tempdir().unwrap();
        let os_file = tmp.path().join("os_written.bin");
        let os = OsFileSystem;
        os.write_bytes(&os_file, b"hello os").unwrap();
        assert_eq!(os.read_bytes(&os_file).unwrap(), b"hello os");
        os.remove_file(&os_file).unwrap();
        assert!(!os.exists(&os_file));
    }

    #[test]
    fn os_fs_read_dir_and_metadata_identify_directory_junctions_safely() {
        let tmp = tempfile::tempdir().unwrap();
        let target_dir = tmp.path().join("target_dir");
        let root_dir = tmp.path().join("root");
        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::create_dir_all(&root_dir).unwrap();
        std::fs::write(target_dir.join("inside.txt"), b"hello").unwrap();

        let link_dir = root_dir.join("dir_link");
        #[cfg(windows)]
        let link_created = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link_dir.to_string_lossy(),
                &target_dir.to_string_lossy(),
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        #[cfg(unix)]
        let link_created = std::os::unix::fs::symlink(&target_dir, &link_dir).is_ok();

        if link_created {
            let os = OsFileSystem;
            let entries = os.read_dir(&root_dir).unwrap();
            assert_eq!(entries.len(), 1);
            assert!(entries[0].is_symlink);
            assert!(entries[0].is_dir);
            assert_eq!(entries[0].size, 0);

            let meta = os.metadata(&link_dir).unwrap();
            assert!(meta.is_symlink);
            assert!(meta.is_dir);

            // Dangling junction/symlink must report is_dir = false without error
            std::fs::remove_dir_all(&target_dir).unwrap();
            let dangling_entries = os.read_dir(&root_dir).unwrap();
            assert_eq!(dangling_entries.len(), 1);
            assert!(dangling_entries[0].is_symlink);
            assert!(!dangling_entries[0].is_dir);

            let _ = std::fs::remove_dir(&link_dir);
        }
    }
}
