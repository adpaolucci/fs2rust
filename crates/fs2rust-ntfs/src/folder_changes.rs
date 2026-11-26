#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{decode_utf16le, read_u32_le};
use chrono::{DateTime, Utc};
use fs2rust_core::{FileEntry, FsError, PolicyContext};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FolderChangeAction {
    Added,
    Removed,
    Modified,
    RenamedOld,
    RenamedNew,
}

impl FolderChangeAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::Removed => "Removed",
            Self::Modified => "Modified",
            Self::RenamedOld => "RenamedOld",
            Self::RenamedNew => "RenamedNew",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderChangeEntry {
    pub timestamp: DateTime<Utc>,
    pub action: FolderChangeAction,
    pub path: String,
    pub full_path: String,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
    pub attributes: String,
    pub extension: String,
    pub source: String,
}

/// Parse a Win32 `FILE_NOTIFY_INFORMATION` byte buffer returned by `ReadDirectoryChangesW`.
pub fn parse_file_notify_buffer(
    base_dir: &Path,
    buf: &[u8],
    timestamp: DateTime<Utc>,
) -> Result<Vec<FolderChangeEntry>, FsError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let mut iterations = 0usize;

    while offset < buf.len() {
        iterations += 1;
        if iterations > 65_536 {
            return Err(FsError::Parse(
                "FILE_NOTIFY_INFORMATION iteration limit exceeded".to_string(),
            ));
        }
        if offset + 12 > buf.len() {
            return Err(FsError::Parse(format!(
                "truncated FILE_NOTIFY_INFORMATION header at offset {offset} (len={})",
                buf.len()
            )));
        }

        let next_offset = read_u32_le(buf, offset)? as usize;
        let action_raw = read_u32_le(buf, offset + 4)?;
        let fn_len = read_u32_le(buf, offset + 8)? as usize;

        if !fn_len.is_multiple_of(2) {
            return Err(FsError::Parse(format!(
                "FILE_NOTIFY_INFORMATION FileNameLength ({fn_len}) is not even"
            )));
        }

        let entry_end = if next_offset == 0 {
            buf.len()
        } else {
            if next_offset < 12 {
                return Err(FsError::Parse(format!(
                    "invalid FILE_NOTIFY_INFORMATION NextEntryOffset ({next_offset} < 12)"
                )));
            }
            offset
                .checked_add(next_offset)
                .filter(|&end| end <= buf.len())
                .ok_or_else(|| FsError::Parse("FILE_NOTIFY_INFORMATION NextEntryOffset out of bounds".to_string()))?
        };

        let name_start = offset + 12;
        let name_end = name_start
            .checked_add(fn_len)
            .filter(|&end| end <= entry_end)
            .ok_or_else(|| FsError::Parse("FILE_NOTIFY_INFORMATION FileNameLength out of bounds".to_string()))?;

        let rel_path = decode_utf16le(&buf[name_start..name_end]);
        let action = match action_raw {
            1 => FolderChangeAction::Added,
            2 => FolderChangeAction::Removed,
            3 => FolderChangeAction::Modified,
            4 => FolderChangeAction::RenamedOld,
            5 => FolderChangeAction::RenamedNew,
            other => {
                return Err(FsError::Parse(format!(
                    "unknown FILE_NOTIFY_INFORMATION Action value {other}"
                )));
            }
        };

        let full_path = base_dir.join(&rel_path);
        let extension = Path::new(&rel_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_string();

        entries.push(FolderChangeEntry {
            timestamp,
            action,
            path: rel_path,
            full_path: full_path.to_string_lossy().to_string(),
            old_size: None,
            new_size: None,
            attributes: String::new(),
            extension,
            source: "ReadDirectoryChangesW".to_string(),
        });

        if next_offset == 0 {
            break;
        }
        offset = entry_end;
    }

    Ok(entries)
}

/// Deterministic directory snapshot for offline change diffing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FolderSnapshot {
    pub entries: Vec<FileEntry>,
}

impl FolderSnapshot {
    pub fn diff(before: &[FileEntry], after: &[FileEntry], event_time: DateTime<Utc>) -> Vec<FolderChangeEntry> {
        let mut before_map: BTreeMap<String, &FileEntry> = BTreeMap::new();
        let mut after_map: BTreeMap<String, &FileEntry> = BTreeMap::new();

        for e in before {
            before_map.insert(e.path.to_string_lossy().to_string(), e);
        }
        for e in after {
            after_map.insert(e.path.to_string_lossy().to_string(), e);
        }

        let mut removed_keys: Vec<String> = before_map
            .keys()
            .filter(|k| !after_map.contains_key(*k))
            .cloned()
            .collect();
        let mut added_keys: Vec<String> = after_map
            .keys()
            .filter(|k| !before_map.contains_key(*k))
            .cloned()
            .collect();

        let mut paired_removed = BTreeSet::new();
        let mut paired_added = BTreeSet::new();
        let mut out = Vec::new();

        // Detect renames when a removed entry and added entry match in size, is_dir, and modified timestamp.
        for r_key in &removed_keys {
            let r_entry = before_map[r_key];
            if let Some(a_key) = added_keys.iter().find(|ak| {
                if paired_added.contains(*ak) {
                    return false;
                }
                let a_entry = after_map[*ak];
                r_entry.is_dir == a_entry.is_dir
                    && r_entry.size == a_entry.size
                    && r_entry.timestamps.modified.is_some()
                    && r_entry.timestamps.modified == a_entry.timestamps.modified
            }) {
                let a_entry = after_map[a_key];
                paired_removed.insert(r_key.clone());
                paired_added.insert(a_key.clone());
                out.push(FolderChangeEntry {
                    timestamp: event_time,
                    action: FolderChangeAction::RenamedOld,
                    path: r_entry.name.clone(),
                    full_path: r_key.clone(),
                    old_size: Some(r_entry.size),
                    new_size: None,
                    attributes: r_entry.attributes.format_flags(),
                    extension: r_entry.extension.clone(),
                    source: "SnapshotDiff".to_string(),
                });
                out.push(FolderChangeEntry {
                    timestamp: event_time,
                    action: FolderChangeAction::RenamedNew,
                    path: a_entry.name.clone(),
                    full_path: a_key.clone(),
                    old_size: Some(r_entry.size),
                    new_size: Some(a_entry.size),
                    attributes: a_entry.attributes.format_flags(),
                    extension: a_entry.extension.clone(),
                    source: "SnapshotDiff".to_string(),
                });
            }
        }

        removed_keys.retain(|k| !paired_removed.contains(k));
        added_keys.retain(|k| !paired_added.contains(k));

        for r_key in removed_keys {
            let e = before_map[&r_key];
            out.push(FolderChangeEntry {
                timestamp: event_time,
                action: FolderChangeAction::Removed,
                path: e.name.clone(),
                full_path: r_key,
                old_size: Some(e.size),
                new_size: None,
                attributes: e.attributes.format_flags(),
                extension: e.extension.clone(),
                source: "SnapshotDiff".to_string(),
            });
        }

        for a_key in added_keys {
            let e = after_map[&a_key];
            out.push(FolderChangeEntry {
                timestamp: event_time,
                action: FolderChangeAction::Added,
                path: e.name.clone(),
                full_path: a_key,
                old_size: None,
                new_size: Some(e.size),
                attributes: e.attributes.format_flags(),
                extension: e.extension.clone(),
                source: "SnapshotDiff".to_string(),
            });
        }

        for (k, b_entry) in &before_map {
            if let Some(a_entry) = after_map.get(k)
                && (b_entry.size != a_entry.size
                    || b_entry.timestamps.modified != a_entry.timestamps.modified
                    || b_entry.attributes != a_entry.attributes)
            {
                out.push(FolderChangeEntry {
                    timestamp: event_time,
                    action: FolderChangeAction::Modified,
                    path: a_entry.name.clone(),
                    full_path: k.clone(),
                    old_size: Some(b_entry.size),
                    new_size: Some(a_entry.size),
                    attributes: a_entry.attributes.format_flags(),
                    extension: a_entry.extension.clone(),
                    source: "SnapshotDiff".to_string(),
                });
            }
        }

        out
    }
}

#[derive(Debug, Clone)]
pub struct FolderChangesConfig {
    pub watch_dir: PathBuf,
    pub recursive: bool,
    pub duration_ms: u64,
    pub max_events: usize,
    pub policy: PolicyContext,
    pub offline_changes: Option<Vec<FolderChangeEntry>>,
}

impl Default for FolderChangesConfig {
    fn default() -> Self {
        Self {
            watch_dir: PathBuf::from("."),
            recursive: true,
            duration_ms: 300,
            max_events: 1024,
            policy: PolicyContext::default(),
            offline_changes: None,
        }
    }
}

pub fn folder_changes_schema() -> TableSchema {
    TableSchema::new(
        "folder_changes_view",
        "Directory Change Monitor & Snapshot Diff",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("action", "Action", ColumnType::Text).with_width_hint(105),
            ColumnDef::new("path", "Relative Path", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("full_path", "Full Path", ColumnType::Text).with_width_hint(300),
            ColumnDef::new("old_size", "Old Size", ColumnType::BytesSize).with_width_hint(100),
            ColumnDef::new("new_size", "New Size", ColumnType::BytesSize).with_width_hint(100),
            ColumnDef::new("attributes", "Attributes", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("extension", "Extension", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("source", "Source", ColumnType::Text).with_width_hint(130),
        ],
    )
    .with_default_sort(2, SortDirection::Asc)
}

pub struct FolderChangesViewProvider {
    config: FolderChangesConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl FolderChangesViewProvider {
    pub fn new(config: FolderChangesConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for FolderChangesViewProvider {
    fn tool_id(&self) -> &'static str {
        "folder_changes_view"
    }

    fn description(&self) -> &'static str {
        "Monitor file/folder creations, deletions, modifications, and renames via ReadDirectoryChangesW or snapshot diff"
    }

    fn schema(&self) -> TableSchema {
        folder_changes_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        self.config
            .policy
            .check_path_allowed(&self.config.watch_dir)
            .map_err(TableError::from)?;

        let changes = if let Some(offline) = &self.config.offline_changes {
            offline.clone()
        } else {
            self.backend
                .watch_folder_changes(
                    &self.config.watch_dir,
                    self.config.recursive,
                    self.config.duration_ms.clamp(25, 30_000),
                    self.config.max_events,
                )
                .map_err(TableError::from)?
        };

        let rows: Vec<Row> = changes
            .iter()
            .enumerate()
            .map(|(idx, c)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(c.timestamp),
                        CellValue::Text(c.action.as_str().to_string()),
                        CellValue::Text(c.path.clone()),
                        CellValue::Text(c.full_path.clone()),
                        c.old_size.map(CellValue::Bytes).unwrap_or(CellValue::Null),
                        c.new_size.map(CellValue::Bytes).unwrap_or(CellValue::Null),
                        CellValue::Text(c.attributes.clone()),
                        CellValue::Text(c.extension.clone()),
                        CellValue::Text(c.source.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(c).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
