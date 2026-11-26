#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{
    decode_utf16le_nul, format_guid_le, read_i32_le, read_u8, read_u16_le, read_u32_le, read_u64_le,
};
use fs2rust_core::{FsError, PolicyContext, windows_filetime_to_datetime};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const FMTID_SUMMARY_INFORMATION: &str = "{F29F85E0-4FF9-1068-AB91-08002B27B3D9}";
pub const FMTID_DOC_SUMMARY_INFORMATION: &str = "{D5CDD502-2E9C-101B-9397-08002B2CF9AE}";
pub const FMTID_STORAGE: &str = "{B725F130-47EF-101A-A5F1-02608C9EEBAC}";
pub const FMTID_CORE_DOCUMENT: &str = "{56616700-C154-11CE-8553-00AA00A1F95B}";

pub fn lookup_canonical_property_name(fmtid: &str, pid: u32) -> String {
    let upper = fmtid.to_ascii_uppercase();
    match (upper.as_str(), pid) {
        (FMTID_SUMMARY_INFORMATION, 2) => "System.Title".to_string(),
        (FMTID_SUMMARY_INFORMATION, 3) => "System.Subject".to_string(),
        (FMTID_SUMMARY_INFORMATION, 4) => "System.Author".to_string(),
        (FMTID_SUMMARY_INFORMATION, 5) => "System.Keywords".to_string(),
        (FMTID_SUMMARY_INFORMATION, 6) => "System.Comment".to_string(),
        (FMTID_SUMMARY_INFORMATION, 9) => "System.Document.RevisionNumber".to_string(),
        (FMTID_SUMMARY_INFORMATION, 12) => "System.Document.DateCreated".to_string(),
        (FMTID_SUMMARY_INFORMATION, 13) => "System.Document.DateSaved".to_string(),
        (FMTID_SUMMARY_INFORMATION, 18) => "System.ApplicationName".to_string(),
        (FMTID_DOC_SUMMARY_INFORMATION, 2) => "System.Category".to_string(),
        (FMTID_DOC_SUMMARY_INFORMATION, 15) => "System.Company".to_string(),
        (FMTID_STORAGE, 10) => "System.ItemNameDisplay".to_string(),
        (FMTID_STORAGE, 12) => "System.Size".to_string(),
        (FMTID_STORAGE, 14) => "System.DateModified".to_string(),
        (FMTID_STORAGE, 15) => "System.DateCreated".to_string(),
        (FMTID_STORAGE, 16) => "System.DateAccessed".to_string(),
        _ => format!("{upper} {pid}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedPropertyEntry {
    pub fmtid: String,
    pub pid: u32,
    pub canonical_name: String,
    pub vt_type: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedPropertyStorageBlock {
    pub storage_size: u32,
    pub fmtid: String,
    pub entries: Vec<SerializedPropertyEntry>,
}

fn decode_serialized_prop_value(vt: u16, payload: &[u8]) -> Result<(&'static str, String), FsError> {
    match vt {
        0x0000 => Ok(("VT_EMPTY", String::new())),
        0x0001 => Ok(("VT_NULL", String::new())),
        0x0003 => {
            if payload.len() < 4 {
                return Err(FsError::Parse("VT_I4 payload truncated".to_string()));
            }
            Ok(("VT_I4", read_i32_le(payload, 0)?.to_string()))
        }
        0x0013 => {
            if payload.len() < 4 {
                return Err(FsError::Parse("VT_UI4 payload truncated".to_string()));
            }
            Ok(("VT_UI4", read_u32_le(payload, 0)?.to_string()))
        }
        0x0014 => {
            if payload.len() < 8 {
                return Err(FsError::Parse("VT_I8 payload truncated".to_string()));
            }
            Ok(("VT_I8", (read_u64_le(payload, 0)? as i64).to_string()))
        }
        0x0015 => {
            if payload.len() < 8 {
                return Err(FsError::Parse("VT_UI8 payload truncated".to_string()));
            }
            Ok(("VT_UI8", read_u64_le(payload, 0)?.to_string()))
        }
        0x000B => {
            if payload.len() < 2 {
                return Err(FsError::Parse("VT_BOOL payload truncated".to_string()));
            }
            let b = read_u16_le(payload, 0)? != 0;
            Ok(("VT_BOOL", b.to_string()))
        }
        0x001E => {
            let s = if payload.len() >= 4 {
                let char_len = read_u32_le(payload, 0)? as usize;
                let str_slice = &payload[4..payload.len().min(4usize.saturating_add(char_len))];
                let end = str_slice.iter().position(|&b| b == 0).unwrap_or(str_slice.len());
                String::from_utf8_lossy(&str_slice[..end]).to_string()
            } else {
                String::from_utf8_lossy(payload).trim_end_matches('\0').to_string()
            };
            Ok(("VT_LPSTR", s))
        }
        0x001F => {
            let s = if payload.len() >= 4 {
                let char_count = read_u32_le(payload, 0)? as usize;
                let byte_len = char_count.saturating_mul(2);
                let avail = payload.len() - 4;
                decode_utf16le_nul(&payload[4..4 + byte_len.min(avail)])
            } else {
                decode_utf16le_nul(payload)
            };
            Ok(("VT_LPWSTR", s))
        }
        0x0040 => {
            if payload.len() < 8 {
                return Err(FsError::Parse("VT_FILETIME payload truncated".to_string()));
            }
            let ft = read_u64_le(payload, 0)?;
            let formatted = windows_filetime_to_datetime(ft)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| ft.to_string());
            Ok(("VT_FILETIME", formatted))
        }
        _ => Ok(("VT_UNKNOWN", format!("0x{}", hex::encode(payload)))),
    }
}

/// Parse a `1SPS` (`SERIALIZEDPROPERTYSTORAGE`) binary buffer in pure Rust.
pub fn parse_serialized_property_storage(bytes: &[u8]) -> Result<Vec<SerializedPropertyStorageBlock>, FsError> {
    let mut blocks = Vec::new();
    let mut block_off = 0usize;
    let mut block_iters = 0usize;

    while block_off < bytes.len() {
        block_iters += 1;
        if block_iters > 1024 {
            return Err(FsError::Parse("1SPS block count limit exceeded".to_string()));
        }
        if block_off + 4 > bytes.len() {
            return Err(FsError::Parse("truncated 1SPS StorageSize".to_string()));
        }
        let storage_size = read_u32_le(bytes, block_off)? as usize;
        if storage_size == 0 {
            break;
        }
        if storage_size < 24 {
            return Err(FsError::Parse(format!(
                "invalid 1SPS StorageSize {storage_size} (< 24) at offset {block_off}"
            )));
        }
        let storage_end = block_off
            .checked_add(storage_size)
            .filter(|&end| end <= bytes.len())
            .ok_or_else(|| FsError::Parse(format!("1SPS block at {block_off} size {storage_size} out of bounds")))?;

        if &bytes[block_off + 4..block_off + 8] != b"1SPS" {
            return Err(FsError::Parse(format!(
                "invalid 1SPS magic at offset {}: {:?}",
                block_off + 4,
                &bytes[block_off + 4..block_off + 8]
            )));
        }

        let mut fmtid_bytes = [0u8; 16];
        fmtid_bytes.copy_from_slice(&bytes[block_off + 8..block_off + 24]);
        let fmtid = format_guid_le(&fmtid_bytes);

        let mut entries = Vec::new();
        let mut cursor = block_off + 24;
        let mut prop_iters = 0usize;
        while cursor + 4 <= storage_end {
            prop_iters += 1;
            if prop_iters > 4096 {
                return Err(FsError::Parse("1SPS property count limit exceeded".to_string()));
            }
            let val_size = read_u32_le(bytes, cursor)? as usize;
            if val_size == 0 {
                break;
            }
            if val_size < 13 {
                return Err(FsError::Parse(format!(
                    "invalid 1SPS SERIALIZEDPROPERTYVALUE size {val_size} (< 13) at {cursor}"
                )));
            }
            let val_end = cursor
                .checked_add(val_size)
                .filter(|&end| end <= storage_end)
                .ok_or_else(|| FsError::Parse(format!("1SPS property value at {cursor} exceeds block end")))?;

            let pid = read_u32_le(bytes, cursor + 4)?;
            let _reserved = read_u8(bytes, cursor + 8)?;
            let vt = read_u16_le(bytes, cursor + 9)?;
            let (vt_type, value) = decode_serialized_prop_value(vt, &bytes[cursor + 13..val_end])?;
            entries.push(SerializedPropertyEntry {
                fmtid: fmtid.clone(),
                pid,
                canonical_name: lookup_canonical_property_name(&fmtid, pid),
                vt_type: vt_type.to_string(),
                value,
            });
            cursor = val_end;
        }

        blocks.push(SerializedPropertyStorageBlock {
            storage_size: storage_size as u32,
            fmtid,
            entries,
        });
        block_off = storage_end;
    }

    Ok(blocks)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePropertyEntry {
    pub file_path: String,
    pub canonical_name: String,
    pub property_key: String,
    pub display_name: String,
    pub value_type: String,
    pub value: String,
    pub read_only_prop: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PropertySystemConfig {
    pub file_paths: Vec<PathBuf>,
    pub policy: PolicyContext,
    pub offline_entries: Option<Vec<FilePropertyEntry>>,
}

pub fn property_system_schema() -> TableSchema {
    TableSchema::new(
        "property_system_view",
        "PropertySystemView - Windows Shell Property Store (IPropertyStore / propsys.dll)",
        vec![
            ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("canonical_name", "Canonical Name", ColumnType::Text).with_width_hint(210),
            ColumnDef::new("property_key", "Property Key", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("display_name", "Display Name", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("value_type", "Type", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("value", "Value", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("read_only_prop", "Read Only", ColumnType::Bool).with_width_hint(85),
        ],
    )
    .with_default_sort(1, SortDirection::Asc)
}

pub struct PropertySystemViewProvider {
    config: PropertySystemConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl PropertySystemViewProvider {
    pub fn new(config: PropertySystemConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for PropertySystemViewProvider {
    fn tool_id(&self) -> &'static str {
        "property_system_view"
    }

    fn description(&self) -> &'static str {
        "Read Windows Property System metadata via SHGetPropertyStoreFromParsingName / IPropertyStore"
    }

    fn schema(&self) -> TableSchema {
        property_system_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let entries = if let Some(offline) = &self.config.offline_entries {
            offline.clone()
        } else {
            let mut all = Vec::new();
            for p in &self.config.file_paths {
                self.config.policy.check_path_allowed(p).map_err(TableError::from)?;
                all.extend(self.backend.read_file_properties(p).map_err(TableError::from)?);
            }
            all
        };

        let rows: Vec<Row> = entries
            .iter()
            .enumerate()
            .map(|(idx, e)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(e.file_path.clone()),
                        CellValue::Text(e.canonical_name.clone()),
                        CellValue::Text(e.property_key.clone()),
                        CellValue::Text(e.display_name.clone()),
                        CellValue::Text(e.value_type.clone()),
                        CellValue::Text(e.value.clone()),
                        CellValue::Bool(e.read_only_prop),
                    ],
                )
                .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

/// Mutating `ActionCommand` writing a canonical Windows Property System property (`IPropertyStore::SetValue` + `Commit`).
pub struct PropertySystemSetAction {
    backend: Arc<dyn NtfsBackend>,
    policy: PolicyContext,
}

impl PropertySystemSetAction {
    pub fn new(backend: Arc<dyn NtfsBackend>) -> Self {
        Self {
            backend,
            policy: PolicyContext::default(),
        }
    }

    pub fn with_policy(mut self, policy: PolicyContext) -> Self {
        self.policy = policy;
        self
    }
}

impl ActionCommand for PropertySystemSetAction {
    fn command_id(&self) -> &'static str {
        "property_system_set"
    }

    fn description(&self) -> &'static str {
        "Set a Windows Property System canonical property on a file via IPropertyStore (GPS_READWRITE)"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["file_path", "canonical_name", "value"],
            "properties": {
                "file_path": { "type": "string" },
                "canonical_name": { "type": "string", "description": "Canonical property name (e.g. 'System.Title', 'System.Comment')" },
                "value": { "type": "string" }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let file_path = args
            .get("file_path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'file_path'".to_string()))?;
        let canonical_name = args
            .get("canonical_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'canonical_name'".to_string()))?;
        let value = args
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'value'".to_string()))?;

        if canonical_name.trim().is_empty() {
            return Err(McpToolError::InvalidParams(
                "canonical_name cannot be empty".to_string(),
            ));
        }

        let target = Path::new(file_path);
        self.policy.check_path_allowed(target).map_err(McpToolError::from)?;

        if dry_run {
            return Ok(json!({
                "mode": "dry_run",
                "file_path": file_path,
                "canonical_name": canonical_name,
                "new_value": value,
            }));
        }

        let confirmed = args
            .get("confirm_destructive")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || self.policy.confirm_destructive;
        if !confirmed {
            return Err(McpToolError::PolicyDenied(
                "modifying file properties requires confirm_destructive = true".to_string(),
            ));
        }

        let updated = self
            .backend
            .set_file_property(target, canonical_name, value)
            .map_err(McpToolError::from)?;

        Ok(json!({
            "mode": "applied",
            "file_path": file_path,
            "canonical_name": updated.canonical_name,
            "property_key": updated.property_key,
            "new_value": updated.value,
        }))
    }
}
