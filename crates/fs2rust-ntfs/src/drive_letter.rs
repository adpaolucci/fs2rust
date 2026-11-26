#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{
    decode_utf16le_nul, ensure_trailing_backslash, format_guid_le, read_u32_le, read_u64_le, validate_volume_guid_path,
};
use fs2rust_core::PolicyContext;
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountedDeviceTarget {
    MbrPartition { disk_signature: u32, partition_offset: u64 },
    GptPartitionGuid { partition_guid: String },
    DevicePath(String),
    RawHex(Vec<u8>),
}

impl MountedDeviceTarget {
    pub fn scheme_name(&self) -> &'static str {
        match self {
            Self::MbrPartition { .. } => "MBR",
            Self::GptPartitionGuid { .. } => "GPT",
            Self::DevicePath(_) => "PnP/Device",
            Self::RawHex(_) => "Unknown",
        }
    }

    pub fn display_target(&self) -> String {
        match self {
            Self::MbrPartition {
                disk_signature,
                partition_offset,
            } => format!("MBR:0x{disk_signature:08X}@{partition_offset}"),
            Self::GptPartitionGuid { partition_guid } => format!("GPT:{partition_guid}"),
            Self::DevicePath(s) => s.clone(),
            Self::RawHex(raw) => format!("0x{}", hex::encode(raw)),
        }
    }
}

/// Parse an `HKLM\SYSTEM\MountedDevices` binary registry value.
pub fn parse_mounted_device_value(bytes: &[u8]) -> MountedDeviceTarget {
    if bytes.len() == 12 {
        let disk_signature = read_u32_le(bytes, 0).unwrap_or(0);
        let partition_offset = read_u64_le(bytes, 4).unwrap_or(0);
        return MountedDeviceTarget::MbrPartition {
            disk_signature,
            partition_offset,
        };
    }
    if bytes.len() == 24 && bytes.starts_with(b"DMIO:ID:") {
        let mut guid_bytes = [0u8; 16];
        guid_bytes.copy_from_slice(&bytes[8..24]);
        return MountedDeviceTarget::GptPartitionGuid {
            partition_guid: format_guid_le(&guid_bytes),
        };
    }
    if bytes.len() >= 8 && bytes.len().is_multiple_of(2) {
        let decoded = decode_utf16le_nul(bytes);
        if decoded.starts_with(r"\??\")
            || decoded.starts_with("_??_")
            || decoded.starts_with(r"\Device\")
            || decoded.starts_with(r"\\?\")
        {
            return MountedDeviceTarget::DevicePath(decoded);
        }
    }
    MountedDeviceTarget::RawHex(bytes.to_vec())
}

pub fn parse_mounted_devices_map(entries: &[(String, Vec<u8>)]) -> BTreeMap<String, MountedDeviceTarget> {
    let mut map = BTreeMap::new();
    for (name, data) in entries {
        map.insert(name.clone(), parse_mounted_device_value(data));
    }
    map
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriveLetterEntry {
    pub drive_letter: String,
    pub drive_type: String,
    pub volume_guid: String,
    pub volume_label: String,
    pub filesystem: String,
    pub serial_number: String,
    pub total_size: Option<u64>,
    pub free_space: Option<u64>,
    pub device_target: String,
    pub partition_scheme: String,
    pub connected: bool,
    pub mounted_device_target: Option<MountedDeviceTarget>,
}

#[derive(Debug, Clone, Default)]
pub struct DriveLetterConfig {
    pub offline_mounted_devices: Option<Vec<(String, Vec<u8>)>>,
    pub offline_entries: Option<Vec<DriveLetterEntry>>,
}

pub fn drive_letter_schema() -> TableSchema {
    TableSchema::new(
        "drive_letter_view",
        "Logical Drives, Volume GUIDs & MountedDevices",
        vec![
            ColumnDef::new("drive_letter", "Drive Letter", ColumnType::Text).with_width_hint(80),
            ColumnDef::new("drive_type", "Drive Type", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("volume_guid", "Volume GUID", ColumnType::Text).with_width_hint(280),
            ColumnDef::new("volume_label", "Volume Label", ColumnType::Text).with_width_hint(140),
            ColumnDef::new("filesystem", "File System", ColumnType::Text).with_width_hint(85),
            ColumnDef::new("serial_number", "Serial Number", ColumnType::Text).with_width_hint(100),
            ColumnDef::new("total_size", "Total Size", ColumnType::BytesSize).with_width_hint(110),
            ColumnDef::new("free_space", "Free Space", ColumnType::BytesSize).with_width_hint(110),
            ColumnDef::new("device_target", "Device Target", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("partition_scheme", "Scheme", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("connected", "Connected", ColumnType::Bool).with_width_hint(85),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

pub fn entries_to_rows(entries: &[DriveLetterEntry]) -> Vec<Row> {
    entries
        .iter()
        .enumerate()
        .map(|(idx, e)| {
            Row::new(
                idx as u64 + 1,
                vec![
                    CellValue::Text(e.drive_letter.clone()),
                    CellValue::Text(e.drive_type.clone()),
                    CellValue::Text(e.volume_guid.clone()),
                    CellValue::Text(e.volume_label.clone()),
                    CellValue::Text(e.filesystem.clone()),
                    CellValue::Text(e.serial_number.clone()),
                    e.total_size.map(CellValue::Bytes).unwrap_or(CellValue::Null),
                    e.free_space.map(CellValue::Bytes).unwrap_or(CellValue::Null),
                    CellValue::Text(e.device_target.clone()),
                    CellValue::Text(e.partition_scheme.clone()),
                    CellValue::Bool(e.connected),
                ],
            )
            .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
        })
        .collect()
}

pub fn entries_from_mounted_devices(entries: &[(String, Vec<u8>)]) -> Vec<DriveLetterEntry> {
    entries
        .iter()
        .map(|(name, raw)| {
            let parsed = parse_mounted_device_value(raw);
            let drive_letter = name
                .strip_prefix(r"\DosDevices\")
                .map(|s| format!(r"{s}\"))
                .unwrap_or_else(|| name.clone());
            let volume_guid = if name.starts_with(r"\??\Volume{") {
                format!(r"\\?\{}\", name.trim_start_matches(r"\??\"))
            } else {
                String::new()
            };
            DriveLetterEntry {
                drive_letter,
                drive_type: "Registry".to_string(),
                volume_guid,
                volume_label: String::new(),
                filesystem: String::new(),
                serial_number: String::new(),
                total_size: None,
                free_space: None,
                device_target: parsed.display_target(),
                partition_scheme: parsed.scheme_name().to_string(),
                connected: false,
                mounted_device_target: Some(parsed),
            }
        })
        .collect()
}

pub struct DriveLetterProvider {
    config: DriveLetterConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl DriveLetterProvider {
    pub fn new(config: DriveLetterConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for DriveLetterProvider {
    fn tool_id(&self) -> &'static str {
        "drive_letter_view"
    }

    fn description(&self) -> &'static str {
        "Enumerate logical drives, volume GUIDs, capacities, DOS targets, and HKLM\\SYSTEM\\MountedDevices mappings"
    }

    fn schema(&self) -> TableSchema {
        drive_letter_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let entries = if let Some(offline) = &self.config.offline_entries {
            offline.clone()
        } else if let Some(reg_entries) = &self.config.offline_mounted_devices {
            entries_from_mounted_devices(reg_entries)
        } else {
            self.backend.list_drive_letters().map_err(TableError::from)?
        };
        let rows = entries_to_rows(&entries);
        apply_query(&self.schema(), &rows, req)
    }
}

fn check_confirm_destructive(args: &Value, policy: &PolicyContext) -> Result<(), McpToolError> {
    let confirmed = args
        .get("confirm_destructive")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || policy.confirm_destructive;
    if !confirmed {
        return Err(McpToolError::PolicyDenied(
            "destructive mount-point mutation requires confirm_destructive = true".to_string(),
        ));
    }
    Ok(())
}

/// Mutating `ActionCommand` assigning a volume GUID to a drive letter / mount point (`SetVolumeMountPointW`).
pub struct DriveLetterAssignAction {
    backend: Arc<dyn NtfsBackend>,
    policy: PolicyContext,
}

impl DriveLetterAssignAction {
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

impl ActionCommand for DriveLetterAssignAction {
    fn command_id(&self) -> &'static str {
        "drive_letter_assign"
    }

    fn description(&self) -> &'static str {
        "Assign a volume GUID to a drive letter or NTFS mount-point directory (SetVolumeMountPointW)"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["mount_point", "volume_guid"],
            "properties": {
                "mount_point": { "type": "string", "description": "Target drive root or empty directory (e.g. 'Z:\\\\' or 'C:\\\\mnt\\\\vol\\\\')" },
                "volume_guid": { "type": "string", "description": "Volume GUID path '\\\\?\\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\\'" }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let mount_raw = args
            .get("mount_point")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'mount_point'".to_string()))?;
        let vol_raw = args
            .get("volume_guid")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'volume_guid'".to_string()))?;

        let mount_point = ensure_trailing_backslash(mount_raw);
        let volume_guid = validate_volume_guid_path(vol_raw).map_err(McpToolError::from)?;
        self.policy
            .check_path_allowed(Path::new(&mount_point))
            .map_err(McpToolError::from)?;

        if dry_run {
            return Ok(json!({
                "mode": "dry_run",
                "action": "assign",
                "mount_point": mount_point,
                "volume_guid": volume_guid,
            }));
        }

        check_confirm_destructive(args, &self.policy)?;
        self.backend
            .set_volume_mount_point(&mount_point, &volume_guid)
            .map_err(McpToolError::from)?;

        Ok(json!({
            "mode": "applied",
            "action": "assign",
            "mount_point": mount_point,
            "volume_guid": volume_guid,
        }))
    }
}

/// Mutating `ActionCommand` removing a drive letter / mount point (`DeleteVolumeMountPointW`).
pub struct DriveLetterRemoveAction {
    backend: Arc<dyn NtfsBackend>,
    policy: PolicyContext,
}

impl DriveLetterRemoveAction {
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

impl ActionCommand for DriveLetterRemoveAction {
    fn command_id(&self) -> &'static str {
        "drive_letter_remove"
    }

    fn description(&self) -> &'static str {
        "Remove a drive letter or NTFS mount-point mapping (DeleteVolumeMountPointW)"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["mount_point"],
            "properties": {
                "mount_point": { "type": "string", "description": "Mount point to remove (e.g. 'Z:\\\\')" }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let mount_raw = args
            .get("mount_point")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'mount_point'".to_string()))?;
        let mount_point = ensure_trailing_backslash(mount_raw);
        self.policy
            .check_path_allowed(Path::new(&mount_point))
            .map_err(McpToolError::from)?;

        if dry_run {
            return Ok(json!({
                "mode": "dry_run",
                "action": "remove",
                "mount_point": mount_point,
            }));
        }

        check_confirm_destructive(args, &self.policy)?;
        self.backend
            .delete_volume_mount_point(&mount_point)
            .map_err(McpToolError::from)?;

        Ok(json!({
            "mode": "applied",
            "action": "remove",
            "mount_point": mount_point,
        }))
    }
}
