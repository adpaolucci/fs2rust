#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{decode_utf16le, read_u16_le, read_u32_le, read_u64_le};
use crate::ntstatus::{NtStatusInfo, decode_ntstatus};
use chrono::{DateTime, Utc};
use fs2rust_core::{FsError, windows_filetime_to_datetime};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub const KERNEL_FILE_PROVIDER_GUID: &str = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}";
pub const KERNEL_FILE_MAGIC: &[u8; 8] = b"FS2FILE1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelFileRawEvent {
    pub event_id: u16,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: DateTime<Utc>,
    pub irp_ptr: u64,
    pub file_object: u64,
    pub file_key: u64,
    pub io_size: u32,
    pub nt_status: u32,
    pub io_flags: u32,
    pub file_path: String,
    pub process_name: String,
}

pub fn kernel_file_operation_name(event_id: u16) -> &'static str {
    match event_id {
        10 => "NameCreate",
        11 => "NameDelete",
        12 => "Create",
        13 => "Cleanup",
        14 => "Close",
        15 => "Read",
        16 => "Write",
        17 => "SetInfo",
        18 => "Delete",
        19 => "Rename",
        20 => "DirEnum",
        21 => "Flush",
        22 => "QueryInfo",
        23 => "FSCTL",
        24 => "OperationEnd",
        25 => "DirNotify",
        26 => "DeletePath",
        27 => "RenamePath",
        28 => "SetLinkPath",
        29 => "SetLink",
        30 => "CreateNewFile",
        _ => "Other",
    }
}

/// Encode a `KernelFileRawEvent` into the deterministic 56B-header + UTF-16LE wire format.
pub fn encode_kernel_file_wire_record(ev: &KernelFileRawEvent, filetime_100ns: u64) -> Vec<u8> {
    let utf16: Vec<u16> = ev.file_path.encode_utf16().collect();
    let path_byte_len = u16::try_from(utf16.len() * 2).unwrap_or(u16::MAX - 1);
    let max_units = usize::from(path_byte_len) / 2;
    let mut out = Vec::with_capacity(56 + usize::from(path_byte_len));
    out.extend_from_slice(&ev.event_id.to_le_bytes());
    out.extend_from_slice(&ev.pid.to_le_bytes());
    out.extend_from_slice(&ev.tid.to_le_bytes());
    out.extend_from_slice(&filetime_100ns.to_le_bytes());
    out.extend_from_slice(&ev.irp_ptr.to_le_bytes());
    out.extend_from_slice(&ev.file_object.to_le_bytes());
    out.extend_from_slice(&ev.file_key.to_le_bytes());
    out.extend_from_slice(&ev.io_size.to_le_bytes());
    out.extend_from_slice(&ev.nt_status.to_le_bytes());
    out.extend_from_slice(&ev.io_flags.to_le_bytes());
    out.extend_from_slice(&path_byte_len.to_le_bytes());
    for unit in utf16.into_iter().take(max_units) {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Parse a single packed wire record starting at `bytes[0..]` and return `(event, bytes_consumed)`.
pub fn parse_kernel_file_wire_record(bytes: &[u8]) -> Result<(KernelFileRawEvent, usize), FsError> {
    if bytes.len() < 56 {
        return Err(FsError::Parse(format!(
            "KernelFile wire record too short: {} bytes (need >= 56)",
            bytes.len()
        )));
    }
    let event_id = read_u16_le(bytes, 0)?;
    let pid = read_u32_le(bytes, 2)?;
    let tid = read_u32_le(bytes, 6)?;
    let filetime = read_u64_le(bytes, 10)?;
    let irp_ptr = read_u64_le(bytes, 18)?;
    let file_object = read_u64_le(bytes, 26)?;
    let file_key = read_u64_le(bytes, 34)?;
    let io_size = read_u32_le(bytes, 42)?;
    let nt_status = read_u32_le(bytes, 46)?;
    let io_flags = read_u32_le(bytes, 50)?;
    let path_byte_len = usize::from(read_u16_le(bytes, 54)?);
    if !path_byte_len.is_multiple_of(2) {
        return Err(FsError::Parse(format!(
            "KernelFile wire record path_byte_len ({path_byte_len}) is not even"
        )));
    }
    let total = 56usize
        .checked_add(path_byte_len)
        .ok_or_else(|| FsError::Parse("KernelFile wire record size overflow".to_string()))?;
    if total > bytes.len() {
        return Err(FsError::Parse(format!(
            "KernelFile wire record truncated: need {total} bytes, got {}",
            bytes.len()
        )));
    }
    let file_path = decode_utf16le(&bytes[56..total]).trim_end_matches('\0').to_string();
    let timestamp = windows_filetime_to_datetime(filetime).unwrap_or(DateTime::UNIX_EPOCH);

    Ok((
        KernelFileRawEvent {
            event_id,
            pid,
            tid,
            timestamp,
            irp_ptr,
            file_object,
            file_key,
            io_size,
            nt_status,
            io_flags,
            file_path,
            process_name: String::new(),
        },
        total,
    ))
}

/// Parse an offline binary stream (optional `FS2FILE1` + `u32 count` header, or packed sequence of wire records).
pub fn parse_kernel_file_wire_stream(bytes: &[u8]) -> Result<Vec<KernelFileRawEvent>, FsError> {
    let mut offset = 0usize;
    let mut expected_count: Option<usize> = None;
    if bytes.starts_with(KERNEL_FILE_MAGIC) {
        if bytes.len() < 12 {
            return Err(FsError::Parse("truncated FS2FILE1 stream header".to_string()));
        }
        expected_count = Some(read_u32_le(bytes, 8)? as usize);
        offset = 12;
    }

    let mut events = Vec::new();
    while offset < bytes.len() {
        if let Some(limit) = expected_count
            && events.len() >= limit
        {
            break;
        }
        let (ev, consumed) = parse_kernel_file_wire_record(&bytes[offset..])?;
        if consumed == 0 {
            return Err(FsError::Parse("zero-byte KernelFile record".to_string()));
        }
        events.push(ev);
        offset += consumed;
    }
    if let Some(limit) = expected_count
        && events.len() != limit
    {
        return Err(FsError::Parse(format!(
            "FS2FILE1 header declared {limit} records, parsed {}",
            events.len()
        )));
    }
    Ok(events)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileActivityEntry {
    pub file_path: String,
    pub process_name: String,
    pub pid: u32,
    pub operation: String,
    pub open_count: u64,
    pub close_count: u64,
    pub read_count: u64,
    pub write_count: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub last_timestamp: DateTime<Utc>,
    pub last_status: String,
}

#[derive(Debug, Clone)]
struct PendingIrpOp {
    operation: &'static str,
    file_path: String,
    file_key: u64,
    file_object: u64,
    pid: u32,
}

fn resolve_path_and_update_cache(
    ev: &KernelFileRawEvent,
    key_paths: &mut HashMap<(u32, u64), String>,
    obj_paths: &mut HashMap<(u32, u64), String>,
    global_key_paths: &mut HashMap<u64, String>,
    global_obj_paths: &mut HashMap<u64, String>,
) -> String {
    if !ev.file_path.is_empty() {
        if ev.file_key != 0 {
            key_paths.insert((ev.pid, ev.file_key), ev.file_path.clone());
            global_key_paths.insert(ev.file_key, ev.file_path.clone());
        }
        if ev.file_object != 0 {
            obj_paths.insert((ev.pid, ev.file_object), ev.file_path.clone());
            global_obj_paths.insert(ev.file_object, ev.file_path.clone());
        }
        return ev.file_path.clone();
    }

    if ev.file_key != 0
        && let Some(p) = key_paths
            .get(&(ev.pid, ev.file_key))
            .or_else(|| global_key_paths.get(&ev.file_key))
    {
        return p.clone();
    }
    if ev.file_object != 0
        && let Some(p) = obj_paths
            .get(&(ev.pid, ev.file_object))
            .or_else(|| global_obj_paths.get(&ev.file_object))
    {
        return p.clone();
    }
    String::new()
}

pub fn correlate_file_activity(
    events: &[KernelFileRawEvent],
    pid_names: &HashMap<u32, String>,
) -> Vec<FileActivityEntry> {
    let mut key_paths: HashMap<(u32, u64), String> = HashMap::new();
    let mut obj_paths: HashMap<(u32, u64), String> = HashMap::new();
    let mut global_key_paths: HashMap<u64, String> = HashMap::new();
    let mut global_obj_paths: HashMap<u64, String> = HashMap::new();
    let mut pending_irps: HashMap<u64, PendingIrpOp> = HashMap::new();
    let mut agg: BTreeMap<(u32, String), FileActivityEntry> = BTreeMap::new();

    for ev in events {
        let mut resolved_path = resolve_path_and_update_cache(
            ev,
            &mut key_paths,
            &mut obj_paths,
            &mut global_key_paths,
            &mut global_obj_paths,
        );
        let mut op_name = kernel_file_operation_name(ev.event_id);

        if ev.event_id == 24 {
            if let Some(pending) = pending_irps.remove(&ev.irp_ptr) {
                if resolved_path.is_empty() {
                    if !pending.file_path.is_empty() {
                        resolved_path = pending.file_path;
                    } else if pending.file_key != 0 {
                        resolved_path = key_paths
                            .get(&(pending.pid, pending.file_key))
                            .or_else(|| global_key_paths.get(&pending.file_key))
                            .cloned()
                            .unwrap_or_default();
                    } else if pending.file_object != 0 {
                        resolved_path = obj_paths
                            .get(&(pending.pid, pending.file_object))
                            .or_else(|| global_obj_paths.get(&pending.file_object))
                            .cloned()
                            .unwrap_or_default();
                    }
                }
                op_name = pending.operation;
            }
        } else if ev.irp_ptr != 0 {
            pending_irps.insert(
                ev.irp_ptr,
                PendingIrpOp {
                    operation: op_name,
                    file_path: resolved_path.clone(),
                    file_key: ev.file_key,
                    file_object: ev.file_object,
                    pid: ev.pid,
                },
            );
        }

        if resolved_path.is_empty() {
            if ev.file_key != 0 {
                resolved_path = format!("<FileKey:0x{:X}>", ev.file_key);
            } else if ev.file_object != 0 {
                resolved_path = format!("<FileObj:0x{:X}>", ev.file_object);
            } else {
                continue;
            }
        }

        let proc_name = if !ev.process_name.is_empty() {
            ev.process_name.clone()
        } else {
            pid_names
                .get(&ev.pid)
                .cloned()
                .unwrap_or_else(|| format!("pid:{}", ev.pid))
        };

        let entry = agg
            .entry((ev.pid, resolved_path.clone()))
            .or_insert_with(|| FileActivityEntry {
                file_path: resolved_path,
                process_name: proc_name,
                pid: ev.pid,
                operation: op_name.to_string(),
                open_count: 0,
                close_count: 0,
                read_count: 0,
                write_count: 0,
                read_bytes: 0,
                write_bytes: 0,
                last_timestamp: ev.timestamp,
                last_status: decode_ntstatus(ev.nt_status).name.to_string(),
            });

        if ev.timestamp >= entry.last_timestamp {
            entry.last_timestamp = ev.timestamp;
            entry.operation = op_name.to_string();
            entry.last_status = decode_ntstatus(ev.nt_status).name.to_string();
        }
        match ev.event_id {
            12 | 30 => entry.open_count += 1,
            13 | 14 => entry.close_count += 1,
            15 => {
                entry.read_count += 1;
                entry.read_bytes = entry.read_bytes.saturating_add(u64::from(ev.io_size));
            }
            16 => {
                entry.write_count += 1;
                entry.write_bytes = entry.write_bytes.saturating_add(u64::from(ev.io_size));
            }
            _ => {}
        }
    }

    agg.into_values().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAccessErrorEntry {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub tid: u32,
    pub process_name: String,
    pub operation: String,
    pub file_path: String,
    pub nt_status_code: u32,
    pub nt_status_hex: String,
    pub nt_status_name: String,
    pub description: String,
    pub call_count: u64,
}

pub fn correlate_file_access_errors(
    events: &[KernelFileRawEvent],
    pid_names: &HashMap<u32, String>,
    include_informational: bool,
) -> Vec<FileAccessErrorEntry> {
    let mut key_paths: HashMap<(u32, u64), String> = HashMap::new();
    let mut obj_paths: HashMap<(u32, u64), String> = HashMap::new();
    let mut global_key_paths: HashMap<u64, String> = HashMap::new();
    let mut global_obj_paths: HashMap<u64, String> = HashMap::new();
    let mut pending_irps: HashMap<u64, PendingIrpOp> = HashMap::new();
    let mut agg: BTreeMap<(u32, String, String, u32), FileAccessErrorEntry> = BTreeMap::new();

    for ev in events {
        let mut resolved_path = resolve_path_and_update_cache(
            ev,
            &mut key_paths,
            &mut obj_paths,
            &mut global_key_paths,
            &mut global_obj_paths,
        );
        let mut op_name = kernel_file_operation_name(ev.event_id);
        let mut effective_pid = ev.pid;

        if ev.event_id == 24 {
            if let Some(pending) = pending_irps.remove(&ev.irp_ptr) {
                op_name = pending.operation;
                if effective_pid == 0 {
                    effective_pid = pending.pid;
                }
                if resolved_path.is_empty() {
                    if !pending.file_path.is_empty() {
                        resolved_path = pending.file_path;
                    } else if pending.file_key != 0 {
                        resolved_path = key_paths
                            .get(&(pending.pid, pending.file_key))
                            .or_else(|| global_key_paths.get(&pending.file_key))
                            .cloned()
                            .unwrap_or_default();
                    } else if pending.file_object != 0 {
                        resolved_path = obj_paths
                            .get(&(pending.pid, pending.file_object))
                            .or_else(|| global_obj_paths.get(&pending.file_object))
                            .cloned()
                            .unwrap_or_default();
                    }
                }
            }
        } else if ev.irp_ptr != 0 {
            pending_irps.insert(
                ev.irp_ptr,
                PendingIrpOp {
                    operation: op_name,
                    file_path: resolved_path.clone(),
                    file_key: ev.file_key,
                    file_object: ev.file_object,
                    pid: ev.pid,
                },
            );
        }

        let status_info: NtStatusInfo = decode_ntstatus(ev.nt_status);
        if status_info.is_success() || ev.nt_status == 0x0000_0103 {
            continue;
        }
        if !include_informational && status_info.is_informational() {
            continue;
        }

        if resolved_path.is_empty() {
            resolved_path = if ev.file_key != 0 {
                format!("<FileKey:0x{:X}>", ev.file_key)
            } else if ev.file_object != 0 {
                format!("<FileObj:0x{:X}>", ev.file_object)
            } else {
                "<UnknownPath>".to_string()
            };
        }

        let proc_name = if !ev.process_name.is_empty() {
            ev.process_name.clone()
        } else {
            pid_names
                .get(&effective_pid)
                .cloned()
                .unwrap_or_else(|| format!("pid:{effective_pid}"))
        };

        let key = (effective_pid, op_name.to_string(), resolved_path.clone(), ev.nt_status);
        let entry = agg.entry(key).or_insert_with(|| FileAccessErrorEntry {
            timestamp: ev.timestamp,
            pid: effective_pid,
            tid: ev.tid,
            process_name: proc_name,
            operation: op_name.to_string(),
            file_path: resolved_path,
            nt_status_code: ev.nt_status,
            nt_status_hex: status_info.hex.clone(),
            nt_status_name: status_info.name.to_string(),
            description: status_info.description.to_string(),
            call_count: 0,
        });
        entry.call_count += 1;
        if ev.timestamp > entry.timestamp {
            entry.timestamp = ev.timestamp;
        }
    }

    agg.into_values().collect()
}

#[derive(Debug, Clone)]
pub struct FileActivityConfig {
    pub duration_ms: u64,
    pub max_events: usize,
    pub pid_filter: Option<u32>,
    pub path_filter: Option<String>,
    pub offline_events: Option<Vec<KernelFileRawEvent>>,
}

impl Default for FileActivityConfig {
    fn default() -> Self {
        Self {
            duration_ms: 500,
            max_events: 4096,
            pid_filter: None,
            path_filter: None,
            offline_events: None,
        }
    }
}

pub fn file_activity_schema() -> TableSchema {
    TableSchema::new(
        "file_activity_watch",
        "ETW Kernel-File I/O Activity Monitor",
        vec![
            ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(300),
            ColumnDef::new("process_name", "Process Name", ColumnType::Text).with_width_hint(140),
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("operation", "Last Operation", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("open_count", "Open Count", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("close_count", "Close Count", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("read_count", "Read Count", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("write_count", "Write Count", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("read_bytes", "Read Bytes", ColumnType::BytesSize).with_width_hint(110),
            ColumnDef::new("write_bytes", "Write Bytes", ColumnType::BytesSize).with_width_hint(110),
            ColumnDef::new("last_timestamp", "Last Event", ColumnType::Timestamp).with_width_hint(180),
        ],
    )
    .with_default_sort(10, SortDirection::Desc)
}

pub struct FileActivityWatchProvider {
    config: FileActivityConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl FileActivityWatchProvider {
    pub fn new(config: FileActivityConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for FileActivityWatchProvider {
    fn tool_id(&self) -> &'static str {
        "file_activity_watch"
    }

    fn description(&self) -> &'static str {
        "Monitor real-time file system read/write/open/close activity via Microsoft-Windows-Kernel-File ETW"
    }

    fn schema(&self) -> TableSchema {
        file_activity_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let events = if let Some(offline) = &self.config.offline_events {
            offline.clone()
        } else {
            self.backend
                .capture_kernel_file_events(self.config.duration_ms.clamp(50, 30_000), self.config.max_events, false)
                .map_err(TableError::from)?
        };
        let pid_names = self.backend.list_process_names().unwrap_or_default();
        let mut entries = correlate_file_activity(&events, &pid_names);
        if let Some(pid) = self.config.pid_filter {
            entries.retain(|e| e.pid == pid);
        }
        if let Some(pat) = &self.config.path_filter {
            let pat_lower = pat.to_ascii_lowercase();
            entries.retain(|e| e.file_path.to_ascii_lowercase().contains(&pat_lower));
        }
        let rows: Vec<Row> = entries
            .iter()
            .enumerate()
            .map(|(idx, e)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(e.file_path.clone()),
                        CellValue::Text(e.process_name.clone()),
                        CellValue::Uint(u64::from(e.pid)),
                        CellValue::Text(e.operation.clone()),
                        CellValue::Uint(e.open_count),
                        CellValue::Uint(e.close_count),
                        CellValue::Uint(e.read_count),
                        CellValue::Uint(e.write_count),
                        CellValue::Bytes(e.read_bytes),
                        CellValue::Bytes(e.write_bytes),
                        CellValue::Timestamp(e.last_timestamp),
                    ],
                )
                .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

#[derive(Debug, Clone)]
pub struct FileAccessErrorConfig {
    pub duration_ms: u64,
    pub max_events: usize,
    pub include_informational: bool,
    pub pid_filter: Option<u32>,
    pub offline_events: Option<Vec<KernelFileRawEvent>>,
}

impl Default for FileAccessErrorConfig {
    fn default() -> Self {
        Self {
            duration_ms: 500,
            max_events: 4096,
            include_informational: false,
            pid_filter: None,
            offline_events: None,
        }
    }
}

pub fn file_access_error_schema() -> TableSchema {
    TableSchema::new(
        "file_access_error_view",
        "ETW Kernel-File Failed File Operations (NTSTATUS)",
        vec![
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("tid", "TID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "Process Name", ColumnType::Text).with_width_hint(140),
            ColumnDef::new("operation", "Operation", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(280),
            ColumnDef::new("nt_status_hex", "NTSTATUS", ColumnType::Text).with_width_hint(105),
            ColumnDef::new("nt_status_name", "Status Name", ColumnType::Text).with_width_hint(200),
            ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("call_count", "Call Count", ColumnType::Uint).with_width_hint(85),
        ],
    )
    .with_default_sort(0, SortDirection::Desc)
}

pub struct FileAccessErrorViewProvider {
    config: FileAccessErrorConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl FileAccessErrorViewProvider {
    pub fn new(config: FileAccessErrorConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for FileAccessErrorViewProvider {
    fn tool_id(&self) -> &'static str {
        "file_access_error_view"
    }

    fn description(&self) -> &'static str {
        "Detect failed file open/read/write/delete operations via ETW Kernel-File OperationEnd non-zero NTSTATUS codes"
    }

    fn schema(&self) -> TableSchema {
        file_access_error_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let events = if let Some(offline) = &self.config.offline_events {
            offline.clone()
        } else {
            self.backend
                .capture_kernel_file_events(self.config.duration_ms.clamp(50, 30_000), self.config.max_events, true)
                .map_err(TableError::from)?
        };
        let pid_names = self.backend.list_process_names().unwrap_or_default();
        let mut entries = correlate_file_access_errors(&events, &pid_names, self.config.include_informational);
        if let Some(pid) = self.config.pid_filter {
            entries.retain(|e| e.pid == pid);
        }
        let rows: Vec<Row> = entries
            .iter()
            .enumerate()
            .map(|(idx, e)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Timestamp(e.timestamp),
                        CellValue::Uint(u64::from(e.pid)),
                        CellValue::Uint(u64::from(e.tid)),
                        CellValue::Text(e.process_name.clone()),
                        CellValue::Text(e.operation.clone()),
                        CellValue::Text(e.file_path.clone()),
                        CellValue::Text(e.nt_status_hex.clone()),
                        CellValue::Text(e.nt_status_name.clone()),
                        CellValue::Text(e.description.clone()),
                        CellValue::Uint(e.call_count),
                    ],
                )
                .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
