#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{decode_utf16le, read_i64_le, read_u32_le};
use fs2rust_core::FsError;
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskPerformanceRecord {
    pub device: String,
    pub storage_device_number: u32,
    pub storage_manager: String,
    pub read_count: u32,
    pub write_count: u32,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_time_ms: u64,
    pub write_time_ms: u64,
    pub idle_time_ms: u64,
    pub queue_depth: u32,
    pub split_count: u32,
    pub query_time_100ns: i64,
}

/// Parse a Windows `DISK_PERFORMANCE` structure (84 bytes payload, 88 bytes with trailing alignment).
pub fn parse_disk_performance(device: &str, bytes: &[u8]) -> Result<DiskPerformanceRecord, FsError> {
    if bytes.len() < 84 {
        return Err(FsError::Parse(format!(
            "DISK_PERFORMANCE buffer too short for '{device}': got {} bytes, need at least 84",
            bytes.len()
        )));
    }
    let bytes_read_raw = read_i64_le(bytes, 0)?;
    let bytes_written_raw = read_i64_le(bytes, 8)?;
    let read_time_100ns = read_i64_le(bytes, 16)?;
    let write_time_100ns = read_i64_le(bytes, 24)?;
    let idle_time_100ns = read_i64_le(bytes, 32)?;
    let read_count = read_u32_le(bytes, 40)?;
    let write_count = read_u32_le(bytes, 44)?;
    let queue_depth = read_u32_le(bytes, 48)?;
    let split_count = read_u32_le(bytes, 52)?;
    let query_time_100ns = read_i64_le(bytes, 56)?;
    let storage_device_number = read_u32_le(bytes, 64)?;
    let storage_manager = decode_utf16le(&bytes[68..84]).trim_end_matches(['\0', ' ']).to_string();

    Ok(DiskPerformanceRecord {
        device: device.to_string(),
        storage_device_number,
        storage_manager,
        read_count,
        write_count,
        bytes_read: u64::try_from(bytes_read_raw).unwrap_or(0),
        bytes_written: u64::try_from(bytes_written_raw).unwrap_or(0),
        read_time_ms: u64::try_from(read_time_100ns).unwrap_or(0) / 10_000,
        write_time_ms: u64::try_from(write_time_100ns).unwrap_or(0) / 10_000,
        idle_time_ms: u64::try_from(idle_time_100ns).unwrap_or(0) / 10_000,
        queue_depth,
        split_count,
        query_time_100ns,
    })
}

#[derive(Debug, Clone, Default)]
pub struct DiskCountersConfig {
    pub device_paths: Vec<String>,
    pub offline_records: Option<Vec<DiskPerformanceRecord>>,
}

pub fn disk_counters_schema() -> TableSchema {
    TableSchema::new(
        "disk_counters_view",
        "DiskCountersView - Physical & Logical Disk Performance Counters",
        vec![
            ColumnDef::new("device", "Device", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("storage_device_number", "Disk #", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("storage_manager", "Storage Manager", ColumnType::Text).with_width_hint(130),
            ColumnDef::new("read_count", "Read Count", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("write_count", "Write Count", ColumnType::Uint).with_width_hint(100),
            ColumnDef::new("bytes_read", "Bytes Read", ColumnType::BytesSize).with_width_hint(115),
            ColumnDef::new("bytes_written", "Bytes Written", ColumnType::BytesSize).with_width_hint(115),
            ColumnDef::new("read_time_ms", "Read Time", ColumnType::Duration).with_width_hint(100),
            ColumnDef::new("write_time_ms", "Write Time", ColumnType::Duration).with_width_hint(100),
            ColumnDef::new("idle_time_ms", "Idle Time", ColumnType::Duration).with_width_hint(100),
            ColumnDef::new("queue_depth", "Queue Depth", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("split_count", "Split Count", ColumnType::Uint).with_width_hint(95),
        ],
    )
    .with_default_sort(1, SortDirection::Asc)
}

pub fn records_to_rows(records: &[DiskPerformanceRecord]) -> Vec<Row> {
    records
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            Row::new(
                idx as u64 + 1,
                vec![
                    CellValue::Text(r.device.clone()),
                    CellValue::Uint(u64::from(r.storage_device_number)),
                    CellValue::Text(r.storage_manager.clone()),
                    CellValue::Uint(u64::from(r.read_count)),
                    CellValue::Uint(u64::from(r.write_count)),
                    CellValue::Bytes(r.bytes_read),
                    CellValue::Bytes(r.bytes_written),
                    CellValue::Uint(r.read_time_ms),
                    CellValue::Uint(r.write_time_ms),
                    CellValue::Uint(r.idle_time_ms),
                    CellValue::Uint(u64::from(r.queue_depth)),
                    CellValue::Uint(u64::from(r.split_count)),
                ],
            )
            .with_detail_json(serde_json::to_value(r).unwrap_or(Value::Null))
        })
        .collect()
}

pub struct DiskCountersProvider {
    config: DiskCountersConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl DiskCountersProvider {
    pub fn new(config: DiskCountersConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for DiskCountersProvider {
    fn tool_id(&self) -> &'static str {
        "disk_counters_view"
    }

    fn description(&self) -> &'static str {
        "Query Windows physical/logical disk read/write counters and queue depth via IOCTL_DISK_PERFORMANCE"
    }

    fn schema(&self) -> TableSchema {
        disk_counters_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let records = if let Some(offline) = &self.config.offline_records {
            offline.clone()
        } else {
            self.backend
                .query_disk_counters(&self.config.device_paths)
                .map_err(TableError::from)?
        };
        let rows = records_to_rows(&records);
        apply_query(&self.schema(), &rows, req)
    }
}
