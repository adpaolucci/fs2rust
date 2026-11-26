#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::read_u64_le;
use fs2rust_core::FsError;
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Pure-Rust representation of Win32 `IO_COUNTERS` (48 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IoCounters {
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

/// Parse a 48-byte Win32 `IO_COUNTERS` structure.
pub fn parse_io_counters(bytes: &[u8]) -> Result<IoCounters, FsError> {
    if bytes.len() < 48 {
        return Err(FsError::Parse(format!(
            "IO_COUNTERS buffer too short: {} bytes (need >= 48)",
            bytes.len()
        )));
    }
    Ok(IoCounters {
        read_operation_count: read_u64_le(bytes, 0)?,
        write_operation_count: read_u64_le(bytes, 8)?,
        other_operation_count: read_u64_le(bytes, 16)?,
        read_transfer_count: read_u64_le(bytes, 24)?,
        write_transfer_count: read_u64_le(bytes, 32)?,
        other_transfer_count: read_u64_le(bytes, 40)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIoSnapshot {
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub counters: IoCounters,
    pub access_denied: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessIoRateEntry {
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub read_ops: u64,
    pub write_ops: u64,
    pub other_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
    pub read_rate_bps: f64,
    pub write_rate_bps: f64,
    pub etw_read_bytes: u64,
    pub etw_write_bytes: u64,
    pub access_denied: bool,
}

/// Compute per-process I/O counters and transfer rates between two snapshots `t0` and `t1`.
/// When `t0` is `None` or `elapsed_ms == 0`, rates default to `0.0`.
pub fn compute_io_rates(
    t0: Option<&[ProcessIoSnapshot]>,
    t1: &[ProcessIoSnapshot],
    elapsed_ms: u64,
    etw_pid_bytes: Option<&HashMap<u32, (u64, u64)>>,
) -> Vec<ProcessIoRateEntry> {
    let prev_map: HashMap<u32, &ProcessIoSnapshot> = t0
        .map(|slice| slice.iter().map(|s| (s.pid, s)).collect())
        .unwrap_or_default();
    let elapsed_sec = if elapsed_ms > 0 {
        elapsed_ms as f64 / 1000.0
    } else {
        0.0
    };

    t1.iter()
        .map(|cur| {
            let (read_rate_bps, write_rate_bps) = if elapsed_sec > 0.0
                && let Some(prev) = prev_map.get(&cur.pid)
                && !cur.access_denied
                && !prev.access_denied
            {
                let d_read = cur
                    .counters
                    .read_transfer_count
                    .saturating_sub(prev.counters.read_transfer_count);
                let d_write = cur
                    .counters
                    .write_transfer_count
                    .saturating_sub(prev.counters.write_transfer_count);
                (d_read as f64 / elapsed_sec, d_write as f64 / elapsed_sec)
            } else {
                (0.0, 0.0)
            };

            let (etw_read_bytes, etw_write_bytes) =
                etw_pid_bytes.and_then(|m| m.get(&cur.pid)).copied().unwrap_or((0, 0));

            ProcessIoRateEntry {
                pid: cur.pid,
                process_name: cur.process_name.clone(),
                process_path: cur.process_path.clone(),
                read_ops: cur.counters.read_operation_count,
                write_ops: cur.counters.write_operation_count,
                other_ops: cur.counters.other_operation_count,
                read_bytes: cur.counters.read_transfer_count,
                write_bytes: cur.counters.write_transfer_count,
                other_bytes: cur.counters.other_transfer_count,
                read_rate_bps,
                write_rate_bps,
                etw_read_bytes,
                etw_write_bytes,
                access_denied: cur.access_denied,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct AppReadWriteConfig {
    pub sample_interval_ms: u64,
    pub pid_filter: Option<u32>,
    pub enable_etw: bool,
    pub offline_t0: Option<Vec<ProcessIoSnapshot>>,
    pub offline_t1: Option<Vec<ProcessIoSnapshot>>,
}

pub fn app_read_write_schema() -> TableSchema {
    TableSchema::new(
        "app_read_write_counter",
        "AppReadWriteCounter - Per-Process Read/Write I/O Counters & Rates",
        vec![
            ColumnDef::new("pid", "PID", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("process_name", "Process Name", ColumnType::Text).with_width_hint(160),
            ColumnDef::new("process_path", "Process Path", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("read_ops", "Read Ops", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("write_ops", "Write Ops", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("other_ops", "Other Ops", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("read_bytes", "Read Bytes", ColumnType::BytesSize).with_width_hint(115),
            ColumnDef::new("write_bytes", "Write Bytes", ColumnType::BytesSize).with_width_hint(115),
            ColumnDef::new("other_bytes", "Other Bytes", ColumnType::BytesSize).with_width_hint(115),
            ColumnDef::new("read_rate_bps", "Read B/s", ColumnType::Float).with_width_hint(105),
            ColumnDef::new("write_rate_bps", "Write B/s", ColumnType::Float).with_width_hint(105),
        ],
    )
    .with_default_sort(6, SortDirection::Desc)
}

pub struct AppReadWriteCounterProvider {
    config: AppReadWriteConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl AppReadWriteCounterProvider {
    pub fn new(config: AppReadWriteConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for AppReadWriteCounterProvider {
    fn tool_id(&self) -> &'static str {
        "app_read_write_counter"
    }

    fn description(&self) -> &'static str {
        "Count per-application read/write operations and byte transfer rates using GetProcessIoCounters"
    }

    fn schema(&self) -> TableSchema {
        app_read_write_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut entries = if let Some(t1) = &self.config.offline_t1 {
            compute_io_rates(
                self.config.offline_t0.as_deref(),
                t1,
                self.config.sample_interval_ms,
                None,
            )
        } else {
            let t0 = if self.config.sample_interval_ms > 0 {
                let snap0 = self.backend.snapshot_process_io().map_err(TableError::from)?;
                let wait = self.config.sample_interval_ms.clamp(10, 10_000);
                std::thread::sleep(std::time::Duration::from_millis(wait));
                Some(snap0)
            } else {
                None
            };
            let t1 = self.backend.snapshot_process_io().map_err(TableError::from)?;
            let etw_map = if self.config.enable_etw {
                self.backend
                    .capture_kernel_file_events(self.config.sample_interval_ms.clamp(100, 5_000), 4096, false)
                    .ok()
                    .map(|evs| {
                        let mut m: HashMap<u32, (u64, u64)> = HashMap::new();
                        for ev in evs {
                            let entry = m.entry(ev.pid).or_insert((0, 0));
                            if ev.event_id == 15 {
                                entry.0 = entry.0.saturating_add(u64::from(ev.io_size));
                            } else if ev.event_id == 16 {
                                entry.1 = entry.1.saturating_add(u64::from(ev.io_size));
                            }
                        }
                        m
                    })
            } else {
                None
            };
            compute_io_rates(t0.as_deref(), &t1, self.config.sample_interval_ms, etw_map.as_ref())
        };

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
                        CellValue::Uint(u64::from(e.pid)),
                        CellValue::Text(e.process_name.clone()),
                        CellValue::Text(e.process_path.clone()),
                        CellValue::Uint(e.read_ops),
                        CellValue::Uint(e.write_ops),
                        CellValue::Uint(e.other_ops),
                        CellValue::Bytes(e.read_bytes),
                        CellValue::Bytes(e.write_bytes),
                        CellValue::Bytes(e.other_bytes),
                        CellValue::Float(e.read_rate_bps),
                        CellValue::Float(e.write_rate_bps),
                    ],
                )
                .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
