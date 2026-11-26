#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{
    decode_utf16le, normalize_volume_device_path, read_i64_le, read_u16_le, read_u32_le, read_u64_le, read_u128_le,
};
use chrono::{DateTime, Utc};
use fs2rust_core::{FileAttributes, FsError, windows_filetime_to_datetime};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub fn decode_usn_reasons(mask: u32) -> String {
    const FLAGS: &[(u32, &str)] = &[
        (0x0000_0001, "DATA_OVERWRITE"),
        (0x0000_0002, "DATA_EXTEND"),
        (0x0000_0004, "DATA_TRUNCATION"),
        (0x0000_0010, "NAMED_DATA_OVERWRITE"),
        (0x0000_0020, "NAMED_DATA_EXTEND"),
        (0x0000_0040, "NAMED_DATA_TRUNCATION"),
        (0x0000_0100, "FILE_CREATE"),
        (0x0000_0200, "FILE_DELETE"),
        (0x0000_0400, "EA_CHANGE"),
        (0x0000_0800, "SECURITY_CHANGE"),
        (0x0000_1000, "RENAME_OLD_NAME"),
        (0x0000_2000, "RENAME_NEW_NAME"),
        (0x0000_4000, "INDEXABLE_CHANGE"),
        (0x0000_8000, "BASIC_INFO_CHANGE"),
        (0x0001_0000, "HARD_LINK_CHANGE"),
        (0x0002_0000, "COMPRESSION_CHANGE"),
        (0x0004_0000, "ENCRYPTION_CHANGE"),
        (0x0008_0000, "OBJECT_ID_CHANGE"),
        (0x0010_0000, "REPARSE_POINT_CHANGE"),
        (0x0020_0000, "STREAM_CHANGE"),
        (0x0040_0000, "TRANSACTED_CHANGE"),
        (0x0080_0000, "INTEGRITY_CHANGE"),
        (0x8000_0000, "CLOSE"),
    ];
    let parts: Vec<&str> = FLAGS
        .iter()
        .filter_map(|(bit, name)| if (mask & *bit) != 0 { Some(*name) } else { None })
        .collect();
    if parts.is_empty() {
        format!("0x{mask:08X}")
    } else {
        parts.join("|")
    }
}

pub fn decode_usn_source_info(mask: u32) -> String {
    let mut parts = Vec::new();
    if (mask & 0x01) != 0 {
        parts.push("DATA_MANAGEMENT");
    }
    if (mask & 0x02) != 0 {
        parts.push("AUXILIARY_DATA");
    }
    if (mask & 0x04) != 0 {
        parts.push("REPLICATION_MANAGEMENT");
    }
    if (mask & 0x08) != 0 {
        parts.push("CLIENT_REPLICATION_MANAGEMENT");
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join("|")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsnRecord {
    pub usn: i64,
    pub timestamp: DateTime<Utc>,
    pub file_name: String,
    pub reason: u32,
    pub reason_flags: String,
    pub mft_entry: u64,
    pub parent_mft_entry: u64,
    pub file_id_hex: String,
    pub parent_file_id_hex: String,
    pub file_attributes: u32,
    pub attributes_text: String,
    pub major_version: u16,
    pub minor_version: u16,
    pub source_info: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsnJournalInfo {
    pub usn_journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub lowest_valid_usn: i64,
    pub max_usn: i64,
    pub maximum_size: u64,
    pub allocation_delta: u64,
}

fn parse_single_usn_record(rec: &[u8]) -> Result<Option<UsnRecord>, FsError> {
    let rec_len = rec.len();
    if rec_len < 8 {
        return Err(FsError::Parse(format!("USN record length {rec_len} < 8")));
    }
    let major = read_u16_le(rec, 4)?;
    let minor = read_u16_le(rec, 6)?;

    match major {
        2 => {
            if rec_len < 60 {
                return Err(FsError::Parse(format!("USN_RECORD_V2 length {rec_len} < 60 bytes")));
            }
            let frn = read_u64_le(rec, 8)?;
            let parent_frn = read_u64_le(rec, 16)?;
            let usn = read_i64_le(rec, 24)?;
            let ts_raw = read_i64_le(rec, 32)?;
            let reason = read_u32_le(rec, 40)?;
            let source_raw = read_u32_le(rec, 44)?;
            let _sec_id = read_u32_le(rec, 48)?;
            let attrs = read_u32_le(rec, 52)?;
            let fn_len = usize::from(read_u16_le(rec, 56)?);
            let fn_off = usize::from(read_u16_le(rec, 58)?);

            if fn_off < 60 {
                return Err(FsError::Parse(format!("USN_RECORD_V2 FileNameOffset {fn_off} < 60")));
            }
            let fn_end = fn_off
                .checked_add(fn_len)
                .filter(|&e| e <= rec_len)
                .ok_or_else(|| FsError::Parse("USN_RECORD_V2 FileName out of bounds".to_string()))?;

            let file_name = decode_utf16le(&rec[fn_off..fn_end]);
            let timestamp = u64::try_from(ts_raw)
                .ok()
                .and_then(windows_filetime_to_datetime)
                .unwrap_or(DateTime::UNIX_EPOCH);

            Ok(Some(UsnRecord {
                usn,
                timestamp,
                file_name,
                reason,
                reason_flags: decode_usn_reasons(reason),
                mft_entry: frn & 0x0000_FFFF_FFFF_FFFF,
                parent_mft_entry: parent_frn & 0x0000_FFFF_FFFF_FFFF,
                file_id_hex: format!("0x{frn:016X}"),
                parent_file_id_hex: format!("0x{parent_frn:016X}"),
                file_attributes: attrs,
                attributes_text: FileAttributes::from_raw(attrs).format_flags(),
                major_version: major,
                minor_version: minor,
                source_info: decode_usn_source_info(source_raw),
            }))
        }
        3 => {
            if rec_len < 76 {
                return Err(FsError::Parse(format!("USN_RECORD_V3 length {rec_len} < 76 bytes")));
            }
            let frn = read_u128_le(rec, 8)?;
            let parent_frn = read_u128_le(rec, 24)?;
            let usn = read_i64_le(rec, 40)?;
            let ts_raw = read_i64_le(rec, 48)?;
            let reason = read_u32_le(rec, 56)?;
            let source_raw = read_u32_le(rec, 60)?;
            let _sec_id = read_u32_le(rec, 64)?;
            let attrs = read_u32_le(rec, 68)?;
            let fn_len = usize::from(read_u16_le(rec, 72)?);
            let fn_off = usize::from(read_u16_le(rec, 74)?);

            if fn_off < 76 {
                return Err(FsError::Parse(format!("USN_RECORD_V3 FileNameOffset {fn_off} < 76")));
            }
            let fn_end = fn_off
                .checked_add(fn_len)
                .filter(|&e| e <= rec_len)
                .ok_or_else(|| FsError::Parse("USN_RECORD_V3 FileName out of bounds".to_string()))?;

            let file_name = decode_utf16le(&rec[fn_off..fn_end]);
            let timestamp = u64::try_from(ts_raw)
                .ok()
                .and_then(windows_filetime_to_datetime)
                .unwrap_or(DateTime::UNIX_EPOCH);

            Ok(Some(UsnRecord {
                usn,
                timestamp,
                file_name,
                reason,
                reason_flags: decode_usn_reasons(reason),
                mft_entry: (frn as u64) & 0x0000_FFFF_FFFF_FFFF,
                parent_mft_entry: (parent_frn as u64) & 0x0000_FFFF_FFFF_FFFF,
                file_id_hex: format!("0x{frn:032X}"),
                parent_file_id_hex: format!("0x{parent_frn:032X}"),
                file_attributes: attrs,
                attributes_text: FileAttributes::from_raw(attrs).format_flags(),
                major_version: major,
                minor_version: minor,
                source_info: decode_usn_source_info(source_raw),
            }))
        }
        _ => Ok(None),
    }
}

/// Parse an offline `$UsnJrnl:$J` stream (with sparse zero runs and 4 KiB page-boundary zero padding).
pub fn parse_usn_journal_stream(bytes: &[u8]) -> Result<Vec<UsnRecord>, FsError> {
    let mut records = Vec::new();
    let mut cursor = 0usize;

    while cursor + 8 <= bytes.len() {
        let rec_len = read_u32_le(bytes, cursor)? as usize;
        if rec_len == 0 {
            if cursor.is_multiple_of(4096)
                && cursor + 4096 <= bytes.len()
                && bytes[cursor..cursor + 4096].iter().all(|&b| b == 0)
            {
                cursor += 4096;
            } else {
                let next_aligned = (cursor + 8) & !7usize;
                cursor = next_aligned.max(cursor + 8);
            }
            continue;
        }
        if rec_len < 8 {
            return Err(FsError::Parse(format!(
                "invalid USN record length {rec_len} (< 8) at offset {cursor}"
            )));
        }
        let rec_end = cursor
            .checked_add(rec_len)
            .filter(|&e| e <= bytes.len())
            .ok_or_else(|| FsError::Parse(format!("USN record at {cursor} len {rec_len} exceeds buffer")))?;

        if let Some(parsed) = parse_single_usn_record(&bytes[cursor..rec_end])? {
            records.push(parsed);
        }
        cursor = rec_end;
    }

    Ok(records)
}

/// Parse a `DeviceIoControl(FSCTL_READ_USN_JOURNAL)` / `FSCTL_ENUM_USN_DATA` reply buffer
/// whose first 8 bytes carry the `next_usn` / `next_frn` `i64` LE cursor.
pub fn parse_usn_ioctl_buffer(bytes: &[u8]) -> Result<(i64, Vec<UsnRecord>), FsError> {
    if bytes.len() < 8 {
        return Err(FsError::Parse(format!(
            "FSCTL USN reply buffer too short: {} bytes (need >= 8)",
            bytes.len()
        )));
    }
    let next_cursor = read_i64_le(bytes, 0)?;
    let records = parse_usn_journal_stream(&bytes[8..])?;
    Ok((next_cursor, records))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsnQueryMode {
    #[default]
    Journal,
    EnumMft,
}

#[derive(Debug, Clone)]
pub struct UsnJournalConfig {
    pub volume: String,
    pub start_usn: i64,
    pub reason_mask: u32,
    pub max_records: usize,
    pub mode: UsnQueryMode,
    pub offline_records: Option<Vec<UsnRecord>>,
}

impl Default for UsnJournalConfig {
    fn default() -> Self {
        Self {
            volume: "C:".to_string(),
            start_usn: 0,
            reason_mask: u32::MAX,
            max_records: 4096,
            mode: UsnQueryMode::Journal,
            offline_records: None,
        }
    }
}

pub fn usn_journal_schema() -> TableSchema {
    TableSchema::new(
        "usn_journal_view",
        "UsnJournalView - NTFS Change Journal ($UsnJrnl:$J)",
        vec![
            ColumnDef::new("usn", "USN", ColumnType::Int).with_width_hint(115),
            ColumnDef::new("timestamp", "Timestamp", ColumnType::Timestamp).with_width_hint(180),
            ColumnDef::new("file_name", "File Name", ColumnType::Text).with_width_hint(210),
            ColumnDef::new("reason", "Reason Flags", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("mft_entry", "MFT Entry", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("parent_mft_entry", "Parent MFT", ColumnType::Uint).with_width_hint(95),
            ColumnDef::new("attributes", "Attributes", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("version", "Version", ColumnType::Uint).with_width_hint(70),
            ColumnDef::new("source_info", "Source Info", ColumnType::Text).with_width_hint(130),
        ],
    )
    .with_default_sort(0, SortDirection::Desc)
}

pub struct UsnJournalViewProvider {
    config: UsnJournalConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl UsnJournalViewProvider {
    pub fn new(config: UsnJournalConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for UsnJournalViewProvider {
    fn tool_id(&self) -> &'static str {
        "usn_journal_view"
    }

    fn description(&self) -> &'static str {
        "Query and read NTFS Change Journal ($UsnJrnl:$J) USN_RECORD_V2/V3 records"
    }

    fn schema(&self) -> TableSchema {
        usn_journal_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let records = if let Some(offline) = &self.config.offline_records {
            offline.clone()
        } else {
            let dev_path = normalize_volume_device_path(&self.config.volume).map_err(TableError::from)?;
            self.backend
                .read_usn_journal(
                    &dev_path,
                    self.config.start_usn,
                    self.config.reason_mask,
                    self.config.max_records,
                    self.config.mode,
                )
                .map_err(TableError::from)?
        };

        let rows: Vec<Row> = records
            .iter()
            .take(self.config.max_records)
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Int(r.usn),
                        CellValue::Timestamp(r.timestamp),
                        CellValue::Text(r.file_name.clone()),
                        CellValue::Text(r.reason_flags.clone()),
                        CellValue::Uint(r.mft_entry),
                        CellValue::Uint(r.parent_mft_entry),
                        CellValue::Text(r.attributes_text.clone()),
                        CellValue::Uint(u64::from(r.major_version)),
                        CellValue::Text(r.source_info.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(r).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
