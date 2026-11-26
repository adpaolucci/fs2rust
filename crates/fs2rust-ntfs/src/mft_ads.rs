#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{decode_utf16le, read_u8, read_u16_le, read_u32_le, read_u64_le};
use fs2rust_core::{FsError, PolicyContext};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdsEntry {
    pub file_path: String,
    pub stream_name: String,
    pub full_stream_path: String,
    pub stream_size: u64,
    pub allocated_size: u64,
    pub resident: bool,
    pub mft_record: Option<u64>,
    pub attributes: String,
    pub content_preview: String,
    pub sha256: String,
}

fn format_attr_flags(flags: u16) -> String {
    let mut parts = Vec::new();
    if (flags & 0x0001) != 0 {
        parts.push("Compressed");
    }
    if (flags & 0x4000) != 0 {
        parts.push("Encrypted");
    }
    if (flags & 0x8000) != 0 {
        parts.push("Sparse");
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join("|")
    }
}

/// Apply NTFS Update Sequence Array (USA) sector fixup restoration on a raw MFT `FILE` record.
pub fn apply_mft_usa_fixup(record_bytes: &[u8]) -> Result<Vec<u8>, FsError> {
    if record_bytes.len() < 512 || !record_bytes.len().is_multiple_of(512) {
        return Err(FsError::Parse(format!(
            "invalid MFT FILE record length {}: must be >= 512 and a multiple of 512",
            record_bytes.len()
        )));
    }
    if &record_bytes[0..4] != b"FILE" {
        return Err(FsError::Parse(format!(
            "invalid MFT FILE record magic: {:?}",
            &record_bytes[0..4]
        )));
    }
    let usa_offset = usize::from(read_u16_le(record_bytes, 0x04)?);
    let usa_count = usize::from(read_u16_le(record_bytes, 0x06)?);
    if usa_count < 2 {
        return Err(FsError::Parse(format!(
            "invalid MFT USA count {usa_count}: must be >= 2"
        )));
    }
    let usa_end = usa_offset
        .checked_add(usa_count * 2)
        .ok_or_else(|| FsError::Parse("MFT USA array offset overflow".to_string()))?;
    if usa_offset < 0x2A || usa_end > record_bytes.len() {
        return Err(FsError::Parse(format!(
            "MFT USA array out of bounds: {usa_offset}..{usa_end} (len={})",
            record_bytes.len()
        )));
    }
    let sectors = usa_count - 1;
    if sectors * 512 > record_bytes.len() {
        return Err(FsError::Parse(format!(
            "MFT USA sector count ({sectors}) exceeds record length {}",
            record_bytes.len()
        )));
    }

    let mut rec = record_bytes.to_vec();
    let usn = [rec[usa_offset], rec[usa_offset + 1]];
    for i in 1..usa_count {
        let sector_tail = i * 512 - 2;
        let fixup_off = usa_offset + i * 2;
        if rec[sector_tail..sector_tail + 2] != usn {
            return Err(FsError::Parse(format!(
                "MFT USA fixup signature mismatch at sector {i} (offset {sector_tail})"
            )));
        }
        let orig0 = rec[fixup_off];
        let orig1 = rec[fixup_off + 1];
        rec[sector_tail] = orig0;
        rec[sector_tail + 1] = orig1;
    }
    Ok(rec)
}

/// Parse a single NTFS `$MFT` `FILE` record and extract all named `$DATA` Alternate Data Streams.
pub fn parse_mft_file_record_ads(record_bytes: &[u8]) -> Result<Vec<AdsEntry>, FsError> {
    let rec = apply_mft_usa_fixup(record_bytes)?;
    let first_attr_off = usize::from(read_u16_le(&rec, 0x14)?);
    let bytes_used = read_u32_le(&rec, 0x18)? as usize;
    let mft_record_number = u64::from(read_u32_le(&rec, 0x2C)?);

    let limit = bytes_used.min(rec.len());
    if first_attr_off < 0x2A || first_attr_off > limit {
        return Err(FsError::Parse(format!(
            "MFT first_attr_offset {first_attr_off} out of bounds (limit={limit})"
        )));
    }

    let mut best_filename: Option<(u8, String)> = None;
    struct RawDataAttr {
        stream_name: String,
        resident: bool,
        stream_size: u64,
        allocated_size: u64,
        flags: u16,
        preview: String,
        sha256: String,
    }
    let mut named_data_attrs: Vec<RawDataAttr> = Vec::new();

    let mut off = first_attr_off;
    let mut attr_count = 0usize;
    while off + 4 <= limit {
        attr_count += 1;
        if attr_count > 256 {
            return Err(FsError::Parse("MFT attribute count exceeded 256".to_string()));
        }
        let attr_type = read_u32_le(&rec, off)?;
        if attr_type == 0xFFFF_FFFF {
            break;
        }
        if off + 16 > limit {
            return Err(FsError::Parse(format!("truncated MFT attribute header at {off}")));
        }
        let attr_len = read_u32_le(&rec, off + 4)? as usize;
        if attr_len < 16 {
            return Err(FsError::Parse(format!(
                "invalid MFT attribute length {attr_len} (< 16) at offset {off}"
            )));
        }
        let attr_end = off
            .checked_add(attr_len)
            .filter(|&end| end <= limit)
            .ok_or_else(|| FsError::Parse(format!("MFT attribute at {off} len {attr_len} exceeds limit {limit}")))?;

        let non_resident = read_u8(&rec, off + 8)?;
        let name_length = usize::from(read_u8(&rec, off + 9)?);
        let name_offset = usize::from(read_u16_le(&rec, off + 0x0A)?);
        let attr_flags = read_u16_le(&rec, off + 0x0C)?;

        if non_resident == 0 && attr_len < 24 {
            return Err(FsError::Parse(format!(
                "resident MFT attribute at {off} has length {attr_len} < 24"
            )));
        }
        if non_resident != 0 && attr_len < 64 {
            return Err(FsError::Parse(format!(
                "non-resident MFT attribute at {off} has length {attr_len} < 64"
            )));
        }

        let attr_name = if name_length > 0 {
            let name_bytes = name_length * 2;
            let name_end = name_offset
                .checked_add(name_bytes)
                .filter(|&e| e <= attr_len)
                .ok_or_else(|| FsError::Parse(format!("MFT attribute name out of bounds at {off}")))?;
            decode_utf16le(&rec[off + name_offset..off + name_end])
        } else {
            String::new()
        };

        if attr_type == 0x30 && non_resident == 0 {
            let content_size = read_u32_le(&rec, off + 0x10)? as usize;
            let content_offset = usize::from(read_u16_le(&rec, off + 0x14)?);
            let content_end = content_offset
                .checked_add(content_size)
                .filter(|&e| e <= attr_len)
                .ok_or_else(|| FsError::Parse(format!("$FILE_NAME payload out of bounds at {off}")))?;
            let payload = &rec[off + content_offset..off + content_end];
            if payload.len() >= 0x42 {
                let fn_chars = usize::from(payload[0x40]);
                let namespace = payload[0x41];
                let fn_end = 0x42usize
                    .checked_add(fn_chars * 2)
                    .filter(|&e| e <= payload.len())
                    .ok_or_else(|| FsError::Parse("$FILE_NAME string out of bounds".to_string()))?;
                let fname = decode_utf16le(&payload[0x42..fn_end]);
                let should_replace = match &best_filename {
                    None => true,
                    Some((prev_ns, _)) => *prev_ns == 2 && namespace != 2,
                };
                if should_replace {
                    best_filename = Some((namespace, fname));
                }
            }
        } else if attr_type == 0x80 && !attr_name.is_empty() {
            if non_resident == 0 {
                let content_size = read_u32_le(&rec, off + 0x10)? as usize;
                let content_offset = usize::from(read_u16_le(&rec, off + 0x14)?);
                let content_end = content_offset
                    .checked_add(content_size)
                    .filter(|&e| e <= attr_len)
                    .ok_or_else(|| FsError::Parse(format!("resident $DATA payload out of bounds at {off}")))?;
                let payload = &rec[off + content_offset..off + content_end];
                let preview_len = payload.len().min(128);
                let preview = String::from_utf8_lossy(&payload[..preview_len])
                    .replace('\r', "\\r")
                    .replace('\n', "\\n");
                let sha256 = hex::encode(Sha256::digest(payload));
                named_data_attrs.push(RawDataAttr {
                    stream_name: attr_name,
                    resident: true,
                    stream_size: content_size as u64,
                    allocated_size: content_size as u64,
                    flags: attr_flags,
                    preview,
                    sha256,
                });
            } else {
                let allocated_size = read_u64_le(&rec, off + 0x28)?;
                let data_size = read_u64_le(&rec, off + 0x30)?;
                named_data_attrs.push(RawDataAttr {
                    stream_name: attr_name,
                    resident: false,
                    stream_size: data_size,
                    allocated_size,
                    flags: attr_flags,
                    preview: "<non-resident>".to_string(),
                    sha256: String::new(),
                });
            }
        }

        off = attr_end;
    }

    let file_name = best_filename
        .map(|(_, n)| n)
        .unwrap_or_else(|| format!("MFT#{mft_record_number}"));

    Ok(named_data_attrs
        .into_iter()
        .map(|d| {
            let formatted_stream = format!(":{}:$DATA", d.stream_name);
            let full_stream_path = format!("{file_name}:{}", d.stream_name);
            AdsEntry {
                file_path: file_name.clone(),
                stream_name: formatted_stream,
                full_stream_path,
                stream_size: d.stream_size,
                allocated_size: d.allocated_size,
                resident: d.resident,
                mft_record: Some(mft_record_number),
                attributes: format_attr_flags(d.flags),
                content_preview: d.preview,
                sha256: d.sha256,
            }
        })
        .collect())
}

/// Parse one or more concatenated 1024-byte MFT `FILE` records.
pub fn parse_mft_ads_records(bytes: &[u8]) -> Result<Vec<AdsEntry>, FsError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(1024) {
        return Err(FsError::Parse(format!(
            "MFT stream length {} must be a non-zero multiple of 1024",
            bytes.len()
        )));
    }
    let mut out = Vec::new();
    for chunk in bytes.as_chunks::<1024>().0 {
        out.extend(parse_mft_file_record_ads(chunk)?);
    }
    Ok(out)
}

pub fn normalize_ads_target(file_path: &str, stream_name: &str) -> Result<(PathBuf, String, String), FsError> {
    let trimmed_file = file_path.trim();
    if trimmed_file.is_empty() || trimmed_file.contains('\0') {
        return Err(FsError::InvalidPath("file_path cannot be empty".to_string()));
    }
    let trimmed_stream = stream_name.trim();
    if trimmed_stream.is_empty() || trimmed_stream.contains('\0') {
        return Err(FsError::InvalidArgument("stream_name cannot be empty".to_string()));
    }
    if trimmed_stream.contains('\\') || trimmed_stream.contains('/') || trimmed_stream.contains("..") {
        return Err(FsError::InvalidArgument(format!(
            "invalid ADS stream_name '{trimmed_stream}': path separators and '..' are forbidden"
        )));
    }
    let core_name = trimmed_stream
        .strip_prefix(':')
        .unwrap_or(trimmed_stream)
        .strip_suffix(":$DATA")
        .or_else(|| {
            trimmed_stream
                .strip_prefix(':')
                .unwrap_or(trimmed_stream)
                .strip_suffix(":$data")
        })
        .unwrap_or_else(|| trimmed_stream.strip_prefix(':').unwrap_or(trimmed_stream));

    if core_name.is_empty() || core_name.eq_ignore_ascii_case("$DATA") || core_name.contains(':') {
        return Err(FsError::PolicyDenied(format!(
            "refusing to target default or malformed data stream '{trimmed_stream}'"
        )));
    }

    let normalized_stream = format!(":{core_name}:$DATA");
    let full_stream = format!("{trimmed_file}:{core_name}");
    Ok((PathBuf::from(trimmed_file), normalized_stream, full_stream))
}

#[derive(Debug, Clone, Default)]
pub struct AlternateStreamConfig {
    pub target_paths: Vec<PathBuf>,
    pub recursive: bool,
    pub include_default_data: bool,
    pub policy: PolicyContext,
    pub offline_records: Option<Vec<AdsEntry>>,
}

pub fn alternate_stream_schema() -> TableSchema {
    TableSchema::new(
        "alternate_stream_view",
        "AlternateStreamView - NTFS Alternate Data Streams (Live & Offline $MFT)",
        vec![
            ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("stream_name", "Stream Name", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("full_stream_path", "Full Stream Path", ColumnType::Text).with_width_hint(320),
            ColumnDef::new("stream_size", "Stream Size", ColumnType::BytesSize).with_width_hint(100),
            ColumnDef::new("allocated_size", "Allocated Size", ColumnType::BytesSize).with_width_hint(100),
            ColumnDef::new("resident", "Resident", ColumnType::Bool).with_width_hint(75),
            ColumnDef::new("mft_record", "MFT Record", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("attributes", "Attributes", ColumnType::Text).with_width_hint(85),
            ColumnDef::new("content_preview", "Preview", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(180),
        ],
    )
    .with_default_sort(2, SortDirection::Asc)
}

pub struct AlternateStreamViewProvider {
    config: AlternateStreamConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl AlternateStreamViewProvider {
    pub fn new(config: AlternateStreamConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for AlternateStreamViewProvider {
    fn tool_id(&self) -> &'static str {
        "alternate_stream_view"
    }

    fn description(&self) -> &'static str {
        "Enumerate NTFS Alternate Data Streams via FindFirstStreamW/FindNextStreamW or offline $MFT records"
    }

    fn schema(&self) -> TableSchema {
        alternate_stream_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut entries = if let Some(offline) = &self.config.offline_records {
            offline.clone()
        } else {
            for p in &self.config.target_paths {
                self.config.policy.check_path_allowed(p).map_err(TableError::from)?;
            }
            self.backend
                .enumerate_ads(
                    &self.config.target_paths,
                    self.config.recursive,
                    self.config.include_default_data,
                )
                .map_err(TableError::from)?
        };
        if !self.config.include_default_data {
            entries.retain(|e| !e.stream_name.eq_ignore_ascii_case("::$DATA"));
        }
        let rows: Vec<Row> = entries
            .iter()
            .enumerate()
            .map(|(idx, e)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(e.file_path.clone()),
                        CellValue::Text(e.stream_name.clone()),
                        CellValue::Text(e.full_stream_path.clone()),
                        CellValue::Bytes(e.stream_size),
                        CellValue::Bytes(e.allocated_size),
                        CellValue::Bool(e.resident),
                        e.mft_record.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Text(e.attributes.clone()),
                        CellValue::Text(e.content_preview.clone()),
                        CellValue::Text(e.sha256.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

/// Mutating `ActionCommand` deleting a named NTFS Alternate Data Stream.
pub struct AlternateStreamDeleteAction {
    backend: Arc<dyn NtfsBackend>,
    policy: PolicyContext,
}

impl AlternateStreamDeleteAction {
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

impl ActionCommand for AlternateStreamDeleteAction {
    fn command_id(&self) -> &'static str {
        "alternate_stream_delete"
    }

    fn description(&self) -> &'static str {
        "Delete a named NTFS Alternate Data Stream (refuses default ::$DATA stream)"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["file_path", "stream_name"],
            "properties": {
                "file_path": { "type": "string", "description": "Path to host file containing the ADS" },
                "stream_name": { "type": "string", "description": "Named stream (e.g. 'Zone.Identifier' or ':Zone.Identifier:$DATA')" }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let file_path = args
            .get("file_path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'file_path'".to_string()))?;
        let stream_name = args
            .get("stream_name")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'stream_name'".to_string()))?;

        let (host_path, norm_stream, full_stream) =
            normalize_ads_target(file_path, stream_name).map_err(McpToolError::from)?;

        self.policy.check_path_allowed(&host_path).map_err(McpToolError::from)?;
        self.policy
            .check_path_allowed(Path::new(&full_stream))
            .map_err(McpToolError::from)?;

        if dry_run {
            return Ok(json!({
                "mode": "dry_run",
                "file_path": file_path,
                "stream_name": norm_stream,
                "full_stream_path": full_stream,
                "deleted": false,
            }));
        }

        let confirmed = args
            .get("confirm_destructive")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || self.policy.confirm_destructive;
        if !confirmed {
            return Err(McpToolError::PolicyDenied(
                "deleting an NTFS Alternate Data Stream requires confirm_destructive = true".to_string(),
            ));
        }

        self.backend.delete_ads(&full_stream).map_err(McpToolError::from)?;

        Ok(json!({
            "mode": "applied",
            "file_path": file_path,
            "stream_name": norm_stream,
            "full_stream_path": full_stream,
            "deleted": true,
        }))
    }
}
