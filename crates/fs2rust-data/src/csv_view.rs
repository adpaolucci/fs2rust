use crate::encoding::{TextEncoding, decode_bytes};
use crate::error::DataError;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use guap_export::{CustodyManifest, ExportFormat, ExportOptions, export_table, write_table_export};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Controls how `CsvTableProvider` treats the first record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderMode {
    #[default]
    Auto,
    HasHeader,
    NoHeader,
}

/// Configuration options for CSV/TSV viewing.
#[derive(Debug, Clone)]
pub struct CsvViewOptions {
    pub delimiter: Option<u8>,
    pub header_mode: HeaderMode,
    pub infer_types: bool,
    pub trim_whitespace: bool,
    pub flexible_columns: bool,
}

impl Default for CsvViewOptions {
    fn default() -> Self {
        Self {
            delimiter: None,
            header_mode: HeaderMode::Auto,
            infer_types: true,
            trim_whitespace: false,
            flexible_columns: true,
        }
    }
}

/// Dynamic CSV/TSV viewer provider (`TableProvider`).
pub struct CsvTableProvider {
    schema: TableSchema,
    rows: Vec<Row>,
    detected_delimiter: u8,
    detected_encoding: TextEncoding,
    has_header: bool,
    source_label: String,
}

impl CsvTableProvider {
    /// Load and parse a CSV/TSV file from disk.
    pub fn from_path(path: &Path, opts: CsvViewOptions) -> Result<Self, DataError> {
        let bytes = std::fs::read(path)?;
        let label = path.to_string_lossy().into_owned();
        Self::from_bytes(&label, &bytes, opts)
    }

    /// Parse a CSV/TSV byte slice with encoding & delimiter auto-detection.
    pub fn from_bytes(source_label: &str, bytes: &[u8], opts: CsvViewOptions) -> Result<Self, DataError> {
        let decoded = decode_bytes(bytes);
        let delimiter = opts.delimiter.unwrap_or_else(|| detect_delimiter(&decoded.text));

        let mut reader = csv::ReaderBuilder::new()
            .delimiter(delimiter)
            .has_headers(false)
            .flexible(opts.flexible_columns)
            .from_reader(decoded.text.as_bytes());

        let mut raw_records: Vec<Vec<String>> = Vec::new();
        for rec in reader.records() {
            let record = rec?;
            let row: Vec<String> = record
                .iter()
                .map(|c| {
                    if opts.trim_whitespace {
                        c.trim().to_string()
                    } else {
                        c.to_string()
                    }
                })
                .collect();
            raw_records.push(row);
        }

        if raw_records.is_empty() {
            let schema = TableSchema::new(
                "fs2rust.data.csv_file_view",
                format!("CSV/TSV Viewer — {source_label}"),
                vec![],
            );
            return Ok(Self {
                schema,
                rows: Vec::new(),
                detected_delimiter: delimiter,
                detected_encoding: decoded.encoding,
                has_header: false,
                source_label: source_label.to_string(),
            });
        }

        let max_cols = raw_records.iter().map(Vec::len).max().unwrap_or(0);
        let has_header = match opts.header_mode {
            HeaderMode::HasHeader => true,
            HeaderMode::NoHeader => false,
            HeaderMode::Auto => detect_has_header(&raw_records),
        };

        let (header_labels, data_records): (Vec<String>, &[Vec<String>]) = if has_header {
            let mut labels = raw_records[0].clone();
            labels.resize_with(max_cols, String::new);
            (labels, &raw_records[1..])
        } else {
            let labels = (0..max_cols).map(|i| format!("Column {}", i + 1)).collect();
            (labels, &raw_records[..])
        };

        let col_ids = normalize_column_ids(&header_labels);
        let mut col_types = vec![ColumnType::Text; max_cols];
        if opts.infer_types {
            for (col_idx, col_type) in col_types.iter_mut().enumerate().take(max_cols) {
                let sample: Vec<&str> = data_records
                    .iter()
                    .take(500)
                    .filter_map(|r| r.get(col_idx).map(String::as_str))
                    .collect();
                *col_type = infer_column_type(&sample);
            }
        }

        let columns: Vec<ColumnDef> = (0..max_cols)
            .map(|i| {
                let label = if header_labels[i].trim().is_empty() {
                    col_ids[i].clone()
                } else {
                    header_labels[i].clone()
                };
                ColumnDef::new(col_ids[i].clone(), label, col_types[i])
            })
            .collect();

        let schema = TableSchema::new(
            "fs2rust.data.csv_file_view",
            format!("CSV/TSV Viewer — {source_label}"),
            columns,
        );

        let mut rows = Vec::with_capacity(data_records.len());
        for (row_idx, raw_row) in data_records.iter().enumerate() {
            let mut cells = Vec::with_capacity(max_cols);
            for (col_idx, &col_type) in col_types.iter().enumerate() {
                let raw_cell = raw_row.get(col_idx).map(String::as_str).unwrap_or("");
                cells.push(parse_typed_cell(raw_cell, col_type));
            }
            let detail = serde_json::json!({
                "line": if has_header { row_idx + 2 } else { row_idx + 1 },
                "raw": raw_row,
            });
            rows.push(Row::new(row_idx as u64, cells).with_detail_json(detail));
        }

        Ok(Self {
            schema,
            rows,
            detected_delimiter: delimiter,
            detected_encoding: decoded.encoding,
            has_header,
            source_label: source_label.to_string(),
        })
    }

    pub fn detected_delimiter(&self) -> u8 {
        self.detected_delimiter
    }

    pub fn detected_encoding(&self) -> TextEncoding {
        self.detected_encoding
    }

    pub fn has_header(&self) -> bool {
        self.has_header
    }

    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    /// Return the full unpaginated `TableData`.
    pub fn into_table_data(self) -> TableData {
        let total_rows = self.rows.len();
        TableData {
            schema: self.schema,
            rows: self.rows,
            total_rows,
        }
    }

    /// Export filtered/sorted results via `guap-export`.
    pub fn export(&self, req: &TableQuery, fmt: ExportFormat, opts: &ExportOptions) -> Result<Vec<u8>, DataError> {
        let data = self.query(req)?;
        Ok(export_table(&data, fmt, opts)?)
    }

    /// Write filtered/sorted results and custody manifest via `guap-export`.
    pub fn export_to_path(
        &self,
        req: &TableQuery,
        output_path: &Path,
        fmt: ExportFormat,
        opts: &ExportOptions,
    ) -> Result<CustodyManifest, DataError> {
        let data = self.query(req)?;
        Ok(write_table_export(&data, output_path, fmt, opts)?)
    }
}

impl TableProvider for CsvTableProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.csv_file_view"
    }

    fn description(&self) -> &'static str {
        "Dynamic CSV/TSV viewer with auto-delimiter, encoding detection, and typed column inference"
    }

    fn schema(&self) -> TableSchema {
        self.schema.clone()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        apply_query(&self.schema, &self.rows, req)
    }
}

/// Detect the most consistent delimiter among `,`, `\t`, `;`, and `|`.
pub fn detect_delimiter(text: &str) -> u8 {
    let candidates = *b",\t;|";
    let mut best_delim = b',';
    let mut best_score = (0usize, 0usize, isize::MIN, 0usize);

    for (priority, &cand) in candidates.iter().enumerate() {
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(cand)
            .has_headers(false)
            .flexible(true)
            .from_reader(text.as_bytes());
        let mut counts = Vec::new();
        for r in reader.records().take(25).flatten() {
            counts.push(r.len());
        }
        if counts.is_empty() {
            continue;
        }
        let mut freq: HashMap<usize, usize> = HashMap::new();
        for &c in &counts {
            *freq.entry(c).or_insert(0) += 1;
        }
        let (mode_cols, mode_hits) = freq
            .into_iter()
            .max_by_key(|&(cols, hits)| (hits, cols))
            .unwrap_or((1, 0));
        let multi_col_flag = usize::from(mode_cols >= 2);
        let consistency_pct = (mode_hits * 100) / counts.len();
        let neg_variance: isize = -(counts
            .iter()
            .map(|&c| (c as isize - mode_cols as isize).abs())
            .sum::<isize>());
        let score = (
            multi_col_flag,
            usize::from(consistency_pct >= 80 && mode_cols >= 2) * 1000 + consistency_pct,
            neg_variance,
            candidates.len() - priority,
        );
        if score > best_score {
            best_score = score;
            best_delim = cand;
        }
    }

    best_delim
}

fn detect_has_header(records: &[Vec<String>]) -> bool {
    if records.len() < 2 {
        return false;
    }
    let row0 = &records[0];
    if row0.is_empty() || row0.iter().any(|c| c.trim().is_empty()) {
        return false;
    }
    let row0_has_scalar = row0.iter().any(|c| is_scalar_value(c.trim()));
    if row0_has_scalar {
        return false;
    }
    let body_has_scalar = records[1..]
        .iter()
        .take(20)
        .any(|r| r.iter().any(|c| is_scalar_value(c.trim())));
    if body_has_scalar {
        return true;
    }
    let mut seen = std::collections::HashSet::new();
    row0.iter().all(|c| seen.insert(c.trim().to_ascii_lowercase()))
}

fn is_scalar_value(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.parse::<i64>().is_ok()
        || s.parse::<f64>().is_ok_and(f64::is_finite)
        || matches!(s.to_ascii_lowercase().as_str(), "true" | "false")
        || parse_timestamp(s).is_some()
}

fn normalize_column_ids(labels: &[String]) -> Vec<String> {
    let mut emitted: HashSet<String> = HashSet::with_capacity(labels.len());
    let mut out = Vec::with_capacity(labels.len());
    for (idx, raw) in labels.iter().enumerate() {
        let mut slug: String = raw
            .trim()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect();
        while slug.contains("__") {
            slug = slug.replace("__", "_");
        }
        let slug = slug.trim_matches('_').to_string();
        let base = if slug.is_empty() {
            format!("col_{}", idx + 1)
        } else {
            slug
        };
        let candidate = if emitted.insert(base.clone()) {
            base
        } else {
            let mut suffix = 2usize;
            loop {
                let next = format!("{base}_{suffix}");
                if emitted.insert(next.clone()) {
                    break next;
                }
                suffix += 1;
            }
        };
        out.push(candidate);
    }
    out
}

/// Infer the tightest `ColumnType` compatible with all non-empty sampled values.
pub fn infer_column_type(values: &[&str]) -> ColumnType {
    let non_empty: Vec<&str> = values.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if non_empty.is_empty() {
        return ColumnType::Text;
    }
    if non_empty
        .iter()
        .all(|s| matches!(s.to_ascii_lowercase().as_str(), "true" | "false" | "yes" | "no"))
    {
        return ColumnType::Bool;
    }
    if non_empty
        .iter()
        .all(|s| !(s.len() > 1 && s.starts_with('0')) && s.parse::<u64>().is_ok())
    {
        return ColumnType::Uint;
    }
    if non_empty.iter().all(|s| {
        let unsigned = s.trim_start_matches('-');
        !(unsigned.len() > 1 && unsigned.starts_with('0')) && s.parse::<i64>().is_ok()
    }) {
        return ColumnType::Int;
    }
    if non_empty.iter().all(|s| {
        let unsigned = s.trim_start_matches('-');
        let leading_zero = unsigned.len() > 1 && unsigned.starts_with('0') && !unsigned.starts_with("0.");
        !leading_zero && s.parse::<f64>().is_ok_and(f64::is_finite)
    }) {
        return ColumnType::Float;
    }
    if non_empty.iter().all(|s| parse_timestamp(s).is_some()) {
        return ColumnType::Timestamp;
    }
    ColumnType::Text
}

fn parse_typed_cell(raw: &str, col_type: ColumnType) -> CellValue {
    let trimmed = raw.trim();
    if trimmed.is_empty() && col_type != ColumnType::Text {
        return CellValue::Null;
    }
    match col_type {
        ColumnType::Bool => match trimmed.to_ascii_lowercase().as_str() {
            "true" | "yes" => CellValue::Bool(true),
            "false" | "no" => CellValue::Bool(false),
            _ => CellValue::Text(raw.to_string()),
        },
        ColumnType::Uint => trimmed
            .parse::<u64>()
            .map(CellValue::Uint)
            .unwrap_or_else(|_| CellValue::Text(raw.to_string())),
        ColumnType::Int => trimmed
            .parse::<i64>()
            .map(CellValue::Int)
            .unwrap_or_else(|_| CellValue::Text(raw.to_string())),
        ColumnType::Float => trimmed
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_finite())
            .map(CellValue::Float)
            .unwrap_or_else(|| CellValue::Text(raw.to_string())),
        ColumnType::Timestamp => parse_timestamp(trimmed)
            .map(CellValue::Timestamp)
            .unwrap_or_else(|| CellValue::Text(raw.to_string())),
        _ => CellValue::Text(raw.to_string()),
    }
}

pub(crate) fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
        }
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        && let Some(ndt) = nd.and_hms_opt(0, 0, 0)
    {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc));
    }
    None
}
