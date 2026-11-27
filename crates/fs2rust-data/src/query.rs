use crate::compare::{load_json_array_table, load_jsonl_table};
use crate::csv_view::{CsvTableProvider, CsvViewOptions};
use crate::encoding::decode_bytes;
use crate::error::DataError;
use guap_export::{ExportFormat, ExportOptions, export_table};
use guap_table::{GuapQuery, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query};
use std::path::PathBuf;
use std::sync::Arc;

/// Input source for tabular query evaluation.
pub enum TabularQuerySource {
    StdinBytes(Vec<u8>),
    CsvFile(PathBuf),
    TsvFile(PathBuf),
    JsonlFile(PathBuf),
    AutoFile(PathBuf),
    Provider(Arc<dyn TableProvider>),
    Table(TableData),
}

/// Output format produced by tabular query evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TabularQueryFormat {
    #[default]
    Table,
    Export(ExportFormat),
    AlignedText,
}

/// Query & output parameters for [`evaluate_query`].
#[derive(Debug, Clone, Default)]
pub struct TabularQueryRequest {
    pub columns: Option<Vec<String>>,
    pub where_expr: Option<String>,
    pub sort: Option<String>,
    pub offset: usize,
    pub top: Option<usize>,
    pub format: TabularQueryFormat,
}

/// Output produced by [`evaluate_query`].
#[derive(Debug, Clone)]
pub struct TabularQueryEvaluation {
    pub table: TableData,
    pub formatted_bytes: Option<Vec<u8>>,
}

/// `TableProvider` wrapping a tabular query evaluation result.
pub struct TabularQueryProvider {
    table: TableData,
}

impl TabularQueryProvider {
    pub fn from_source(source: TabularQuerySource, req: &TabularQueryRequest) -> Result<Self, DataError> {
        let eval = evaluate_query(source, req)?;
        Ok(Self { table: eval.table })
    }

    pub fn table_data(&self) -> &TableData {
        &self.table
    }
}

impl TableProvider for TabularQueryProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.query"
    }

    fn description(&self) -> &'static str {
        "Evaluate tabular queries (columns, where, sort, top) and format outputs"
    }

    fn schema(&self) -> TableSchema {
        let mut s = self.table.schema.clone();
        s.tool_id = "fs2rust.data.query".to_string();
        s
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        apply_query(&schema, &self.table.rows, req)
    }
}

/// Evaluate a [`TabularQueryRequest`] over any [`TabularQuerySource`].
pub fn evaluate_query(
    source: TabularQuerySource,
    req: &TabularQueryRequest,
) -> Result<TabularQueryEvaluation, DataError> {
    let sort = match &req.sort {
        Some(spec) if !spec.trim().is_empty() => GuapQuery::parse_sort(spec)?,
        _ => Vec::new(),
    };

    let query = GuapQuery {
        columns: req.columns.clone(),
        filter_expr: req.where_expr.clone(),
        sort,
        offset: req.offset,
        limit: req.top,
    };

    let table = match source {
        TabularQuerySource::Provider(provider) => query.execute_provider(provider.as_ref())?,
        TabularQuerySource::Table(td) => query.execute(&td)?,
        TabularQuerySource::CsvFile(path) => {
            let td = CsvTableProvider::from_path(&path, CsvViewOptions::default())?.into_table_data();
            query.execute(&td)?
        }
        TabularQuerySource::TsvFile(path) => {
            let td = CsvTableProvider::from_path(
                &path,
                CsvViewOptions {
                    delimiter: Some(b'\t'),
                    ..CsvViewOptions::default()
                },
            )?
            .into_table_data();
            query.execute(&td)?
        }
        TabularQuerySource::JsonlFile(path) => {
            let bytes = std::fs::read(&path)?;
            let td = load_jsonl_table(&bytes, &path.to_string_lossy())?;
            query.execute(&td)?
        }
        TabularQuerySource::StdinBytes(bytes) => {
            let td = auto_parse_bytes("stdin", &bytes)?;
            query.execute(&td)?
        }
        TabularQuerySource::AutoFile(path) => {
            let bytes = std::fs::read(&path)?;
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let label = path.to_string_lossy();
            let td = match ext.as_str() {
                "tsv" | "tab" => CsvTableProvider::from_bytes(
                    &label,
                    &bytes,
                    CsvViewOptions {
                        delimiter: Some(b'\t'),
                        ..CsvViewOptions::default()
                    },
                )?
                .into_table_data(),
                "jsonl" | "ndjson" => load_jsonl_table(&bytes, &label)?,
                "json" => auto_parse_json_bytes(&label, &bytes)?,
                _ => auto_parse_bytes(&label, &bytes)?,
            };
            query.execute(&td)?
        }
    };

    let formatted_bytes = match req.format {
        TabularQueryFormat::Table => None,
        TabularQueryFormat::Export(fmt) => Some(export_table(&table, fmt, &ExportOptions::default())?),
        TabularQueryFormat::AlignedText => Some(format_aligned_text(&table).into_bytes()),
    };

    Ok(TabularQueryEvaluation { table, formatted_bytes })
}

fn auto_parse_json_bytes(label: &str, bytes: &[u8]) -> Result<TableData, DataError> {
    let decoded = decode_bytes(bytes);
    let trimmed = decoded.text.trim_start();
    if trimmed.starts_with('[') {
        load_json_array_table(bytes, label)
    } else {
        load_jsonl_table(bytes, label)
    }
}

fn auto_parse_bytes(label: &str, bytes: &[u8]) -> Result<TableData, DataError> {
    let decoded = decode_bytes(bytes);
    let trimmed = decoded.text.trim_start();
    if trimmed.starts_with('[') {
        load_json_array_table(bytes, label)
    } else if trimmed.starts_with('{') {
        load_jsonl_table(bytes, label)
    } else {
        Ok(CsvTableProvider::from_bytes(label, bytes, CsvViewOptions::default())?.into_table_data())
    }
}

/// Format a `TableData` into padded fixed-width aligned console text.
pub fn format_aligned_text(table: &TableData) -> String {
    if table.schema.columns.is_empty() {
        return String::new();
    }
    let col_count = table.schema.columns.len();
    let mut widths: Vec<usize> = table
        .schema
        .columns
        .iter()
        .map(|c| c.label.chars().count().max(1))
        .collect();

    let mut rendered_rows: Vec<Vec<String>> = Vec::with_capacity(table.rows.len());
    for row in &table.rows {
        let mut cells = Vec::with_capacity(col_count);
        for (i, col) in table.schema.columns.iter().enumerate() {
            let text = row
                .cells
                .get(i)
                .map(|c| c.format_human(col.col_type))
                .unwrap_or_default();
            widths[i] = widths[i].max(text.chars().count());
            cells.push(text);
        }
        rendered_rows.push(cells);
    }

    let mut out = String::new();
    for (i, col) in table.schema.columns.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        out.push_str(&format!("{:<width$}", col.label, width = widths[i]));
    }
    out.push('\n');
    for (i, w) in widths.iter().enumerate() {
        if i > 0 {
            out.push_str("  ");
        }
        out.push_str(&"-".repeat(*w));
    }
    out.push('\n');
    for r in rendered_rows {
        for (i, cell) in r.iter().enumerate() {
            if i > 0 {
                out.push_str("  ");
            }
            out.push_str(&format!("{:<width$}", cell, width = widths[i]));
        }
        out.push('\n');
    }
    out
}
