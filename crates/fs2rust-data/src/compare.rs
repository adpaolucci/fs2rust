use crate::csv_view::{CsvTableProvider, CsvViewOptions};
use crate::encoding::decode_bytes;
use crate::error::DataError;
use guap_table::{
    CellValue, ColumnDef, ColumnType, DiffKind, DiffSummary, Row, TableData, TableDiff, TableError, TableProvider,
    TableQuery, TableSchema, TableTextCompare as GuapTableTextCompare, apply_query,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

/// Input source accepted by `TableTextCompare`.
pub enum TableInput {
    Csv { path: PathBuf, options: CsvViewOptions },
    Tsv { path: PathBuf },
    Jsonl { path: PathBuf },
    TableData(TableData),
    Provider(Arc<dyn TableProvider>),
}

/// Key matching strategy for row alignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareKeyMode {
    Columns(Vec<String>),
    Positional,
}

/// Options controlling `TableTextCompare`.
#[derive(Debug, Clone)]
pub struct TableCompareOptions {
    pub key_mode: CompareKeyMode,
    pub align_union_columns: bool,
    pub include_unchanged: bool,
}

impl Default for TableCompareOptions {
    fn default() -> Self {
        Self {
            key_mode: CompareKeyMode::Positional,
            align_union_columns: true,
            include_unchanged: true,
        }
    }
}

/// Result of comparing two tabular inputs.
#[derive(Debug, Clone)]
pub struct TableCompareResult {
    pub diff: TableDiff,
    pub table: TableData,
}

/// `TableProvider` wrapping a `TableTextCompare` diff result.
pub struct TableCompareProvider {
    result: TableCompareResult,
}

impl TableCompareProvider {
    /// Execute a diff between `left` and `right`.
    pub fn compare(left: TableInput, right: TableInput, opts: TableCompareOptions) -> Result<Self, DataError> {
        let left_data = load_table_input(left, "left")?;
        let right_data = load_table_input(right, "right")?;

        let (norm_left, norm_right) = if opts.align_union_columns {
            align_union_schemas(&left_data, &right_data)
        } else {
            reconcile_same_columns(&left_data, &right_data)
        };

        let (diff_left, diff_right, key_cols) = match &opts.key_mode {
            CompareKeyMode::Columns(cols) => (norm_left, norm_right, cols.clone()),
            CompareKeyMode::Positional => (
                prepend_positional_col(&norm_left),
                prepend_positional_col(&norm_right),
                vec!["__row_pos".to_string()],
            ),
        };

        let diff = GuapTableTextCompare::diff(&diff_left, &diff_right, &key_cols)?;
        let mut table = diff.to_table_data();
        table.schema.tool_id = "fs2rust.data.table_text_compare".to_string();
        table.schema.title = "TableTextCompare — Tabular Diff".to_string();

        let left_col_ids: Vec<String> = diff_left.schema.columns.iter().map(|c| c.id.clone()).collect();
        let right_col_ids: Vec<String> = diff_right.schema.columns.iter().map(|c| c.id.clone()).collect();

        let mut enriched_rows = Vec::with_capacity(diff.rows.len());
        for (idx, diff_row) in diff.rows.iter().enumerate() {
            if !opts.include_unchanged && diff_row.kind == DiffKind::Unchanged {
                continue;
            }
            let Some(mut out_row) = table.rows.get(idx).cloned() else {
                continue;
            };
            let changes_json: Vec<Value> = diff_row
                .changed_columns
                .iter()
                .map(|c| {
                    json!({
                        "column_id": c.column_id,
                        "left": c.left.to_json_value(),
                        "right": c.right.to_json_value(),
                    })
                })
                .collect();
            let key_json: Vec<Value> = diff_row.key.iter().map(CellValue::to_json_value).collect();
            let left_obj = diff_row.left_row.as_ref().map(|r| row_to_json_obj(&left_col_ids, r));
            let right_obj = diff_row.right_row.as_ref().map(|r| row_to_json_obj(&right_col_ids, r));
            out_row.detail_json = Some(json!({
                "kind": format!("{:?}", diff_row.kind),
                "key": key_json,
                "changed_columns": changes_json,
                "left_row": left_obj,
                "right_row": right_obj,
            }));
            out_row.id = enriched_rows.len() as u64;
            enriched_rows.push(out_row);
        }

        table.rows = enriched_rows;
        table.total_rows = table.rows.len();

        Ok(Self {
            result: TableCompareResult { diff, table },
        })
    }

    pub fn summary(&self) -> &DiffSummary {
        &self.result.diff.summary
    }

    pub fn result(&self) -> &TableCompareResult {
        &self.result
    }
}

impl TableProvider for TableCompareProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.table_text_compare"
    }

    fn description(&self) -> &'static str {
        "Compare two CSV/TSV/JSONL/TableData inputs by key columns or row position"
    }

    fn schema(&self) -> TableSchema {
        self.result.table.schema.clone()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        apply_query(&self.result.table.schema, &self.result.table.rows, req)
    }
}

pub(crate) fn load_table_input(input: TableInput, label: &str) -> Result<TableData, DataError> {
    match input {
        TableInput::Csv { path, options } => Ok(CsvTableProvider::from_path(&path, options)?.into_table_data()),
        TableInput::Tsv { path } => Ok(CsvTableProvider::from_path(
            &path,
            CsvViewOptions {
                delimiter: Some(b'\t'),
                ..CsvViewOptions::default()
            },
        )?
        .into_table_data()),
        TableInput::Jsonl { path } => {
            let bytes = std::fs::read(&path)?;
            load_jsonl_table(&bytes, &path.to_string_lossy())
        }
        TableInput::TableData(td) => Ok(td),
        TableInput::Provider(p) => Ok(p.query(&TableQuery::default())?),
    }
    .map_err(|e| DataError::InvalidInput(format!("failed loading {label} table: {e}")))
}

/// Load a newline-delimited JSON objects stream into `TableData`.
pub fn load_jsonl_table(bytes: &[u8], title: &str) -> Result<TableData, DataError> {
    let decoded = decode_bytes(bytes);
    let mut objects = Vec::new();
    for (line_no, line) in decoded.text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let val: Value = serde_json::from_str(trimmed)?;
        let obj = val
            .as_object()
            .ok_or_else(|| DataError::InvalidInput(format!("JSONL line {} is not a JSON object", line_no + 1)))?;
        objects.push(obj.clone());
    }
    json_objects_to_table(objects, "fs2rust.data.jsonl", title)
}

/// Load a JSON array of objects into `TableData`.
pub fn load_json_array_table(bytes: &[u8], title: &str) -> Result<TableData, DataError> {
    let decoded = decode_bytes(bytes);
    let val: Value = serde_json::from_str(&decoded.text)?;
    let arr = val
        .as_array()
        .ok_or_else(|| DataError::InvalidInput("expected JSON array of objects".to_string()))?;
    let mut objects = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let obj = item
            .as_object()
            .ok_or_else(|| DataError::InvalidInput(format!("JSON array element {idx} is not an object")))?;
        objects.push(obj.clone());
    }
    json_objects_to_table(objects, "fs2rust.data.json", title)
}

fn json_objects_to_table(
    objects: Vec<serde_json::Map<String, Value>>,
    tool_id: &str,
    title: &str,
) -> Result<TableData, DataError> {
    let mut col_names: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for obj in &objects {
        for key in obj.keys() {
            if seen.insert(key.clone()) {
                col_names.push(key.clone());
            }
        }
    }

    let columns: Vec<ColumnDef> = col_names
        .iter()
        .map(|name| {
            let col_type = infer_json_column_type(name, &objects);
            ColumnDef::new(name.clone(), name.clone(), col_type)
        })
        .collect();

    let mut rows = Vec::with_capacity(objects.len());
    for (idx, obj) in objects.into_iter().enumerate() {
        let cells = col_names
            .iter()
            .zip(columns.iter())
            .map(|(name, col)| match obj.get(name) {
                Some(v) => json_val_to_cell(v, col.col_type),
                None => CellValue::Null,
            })
            .collect();
        rows.push(Row::new(idx as u64, cells).with_detail_json(Value::Object(obj)));
    }

    let total_rows = rows.len();
    Ok(TableData {
        schema: TableSchema::new(tool_id, title, columns),
        rows,
        total_rows,
    })
}

fn infer_json_column_type(key: &str, objects: &[serde_json::Map<String, Value>]) -> ColumnType {
    let non_null: Vec<&Value> = objects
        .iter()
        .filter_map(|o| o.get(key))
        .filter(|v| !v.is_null())
        .take(500)
        .collect();
    if non_null.is_empty() {
        return ColumnType::Text;
    }
    if non_null.iter().all(|v| v.is_boolean()) {
        return ColumnType::Bool;
    }
    if non_null.iter().all(|v| v.as_u64().is_some()) {
        return ColumnType::Uint;
    }
    if non_null.iter().all(|v| v.as_i64().is_some()) {
        return ColumnType::Int;
    }
    if non_null.iter().all(|v| v.as_f64().is_some()) {
        return ColumnType::Float;
    }
    ColumnType::Text
}

fn json_val_to_cell(val: &Value, col_type: ColumnType) -> CellValue {
    if val.is_null() {
        return CellValue::Null;
    }
    match col_type {
        ColumnType::Bool => val
            .as_bool()
            .map(CellValue::Bool)
            .unwrap_or_else(|| CellValue::Text(val.to_string())),
        ColumnType::Uint => val
            .as_u64()
            .map(CellValue::Uint)
            .unwrap_or_else(|| CellValue::Text(val.to_string())),
        ColumnType::Int => val
            .as_i64()
            .map(CellValue::Int)
            .unwrap_or_else(|| CellValue::Text(val.to_string())),
        ColumnType::Float => val
            .as_f64()
            .map(CellValue::Float)
            .unwrap_or_else(|| CellValue::Text(val.to_string())),
        _ => match val {
            Value::String(s) => CellValue::Text(s.clone()),
            other => CellValue::Text(other.to_string()),
        },
    }
}

const MAX_EXACT_F64_INT: u64 = 1u64 << 53;

fn reconcile_column_type(a: ColumnType, b: ColumnType) -> ColumnType {
    if a == b {
        return a;
    }
    match (a, b) {
        (ColumnType::Uint, ColumnType::Int)
        | (ColumnType::Int, ColumnType::Uint)
        | (ColumnType::BytesSize, ColumnType::Int)
        | (ColumnType::Int, ColumnType::BytesSize) => ColumnType::Int,
        (ColumnType::Uint | ColumnType::Int | ColumnType::BytesSize, ColumnType::Float)
        | (ColumnType::Float, ColumnType::Uint | ColumnType::Int | ColumnType::BytesSize) => ColumnType::Float,
        (ColumnType::BytesSize, ColumnType::Uint) | (ColumnType::Uint, ColumnType::BytesSize) => ColumnType::Uint,
        _ => ColumnType::Text,
    }
}

fn has_unsigned_exceeding_i64(data: &TableData, col_id: &str) -> bool {
    let Some(idx) = data.schema.column_index(col_id) else {
        return false;
    };
    data.rows.iter().any(|row| {
        matches!(
            row.cells.get(idx),
            Some(CellValue::Uint(v) | CellValue::Bytes(v)) if *v > i64::MAX as u64
        )
    })
}

fn has_int_exceeding_f64_exact(data: &TableData, col_id: &str) -> bool {
    let Some(idx) = data.schema.column_index(col_id) else {
        return false;
    };
    data.rows.iter().any(|row| match row.cells.get(idx) {
        Some(CellValue::Uint(v) | CellValue::Bytes(v)) => *v > MAX_EXACT_F64_INT,
        Some(CellValue::Int(v)) => v.unsigned_abs() > MAX_EXACT_F64_INT,
        _ => false,
    })
}

fn resolve_reconciled_column_type(
    col_type: ColumnType,
    col_id: &str,
    left: &TableData,
    right: &TableData,
) -> ColumnType {
    match col_type {
        ColumnType::Int if has_unsigned_exceeding_i64(left, col_id) || has_unsigned_exceeding_i64(right, col_id) => {
            ColumnType::Text
        }
        ColumnType::Float
            if has_int_exceeding_f64_exact(left, col_id) || has_int_exceeding_f64_exact(right, col_id) =>
        {
            ColumnType::Text
        }
        _ => col_type,
    }
}

fn coerce_cell(cell: CellValue, target: ColumnType) -> CellValue {
    if cell.is_null() {
        return CellValue::Null;
    }
    match target {
        ColumnType::Int => match cell {
            CellValue::Int(v) => CellValue::Int(v),
            CellValue::Uint(v) => i64::try_from(v)
                .map(CellValue::Int)
                .unwrap_or_else(|_| CellValue::Text(v.to_string())),
            CellValue::Bytes(b) => i64::try_from(b)
                .map(CellValue::Int)
                .unwrap_or_else(|_| CellValue::Text(b.to_string())),
            other => other,
        },
        ColumnType::Uint => match cell {
            CellValue::Uint(v) => CellValue::Uint(v),
            CellValue::Bytes(b) => CellValue::Uint(b),
            other => other,
        },
        ColumnType::Float => match cell {
            CellValue::Float(f) => CellValue::Float(f),
            CellValue::Uint(v) => CellValue::Float(v as f64),
            CellValue::Int(v) => CellValue::Float(v as f64),
            CellValue::Bytes(b) => CellValue::Float(b as f64),
            other => other,
        },
        ColumnType::Text => match cell {
            CellValue::Text(s) => CellValue::Text(s),
            CellValue::Uint(v) => CellValue::Text(v.to_string()),
            CellValue::Int(v) => CellValue::Text(v.to_string()),
            CellValue::Float(v) => CellValue::Text(if v == 0.0 { "0".to_string() } else { v.to_string() }),
            CellValue::Bool(b) => CellValue::Text(if b { "true" } else { "false" }.to_string()),
            other => CellValue::Text(other.to_string()),
        },
        _ => cell,
    }
}

fn reconcile_same_columns(left: &TableData, right: &TableData) -> (TableData, TableData) {
    let right_types: HashMap<&str, ColumnType> = right
        .schema
        .columns
        .iter()
        .map(|c| (c.id.as_str(), c.col_type))
        .collect();
    let mut reconciled_types: HashMap<String, ColumnType> = HashMap::new();
    for col in &left.schema.columns {
        if let Some(&r_type) = right_types.get(col.id.as_str()) {
            let merged =
                resolve_reconciled_column_type(reconcile_column_type(col.col_type, r_type), &col.id, left, right);
            reconciled_types.insert(col.id.clone(), merged);
        }
    }

    let apply_types = |data: &TableData| -> TableData {
        let mut out = data.clone();
        for col in &mut out.schema.columns {
            if let Some(&t) = reconciled_types.get(&col.id) {
                col.col_type = t;
            }
        }
        for row in &mut out.rows {
            for (idx, col) in out.schema.columns.iter().enumerate() {
                if let Some(cell) = row.cells.get_mut(idx) {
                    let old = std::mem::take(cell);
                    *cell = coerce_cell(old, col.col_type);
                }
            }
        }
        out
    };

    (apply_types(left), apply_types(right))
}

fn align_union_schemas(left: &TableData, right: &TableData) -> (TableData, TableData) {
    let mut union_cols: Vec<ColumnDef> = Vec::new();
    let mut index_by_id: HashMap<String, usize> = HashMap::new();

    for col in left.schema.columns.iter().chain(right.schema.columns.iter()) {
        if let Some(&pos) = index_by_id.get(&col.id) {
            let merged = reconcile_column_type(union_cols[pos].col_type, col.col_type);
            union_cols[pos].col_type = merged;
        } else {
            index_by_id.insert(col.id.clone(), union_cols.len());
            union_cols.push(col.clone());
        }
    }

    for col in &mut union_cols {
        col.col_type = resolve_reconciled_column_type(col.col_type, &col.id, left, right);
    }

    (
        project_to_union(left, &union_cols),
        project_to_union(right, &union_cols),
    )
}

fn project_to_union(data: &TableData, union_cols: &[ColumnDef]) -> TableData {
    let index_map: HashMap<&str, usize> = data
        .schema
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.as_str(), i))
        .collect();

    let rows = data
        .rows
        .iter()
        .map(|row| {
            let cells = union_cols
                .iter()
                .map(|c| {
                    let raw = index_map
                        .get(c.id.as_str())
                        .and_then(|&idx| row.cells.get(idx))
                        .cloned()
                        .unwrap_or(CellValue::Null);
                    coerce_cell(raw, c.col_type)
                })
                .collect();
            let mut new_row = Row::new(row.id, cells);
            new_row.detail_json = row.detail_json.clone();
            new_row.raw_bytes = row.raw_bytes.clone();
            new_row
        })
        .collect::<Vec<_>>();

    let mut schema = data.schema.clone();
    schema.columns = union_cols.to_vec();
    let total_rows = rows.len();
    TableData {
        schema,
        rows,
        total_rows,
    }
}

fn prepend_positional_col(data: &TableData) -> TableData {
    let mut cols = Vec::with_capacity(data.schema.columns.len() + 1);
    cols.push(ColumnDef::new("__row_pos", "Row #", ColumnType::Uint));
    cols.extend(data.schema.columns.clone());

    let mut schema = data.schema.clone();
    schema.columns = cols;

    let rows = data
        .rows
        .iter()
        .enumerate()
        .map(|(idx, row)| {
            let mut cells = Vec::with_capacity(row.cells.len() + 1);
            cells.push(CellValue::Uint((idx + 1) as u64));
            cells.extend(row.cells.clone());
            let mut new_row = Row::new(row.id, cells);
            new_row.detail_json = row.detail_json.clone();
            new_row.raw_bytes = row.raw_bytes.clone();
            new_row
        })
        .collect::<Vec<_>>();

    let total_rows = rows.len();
    TableData {
        schema,
        rows,
        total_rows,
    }
}

fn row_to_json_obj(col_ids: &[String], row: &Row) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    for (col_id, cell) in col_ids.iter().zip(row.cells.iter()) {
        map.insert(col_id.clone(), cell.to_json_value());
    }
    map
}
