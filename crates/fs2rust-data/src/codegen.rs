use crate::csv_view::{CsvTableProvider, CsvViewOptions};
use crate::error::DataError;
use guap_export::{escape_html, escape_markdown_cell};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Input data source for `SimpleCodeGenerator`.
#[derive(Debug, Clone)]
pub enum CodegenInput {
    RegexCapture {
        text: String,
        pattern: String,
        line_by_line: bool,
    },
    Csv {
        bytes: Vec<u8>,
        options: CsvViewOptions,
    },
    Json {
        json_text: String,
    },
    Table(TableData),
}

/// Output language/format target influencing default escaping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodegenTarget {
    Rust,
    Sql,
    Markdown,
    Json,
    Custom,
}

/// Escaping mode applied to substituted values (unless `|raw` filter is specified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EscapeMode {
    #[default]
    Auto,
    None,
    RustString,
    SqlLiteral,
    MarkdownCell,
    JsonString,
    Html,
}

impl EscapeMode {
    fn resolve(self, target: CodegenTarget) -> Self {
        match self {
            Self::Auto => match target {
                CodegenTarget::Rust => Self::RustString,
                CodegenTarget::Sql => Self::SqlLiteral,
                CodegenTarget::Markdown => Self::MarkdownCell,
                CodegenTarget::Json => Self::JsonString,
                CodegenTarget::Custom => Self::None,
            },
            other => other,
        }
    }
}

/// Template specification for `SimpleCodeGenerator`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodegenTemplate {
    pub rule_name: String,
    pub target: CodegenTarget,
    pub header_template: String,
    pub body_template: String,
    pub footer_template: String,
    pub separator: String,
    pub escape_mode: EscapeMode,
    pub strict_placeholders: bool,
}

impl Default for CodegenTemplate {
    fn default() -> Self {
        Self {
            rule_name: "default".to_string(),
            target: CodegenTarget::Custom,
            header_template: String::new(),
            body_template: String::new(),
            footer_template: String::new(),
            separator: "\n".to_string(),
            escape_mode: EscapeMode::Auto,
            strict_placeholders: false,
        }
    }
}

/// Generated output envelope from `SimpleCodeGenerator`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodegenResult {
    pub rule_name: String,
    pub matched_count: usize,
    pub header: String,
    pub snippets: Vec<String>,
    pub footer: String,
    pub combined_output: String,
    pub variables_per_row: Vec<BTreeMap<String, String>>,
}

/// Execute template-based code/snippet generation over `CodegenInput`.
pub fn generate_code(input: &CodegenInput, template: &CodegenTemplate) -> Result<CodegenResult, DataError> {
    let mut records = extract_records(input)?;
    let total = records.len();
    let escape = template.escape_mode.resolve(template.target);

    for (idx, rec) in records.iter_mut().enumerate() {
        rec.insert("row_index".to_string(), idx.to_string());
        rec.insert("row_number".to_string(), (idx + 1).to_string());
        rec.insert("row_count".to_string(), total.to_string());
        rec.insert("rule_name".to_string(), template.rule_name.clone());
    }

    let mut global_vars = BTreeMap::new();
    global_vars.insert("row_count".to_string(), total.to_string());
    global_vars.insert("rule_name".to_string(), template.rule_name.clone());

    let header = substitute_single_pass(
        &template.header_template,
        &global_vars,
        escape,
        template.strict_placeholders,
    )?;
    let footer = substitute_single_pass(
        &template.footer_template,
        &global_vars,
        escape,
        template.strict_placeholders,
    )?;

    let mut snippets = Vec::with_capacity(records.len());
    for rec in &records {
        snippets.push(substitute_single_pass(
            &template.body_template,
            rec,
            escape,
            template.strict_placeholders,
        )?);
    }

    let mut parts = Vec::new();
    if !header.is_empty() {
        parts.push(header.clone());
    }
    if !snippets.is_empty() {
        parts.push(snippets.join(&template.separator));
    }
    if !footer.is_empty() {
        parts.push(footer.clone());
    }
    let combined_output = parts.join(&template.separator);

    Ok(CodegenResult {
        rule_name: template.rule_name.clone(),
        matched_count: total,
        header,
        snippets,
        footer,
        combined_output,
        variables_per_row: records,
    })
}

fn extract_records(input: &CodegenInput) -> Result<Vec<BTreeMap<String, String>>, DataError> {
    match input {
        CodegenInput::RegexCapture {
            text,
            pattern,
            line_by_line,
        } => {
            let re = Regex::new(pattern)?;
            let named: Vec<(usize, String)> = re
                .capture_names()
                .enumerate()
                .filter_map(|(idx, opt)| opt.map(|n| (idx, n.to_string())))
                .collect();
            let mut records = Vec::new();
            let chunks: Vec<&str> = if *line_by_line {
                text.lines().collect()
            } else {
                vec![text.as_str()]
            };
            for chunk in chunks {
                for caps in re.captures_iter(chunk) {
                    let mut map = BTreeMap::new();
                    for i in 0..caps.len() {
                        if let Some(m) = caps.get(i) {
                            map.insert(i.to_string(), m.as_str().to_string());
                        }
                    }
                    for (idx, name) in &named {
                        if let Some(m) = caps.get(*idx) {
                            map.insert(name.clone(), m.as_str().to_string());
                        }
                    }
                    records.push(map);
                }
            }
            Ok(records)
        }
        CodegenInput::Csv { bytes, options } => {
            let td = CsvTableProvider::from_bytes("codegen.csv", bytes, options.clone())?.into_table_data();
            Ok(table_to_records(&td))
        }
        CodegenInput::Table(td) => Ok(table_to_records(td)),
        CodegenInput::Json { json_text } => {
            let val: Value = serde_json::from_str(json_text)?;
            let arr = if let Some(a) = val.as_array() {
                a.clone()
            } else if let Some(rows) = val.get("rows").and_then(Value::as_array) {
                rows.clone()
            } else if val.is_object() {
                vec![val]
            } else {
                return Err(DataError::Template(
                    "JSON codegen input must be an object, array, or {rows: [...]}".to_string(),
                ));
            };

            let mut records = Vec::with_capacity(arr.len());
            for item in arr {
                let obj = item
                    .as_object()
                    .ok_or_else(|| DataError::Template("JSON codegen record must be an object".to_string()))?;
                let mut map = BTreeMap::new();
                for (pos, (k, v)) in obj.iter().enumerate() {
                    let s = match v {
                        Value::Null => String::new(),
                        Value::String(st) => st.clone(),
                        other => other.to_string(),
                    };
                    map.insert(k.clone(), s.clone());
                    map.insert((pos + 1).to_string(), s);
                }
                records.push(map);
            }
            Ok(records)
        }
    }
}

fn table_to_records(td: &TableData) -> Vec<BTreeMap<String, String>> {
    td.rows
        .iter()
        .map(|row| {
            let mut map = BTreeMap::new();
            for (idx, col) in td.schema.columns.iter().enumerate() {
                let val = row
                    .cells
                    .get(idx)
                    .map(|c| {
                        if c.is_null() {
                            String::new()
                        } else {
                            c.format_human(col.col_type)
                        }
                    })
                    .unwrap_or_default();
                map.insert(col.id.clone(), val.clone());
                map.insert(col.label.clone(), val.clone());
                map.insert((idx + 1).to_string(), val);
            }
            map
        })
        .collect()
}

fn substitute_single_pass(
    template: &str,
    vars: &BTreeMap<String, String>,
    default_escape: EscapeMode,
    strict: bool,
) -> Result<String, DataError> {
    let mut out = String::with_capacity(template.len());
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] == '\\' && i + 2 < chars.len() && chars[i + 1] == '{' && chars[i + 2] == '{' {
            out.push_str("{{");
            i += 3;
            continue;
        }
        if chars[i] == '{'
            && i + 1 < chars.len()
            && chars[i + 1] == '{'
            && let Some(close_rel) = find_double_brace_end(&chars[i + 2..])
        {
            let expr: String = chars[i + 2..i + 2 + close_rel].iter().collect();
            let rendered = eval_placeholder(&expr, vars, default_escape, strict)?;
            out.push_str(&rendered);
            i = i + 2 + close_rel + 2;
            continue;
        }
        if chars[i] == '%' {
            if i + 1 < chars.len() && chars[i + 1] == '%' {
                out.push('%');
                i += 2;
                continue;
            }
            if let Some(close_rel) = chars[i + 1..].iter().position(|&c| c == '%') {
                let expr: String = chars[i + 1..i + 1 + close_rel].iter().collect();
                if !expr.is_empty() && !expr.contains('\n') {
                    let key = expr.split('|').next().unwrap_or("").trim();
                    let is_valid_key = !key.is_empty()
                        && key
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
                    if strict || (is_valid_key && vars.contains_key(key)) {
                        let rendered = eval_placeholder(&expr, vars, default_escape, strict)?;
                        out.push_str(&rendered);
                        i = i + 1 + close_rel + 1;
                        continue;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }

    Ok(out)
}

fn find_double_brace_end(slice: &[char]) -> Option<usize> {
    (0..slice.len().saturating_sub(1)).find(|&idx| slice[idx] == '}' && slice[idx + 1] == '}')
}

fn eval_placeholder(
    expr: &str,
    vars: &BTreeMap<String, String>,
    default_escape: EscapeMode,
    strict: bool,
) -> Result<String, DataError> {
    let mut parts = expr.split('|').map(str::trim);
    let key = parts.next().unwrap_or("");
    let raw_val = match vars.get(key) {
        Some(v) => v.clone(),
        None if strict => {
            return Err(DataError::Template(format!("missing placeholder key '{key}'")));
        }
        None => String::new(),
    };

    let mut current = raw_val;
    let mut bypass_escape = false;
    for filter in parts {
        match filter {
            "" => {}
            "upper" => current = current.to_uppercase(),
            "lower" => current = current.to_lowercase(),
            "trim" => current = current.trim().to_string(),
            "rust_ident" => current = to_rust_ident(&current),
            "raw" => bypass_escape = true,
            other => {
                return Err(DataError::Template(format!("unknown placeholder filter '{other}'")));
            }
        }
    }

    if bypass_escape {
        Ok(current)
    } else {
        Ok(apply_escape(&current, default_escape))
    }
}

fn to_rust_ident(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        return "_".to_string();
    }
    if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

fn apply_escape(val: &str, mode: EscapeMode) -> String {
    match mode {
        EscapeMode::Auto | EscapeMode::None => val.to_string(),
        EscapeMode::RustString => {
            let mut out = String::with_capacity(val.len());
            for ch in val.chars() {
                match ch {
                    '\\' => out.push_str("\\\\"),
                    '"' => out.push_str("\\\""),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\0' => out.push_str("\\0"),
                    c => out.push(c),
                }
            }
            out
        }
        EscapeMode::SqlLiteral => val.replace('\0', "").replace('\'', "''"),
        EscapeMode::MarkdownCell => escape_markdown_cell(val),
        EscapeMode::JsonString => {
            let serialized = serde_json::to_string(val).unwrap_or_else(|_| "\"\"".to_string());
            serialized
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&serialized)
                .to_string()
        }
        EscapeMode::Html => escape_html(val),
    }
}

/// `TableProvider` wrapping generated `SimpleCodeGenerator` snippets.
pub struct SimpleCodeGeneratorProvider {
    result: CodegenResult,
}

impl SimpleCodeGeneratorProvider {
    pub fn from_input(input: &CodegenInput, template: &CodegenTemplate) -> Result<Self, DataError> {
        let result = generate_code(input, template)?;
        Ok(Self { result })
    }

    pub fn result(&self) -> &CodegenResult {
        &self.result
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "fs2rust.data.simple_code_generator",
            "SimpleCodeGenerator — Generated Code Snippets",
            vec![
                ColumnDef::new("rule_name", "Rule Name", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("row_index", "Row #", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("matched_count", "Matched Count", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("generated_output", "Generated Output", ColumnType::Text).with_width_hint(360),
                ColumnDef::new("source_preview", "Source Variables", ColumnType::Text).with_width_hint(260),
            ],
        )
    }
}

impl TableProvider for SimpleCodeGeneratorProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.simple_code_generator"
    }

    fn description(&self) -> &'static str {
        "Template-based snippet generator from regex captures, CSV, JSON, or TableData"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let rows: Vec<Row> = self
            .result
            .snippets
            .iter()
            .enumerate()
            .map(|(idx, snippet)| {
                let vars = self.result.variables_per_row.get(idx).cloned().unwrap_or_default();
                let preview = serde_json::to_string(&vars).unwrap_or_default();
                let detail = json!({
                    "variables": vars,
                    "header": self.result.header,
                    "footer": self.result.footer,
                    "combined_output": if idx == 0 { Some(&self.result.combined_output) } else { None },
                });
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(self.result.rule_name.clone()),
                        CellValue::Uint(idx as u64),
                        CellValue::Uint(self.result.matched_count as u64),
                        CellValue::Text(snippet.clone()),
                        CellValue::Text(preview),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
