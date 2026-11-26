use chrono::{DateTime, TimeDelta, Utc};
use fs2rust_core::{FileAttributes, FileEntry, FileSystemOps, FileTimestamps, FsError, PolicyContext};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Selects which timestamp field to copy from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampField {
    Created,
    Modified,
    Accessed,
}

/// Specifies how a single timestamp field should be transformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampChange {
    #[default]
    Keep,
    SetExact(DateTime<Utc>),
    ShiftSeconds(i64),
    CopyFrom(TimestampField),
}

impl TimestampChange {
    fn resolve(self, current: Option<DateTime<Utc>>, ts: &FileTimestamps) -> Result<Option<DateTime<Utc>>, FsError> {
        match self {
            Self::Keep => Ok(current),
            Self::SetExact(dt) => Ok(Some(dt)),
            Self::ShiftSeconds(secs) => match current {
                None => Ok(None),
                Some(dt) => {
                    let delta = TimeDelta::try_seconds(secs)
                        .ok_or_else(|| FsError::TimeConversion(format!("shift_seconds {secs} overflows TimeDelta")))?;
                    let shifted = dt
                        .checked_add_signed(delta)
                        .ok_or_else(|| FsError::TimeConversion(format!("shift_seconds {secs} overflows DateTime")))?;
                    Ok(Some(shifted))
                }
            },
            Self::CopyFrom(field) => Ok(match field {
                TimestampField::Created => ts.created,
                TimestampField::Modified => ts.modified,
                TimestampField::Accessed => ts.accessed,
            }),
        }
    }
}

/// Specification for bulk timestamp & attribute changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BulkChangeSpec {
    pub targets: Vec<PathBuf>,
    pub recursive: bool,
    pub created: TimestampChange,
    pub modified: TimestampChange,
    pub accessed: TimestampChange,
    pub set_attrs: FileAttributes,
    pub clear_attrs: FileAttributes,
}

#[derive(Debug, Clone, Serialize)]
struct PlannedBulkChange {
    path: PathBuf,
    is_dir: bool,
    old_ts: FileTimestamps,
    new_ts: FileTimestamps,
    old_attrs: FileAttributes,
    new_attrs: FileAttributes,
    times_changed: bool,
    attrs_changed: bool,
    will_change: bool,
}

/// Read-only preview `TableProvider` for `BulkFileChanger`.
pub struct BulkFileChangerPreviewProvider {
    spec: BulkChangeSpec,
    backend: Arc<dyn FileSystemOps>,
}

impl BulkFileChangerPreviewProvider {
    pub fn new(spec: BulkChangeSpec, backend: Arc<dyn FileSystemOps>) -> Self {
        Self { spec, backend }
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "bulk_file_changer",
            "BulkFileChanger — Preview Timestamp & Attribute Changes",
            vec![
                ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("old_created", "Old Created", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("old_modified", "Old Modified", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("old_accessed", "Old Accessed", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("new_created", "New Created", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("new_modified", "New Modified", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("new_accessed", "New Accessed", ColumnType::Timestamp).with_width_hint(175),
                ColumnDef::new("old_attributes", "Old Attrs", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("new_attributes", "New Attrs", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("will_change", "Will Change", ColumnType::Bool).with_width_hint(80),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(130),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn expand_targets(spec: &BulkChangeSpec, backend: &dyn FileSystemOps) -> Result<Vec<FileEntry>, FsError> {
        let mut entries = Vec::new();
        for target in &spec.targets {
            let meta = backend.metadata(target)?;
            let is_dir = meta.is_dir && !meta.is_symlink;
            entries.push(meta);
            if spec.recursive && is_dir {
                collect_recursive(target, backend, &mut entries)?;
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries.dedup_by(|a, b| a.path == b.path);
        Ok(entries)
    }

    fn plan_changes(spec: &BulkChangeSpec, backend: &dyn FileSystemOps) -> Result<Vec<PlannedBulkChange>, FsError> {
        let entries = Self::expand_targets(spec, backend)?;
        let mut plans = Vec::with_capacity(entries.len());
        for entry in entries {
            let new_ts = FileTimestamps {
                created: spec.created.resolve(entry.timestamps.created, &entry.timestamps)?,
                modified: spec.modified.resolve(entry.timestamps.modified, &entry.timestamps)?,
                accessed: spec.accessed.resolve(entry.timestamps.accessed, &entry.timestamps)?,
            };
            let new_attrs = entry.attributes.with_applied(&spec.set_attrs, &spec.clear_attrs);
            let times_changed = new_ts != entry.timestamps;
            let attrs_changed = (new_attrs.to_raw() & FileAttributes::USER_MUTABLE_MASK)
                != (entry.attributes.to_raw() & FileAttributes::USER_MUTABLE_MASK);
            let will_change = times_changed || attrs_changed;
            plans.push(PlannedBulkChange {
                path: entry.path,
                is_dir: entry.is_dir,
                old_ts: entry.timestamps,
                new_ts,
                old_attrs: entry.attributes,
                new_attrs,
                times_changed,
                attrs_changed,
                will_change,
            });
        }
        Ok(plans)
    }
}

fn collect_recursive(dir: &Path, backend: &dyn FileSystemOps, out: &mut Vec<FileEntry>) -> Result<(), FsError> {
    let children = backend.read_dir(dir)?;
    for child in children {
        if child.is_symlink {
            continue;
        }
        let is_dir = child.is_dir;
        let p = child.path.clone();
        out.push(child);
        if is_dir {
            collect_recursive(&p, backend, out)?;
        }
    }
    Ok(())
}

impl TableProvider for BulkFileChangerPreviewProvider {
    fn tool_id(&self) -> &'static str {
        "bulk_file_changer"
    }

    fn description(&self) -> &'static str {
        "Preview bulk file/folder timestamp and attribute changes (ReadOnly dry-run)"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let plans = Self::plan_changes(&self.spec, self.backend.as_ref()).map_err(TableError::from)?;
        let rows: Vec<Row> = plans
            .into_iter()
            .enumerate()
            .map(|(idx, p)| {
                let status = if p.will_change { "Preview" } else { "Unchanged" };
                let detail = json!({
                    "is_dir": p.is_dir,
                    "old_attr_bits": p.old_attrs.to_raw(),
                    "new_attr_bits": p.new_attrs.to_raw(),
                    "error": Value::Null,
                });
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(p.path.to_string_lossy().into_owned()),
                        p.old_ts.created.map_or(CellValue::Null, CellValue::Timestamp),
                        p.old_ts.modified.map_or(CellValue::Null, CellValue::Timestamp),
                        p.old_ts.accessed.map_or(CellValue::Null, CellValue::Timestamp),
                        p.new_ts.created.map_or(CellValue::Null, CellValue::Timestamp),
                        p.new_ts.modified.map_or(CellValue::Null, CellValue::Timestamp),
                        p.new_ts.accessed.map_or(CellValue::Null, CellValue::Timestamp),
                        CellValue::Text(p.old_attrs.format_flags()),
                        CellValue::Text(p.new_attrs.format_flags()),
                        CellValue::Bool(p.will_change),
                        CellValue::Text(status.to_string()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&self.schema(), &rows, req)
    }
}

/// Mutating `ActionCommand` applying `BulkFileChanger` timestamps & attributes.
pub struct BulkFileChangerAction {
    backend: Arc<dyn FileSystemOps>,
    policy: PolicyContext,
}

impl BulkFileChangerAction {
    pub fn new(backend: Arc<dyn FileSystemOps>) -> Self {
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

fn parse_timestamp_change(val: Option<&Value>) -> Result<TimestampChange, McpToolError> {
    let Some(v) = val else {
        return Ok(TimestampChange::Keep);
    };
    if v.is_null() {
        return Ok(TimestampChange::Keep);
    }
    if let Some(s) = v.as_str() {
        if s.eq_ignore_ascii_case("keep") {
            return Ok(TimestampChange::Keep);
        }
        let dt = DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|e| McpToolError::InvalidParams(format!("invalid RFC3339 timestamp '{s}': {e}")))?;
        return Ok(TimestampChange::SetExact(dt));
    }
    if let Some(obj) = v.as_object() {
        if let Some(exact) = obj.get("set_exact").and_then(Value::as_str) {
            let dt = DateTime::parse_from_rfc3339(exact)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| McpToolError::InvalidParams(format!("invalid set_exact '{exact}': {e}")))?;
            return Ok(TimestampChange::SetExact(dt));
        }
        if let Some(secs) = obj.get("shift_seconds").and_then(Value::as_i64) {
            return Ok(TimestampChange::ShiftSeconds(secs));
        }
        if let Some(field) = obj.get("copy_from").and_then(Value::as_str) {
            let tf = match field.to_ascii_lowercase().as_str() {
                "created" => TimestampField::Created,
                "modified" => TimestampField::Modified,
                "accessed" => TimestampField::Accessed,
                other => {
                    return Err(McpToolError::InvalidParams(format!(
                        "invalid copy_from field '{other}'"
                    )));
                }
            };
            return Ok(TimestampChange::CopyFrom(tf));
        }
    }
    serde_json::from_value::<TimestampChange>(v.clone())
        .map_err(|e| McpToolError::InvalidParams(format!("invalid timestamp change: {e}")))
}

fn parse_attr_list(val: Option<&Value>) -> Result<FileAttributes, McpToolError> {
    let Some(v) = val else {
        return Ok(FileAttributes::default());
    };
    if v.is_null() {
        return Ok(FileAttributes::default());
    }
    if let Some(s) = v.as_str() {
        return FileAttributes::parse_flags(s).map_err(McpToolError::from);
    }
    if let Some(arr) = v.as_array() {
        let mut raw = 0u32;
        for item in arr {
            let s = item
                .as_str()
                .ok_or_else(|| McpToolError::InvalidParams("attribute list items must be strings".to_string()))?;
            raw |= FileAttributes::parse_flags(s).map_err(McpToolError::from)?.to_raw();
        }
        return Ok(FileAttributes::from_raw(raw));
    }
    Err(McpToolError::InvalidParams(
        "attributes must be a flag string or string array".to_string(),
    ))
}

fn apply_single_plan(plan: &PlannedBulkChange, backend: &dyn FileSystemOps) -> Result<(), FsError> {
    if !plan.will_change {
        return Ok(());
    }

    let delta_ts = FileTimestamps {
        created: if plan.new_ts.created != plan.old_ts.created {
            plan.new_ts.created
        } else {
            None
        },
        modified: if plan.new_ts.modified != plan.old_ts.modified {
            plan.new_ts.modified
        } else {
            None
        },
        accessed: if plan.new_ts.accessed != plan.old_ts.accessed {
            plan.new_ts.accessed
        } else {
            None
        },
    };

    // Enforce ReadOnly ordering invariant:
    // - Clear READONLY before writing timestamps.
    // - Set READONLY after writing timestamps.
    if plan.times_changed {
        if plan.old_attrs.read_only && !plan.is_dir {
            let mut unlocked = plan.old_attrs;
            unlocked.read_only = false;
            backend.set_attributes(&plan.path, &unlocked)?;
        }
        backend.set_timestamps(&plan.path, &delta_ts)?;
        if plan.attrs_changed || (plan.old_attrs.read_only && plan.new_attrs.read_only && !plan.is_dir) {
            backend.set_attributes(&plan.path, &plan.new_attrs)?;
        }
    } else if plan.attrs_changed {
        backend.set_attributes(&plan.path, &plan.new_attrs)?;
    }

    Ok(())
}

impl ActionCommand for BulkFileChangerAction {
    fn command_id(&self) -> &'static str {
        "bulk_file_changer_apply"
    }

    fn description(&self) -> &'static str {
        "Apply bulk timestamp and attribute changes to target files and folders"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["targets"],
            "properties": {
                "targets": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of file or folder paths to update"
                },
                "recursive": { "type": "boolean", "default": false },
                "created": { "description": "TimestampChange ('keep', RFC3339 string, or {set_exact/shift_seconds/copy_from})" },
                "modified": { "description": "TimestampChange" },
                "accessed": { "description": "TimestampChange" },
                "set_attributes": { "type": "array", "items": { "type": "string" } },
                "clear_attributes": { "type": "array", "items": { "type": "string" } }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let targets_arr = args
            .get("targets")
            .and_then(Value::as_array)
            .ok_or_else(|| McpToolError::InvalidParams("missing required array 'targets'".to_string()))?;
        if targets_arr.is_empty() {
            return Err(McpToolError::InvalidParams("'targets' cannot be empty".to_string()));
        }
        let mut targets = Vec::with_capacity(targets_arr.len());
        for t in targets_arr {
            let s = t
                .as_str()
                .ok_or_else(|| McpToolError::InvalidParams("target path must be a string".to_string()))?;
            let target_path = PathBuf::from(s);
            self.policy
                .check_path_allowed(&target_path)
                .map_err(McpToolError::from)?;
            targets.push(target_path);
        }

        let spec = BulkChangeSpec {
            targets,
            recursive: args.get("recursive").and_then(Value::as_bool).unwrap_or(false),
            created: parse_timestamp_change(args.get("created"))?,
            modified: parse_timestamp_change(args.get("modified"))?,
            accessed: parse_timestamp_change(args.get("accessed"))?,
            set_attrs: parse_attr_list(args.get("set_attributes"))?,
            clear_attrs: parse_attr_list(args.get("clear_attributes"))?,
        };

        let plans =
            BulkFileChangerPreviewProvider::plan_changes(&spec, self.backend.as_ref()).map_err(McpToolError::from)?;

        for plan in &plans {
            self.policy.check_path_allowed(&plan.path).map_err(McpToolError::from)?;
        }

        if dry_run {
            let planned_changes: Vec<Value> = plans
                .iter()
                .map(|p| {
                    json!({
                        "path": p.path.to_string_lossy(),
                        "will_change": p.will_change,
                        "old_attributes": p.old_attrs.format_flags(),
                        "new_attributes": p.new_attrs.format_flags(),
                        "old_modified": p.old_ts.modified,
                        "new_modified": p.new_ts.modified,
                    })
                })
                .collect();
            return Ok(json!({
                "mode": "dry_run",
                "planned": planned_changes.len(),
                "changes": planned_changes,
            }));
        }

        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let mut results = Vec::with_capacity(plans.len());

        for plan in &plans {
            match apply_single_plan(plan, self.backend.as_ref()) {
                Ok(()) => {
                    if plan.will_change {
                        succeeded += 1;
                    }
                    results.push(json!({
                        "path": plan.path.to_string_lossy(),
                        "status": if plan.will_change { "Applied" } else { "Unchanged" },
                        "old_attributes": plan.old_attrs.format_flags(),
                        "new_attributes": plan.new_attrs.format_flags(),
                    }));
                }
                Err(err) => {
                    failed += 1;
                    results.push(json!({
                        "path": plan.path.to_string_lossy(),
                        "status": "Error",
                        "error": err.to_string(),
                    }));
                }
            }
        }

        Ok(json!({
            "mode": "applied",
            "succeeded": succeeded,
            "failed": failed,
            "results": results,
        }))
    }
}
