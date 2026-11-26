use chrono::{DateTime, Utc};
use fs2rust_core::{FileSystemOps, FileTimestamps, FsError, PolicyContext, WildcardMatcher};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Timestamp propagation mode for folder timestamp updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderTimeSource {
    #[default]
    NewestFileOnly,
    NewestFileOrSubdir,
}

/// Configuration for folder timestamp updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderTimeUpdateConfig {
    pub root: PathBuf,
    pub source: FolderTimeSource,
    pub update_modified: bool,
    pub update_created: bool,
    pub update_accessed: bool,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub update_empty_dirs: bool,
    pub exclude_dirs: Vec<String>,
}

impl Default for FolderTimeUpdateConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            source: FolderTimeSource::NewestFileOnly,
            update_modified: true,
            update_created: false,
            update_accessed: false,
            max_depth: None,
            follow_symlinks: false,
            update_empty_dirs: false,
            exclude_dirs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SubtreeTimes {
    newest_modified: Option<(DateTime<Utc>, PathBuf)>,
    newest_created: Option<(DateTime<Utc>, PathBuf)>,
    newest_accessed: Option<(DateTime<Utc>, PathBuf)>,
    files_scanned: u64,
}

impl SubtreeTimes {
    fn observe_time(slot: &mut Option<(DateTime<Utc>, PathBuf)>, candidate: Option<DateTime<Utc>>, path: &Path) {
        let Some(dt) = candidate else {
            return;
        };
        let replace = match slot {
            Some((existing, _)) => dt > *existing,
            None => true,
        };
        if replace {
            *slot = Some((dt, path.to_path_buf()));
        }
    }

    fn merge(&mut self, child: &SubtreeTimes) {
        self.files_scanned += child.files_scanned;
        if let Some((dt, p)) = &child.newest_modified {
            Self::observe_time(&mut self.newest_modified, Some(*dt), p);
        }
        if let Some((dt, p)) = &child.newest_created {
            Self::observe_time(&mut self.newest_created, Some(*dt), p);
        }
        if let Some((dt, p)) = &child.newest_accessed {
            Self::observe_time(&mut self.newest_accessed, Some(*dt), p);
        }
    }
}

#[derive(Debug, Clone)]
struct FolderUpdatePlan {
    folder_path: PathBuf,
    old_modified: Option<DateTime<Utc>>,
    old_created: Option<DateTime<Utc>>,
    old_accessed: Option<DateTime<Utc>>,
    target_modified: Option<DateTime<Utc>>,
    target_created: Option<DateTime<Utc>>,
    target_accessed: Option<DateTime<Utc>>,
    source_child_path: Option<PathBuf>,
    files_scanned: u64,
    would_update: bool,
}

/// Read-only preview `TableProvider` for bottom-up folder timestamp propagation.
pub struct FolderTimeUpdatePreviewProvider {
    config: FolderTimeUpdateConfig,
    backend: Arc<dyn FileSystemOps>,
}

impl FolderTimeUpdatePreviewProvider {
    pub fn new(config: FolderTimeUpdateConfig, backend: Arc<dyn FileSystemOps>) -> Self {
        Self { config, backend }
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "folder_time_update",
            "Folder Time Update — Preview Bottom-Up Folder Timestamps",
            vec![
                ColumnDef::new("folder_path", "Folder Path", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("old_modified", "Old Modified", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("old_created", "Old Created", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("latest_child_time", "Latest Child Time", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("files_scanned", "Files Scanned", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("updated", "Updated", ColumnType::Bool).with_width_hint(80),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(130),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn plan_post_order(
        cfg: &FolderTimeUpdateConfig,
        backend: &dyn FileSystemOps,
    ) -> Result<Vec<FolderUpdatePlan>, FsError> {
        let root_meta = backend.metadata(&cfg.root)?;
        if !root_meta.is_dir {
            return Err(FsError::InvalidPath(format!(
                "folder_time_update root is not a directory: {}",
                cfg.root.display()
            )));
        }
        let exclude_matcher = WildcardMatcher::from_patterns(&cfg.exclude_dirs, false);
        let mut visited = HashSet::new();
        if cfg.follow_symlinks {
            let canon = std::fs::canonicalize(&cfg.root).unwrap_or_else(|_| cfg.root.clone());
            visited.insert(canon);
        }
        let mut plans = Vec::new();
        let _ = walk_post_order(&cfg.root, 0, cfg, backend, &exclude_matcher, &mut visited, &mut plans)?;
        Ok(plans)
    }
}

fn walk_post_order(
    dir: &Path,
    depth: usize,
    cfg: &FolderTimeUpdateConfig,
    backend: &dyn FileSystemOps,
    exclude_matcher: &WildcardMatcher,
    visited: &mut HashSet<PathBuf>,
    plans: &mut Vec<FolderUpdatePlan>,
) -> Result<(SubtreeTimes, FileTimestamps), FsError> {
    let dir_meta = backend.metadata(dir)?;
    let mut current = SubtreeTimes::default();

    let children = backend.read_dir(dir)?;
    for child in children {
        if child.is_symlink && !cfg.follow_symlinks {
            continue;
        }
        if child.is_dir {
            if !exclude_matcher.is_empty() && exclude_matcher.is_match(&child.name) {
                continue;
            }
            if cfg.max_depth.is_none_or(|max| depth < max) {
                if cfg.follow_symlinks {
                    let child_canon = std::fs::canonicalize(&child.path).unwrap_or_else(|_| child.path.clone());
                    if !visited.insert(child_canon) {
                        continue;
                    }
                }
                let (sub, child_effective_ts) =
                    walk_post_order(&child.path, depth + 1, cfg, backend, exclude_matcher, visited, plans)?;
                current.merge(&sub);
                if cfg.source == FolderTimeSource::NewestFileOrSubdir {
                    SubtreeTimes::observe_time(&mut current.newest_modified, child_effective_ts.modified, &child.path);
                    SubtreeTimes::observe_time(&mut current.newest_created, child_effective_ts.created, &child.path);
                    SubtreeTimes::observe_time(&mut current.newest_accessed, child_effective_ts.accessed, &child.path);
                }
            }
        } else {
            if child.is_symlink && !std::fs::metadata(&child.path).map(|m| m.is_file()).unwrap_or(false) {
                continue;
            }
            current.files_scanned += 1;
            SubtreeTimes::observe_time(&mut current.newest_modified, child.timestamps.modified, &child.path);
            SubtreeTimes::observe_time(&mut current.newest_created, child.timestamps.created, &child.path);
            SubtreeTimes::observe_time(&mut current.newest_accessed, child.timestamps.accessed, &child.path);
        }
    }

    let eligible = current.files_scanned > 0 || cfg.update_empty_dirs;
    let target_modified = if eligible && cfg.update_modified {
        current.newest_modified.as_ref().map(|(dt, _)| *dt)
    } else {
        None
    };
    let target_created = if eligible && cfg.update_created {
        current.newest_created.as_ref().map(|(dt, _)| *dt)
    } else {
        None
    };
    let target_accessed = if eligible && cfg.update_accessed {
        current.newest_accessed.as_ref().map(|(dt, _)| *dt)
    } else {
        None
    };

    let mut would_update = false;
    if let Some(m) = target_modified
        && dir_meta.timestamps.modified != Some(m)
    {
        would_update = true;
    }
    if let Some(c) = target_created
        && dir_meta.timestamps.created != Some(c)
    {
        would_update = true;
    }
    if let Some(a) = target_accessed
        && dir_meta.timestamps.accessed != Some(a)
    {
        would_update = true;
    }

    let source_child_path = current
        .newest_modified
        .as_ref()
        .or(current.newest_created.as_ref())
        .or(current.newest_accessed.as_ref())
        .map(|(_, p)| p.clone());

    let effective_ts = FileTimestamps {
        created: target_created.or(dir_meta.timestamps.created),
        modified: target_modified.or(dir_meta.timestamps.modified),
        accessed: target_accessed.or(dir_meta.timestamps.accessed),
    };

    plans.push(FolderUpdatePlan {
        folder_path: dir.to_path_buf(),
        old_modified: dir_meta.timestamps.modified,
        old_created: dir_meta.timestamps.created,
        old_accessed: dir_meta.timestamps.accessed,
        target_modified,
        target_created,
        target_accessed,
        source_child_path,
        files_scanned: current.files_scanned,
        would_update,
    });

    Ok((current, effective_ts))
}

impl TableProvider for FolderTimeUpdatePreviewProvider {
    fn tool_id(&self) -> &'static str {
        "folder_time_update"
    }

    fn description(&self) -> &'static str {
        "Preview bottom-up folder timestamp updates from newest child files (ReadOnly)"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let plans = Self::plan_post_order(&self.config, self.backend.as_ref()).map_err(TableError::from)?;
        let rows: Vec<Row> = plans
            .into_iter()
            .enumerate()
            .map(|(idx, p)| {
                let latest = p.target_modified.or(p.target_created).or(p.target_accessed);
                let status = if p.would_update { "Preview" } else { "NoChange" };
                let detail = json!({
                    "source_child_path": p.source_child_path.map(|s| s.to_string_lossy().into_owned()),
                    "old_accessed": p.old_accessed,
                    "target_modified": p.target_modified,
                    "target_created": p.target_created,
                    "error": Value::Null,
                });
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(p.folder_path.to_string_lossy().into_owned()),
                        p.old_modified.map_or(CellValue::Null, CellValue::Timestamp),
                        p.old_created.map_or(CellValue::Null, CellValue::Timestamp),
                        latest.map_or(CellValue::Null, CellValue::Timestamp),
                        CellValue::Uint(p.files_scanned),
                        CellValue::Bool(false),
                        CellValue::Text(status.to_string()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        apply_query(&self.schema(), &rows, req)
    }
}

/// Mutating `ActionCommand` applying post-order folder timestamp propagation.
pub struct FolderTimeUpdateAction {
    backend: Arc<dyn FileSystemOps>,
    policy: PolicyContext,
}

impl FolderTimeUpdateAction {
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

impl ActionCommand for FolderTimeUpdateAction {
    fn command_id(&self) -> &'static str {
        "folder_time_update_apply"
    }

    fn description(&self) -> &'static str {
        "Update folder timestamps bottom-up to match their newest child files"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["root"],
            "properties": {
                "root": { "type": "string" },
                "source": { "type": "string", "enum": ["newest_file_only", "newest_file_or_subdir"], "default": "newest_file_only" },
                "update_modified": { "type": "boolean", "default": true },
                "update_created": { "type": "boolean", "default": false },
                "update_accessed": { "type": "boolean", "default": false },
                "max_depth": { "type": "integer", "minimum": 0 },
                "follow_symlinks": { "type": "boolean", "default": false },
                "update_empty_dirs": { "type": "boolean", "default": false },
                "exclude_dirs": { "type": "array", "items": { "type": "string" } }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let root = args
            .get("root")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing required string 'root'".to_string()))?;

        let source = match args.get("source").and_then(Value::as_str) {
            None | Some("newest_file_only") => FolderTimeSource::NewestFileOnly,
            Some("newest_file_or_subdir") => FolderTimeSource::NewestFileOrSubdir,
            Some(other) => {
                return Err(McpToolError::InvalidParams(format!("invalid source mode '{other}'")));
            }
        };

        let exclude_dirs = args
            .get("exclude_dirs")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let cfg = FolderTimeUpdateConfig {
            root: PathBuf::from(root),
            source,
            update_modified: args.get("update_modified").and_then(Value::as_bool).unwrap_or(true),
            update_created: args.get("update_created").and_then(Value::as_bool).unwrap_or(false),
            update_accessed: args.get("update_accessed").and_then(Value::as_bool).unwrap_or(false),
            max_depth: args.get("max_depth").and_then(Value::as_u64).map(|v| v as usize),
            follow_symlinks: args.get("follow_symlinks").and_then(Value::as_bool).unwrap_or(false),
            update_empty_dirs: args.get("update_empty_dirs").and_then(Value::as_bool).unwrap_or(false),
            exclude_dirs,
        };

        self.policy.check_path_allowed(&cfg.root).map_err(McpToolError::from)?;

        let plans = FolderTimeUpdatePreviewProvider::plan_post_order(&cfg, self.backend.as_ref())
            .map_err(McpToolError::from)?;

        for p in &plans {
            self.policy
                .check_path_allowed(&p.folder_path)
                .map_err(McpToolError::from)?;
        }

        if dry_run {
            let preview: Vec<Value> = plans
                .iter()
                .map(|p| {
                    json!({
                        "folder_path": p.folder_path.to_string_lossy(),
                        "would_update": p.would_update,
                        "old_modified": p.old_modified,
                        "target_modified": p.target_modified,
                        "files_scanned": p.files_scanned,
                    })
                })
                .collect();
            return Ok(json!({
                "mode": "dry_run",
                "folders_scanned": preview.len(),
                "folders": preview,
            }));
        }

        let mut updated = 0usize;
        let mut failed = 0usize;
        let mut results = Vec::with_capacity(plans.len());

        // Plans are already ordered bottom-up (post-order).
        for p in &plans {
            if !p.would_update {
                results.push(json!({
                    "folder_path": p.folder_path.to_string_lossy(),
                    "updated": false,
                    "status": "NoChange",
                }));
                continue;
            }
            let ts = FileTimestamps {
                created: p.target_created,
                modified: p.target_modified,
                accessed: p.target_accessed,
            };
            match self.backend.set_timestamps(&p.folder_path, &ts) {
                Ok(()) => {
                    updated += 1;
                    results.push(json!({
                        "folder_path": p.folder_path.to_string_lossy(),
                        "updated": true,
                        "status": "Applied",
                        "target_modified": p.target_modified,
                    }));
                }
                Err(err) => {
                    failed += 1;
                    results.push(json!({
                        "folder_path": p.folder_path.to_string_lossy(),
                        "updated": false,
                        "status": "Error",
                        "error": err.to_string(),
                    }));
                }
            }
        }

        Ok(json!({
            "mode": "applied",
            "updated": updated,
            "failed": failed,
            "results": results,
        }))
    }
}
