use chrono::{DateTime, Utc};
use fs2rust_core::{FileEntry, FileSystemOps, FsError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Configuration for `FoldersReport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldersReportConfig {
    pub root: PathBuf,
    pub depth: usize,
    pub include_root_files_row: bool,
    pub follow_symlinks: bool,
    pub threads: usize,
}

impl Default for FoldersReportConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            depth: 1,
            include_root_files_row: true,
            follow_symlinks: false,
            threads: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct FolderStats {
    name: String,
    path: PathBuf,
    parent_path: PathBuf,
    depth: usize,
    files_count: u64,
    subfolders_count: u64,
    total_size_bytes: u64,
    size_on_disk_bytes: u64,
    modified: Option<DateTime<Utc>>,
    skipped_errors: u64,
}

/// Parallel directory size, allocated/compressed size, and count reporter (`TableProvider`).
pub struct FoldersReportProvider {
    config: FoldersReportConfig,
    backend: Arc<dyn FileSystemOps>,
}

impl FoldersReportProvider {
    pub fn new(config: FoldersReportConfig, backend: Arc<dyn FileSystemOps>) -> Self {
        Self { config, backend }
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "folders_report",
            "FoldersReport — Subtree Size & File Counts",
            vec![
                ColumnDef::new("folder_name", "Folder Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("folder_path", "Folder Path", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("files_count", "Files", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("subfolders_count", "Subfolders", ColumnType::Uint).with_width_hint(110),
                ColumnDef::new("total_size_bytes", "Total Size", ColumnType::BytesSize).with_width_hint(120),
                ColumnDef::new("size_on_disk_bytes", "Size on Disk", ColumnType::BytesSize).with_width_hint(120),
                ColumnDef::new("pct_of_parent", "% of Parent", ColumnType::Float).with_width_hint(90),
                ColumnDef::new("modified", "Modified", ColumnType::Timestamp).with_width_hint(180),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    pub fn execute(&self) -> Result<Vec<Row>, FsError> {
        let root_meta = self.backend.metadata(&self.config.root)?;
        if !root_meta.is_dir {
            return Err(FsError::InvalidPath(format!(
                "folders_report root is not a directory: {}",
                self.config.root.display()
            )));
        }

        let top_children = self.backend.read_dir(&self.config.root)?;
        let mut root_direct_files = FolderStats {
            name: "(root files)".to_string(),
            path: self.config.root.clone(),
            depth: 0,
            modified: root_meta.timestamps.modified,
            ..FolderStats::default()
        };
        let mut child_dirs = Vec::new();

        let root_canon = if self.config.follow_symlinks {
            Some(std::fs::canonicalize(&self.config.root).unwrap_or_else(|_| self.config.root.clone()))
        } else {
            None
        };

        for child in top_children {
            if child.is_symlink && !self.config.follow_symlinks {
                continue;
            }
            if child.is_dir {
                if let Some(rc) = &root_canon {
                    let child_canon = std::fs::canonicalize(&child.path).unwrap_or_else(|_| child.path.clone());
                    if &child_canon == rc {
                        continue;
                    }
                }
                child_dirs.push(child);
            } else {
                if child.is_symlink && !std::fs::metadata(&child.path).map(|m| m.is_file()).unwrap_or(false) {
                    continue;
                }
                root_direct_files.files_count += 1;
                root_direct_files.total_size_bytes += child.size;
                let on_disk = child
                    .compressed_size
                    .unwrap_or_else(|| self.backend.compressed_size(&child.path).unwrap_or(child.size));
                root_direct_files.size_on_disk_bytes += on_disk;
            }
        }

        let threads = if self.config.threads > 0 {
            self.config.threads.min(64)
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get().clamp(1, 16))
                .unwrap_or(4)
        };

        let queue = Mutex::new(VecDeque::from(child_dirs));
        let all_stats = Mutex::new(Vec::<FolderStats>::new());
        let max_report_depth = self.config.depth.max(1);
        let follow_symlinks = self.config.follow_symlinks;
        let backend = Arc::clone(&self.backend);
        let root_path = &self.config.root;
        let root_canon_ref = &root_canon;

        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    loop {
                        let next: Option<FileEntry> = queue.lock().expect("folders queue poisoned").pop_front();
                        let Some(dir_entry) = next else {
                            break;
                        };
                        let mut ancestors = HashSet::new();
                        if let Some(rc) = root_canon_ref {
                            ancestors.insert(rc.clone());
                        }
                        let mut collected = Vec::new();
                        let _ = aggregate_subtree(
                            &dir_entry,
                            root_path,
                            1,
                            max_report_depth,
                            follow_symlinks,
                            backend.as_ref(),
                            &mut ancestors,
                            &mut collected,
                        );
                        all_stats.lock().expect("folders stats poisoned").extend(collected);
                    }
                });
            }
        });

        let mut stats = all_stats.into_inner().expect("folders stats poisoned");
        let depth1_sum: u64 = stats.iter().filter(|s| s.depth == 1).map(|s| s.total_size_bytes).sum();
        let root_total = depth1_sum + root_direct_files.total_size_bytes;

        let mut folder_totals: HashMap<PathBuf, u64> = HashMap::with_capacity(stats.len() + 1);
        folder_totals.insert(self.config.root.clone(), root_total);
        for st in &stats {
            folder_totals.insert(st.path.clone(), st.total_size_bytes);
        }

        if self.config.include_root_files_row && root_direct_files.files_count > 0 {
            stats.push(root_direct_files);
        }

        stats.sort_by(|a, b| {
            b.total_size_bytes
                .cmp(&a.total_size_bytes)
                .then_with(|| a.path.cmp(&b.path))
        });

        let rows = stats
            .into_iter()
            .enumerate()
            .map(|(idx, st)| {
                let parent_total = if st.depth == 0 {
                    root_total
                } else {
                    folder_totals.get(&st.parent_path).copied().unwrap_or(root_total)
                };
                let pct = if parent_total == 0 {
                    0.0
                } else {
                    (st.total_size_bytes as f64 / parent_total as f64) * 100.0
                };
                let compression_ratio = if st.total_size_bytes == 0 {
                    100.0
                } else {
                    (st.size_on_disk_bytes as f64 / st.total_size_bytes as f64) * 100.0
                };
                let detail = json!({
                    "depth": st.depth,
                    "total_size_human": CellValue::Bytes(st.total_size_bytes).format_human(ColumnType::BytesSize),
                    "size_on_disk_human": CellValue::Bytes(st.size_on_disk_bytes).format_human(ColumnType::BytesSize),
                    "compression_ratio_pct": compression_ratio,
                    "skipped_errors": st.skipped_errors,
                });
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(st.name),
                        CellValue::Text(st.path.to_string_lossy().into_owned()),
                        CellValue::Uint(st.files_count),
                        CellValue::Uint(st.subfolders_count),
                        CellValue::Bytes(st.total_size_bytes),
                        CellValue::Bytes(st.size_on_disk_bytes),
                        CellValue::Float((pct * 100.0).round() / 100.0),
                        st.modified.map_or(CellValue::Null, CellValue::Timestamp),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();

        Ok(rows)
    }
}

#[allow(clippy::too_many_arguments)]
fn aggregate_subtree(
    dir_entry: &FileEntry,
    parent_path: &Path,
    depth: usize,
    max_report_depth: usize,
    follow_symlinks: bool,
    backend: &dyn FileSystemOps,
    ancestors: &mut HashSet<PathBuf>,
    out: &mut Vec<FolderStats>,
) -> FolderStats {
    let canon = if follow_symlinks {
        let c = std::fs::canonicalize(&dir_entry.path).unwrap_or_else(|_| dir_entry.path.clone());
        if !ancestors.insert(c.clone()) {
            return FolderStats::default();
        }
        Some(c)
    } else {
        None
    };

    let mut stats = FolderStats {
        name: dir_entry.name.clone(),
        path: dir_entry.path.clone(),
        parent_path: parent_path.to_path_buf(),
        depth,
        modified: dir_entry.timestamps.modified,
        ..FolderStats::default()
    };

    let children = match backend.read_dir(&dir_entry.path) {
        Ok(c) => c,
        Err(_) => {
            stats.skipped_errors += 1;
            if depth <= max_report_depth {
                out.push(stats.clone());
            }
            if let Some(c) = canon {
                ancestors.remove(&c);
            }
            return stats;
        }
    };

    for child in children {
        if child.is_symlink && !follow_symlinks {
            continue;
        }
        if child.is_dir {
            if follow_symlinks {
                let child_canon = std::fs::canonicalize(&child.path).unwrap_or_else(|_| child.path.clone());
                if ancestors.contains(&child_canon) {
                    continue;
                }
            }
            stats.subfolders_count += 1;
            let sub = aggregate_subtree(
                &child,
                &dir_entry.path,
                depth + 1,
                max_report_depth,
                follow_symlinks,
                backend,
                ancestors,
                out,
            );
            stats.files_count += sub.files_count;
            stats.subfolders_count += sub.subfolders_count;
            stats.total_size_bytes += sub.total_size_bytes;
            stats.size_on_disk_bytes += sub.size_on_disk_bytes;
            stats.skipped_errors += sub.skipped_errors;
        } else {
            if child.is_symlink && !std::fs::metadata(&child.path).map(|m| m.is_file()).unwrap_or(false) {
                continue;
            }
            stats.files_count += 1;
            stats.total_size_bytes += child.size;
            let on_disk = child
                .compressed_size
                .unwrap_or_else(|| backend.compressed_size(&child.path).unwrap_or(child.size));
            stats.size_on_disk_bytes += on_disk;
        }
    }

    if depth <= max_report_depth {
        out.push(stats.clone());
    }
    if let Some(c) = canon {
        ancestors.remove(&c);
    }
    stats
}

/// Helper to read compressed size with fallback for callers outside `FoldersReportProvider`.
pub fn safe_compressed_size(path: &Path, fallback: u64, backend: &dyn FileSystemOps) -> u64 {
    backend.compressed_size(path).unwrap_or(fallback)
}

impl TableProvider for FoldersReportProvider {
    fn tool_id(&self) -> &'static str {
        "folders_report"
    }

    fn description(&self) -> &'static str {
        "Compute directory logical size, allocated/compressed size on disk, file/subfolder counts, and parent percentage"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let rows = self.execute().map_err(TableError::from)?;
        apply_query(&self.schema(), &rows, req)
    }
}
