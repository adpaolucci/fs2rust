use chrono::{DateTime, Utc};
use fs2rust_core::{FileAttributes, FileEntry, FileTimestamps, FsError, WildcardMatcher};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use regex::bytes::Regex as BytesRegex;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use walkdir::WalkDir;

const CHUNK_SIZE: usize = 65_536;
const MAX_REGEX_BYTES: u64 = 64 * 1024 * 1024;
const SNIPPET_CAP: usize = 256;

/// Content grep mode for `SearchMyFiles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentSearchMode {
    PlainText { needle: String, case_sensitive: bool },
    Regex(String),
    BinaryHex(Vec<u8>),
}

/// Parse a hex byte string like `"4D 5A 90 00"` or `"4d5a9000"` into raw bytes.
pub fn parse_hex_pattern(spec: &str) -> Result<Vec<u8>, FsError> {
    let compact: String = spec.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    if compact.is_empty() {
        return Err(FsError::InvalidArgument(
            "binary hex pattern cannot be empty".to_string(),
        ));
    }
    if !compact.len().is_multiple_of(2) {
        return Err(FsError::InvalidArgument(
            "binary hex pattern must contain an even number of hex digits".to_string(),
        ));
    }
    hex::decode(&compact).map_err(|e| FsError::InvalidArgument(format!("invalid hex pattern: {e}")))
}

/// Configuration for `SearchMyFiles`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMyFilesConfig {
    pub roots: Vec<PathBuf>,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub exclude_dirs: Vec<String>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub modified_after: Option<DateTime<Utc>>,
    pub modified_before: Option<DateTime<Utc>>,
    pub accessed_after: Option<DateTime<Utc>>,
    pub accessed_before: Option<DateTime<Utc>>,
    pub required_attrs: FileAttributes,
    pub excluded_attrs: FileAttributes,
    pub include_files: bool,
    pub include_dirs: bool,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub content_filter: Option<ContentSearchMode>,
    pub compute_sha256: bool,
    pub group_duplicates: bool,
    pub threads: usize,
}

impl Default for SearchMyFilesConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            exclude_dirs: Vec::new(),
            min_size: None,
            max_size: None,
            created_after: None,
            created_before: None,
            modified_after: None,
            modified_before: None,
            accessed_after: None,
            accessed_before: None,
            required_attrs: FileAttributes::default(),
            excluded_attrs: FileAttributes::default(),
            include_files: true,
            include_dirs: false,
            max_depth: None,
            follow_symlinks: false,
            content_filter: None,
            compute_sha256: false,
            group_duplicates: false,
            threads: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct CandidateEntry {
    entry: FileEntry,
}

#[derive(Debug, Clone)]
struct EvaluatedMatch {
    entry: FileEntry,
    matched_offset: Option<u64>,
    matched_snippet: Option<Vec<u8>>,
    sha256: Option<String>,
    duplicate_group: Option<u64>,
    duplicate_count: Option<usize>,
    read_error: Option<String>,
}

enum CompiledContent {
    PlainExact(Vec<u8>),
    PlainAsciiCi(Vec<u8>),
    Regex(BytesRegex),
    BinaryHex(Vec<u8>),
}

/// Pure-Rust multi-threaded `SearchMyFiles` provider (`TableProvider`).
pub struct SearchMyFilesProvider {
    config: SearchMyFilesConfig,
}

impl SearchMyFilesProvider {
    pub fn new(config: SearchMyFilesConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SearchMyFilesConfig {
        &self.config
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "search_my_files",
            "SearchMyFiles — File & Content Search",
            vec![
                ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("folder", "Folder", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("extension", "Extension", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("size_bytes", "Size", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("created", "Created", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("modified", "Modified", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("accessed", "Accessed", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("attributes", "Attributes", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("matched_offset", "Match Offset", ColumnType::Uint).with_width_hint(110),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("duplicate_group", "Dup Group", ColumnType::Uint).with_width_hint(100),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    /// Execute the configured search and build all `Row`s.
    pub fn execute(&self) -> Result<Vec<Row>, FsError> {
        let compiled_content = match &self.config.content_filter {
            Some(ContentSearchMode::PlainText { needle, case_sensitive }) => {
                if needle.is_empty() {
                    return Err(FsError::InvalidArgument(
                        "plain-text needle cannot be empty".to_string(),
                    ));
                }
                if *case_sensitive {
                    Some(CompiledContent::PlainExact(needle.as_bytes().to_vec()))
                } else {
                    Some(CompiledContent::PlainAsciiCi(
                        needle.as_bytes().iter().map(|b| b.to_ascii_lowercase()).collect(),
                    ))
                }
            }
            Some(ContentSearchMode::Regex(pat)) => {
                let re = BytesRegex::new(pat)
                    .map_err(|e| FsError::InvalidArgument(format!("invalid search regex '{pat}': {e}")))?;
                Some(CompiledContent::Regex(re))
            }
            Some(ContentSearchMode::BinaryHex(bytes)) => {
                if bytes.is_empty() {
                    return Err(FsError::InvalidArgument(
                        "binary hex needle cannot be empty".to_string(),
                    ));
                }
                Some(CompiledContent::BinaryHex(bytes.clone()))
            }
            None => None,
        };

        let include_matcher = WildcardMatcher::from_patterns(&self.config.include_patterns, false);
        let exclude_matcher = WildcardMatcher::from_patterns(&self.config.exclude_patterns, false);
        let exclude_dir_matcher = WildcardMatcher::from_patterns(&self.config.exclude_dirs, false);

        let mut candidates = Vec::new();
        for root in &self.config.roots {
            if !root.exists() {
                return Err(FsError::SourceUnavailable(format!(
                    "search root does not exist: {}",
                    root.display()
                )));
            }
            let mut walker = WalkDir::new(root).follow_links(self.config.follow_symlinks);
            if let Some(depth) = self.config.max_depth {
                walker = walker.max_depth(depth);
            }
            let iter = walker.into_iter().filter_entry(|e| {
                if e.depth() > 0 && e.file_type().is_dir() && !exclude_dir_matcher.is_empty() {
                    let name = e.file_name().to_string_lossy();
                    return !exclude_dir_matcher.is_match(&name);
                }
                true
            });

            for item in iter {
                let Ok(dir_entry) = item else {
                    continue;
                };
                let path = dir_entry.path();
                if !self.config.follow_symlinks && dir_entry.path_is_symlink() {
                    continue;
                }
                let meta_res = if self.config.follow_symlinks {
                    std::fs::metadata(path)
                } else {
                    std::fs::symlink_metadata(path)
                };
                let Ok(meta) = meta_res else {
                    continue;
                };
                let is_dir = meta.is_dir();
                if is_dir && !self.config.include_dirs {
                    continue;
                }
                if !is_dir && !self.config.include_files {
                    continue;
                }
                let entry = FileEntry::from_metadata(path.to_path_buf(), &meta, None);
                if !self.matches_metadata_filters(&entry, &include_matcher, &exclude_matcher) {
                    continue;
                }
                candidates.push(CandidateEntry { entry });
            }
        }

        // Size pre-counting so duplicate grouping skips hashing unique-sized files unless compute_sha256 is set.
        let mut size_counts: HashMap<u64, usize> = HashMap::new();
        if self.config.group_duplicates && !self.config.compute_sha256 {
            for c in &candidates {
                if !c.entry.is_dir {
                    *size_counts.entry(c.entry.size).or_insert(0) += 1;
                }
            }
        }

        let threads = if self.config.threads > 0 {
            self.config.threads.min(64)
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get().clamp(1, 16))
                .unwrap_or(4)
        };

        let queue = Mutex::new(VecDeque::from(candidates));
        let results = Mutex::new(Vec::<EvaluatedMatch>::new());
        let compute_sha256 = self.config.compute_sha256;
        let group_duplicates = self.config.group_duplicates;

        std::thread::scope(|s| {
            let worker_count = threads.max(1);
            for _ in 0..worker_count {
                s.spawn(|| {
                    loop {
                        let batch: Vec<CandidateEntry> = {
                            let mut q = queue.lock().expect("search queue poisoned");
                            let take = q.len().min(16);
                            q.drain(..take).collect()
                        };
                        if batch.is_empty() {
                            break;
                        }
                        let mut local_out = Vec::with_capacity(batch.len());
                        for item in batch {
                            if let Some(ev) = evaluate_candidate(
                                item.entry,
                                compiled_content.as_ref(),
                                compute_sha256,
                                group_duplicates,
                                &size_counts,
                            ) {
                                local_out.push(ev);
                            }
                        }
                        if !local_out.is_empty() {
                            results.lock().expect("search results poisoned").extend(local_out);
                        }
                    }
                });
            }
        });

        let mut evaluated = results.into_inner().expect("search results poisoned");

        // Assign deterministic duplicate groups for identical SHA-256 hashes (count >= 2).
        if self.config.group_duplicates {
            let mut by_hash: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (idx, item) in evaluated.iter().enumerate() {
                if !item.entry.is_dir
                    && let Some(hash) = &item.sha256
                {
                    by_hash.entry(hash.clone()).or_default().push(idx);
                }
            }
            let mut next_group = 1u64;
            for indices in by_hash.values() {
                if indices.len() >= 2 {
                    let count = indices.len();
                    for &idx in indices {
                        evaluated[idx].duplicate_group = Some(next_group);
                        evaluated[idx].duplicate_count = Some(count);
                    }
                    next_group += 1;
                }
            }
        }

        if self.config.group_duplicates {
            evaluated.sort_by(|a, b| {
                a.duplicate_group
                    .unwrap_or(u64::MAX)
                    .cmp(&b.duplicate_group.unwrap_or(u64::MAX))
                    .then_with(|| a.entry.path.cmp(&b.entry.path))
            });
        } else {
            evaluated.sort_by(|a, b| a.entry.path.cmp(&b.entry.path));
        }

        let rows = evaluated
            .into_iter()
            .enumerate()
            .map(|(idx, item)| {
                let folder = item
                    .entry
                    .path
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let preview = item
                    .matched_snippet
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned());
                let detail = serde_json::json!({
                    "full_path": item.entry.path.to_string_lossy(),
                    "is_dir": item.entry.is_dir,
                    "attr_bits": item.entry.attributes.to_raw(),
                    "matched_preview": preview,
                    "duplicate_count": item.duplicate_count,
                    "read_error": item.read_error,
                });
                let mut row = Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(item.entry.name),
                        CellValue::Text(folder),
                        CellValue::Text(item.entry.extension),
                        CellValue::Bytes(item.entry.size),
                        item.entry
                            .timestamps
                            .created
                            .map_or(CellValue::Null, CellValue::Timestamp),
                        item.entry
                            .timestamps
                            .modified
                            .map_or(CellValue::Null, CellValue::Timestamp),
                        item.entry
                            .timestamps
                            .accessed
                            .map_or(CellValue::Null, CellValue::Timestamp),
                        CellValue::Text(item.entry.attributes.format_flags()),
                        item.matched_offset.map_or(CellValue::Null, CellValue::Uint),
                        item.sha256.map_or(CellValue::Null, CellValue::Text),
                        item.duplicate_group.map_or(CellValue::Null, CellValue::Uint),
                    ],
                )
                .with_detail_json(detail);
                if let Some(raw) = item.matched_snippet {
                    row = row.with_raw_bytes(raw);
                }
                row
            })
            .collect();

        Ok(rows)
    }

    fn matches_metadata_filters(
        &self,
        entry: &FileEntry,
        include_matcher: &WildcardMatcher,
        exclude_matcher: &WildcardMatcher,
    ) -> bool {
        if !include_matcher.is_empty() && !include_matcher.is_match(&entry.name) {
            return false;
        }
        if !exclude_matcher.is_empty() && exclude_matcher.is_match(&entry.name) {
            return false;
        }
        if !entry.is_dir {
            if let Some(min_sz) = self.config.min_size
                && entry.size < min_sz
            {
                return false;
            }
            if let Some(max_sz) = self.config.max_size
                && entry.size > max_sz
            {
                return false;
            }
        }
        if !matches_time_bounds(&entry.timestamps, &self.config) {
            return false;
        }
        if !entry.attributes.contains_all(&self.config.required_attrs) {
            return false;
        }
        if entry.attributes.intersects(&self.config.excluded_attrs) {
            return false;
        }
        true
    }
}

fn matches_time_bounds(ts: &FileTimestamps, cfg: &SearchMyFilesConfig) -> bool {
    if let Some(after) = cfg.created_after
        && ts.created.is_none_or(|t| t < after)
    {
        return false;
    }
    if let Some(before) = cfg.created_before
        && ts.created.is_none_or(|t| t > before)
    {
        return false;
    }
    if let Some(after) = cfg.modified_after
        && ts.modified.is_none_or(|t| t < after)
    {
        return false;
    }
    if let Some(before) = cfg.modified_before
        && ts.modified.is_none_or(|t| t > before)
    {
        return false;
    }
    if let Some(after) = cfg.accessed_after
        && ts.accessed.is_none_or(|t| t < after)
    {
        return false;
    }
    if let Some(before) = cfg.accessed_before
        && ts.accessed.is_none_or(|t| t > before)
    {
        return false;
    }
    true
}

fn evaluate_candidate(
    entry: FileEntry,
    content: Option<&CompiledContent>,
    compute_sha256: bool,
    group_duplicates: bool,
    size_counts: &HashMap<u64, usize>,
) -> Option<EvaluatedMatch> {
    if entry.is_dir {
        if content.is_some() {
            return None;
        }
        return Some(EvaluatedMatch {
            entry,
            matched_offset: None,
            matched_snippet: None,
            sha256: None,
            duplicate_group: None,
            duplicate_count: None,
            read_error: None,
        });
    }

    let need_hash = compute_sha256 || (group_duplicates && size_counts.get(&entry.size).copied().unwrap_or(0) >= 2);

    let mut matched_offset = None;
    let mut matched_snippet = None;
    let mut read_error = None;

    if let Some(filter) = content {
        match search_file_content(&entry.path, entry.size, filter) {
            Ok(Some((offset, snippet))) => {
                matched_offset = Some(offset);
                matched_snippet = Some(snippet);
            }
            Ok(None) => return None,
            Err(_) => return None,
        }
    }

    let sha256 = if need_hash {
        match compute_file_sha256(&entry.path) {
            Ok(digest) => Some(digest),
            Err(err) => {
                read_error = Some(err.to_string());
                None
            }
        }
    } else {
        None
    };

    Some(EvaluatedMatch {
        entry,
        matched_offset,
        matched_snippet,
        sha256,
        duplicate_group: None,
        duplicate_count: None,
        read_error,
    })
}

fn compute_file_sha256(path: &Path) -> Result<String, FsError> {
    let mut file = File::open(path).map_err(|e| FsError::from_io(path, e))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).map_err(|e| FsError::from_io(path, e))?;
        if n == 0 {
            break;
        }
        sha2::Digest::update(&mut hasher, &buf[..n]);
    }
    Ok(hex::encode(sha2::Digest::finalize(hasher)))
}

fn search_file_content(path: &Path, size: u64, compiled: &CompiledContent) -> Result<Option<(u64, Vec<u8>)>, FsError> {
    match compiled {
        CompiledContent::PlainExact(needle) | CompiledContent::BinaryHex(needle) => {
            search_chunked_bytes(path, needle, false)
        }
        CompiledContent::PlainAsciiCi(needle_lower) => search_chunked_bytes(path, needle_lower, true),
        CompiledContent::Regex(re) => {
            if size > MAX_REGEX_BYTES {
                return Err(FsError::InvalidArgument(format!(
                    "file exceeds {MAX_REGEX_BYTES} byte regex scan limit: {}",
                    path.display()
                )));
            }
            let bytes = std::fs::read(path).map_err(|e| FsError::from_io(path, e))?;
            if let Some(m) = re.find(&bytes) {
                let end = (m.start() + SNIPPET_CAP).min(bytes.len());
                Ok(Some((m.start() as u64, bytes[m.start()..end].to_vec())))
            } else {
                Ok(None)
            }
        }
    }
}

fn search_chunked_bytes(path: &Path, needle: &[u8], ascii_ci: bool) -> Result<Option<(u64, Vec<u8>)>, FsError> {
    let mut file = File::open(path).map_err(|e| FsError::from_io(path, e))?;
    let overlap = needle.len().saturating_sub(1);
    let mut buf = Vec::with_capacity(CHUNK_SIZE + overlap);
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut stream_offset = 0u64;

    loop {
        let n = file.read(&mut chunk).map_err(|e| FsError::from_io(path, e))?;
        if n == 0 {
            break;
        }
        buf.clear();
        let tail_len = tail.len();
        buf.extend_from_slice(&tail);
        buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = find_subslice(&buf, needle, ascii_ci) {
            let abs_offset = stream_offset - tail_len as u64 + pos as u64;
            let snip_end = (pos + SNIPPET_CAP).min(buf.len());
            return Ok(Some((abs_offset, buf[pos..snip_end].to_vec())));
        }

        tail.clear();
        if overlap > 0 {
            let keep = overlap.min(buf.len());
            tail.extend_from_slice(&buf[buf.len() - keep..]);
        }
        stream_offset += n as u64;
    }

    Ok(None)
}

fn find_subslice(haystack: &[u8], needle: &[u8], ascii_ci: bool) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    if !ascii_ci {
        return haystack.windows(needle.len()).position(|w| w == needle);
    }
    haystack
        .windows(needle.len())
        .position(|w| w.iter().zip(needle.iter()).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

impl TableProvider for SearchMyFilesProvider {
    fn tool_id(&self) -> &'static str {
        "search_my_files"
    }

    fn description(&self) -> &'static str {
        "Search files and directories with wildcards, size/time/attribute filters, text/regex/binary content grep, and SHA-256 duplicate grouping"
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
