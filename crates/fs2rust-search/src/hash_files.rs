use fs2rust_core::{FileEntry, FsError, WildcardMatcher};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;
use walkdir::WalkDir;

const HASH_CHUNK_SIZE: usize = 65_536;
const RAW_PREVIEW_CAP: usize = 256;

/// Which digest algorithms to compute during the single-pass file read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashAlgorithmSet {
    pub md5: bool,
    pub sha1: bool,
    pub sha256: bool,
    pub sha512: bool,
    pub crc32: bool,
}

impl Default for HashAlgorithmSet {
    fn default() -> Self {
        Self {
            md5: true,
            sha1: true,
            sha256: true,
            sha512: true,
            crc32: true,
        }
    }
}

impl HashAlgorithmSet {
    fn enabled_names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.md5 {
            names.push("md5");
        }
        if self.sha1 {
            names.push("sha1");
        }
        if self.sha256 {
            names.push("sha256");
        }
        if self.sha512 {
            names.push("sha512");
        }
        if self.crc32 {
            names.push("crc32");
        }
        names
    }
}

/// Configuration for multi-algorithm file hashing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HashFilesConfig {
    pub targets: Vec<PathBuf>,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub algorithms: HashAlgorithmSet,
    pub threads: usize,
}

#[derive(Debug, Clone)]
struct HashedFileResult {
    entry: FileEntry,
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
    sha512: Option<String>,
    crc32: Option<String>,
    raw_preview: Vec<u8>,
    identical_group: Option<u64>,
    identical_count: Option<usize>,
    read_error: Option<String>,
}

/// Single-pass streaming multi-hasher (`TableProvider`).
pub struct HashFilesProvider {
    config: HashFilesConfig,
}

impl HashFilesProvider {
    pub fn new(config: HashFilesConfig) -> Self {
        Self { config }
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "hash_files",
            "Single-Pass Multi-Algorithm File Hasher",
            vec![
                ColumnDef::new("filename", "Filename", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("full_path", "Full Path", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("md5", "MD5", ColumnType::Text).with_width_hint(230),
                ColumnDef::new("sha1", "SHA-1", ColumnType::Text).with_width_hint(270),
                ColumnDef::new("sha256", "SHA-256", ColumnType::Text).with_width_hint(420),
                ColumnDef::new("sha512", "SHA-512", ColumnType::Text).with_width_hint(420),
                ColumnDef::new("crc32", "CRC32", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("size_bytes", "Size", ColumnType::BytesSize).with_width_hint(110),
                ColumnDef::new("modified", "Modified", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("identical_group", "Identical Group", ColumnType::Uint).with_width_hint(100),
            ],
        )
        .with_default_sort(1, SortDirection::Asc)
    }

    pub fn execute(&self) -> Result<Vec<Row>, FsError> {
        let include_matcher = WildcardMatcher::from_patterns(&self.config.include_patterns, false);
        let exclude_matcher = WildcardMatcher::from_patterns(&self.config.exclude_patterns, false);

        let mut files = Vec::new();
        for target in &self.config.targets {
            if !target.exists() {
                return Err(FsError::SourceUnavailable(format!(
                    "hash target does not exist: {}",
                    target.display()
                )));
            }
            let mut walker = WalkDir::new(target).follow_links(self.config.follow_symlinks);
            if let Some(depth) = self.config.max_depth {
                walker = walker.max_depth(depth);
            }
            for item in walker.into_iter().flatten() {
                let p = item.path();
                if !self.config.follow_symlinks && item.path_is_symlink() {
                    continue;
                }
                let meta_res = if self.config.follow_symlinks {
                    std::fs::metadata(p)
                } else {
                    std::fs::symlink_metadata(p)
                };
                let Ok(meta) = meta_res else {
                    continue;
                };
                if meta.is_dir() {
                    continue;
                }
                let entry = FileEntry::from_metadata(p.to_path_buf(), &meta, None);
                if !include_matcher.is_empty() && !include_matcher.is_match(&entry.name) {
                    continue;
                }
                if !exclude_matcher.is_empty() && exclude_matcher.is_match(&entry.name) {
                    continue;
                }
                files.push(entry);
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        files.dedup_by(|a, b| a.path == b.path);

        let threads = if self.config.threads > 0 {
            self.config.threads.min(64)
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get().clamp(1, 16))
                .unwrap_or(4)
        };

        let queue = Mutex::new(VecDeque::from(files));
        let results = Mutex::new(Vec::<HashedFileResult>::new());
        let algos = self.config.algorithms;

        std::thread::scope(|s| {
            for _ in 0..threads.max(1) {
                s.spawn(|| {
                    loop {
                        let entry = queue.lock().expect("hash queue poisoned").pop_front();
                        let Some(entry) = entry else {
                            break;
                        };
                        let res = hash_single_file(entry, algos);
                        results.lock().expect("hash results poisoned").push(res);
                    }
                });
            }
        });

        let mut hashed = results.into_inner().expect("hash results poisoned");
        hashed.sort_by(|a, b| a.entry.path.cmp(&b.entry.path));

        // Group identical files using all enabled digest fields + size.
        #[derive(Ord, PartialOrd, Eq, PartialEq)]
        struct GroupKey(
            u64,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );

        let mut groups: BTreeMap<GroupKey, Vec<usize>> = BTreeMap::new();
        for (idx, item) in hashed.iter().enumerate() {
            if item.read_error.is_some() {
                continue;
            }
            if item.md5.is_none()
                && item.sha1.is_none()
                && item.sha256.is_none()
                && item.sha512.is_none()
                && item.crc32.is_none()
            {
                continue;
            }
            let key = GroupKey(
                item.entry.size,
                item.md5.clone(),
                item.sha1.clone(),
                item.sha256.clone(),
                item.sha512.clone(),
                item.crc32.clone(),
            );
            groups.entry(key).or_default().push(idx);
        }

        let mut next_group = 1u64;
        for indices in groups.values() {
            if indices.len() >= 2 {
                let count = indices.len();
                for &idx in indices {
                    hashed[idx].identical_group = Some(next_group);
                    hashed[idx].identical_count = Some(count);
                }
                next_group += 1;
            }
        }

        let enabled = algos.enabled_names();
        let rows = hashed
            .into_iter()
            .enumerate()
            .map(|(idx, item)| {
                let detail = json!({
                    "extension": item.entry.extension,
                    "created": item.entry.timestamps.created,
                    "identical_count": item.identical_count,
                    "algorithms_computed": enabled,
                    "read_error": item.read_error,
                });
                let mut row = Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(item.entry.name),
                        CellValue::Text(item.entry.path.to_string_lossy().into_owned()),
                        item.md5.map_or(CellValue::Null, CellValue::Text),
                        item.sha1.map_or(CellValue::Null, CellValue::Text),
                        item.sha256.map_or(CellValue::Null, CellValue::Text),
                        item.sha512.map_or(CellValue::Null, CellValue::Text),
                        item.crc32.map_or(CellValue::Null, CellValue::Text),
                        CellValue::Bytes(item.entry.size),
                        item.entry
                            .timestamps
                            .modified
                            .map_or(CellValue::Null, CellValue::Timestamp),
                        item.identical_group.map_or(CellValue::Null, CellValue::Uint),
                    ],
                )
                .with_detail_json(detail);
                if !item.raw_preview.is_empty() {
                    row = row.with_raw_bytes(item.raw_preview);
                }
                row
            })
            .collect();

        Ok(rows)
    }
}

fn hash_single_file(entry: FileEntry, algos: HashAlgorithmSet) -> HashedFileResult {
    let mut file = match File::open(&entry.path) {
        Ok(f) => f,
        Err(err) => {
            return HashedFileResult {
                entry,
                md5: None,
                sha1: None,
                sha256: None,
                sha512: None,
                crc32: None,
                raw_preview: Vec::new(),
                identical_group: None,
                identical_count: None,
                read_error: Some(err.to_string()),
            };
        }
    };

    let mut md5_h = algos.md5.then(<md5::Md5 as md5::Digest>::new);
    let mut sha1_h = algos.sha1.then(<sha1::Sha1 as sha1::Digest>::new);
    let mut sha256_h = algos.sha256.then(<sha2::Sha256 as sha2::Digest>::new);
    let mut sha512_h = algos.sha512.then(<sha2::Sha512 as sha2::Digest>::new);
    let mut crc32_h = algos.crc32.then(crc32fast::Hasher::new);

    let mut raw_preview = Vec::new();
    let mut buf = [0u8; HASH_CHUNK_SIZE];

    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                return HashedFileResult {
                    entry,
                    md5: None,
                    sha1: None,
                    sha256: None,
                    sha512: None,
                    crc32: None,
                    raw_preview,
                    identical_group: None,
                    identical_count: None,
                    read_error: Some(err.to_string()),
                };
            }
        };
        let slice = &buf[..n];
        if raw_preview.is_empty() {
            raw_preview.extend_from_slice(&slice[..n.min(RAW_PREVIEW_CAP)]);
        }
        if let Some(h) = md5_h.as_mut() {
            <md5::Md5 as md5::Digest>::update(h, slice);
        }
        if let Some(h) = sha1_h.as_mut() {
            <sha1::Sha1 as sha1::Digest>::update(h, slice);
        }
        if let Some(h) = sha256_h.as_mut() {
            <sha2::Sha256 as sha2::Digest>::update(h, slice);
        }
        if let Some(h) = sha512_h.as_mut() {
            <sha2::Sha512 as sha2::Digest>::update(h, slice);
        }
        if let Some(h) = crc32_h.as_mut() {
            h.update(slice);
        }
    }

    HashedFileResult {
        entry,
        md5: md5_h.map(|h| hex::encode(<md5::Md5 as md5::Digest>::finalize(h))),
        sha1: sha1_h.map(|h| hex::encode(<sha1::Sha1 as sha1::Digest>::finalize(h))),
        sha256: sha256_h.map(|h| hex::encode(<sha2::Sha256 as sha2::Digest>::finalize(h))),
        sha512: sha512_h.map(|h| hex::encode(<sha2::Sha512 as sha2::Digest>::finalize(h))),
        crc32: crc32_h.map(|h| format!("{:08x}", h.finalize())),
        raw_preview,
        identical_group: None,
        identical_count: None,
        read_error: None,
    }
}

impl TableProvider for HashFilesProvider {
    fn tool_id(&self) -> &'static str {
        "hash_files"
    }

    fn description(&self) -> &'static str {
        "Compute MD5, SHA1, SHA256, SHA512, and CRC32 in a single streaming read pass and group identical files"
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
