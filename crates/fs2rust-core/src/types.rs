use crate::error::FsError;
use chrono::{DateTime, TimeZone, Utc};
use guap_mcp::PolicyMode;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 100-nanosecond intervals between Windows FILETIME epoch (1601-01-01) and Unix epoch (1970-01-01).
pub const WINDOWS_EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

/// Win32 file attributes bitflags and decoded booleans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct FileAttributes {
    pub raw: u32,
    pub read_only: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub compressed: bool,
    pub encrypted: bool,
    pub reparse_point: bool,
    pub sparse_file: bool,
    pub temporary: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
}

impl FileAttributes {
    pub const READONLY: u32 = 0x0000_0001;
    pub const HIDDEN: u32 = 0x0000_0002;
    pub const SYSTEM: u32 = 0x0000_0004;
    pub const DIRECTORY: u32 = 0x0000_0010;
    pub const ARCHIVE: u32 = 0x0000_0020;
    pub const NORMAL: u32 = 0x0000_0080;
    pub const TEMPORARY: u32 = 0x0000_0100;
    pub const SPARSE_FILE: u32 = 0x0000_0200;
    pub const REPARSE_POINT: u32 = 0x0000_0400;
    pub const COMPRESSED: u32 = 0x0000_0800;
    pub const OFFLINE: u32 = 0x0000_1000;
    pub const NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
    pub const ENCRYPTED: u32 = 0x0000_4000;

    /// Attribute bits that may be safely toggled by user-space `SetFileAttributesW`.
    pub const USER_MUTABLE_MASK: u32 =
        Self::READONLY | Self::HIDDEN | Self::SYSTEM | Self::ARCHIVE | Self::TEMPORARY | Self::NOT_CONTENT_INDEXED;

    /// Construct from a raw Win32 `dwFileAttributes` bitmask.
    pub fn from_raw(raw: u32) -> Self {
        Self {
            raw,
            read_only: (raw & Self::READONLY) != 0,
            hidden: (raw & Self::HIDDEN) != 0,
            system: (raw & Self::SYSTEM) != 0,
            directory: (raw & Self::DIRECTORY) != 0,
            archive: (raw & Self::ARCHIVE) != 0,
            compressed: (raw & Self::COMPRESSED) != 0,
            encrypted: (raw & Self::ENCRYPTED) != 0,
            reparse_point: (raw & Self::REPARSE_POINT) != 0,
            sparse_file: (raw & Self::SPARSE_FILE) != 0,
            temporary: (raw & Self::TEMPORARY) != 0,
            offline: (raw & Self::OFFLINE) != 0,
            not_content_indexed: (raw & Self::NOT_CONTENT_INDEXED) != 0,
        }
    }

    /// Reconstruct the Win32 `dwFileAttributes` bitmask from the boolean fields and preserved raw bits.
    pub fn to_raw(&self) -> u32 {
        let mut bits = self.raw
            & !(Self::READONLY
                | Self::HIDDEN
                | Self::SYSTEM
                | Self::DIRECTORY
                | Self::ARCHIVE
                | Self::COMPRESSED
                | Self::ENCRYPTED
                | Self::REPARSE_POINT
                | Self::SPARSE_FILE
                | Self::TEMPORARY
                | Self::OFFLINE
                | Self::NOT_CONTENT_INDEXED);
        if self.read_only {
            bits |= Self::READONLY;
        }
        if self.hidden {
            bits |= Self::HIDDEN;
        }
        if self.system {
            bits |= Self::SYSTEM;
        }
        if self.directory {
            bits |= Self::DIRECTORY;
        }
        if self.archive {
            bits |= Self::ARCHIVE;
        }
        if self.compressed {
            bits |= Self::COMPRESSED;
        }
        if self.encrypted {
            bits |= Self::ENCRYPTED;
        }
        if self.reparse_point {
            bits |= Self::REPARSE_POINT;
        }
        if self.sparse_file {
            bits |= Self::SPARSE_FILE;
        }
        if self.temporary {
            bits |= Self::TEMPORARY;
        }
        if self.offline {
            bits |= Self::OFFLINE;
        }
        if self.not_content_indexed {
            bits |= Self::NOT_CONTENT_INDEXED;
        }
        bits
    }

    /// Extract attributes from `std::fs::Metadata`.
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            Self::from_raw(meta.file_attributes())
        }
        #[cfg(not(windows))]
        {
            let mut raw = 0u32;
            if meta.permissions().readonly() {
                raw |= Self::READONLY;
            }
            if meta.is_dir() {
                raw |= Self::DIRECTORY;
            }
            Self::from_raw(raw)
        }
    }

    /// Return a compact attribute flag string such as `"RHSA"`, `"D"`, or `"-"`.
    pub fn format_flags(&self) -> String {
        let mut out = String::new();
        if self.read_only {
            out.push('R');
        }
        if self.hidden {
            out.push('H');
        }
        if self.system {
            out.push('S');
        }
        if self.directory {
            out.push('D');
        }
        if self.archive {
            out.push('A');
        }
        if self.compressed {
            out.push('C');
        }
        if self.encrypted {
            out.push('E');
        }
        if self.reparse_point {
            out.push('L');
        }
        if self.sparse_file {
            out.push('P');
        }
        if self.temporary {
            out.push('T');
        }
        if self.offline {
            out.push('O');
        }
        if self.not_content_indexed {
            out.push('I');
        }
        if out.is_empty() {
            out.push('-');
        }
        out
    }

    /// Parse flag letters (e.g. `"RHS"`, `"R,A"`) or symbolic attribute names (`"readonly"`, `"hidden"`).
    pub fn parse_flags(spec: &str) -> Result<Self, FsError> {
        let trimmed = spec.trim();
        if trimmed.is_empty() || trimmed == "-" {
            return Ok(Self::default());
        }

        let mut raw = 0u32;
        if trimmed.contains(',') || trimmed.contains(';') || trimmed.contains(' ') {
            for token in trimmed.split([',', ';', ' ']).map(str::trim).filter(|s| !s.is_empty()) {
                raw |= Self::parse_single_token(token)?;
            }
        } else {
            let upper = trimmed.to_ascii_uppercase();
            if matches!(
                upper.as_str(),
                "READONLY"
                    | "READ_ONLY"
                    | "HIDDEN"
                    | "SYSTEM"
                    | "DIRECTORY"
                    | "DIR"
                    | "ARCHIVE"
                    | "COMPRESSED"
                    | "ENCRYPTED"
                    | "REPARSE"
                    | "REPARSE_POINT"
                    | "SPARSE"
                    | "TEMPORARY"
                    | "TEMP"
                    | "OFFLINE"
                    | "NOT_CONTENT_INDEXED"
                    | "NONE"
            ) {
                raw |= Self::parse_single_token(&upper)?;
            } else {
                for ch in upper.chars() {
                    raw |= match ch {
                        'R' => Self::READONLY,
                        'H' => Self::HIDDEN,
                        'S' => Self::SYSTEM,
                        'D' => Self::DIRECTORY,
                        'A' => Self::ARCHIVE,
                        'C' => Self::COMPRESSED,
                        'E' => Self::ENCRYPTED,
                        'L' => Self::REPARSE_POINT,
                        'P' => Self::SPARSE_FILE,
                        'T' => Self::TEMPORARY,
                        'O' => Self::OFFLINE,
                        'I' => Self::NOT_CONTENT_INDEXED,
                        '-' => 0,
                        other => {
                            return Err(FsError::InvalidArgument(format!(
                                "unknown file attribute flag '{other}'"
                            )));
                        }
                    };
                }
            }
        }
        Ok(Self::from_raw(raw))
    }

    fn parse_single_token(token: &str) -> Result<u32, FsError> {
        match token.to_ascii_uppercase().as_str() {
            "R" | "READONLY" | "READ_ONLY" => Ok(Self::READONLY),
            "H" | "HIDDEN" => Ok(Self::HIDDEN),
            "S" | "SYSTEM" => Ok(Self::SYSTEM),
            "D" | "DIRECTORY" | "DIR" => Ok(Self::DIRECTORY),
            "A" | "ARCHIVE" => Ok(Self::ARCHIVE),
            "C" | "COMPRESSED" => Ok(Self::COMPRESSED),
            "E" | "ENCRYPTED" => Ok(Self::ENCRYPTED),
            "L" | "REPARSE" | "REPARSE_POINT" => Ok(Self::REPARSE_POINT),
            "P" | "SPARSE" | "SPARSE_FILE" => Ok(Self::SPARSE_FILE),
            "T" | "TEMPORARY" | "TEMP" => Ok(Self::TEMPORARY),
            "O" | "OFFLINE" => Ok(Self::OFFLINE),
            "I" | "NOT_CONTENT_INDEXED" => Ok(Self::NOT_CONTENT_INDEXED),
            "-" | "NONE" => Ok(0),
            other => Err(FsError::InvalidArgument(format!("unknown file attribute '{other}'"))),
        }
    }

    /// Return attributes with all bits in `set_mask` enabled.
    pub fn with_applied(&self, set_mask: &Self, clear_mask: &Self) -> Self {
        let raw = (self.to_raw() | (set_mask.to_raw() & Self::USER_MUTABLE_MASK))
            & !(clear_mask.to_raw() & Self::USER_MUTABLE_MASK);
        Self::from_raw(raw)
    }

    /// Check if all enabled bits in `required` are present in `self`.
    pub fn contains_all(&self, required: &Self) -> bool {
        let req = required.to_raw();
        (self.to_raw() & req) == req
    }

    /// Check if any enabled bit in `excluded` is present in `self`.
    pub fn intersects(&self, excluded: &Self) -> bool {
        (self.to_raw() & excluded.to_raw()) != 0
    }
}

/// File creation, modification, and last-access timestamps in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FileTimestamps {
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
}

impl FileTimestamps {
    /// Extract timestamps from `std::fs::Metadata`.
    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        Self {
            created: meta.created().ok().map(system_time_to_utc),
            modified: meta.modified().ok().map(system_time_to_utc),
            accessed: meta.accessed().ok().map(system_time_to_utc),
        }
    }
}

/// Convert a 64-bit Windows `FILETIME` (100ns ticks since 1601-01-01 UTC) into `DateTime<Utc>`.
/// Returns `None` for zero or pre-Unix-epoch timestamps that cannot be represented if out of range.
pub fn windows_filetime_to_datetime(filetime: u64) -> Option<DateTime<Utc>> {
    if filetime == 0 {
        return None;
    }
    if filetime >= WINDOWS_EPOCH_DIFF_100NS {
        let unix_100ns = filetime - WINDOWS_EPOCH_DIFF_100NS;
        let secs = (unix_100ns / 10_000_000) as i64;
        let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
        Utc.timestamp_opt(secs, nanos).single()
    } else {
        let before_unix_100ns = WINDOWS_EPOCH_DIFF_100NS - filetime;
        let whole_secs = (before_unix_100ns / 10_000_000) as i64;
        let rem_100ns = (before_unix_100ns % 10_000_000) as u32;
        if rem_100ns == 0 {
            Utc.timestamp_opt(-whole_secs, 0).single()
        } else {
            Utc.timestamp_opt(-whole_secs - 1, (10_000_000 - rem_100ns) * 100)
                .single()
        }
    }
}

/// Convert low/high `u32` parts of a Windows `FILETIME` into `DateTime<Utc>`.
pub fn windows_filetime_parts_to_datetime(low: u32, high: u32) -> Option<DateTime<Utc>> {
    windows_filetime_to_datetime(((high as u64) << 32) | (low as u64))
}

/// Convert a `DateTime<Utc>` into a 64-bit Windows `FILETIME`.
pub fn datetime_to_windows_filetime(dt: DateTime<Utc>) -> Result<u64, FsError> {
    let secs = dt.timestamp();
    let nanos = dt.timestamp_subsec_nanos();
    let total_100ns = i128::from(secs) * 10_000_000 + i128::from(nanos / 100) + i128::from(WINDOWS_EPOCH_DIFF_100NS);
    if total_100ns < 0 || total_100ns > i128::from(u64::MAX) {
        return Err(FsError::TimeConversion(format!(
            "timestamp {} is outside Windows FILETIME range",
            dt.to_rfc3339()
        )));
    }
    Ok(total_100ns as u64)
}

/// Convert a `DateTime<Utc>` into `(dwLowDateTime, dwHighDateTime)`.
pub fn datetime_to_windows_filetime_parts(dt: DateTime<Utc>) -> Result<(u32, u32), FsError> {
    let ft = datetime_to_windows_filetime(dt)?;
    Ok((ft as u32, (ft >> 32) as u32))
}

/// Convert `std::time::SystemTime` into `DateTime<Utc>`.
pub fn system_time_to_utc(st: SystemTime) -> DateTime<Utc> {
    match st.duration_since(UNIX_EPOCH) {
        Ok(dur) => DateTime::<Utc>::from(UNIX_EPOCH + dur),
        Err(err) => {
            let d = err.duration();
            let neg_st = UNIX_EPOCH
                .checked_sub(Duration::new(d.as_secs(), d.subsec_nanos()))
                .unwrap_or(UNIX_EPOCH);
            DateTime::<Utc>::from(neg_st)
        }
    }
}

/// Canonical filesystem entry snapshot shared across `fs2rust` crates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub compressed_size: Option<u64>,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub timestamps: FileTimestamps,
    pub attributes: FileAttributes,
}

impl FileEntry {
    /// Construct a `FileEntry` from a path and `std::fs::Metadata`.
    pub fn from_metadata(path: PathBuf, meta: &std::fs::Metadata, compressed_size: Option<u64>) -> Self {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        let extension = if meta.is_dir() {
            String::new()
        } else {
            path.extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default()
        };
        Self {
            path,
            name,
            extension,
            size: if meta.is_dir() { 0 } else { meta.len() },
            compressed_size,
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
            timestamps: FileTimestamps::from_metadata(meta),
            attributes: FileAttributes::from_metadata(meta),
        }
    }
}

/// Execution policy context enforcing read-only vs mutating safety gates and root scoping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    pub mode: PolicyMode,
    pub dry_run: bool,
    pub confirm_destructive: bool,
    pub allowed_roots: Vec<PathBuf>,
    pub max_entries: Option<usize>,
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self::read_only()
    }
}

impl PolicyContext {
    /// Construct a strict read-only policy context.
    pub fn read_only() -> Self {
        Self {
            mode: PolicyMode::ReadOnlyOnly,
            dry_run: true,
            confirm_destructive: false,
            allowed_roots: Vec::new(),
            max_entries: None,
        }
    }

    /// Construct a policy context permitting mutations when confirmed and not dry-run.
    pub fn allow_mutating(dry_run: bool, confirm_destructive: bool) -> Self {
        Self {
            mode: PolicyMode::AllowMutating,
            dry_run,
            confirm_destructive,
            allowed_roots: Vec::new(),
            max_entries: None,
        }
    }

    /// Validate whether a mutating operation is permitted to modify disk state.
    pub fn require_mutation_allowed(&self, action: &str) -> Result<(), FsError> {
        if self.dry_run {
            return Err(FsError::PolicyDenied(format!(
                "action '{action}' cannot mutate while dry_run is enabled"
            )));
        }
        if self.mode != PolicyMode::AllowMutating {
            return Err(FsError::PolicyDenied(format!(
                "action '{action}' denied under PolicyMode::ReadOnlyOnly"
            )));
        }
        if !self.confirm_destructive {
            return Err(FsError::PolicyDenied(format!(
                "action '{action}' requires confirm_destructive = true"
            )));
        }
        Ok(())
    }

    /// Verify `path` resides under one of `allowed_roots` (when `allowed_roots` is non-empty).
    pub fn check_path_allowed(&self, path: &Path) -> Result<(), FsError> {
        if self.allowed_roots.is_empty() {
            return Ok(());
        }
        let norm_target = normalize_policy_path(path)?;
        for root in &self.allowed_roots {
            if let Ok(norm_root) = normalize_policy_path(root)
                && norm_target.starts_with(&norm_root)
            {
                return Ok(());
            }
        }
        Err(FsError::PolicyDenied(format!(
            "path '{}' is outside allowed_roots",
            path.display()
        )))
    }
}

fn strip_windows_verbatim(raw: &str) -> String {
    #[cfg(windows)]
    {
        if let Some(rest) = raw.strip_prefix(r"\\?\") {
            if rest
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case(r"UNC\") || p.eq_ignore_ascii_case("UNC/"))
            {
                let unc_tail = &rest[4..];
                if !unc_tail.is_empty() && !unc_tail.starts_with(['\\', '/']) {
                    return format!(r"\\{unc_tail}");
                }
                return raw.to_string();
            }
            let bytes = rest.as_bytes();
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                return rest.to_string();
            }
            return raw.to_string();
        }
        if let Some(rest) = raw.strip_prefix("//?/") {
            if rest
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case("UNC/") || p.eq_ignore_ascii_case(r"UNC\"))
            {
                let unc_tail = &rest[4..];
                if !unc_tail.is_empty() && !unc_tail.starts_with(['\\', '/']) {
                    return format!("//{unc_tail}");
                }
                return raw.to_string();
            }
            let bytes = rest.as_bytes();
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                return rest.to_string();
            }
            return raw.to_string();
        }
    }
    raw.to_string()
}

#[cfg(windows)]
fn is_nt_object_namespace_path(raw: &str) -> bool {
    let normalized: String = raw
        .chars()
        .take(16)
        .map(|c| if c == '/' { '\\' } else { c.to_ascii_lowercase() })
        .collect();
    const PREFIXES: &[&str] = &[r"\??\", r"\device\", r"\dosdevices\", r"\global??\"];
    PREFIXES.iter().any(|p| normalized.starts_with(p))
        || matches!(normalized.as_str(), r"\??" | r"\device" | r"\dosdevices" | r"\global??")
}

fn push_literal_segment(buf: &mut PathBuf, seg: &std::ffi::OsStr) {
    if seg.is_empty() {
        return;
    }
    let mut os = std::mem::take(buf).into_os_string();
    let needs_sep = {
        let bytes = os.as_encoded_bytes();
        !bytes.is_empty() && !matches!(bytes.last(), Some(b'\\' | b'/'))
    };
    if needs_sep {
        os.push(std::path::MAIN_SEPARATOR_STR);
    }
    os.push(seg);
    *buf = PathBuf::from(os);
}

fn push_root_sep(buf: &mut PathBuf) {
    let mut os = std::mem::take(buf).into_os_string();
    if !matches!(os.as_encoded_bytes().last(), Some(b'\\' | b'/')) {
        os.push(std::path::MAIN_SEPARATOR_STR);
    }
    *buf = PathBuf::from(os);
}

fn extract_path_root(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut root = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Prefix(pref) => root.push(pref.as_os_str()),
            Component::RootDir => {
                push_root_sep(&mut root);
                break;
            }
            _ => break,
        }
    }
    root
}

fn normalize_policy_path(path: &Path) -> Result<PathBuf, FsError> {
    normalize_policy_path_with_drive_cwd(path, &|drive_char| {
        let drive_spec = format!("{drive_char}:");
        let drive_cwd = std::fs::canonicalize(&drive_spec).map_err(|err| {
            FsError::PolicyDenied(format!(
                "cannot resolve drive-relative path '{}': failed to canonicalize '{drive_spec}': {err}",
                path.display()
            ))
        })?;
        Ok(PathBuf::from(strip_windows_verbatim(&drive_cwd.to_string_lossy())))
    })
}

fn normalize_policy_path_with_drive_cwd<F>(path: &Path, resolve_drive_cwd: &F) -> Result<PathBuf, FsError>
where
    F: Fn(char) -> Result<PathBuf, FsError>,
{
    use std::path::{Component, Prefix};

    let raw = path.to_string_lossy();
    #[cfg(windows)]
    if is_nt_object_namespace_path(&raw) {
        return Err(FsError::PolicyDenied(format!(
            "unsupported NT object-manager namespace path '{}'",
            path.display()
        )));
    }
    let cleaned_str = strip_windows_verbatim(&raw);
    #[cfg(windows)]
    if is_nt_object_namespace_path(&cleaned_str) {
        return Err(FsError::PolicyDenied(format!(
            "unsupported NT object-manager namespace path '{}'",
            path.display()
        )));
    }
    let cleaned_path = Path::new(&cleaned_str);

    let mut comps = cleaned_path.components().peekable();
    let mut lexical = match comps.peek().copied() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Verbatim(_) | Prefix::DeviceNS(_) | Prefix::VerbatimUNC(_, _) | Prefix::VerbatimDisk(_) => {
                return Err(FsError::PolicyDenied(format!(
                    "unsupported or non-disk Windows device/verbatim path '{}'",
                    path.display()
                )));
            }
            Prefix::UNC(server, _) if server == "?" || server == "." || server.is_empty() => {
                return Err(FsError::PolicyDenied(format!(
                    "unsupported or non-disk Windows device/verbatim path '{}'",
                    path.display()
                )));
            }
            Prefix::Disk(drive_byte) => {
                comps.next();
                if matches!(comps.peek(), Some(Component::RootDir)) {
                    comps.next();
                    let mut buf = PathBuf::from(prefix.as_os_str());
                    push_root_sep(&mut buf);
                    buf
                } else {
                    let drive_cwd = resolve_drive_cwd(drive_byte as char)?;
                    PathBuf::from(strip_windows_verbatim(&drive_cwd.to_string_lossy()))
                }
            }
            Prefix::UNC(_, _) => {
                comps.next();
                let mut buf = PathBuf::from(prefix.as_os_str());
                if matches!(comps.peek(), Some(Component::RootDir)) {
                    comps.next();
                    push_root_sep(&mut buf);
                }
                buf
            }
        },
        Some(Component::RootDir) if cleaned_path.is_relative() => {
            comps.next();
            let cwd = std::env::current_dir().map_err(|err| {
                FsError::PolicyDenied(format!(
                    "cannot resolve root-relative path '{}': failed to query current directory: {err}",
                    path.display()
                ))
            })?;
            let cwd_canon = std::fs::canonicalize(&cwd).unwrap_or(cwd);
            let cwd_stripped = PathBuf::from(strip_windows_verbatim(&cwd_canon.to_string_lossy()));
            let root = extract_path_root(&cwd_stripped);
            if root.as_os_str().is_empty() {
                return Err(FsError::PolicyDenied(format!(
                    "cannot resolve root-relative path '{}': missing root in current directory",
                    path.display()
                )));
            }
            root
        }
        Some(Component::RootDir) => {
            comps.next();
            PathBuf::from(std::path::MAIN_SEPARATOR_STR)
        }
        _ if cleaned_path.is_relative() && !cleaned_path.as_os_str().is_empty() => {
            let cwd = std::env::current_dir().map_err(|err| {
                FsError::PolicyDenied(format!(
                    "cannot resolve relative path '{}': failed to query current directory: {err}",
                    path.display()
                ))
            })?;
            let cwd_canon = std::fs::canonicalize(&cwd).unwrap_or(cwd);
            PathBuf::from(strip_windows_verbatim(&cwd_canon.to_string_lossy()))
        }
        _ => PathBuf::new(),
    };

    for comp in comps {
        match comp {
            Component::Prefix(p) => {
                lexical.push(p.as_os_str());
            }
            Component::RootDir => {
                push_root_sep(&mut lexical);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(lexical.components().next_back(), Some(Component::Normal(_))) {
                    lexical.pop();
                } else if lexical.as_os_str().is_empty()
                    || matches!(lexical.components().next_back(), Some(Component::ParentDir))
                {
                    push_literal_segment(&mut lexical, std::ffi::OsStr::new(".."));
                }
            }
            Component::Normal(seg) => {
                push_literal_segment(&mut lexical, seg);
            }
        }
    }

    let mut prefix = lexical.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let resolved = loop {
        if let Ok(canon) = std::fs::canonicalize(&prefix) {
            let mut out = PathBuf::from(strip_windows_verbatim(&canon.to_string_lossy()));
            for seg in tail.into_iter().rev() {
                push_literal_segment(&mut out, &seg);
            }
            break out;
        }
        match prefix.components().next_back() {
            Some(Component::Normal(seg)) => {
                let seg_os = seg.to_os_string();
                prefix.pop();
                #[cfg(windows)]
                if let Some(seg_str) = seg_os.to_str()
                    && let Some(colon_idx) = seg_str.find(':')
                    && colon_idx > 0
                {
                    let host = &seg_str[..colon_idx];
                    let stream_suffix = &seg_str[colon_idx..];
                    let mut host_path = prefix.clone();
                    push_literal_segment(&mut host_path, std::ffi::OsStr::new(host));
                    if let Ok(canon_host) = std::fs::canonicalize(&host_path) {
                        let mut os =
                            PathBuf::from(strip_windows_verbatim(&canon_host.to_string_lossy())).into_os_string();
                        os.push(stream_suffix);
                        let mut out = PathBuf::from(os);
                        for t in tail.into_iter().rev() {
                            push_literal_segment(&mut out, &t);
                        }
                        break out;
                    }
                }
                tail.push(seg_os);
            }
            _ => break lexical,
        }
    };

    #[cfg(windows)]
    {
        Ok(PathBuf::from(resolved.to_string_lossy().to_lowercase()))
    }
    #[cfg(not(windows))]
    {
        Ok(resolved)
    }
}

/// Audit record describing a planned or applied filesystem mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationRecord {
    pub path: PathBuf,
    pub action: String,
    pub applied: bool,
    pub before: Option<String>,
    pub after: Option<String>,
    pub error: Option<String>,
}

/// Generic structured result envelope returned by `fs2rust` tool engines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult<T> {
    pub tool_id: String,
    pub dry_run: bool,
    pub items_processed: usize,
    pub items_modified: usize,
    pub warnings: Vec<String>,
    pub data: T,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_filetime_roundtrip_is_exact() {
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 12, 34, 56).unwrap();
        let ft = datetime_to_windows_filetime(dt).unwrap();
        let back = windows_filetime_to_datetime(ft).unwrap();
        assert_eq!(back, dt);

        let (low, high) = datetime_to_windows_filetime_parts(dt).unwrap();
        assert_eq!(windows_filetime_parts_to_datetime(low, high).unwrap(), dt);
        assert_eq!(windows_filetime_to_datetime(0), None);
    }

    #[test]
    fn windows_filetime_rejects_pre_1601() {
        let pre = Utc.with_ymd_and_hms(1500, 1, 1, 0, 0, 0).unwrap();
        assert!(matches!(
            datetime_to_windows_filetime(pre),
            Err(FsError::TimeConversion(_))
        ));
    }

    #[test]
    fn file_attributes_roundtrip_and_parse() {
        let attrs = FileAttributes::parse_flags("RHSA").unwrap();
        assert!(attrs.read_only);
        assert!(attrs.hidden);
        assert!(attrs.system);
        assert!(attrs.archive);
        assert!(!attrs.directory);
        assert_eq!(attrs.format_flags(), "RHSA");
        assert_eq!(FileAttributes::from_raw(attrs.to_raw()), attrs);

        let by_name = FileAttributes::parse_flags("readonly, hidden").unwrap();
        assert!(by_name.read_only && by_name.hidden && !by_name.system);
        assert_eq!(FileAttributes::parse_flags("NONE").unwrap().to_raw(), 0);
        assert_eq!(FileAttributes::parse_flags("none").unwrap().to_raw(), 0);
        assert!(FileAttributes::parse_flags("Z").is_err());
    }

    #[test]
    fn policy_context_rejects_traversal_and_accepts_existing_root_child() {
        #[cfg(windows)]
        let (root, traversal, sibling, valid) = (
            r"C:\allowed",
            r"C:\allowed\..\secret\file.txt",
            r"C:\allowed_other\file.txt",
            r"C:\allowed\sub\file.txt",
        );
        #[cfg(not(windows))]
        let (root, traversal, sibling, valid) = (
            "/allowed",
            "/allowed/../secret/file.txt",
            "/allowed_other/file.txt",
            "/allowed/sub/file.txt",
        );
        let mock_policy = PolicyContext {
            allowed_roots: vec![PathBuf::from(root)],
            ..PolicyContext::allow_mutating(false, true)
        };
        assert!(matches!(
            mock_policy.check_path_allowed(Path::new(traversal)),
            Err(FsError::PolicyDenied(_))
        ));
        assert!(matches!(
            mock_policy.check_path_allowed(Path::new(sibling)),
            Err(FsError::PolicyDenied(_))
        ));
        assert!(mock_policy.check_path_allowed(Path::new(valid)).is_ok());

        let tmp = tempfile::tempdir().unwrap();
        let real_policy = PolicyContext {
            allowed_roots: vec![tmp.path().to_path_buf()],
            ..PolicyContext::allow_mutating(false, true)
        };
        let nonexistent_child = tmp.path().join("nonexistent_child.txt");
        assert!(real_policy.check_path_allowed(&nonexistent_child).is_ok());

        let escaped = tmp.path().join("..").join("escaped_child.txt");
        assert!(matches!(
            real_policy.check_path_allowed(&escaped),
            Err(FsError::PolicyDenied(_))
        ));

        #[cfg(windows)]
        {
            let verbatim_root = PathBuf::from(format!(r"\\?\{}", tmp.path().display()));
            let verbatim_policy = PolicyContext {
                allowed_roots: vec![verbatim_root],
                ..PolicyContext::allow_mutating(false, true)
            };
            assert!(verbatim_policy.check_path_allowed(&nonexistent_child).is_ok());
        }
    }

    #[test]
    fn policy_context_canonicalizes_after_nonexistent_parent_bounce() {
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().join("allowed");
        let allowed_sub = allowed.join("sub");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&allowed_sub).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let policy = PolicyContext {
            allowed_roots: vec![allowed.clone()],
            ..PolicyContext::allow_mutating(false, true)
        };

        // Bounce over nonexistent segment back into real subdirectory inside allowed root
        let bounced_inside = allowed.join("nonexistent").join("..").join("sub").join("future.txt");
        assert!(policy.check_path_allowed(&bounced_inside).is_ok());

        // Bounce over nonexistent segment and out of allowed root must be rejected
        let bounced_outside = allowed
            .join("nonexistent")
            .join("..")
            .join("..")
            .join("outside")
            .join("secret.txt");
        assert!(matches!(
            policy.check_path_allowed(&bounced_outside),
            Err(FsError::PolicyDenied(_))
        ));

        // Real NTFS directory junction (Windows) or symlink (Unix) escape via nonexistent\..\escape_link
        let escape_link = allowed.join("escape_link");
        #[cfg(windows)]
        let link_created = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &escape_link.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        #[cfg(unix)]
        let link_created = std::os::unix::fs::symlink(&outside, &escape_link).is_ok();

        if link_created {
            let link_bounce = allowed
                .join("nonexistent")
                .join("..")
                .join("escape_link")
                .join("secret.txt");
            assert!(matches!(
                policy.check_path_allowed(&link_bounce),
                Err(FsError::PolicyDenied(_))
            ));
            let _ = std::fs::remove_dir(&escape_link);
        }
    }

    #[test]
    fn policy_context_blocks_unconfirmed_mutations() {
        let ro = PolicyContext::read_only();
        assert!(matches!(
            ro.require_mutation_allowed("test"),
            Err(FsError::PolicyDenied(_))
        ));

        let dry = PolicyContext::allow_mutating(true, true);
        assert!(matches!(
            dry.require_mutation_allowed("test"),
            Err(FsError::PolicyDenied(_))
        ));

        let unconfirmed = PolicyContext::allow_mutating(false, false);
        assert!(matches!(
            unconfirmed.require_mutation_allowed("test"),
            Err(FsError::PolicyDenied(_))
        ));

        let ok = PolicyContext::allow_mutating(false, true);
        assert!(ok.require_mutation_allowed("test").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn policy_context_rejects_drive_relative_parent_escape_without_mutating_cwd() {
        use std::path::{Component, Prefix};

        // 1. Pure helper tests with deterministic drive-CWD resolver (no process-global CWD mutation)
        let resolver = |drive: char| -> Result<PathBuf, FsError> {
            match drive.to_ascii_uppercase() {
                'C' => Ok(PathBuf::from(r"C:\allowed\sub")),
                other => Err(FsError::PolicyDenied(format!("unmounted drive '{other}:'"))),
            }
        };

        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new(r"C:..\..\outside\secret.txt"), &resolver).unwrap(),
            PathBuf::from(r"c:\outside\secret.txt")
        );
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new(r"C:inside.txt"), &resolver).unwrap(),
            PathBuf::from(r"c:\allowed\sub\inside.txt")
        );
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new("C:"), &resolver).unwrap(),
            PathBuf::from(r"c:\allowed\sub")
        );
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new(r"\\?\C:..\..\outside\secret.txt"), &resolver).unwrap(),
            PathBuf::from(r"c:\outside\secret.txt")
        );
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new("//?/C:../../outside/secret.txt"), &resolver).unwrap(),
            PathBuf::from(r"c:\outside\secret.txt")
        );
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new(r"\\?\UNC\server\share\dir\file.txt"), &resolver).unwrap(),
            PathBuf::from(r"\\server\share\dir\file.txt")
        );
        assert!(matches!(
            normalize_policy_path_with_drive_cwd(Path::new(r"Z:..\..\outside\secret.txt"), &resolver),
            Err(FsError::PolicyDenied(_))
        ));

        // 2. End-to-end PolicyContext::check_path_allowed relative to actual process CWD
        let cwd = std::env::current_dir().unwrap();
        let drive_char = match cwd.components().next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(b) | Prefix::VerbatimDisk(b) => Some(b as char),
                _ => None,
            },
            _ => None,
        };
        if let Some(drive) = drive_char {
            let policy = PolicyContext {
                allowed_roots: vec![cwd.clone()],
                ..PolicyContext::allow_mutating(false, true)
            };
            let escape_one = format!(r"{drive}:..\outside_secret.txt");
            let escape_two = format!(r"{drive}:..\..\outside\secret.txt");
            let inside_rel = format!(r"{drive}:inside_ok.txt");
            assert!(matches!(
                policy.check_path_allowed(Path::new(&escape_one)),
                Err(FsError::PolicyDenied(_))
            ));
            assert!(matches!(
                policy.check_path_allowed(Path::new(&escape_two)),
                Err(FsError::PolicyDenied(_))
            ));
            assert!(policy.check_path_allowed(Path::new(&inside_rel)).is_ok());
            assert!(matches!(
                policy.check_path_allowed(Path::new(r"\outside_root_relative\secret.txt")),
                Err(FsError::PolicyDenied(_))
            ));

            if let Some(unused_drive) = ('A'..='Z')
                .rev()
                .find(|ch| std::fs::canonicalize(format!("{ch}:")).is_err())
            {
                let unmounted_escape = format!(r"{unused_drive}:..\..\outside\secret.txt");
                assert!(matches!(
                    policy.check_path_allowed(Path::new(&unmounted_escape)),
                    Err(FsError::PolicyDenied(_))
                ));
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn policy_context_rejects_non_disk_verbatim_device_and_mixed_case_unc_paths() {
        let cwd = std::env::current_dir().unwrap();
        let policy = PolicyContext {
            allowed_roots: vec![cwd],
            ..PolicyContext::allow_mutating(false, true)
        };

        let denied_inputs = [
            r"\\?\Volume{00000000-0000-0000-0000-000000000000}\secret.txt",
            r"\\?\GLOBALROOT\??\C:\Windows\System32\secret.txt",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\Windows\System32\cmd.exe",
            "//?/GLOBALROOT/??/C:/secret.txt",
            "//?/Volume{00000000-0000-0000-0000-000000000000}/secret.txt",
            r"\\?\PIPE\evil",
            r"\\?\Unc\evil-server\share\secret.txt",
            "//?/Unc/evil-server/share/secret.txt",
            r"\\?\UNC\?\GLOBALROOT\??\C:\secret.txt",
            r"\\.\C:\Windows\System32\cmd.exe",
            "//./C:/Windows/System32/cmd.exe",
        ];

        for raw in denied_inputs {
            assert!(
                matches!(policy.check_path_allowed(Path::new(raw)), Err(FsError::PolicyDenied(_))),
                "expected PolicyDenied for '{raw}'"
            );
        }

        let unc_policy = PolicyContext {
            allowed_roots: vec![PathBuf::from(r"\\server\share\allowed")],
            ..PolicyContext::allow_mutating(false, true)
        };
        assert!(
            unc_policy
                .check_path_allowed(Path::new(r"\\?\Unc\server\share\allowed\file.txt"))
                .is_ok()
        );
        assert!(
            unc_policy
                .check_path_allowed(Path::new("//?/Unc/server/share/allowed/file.txt"))
                .is_ok()
        );
        assert!(matches!(
            unc_policy.check_path_allowed(Path::new(r"\\?\Unc\server\share\allowed\..\secret.txt")),
            Err(FsError::PolicyDenied(_))
        ));
        assert!(matches!(
            unc_policy.check_path_allowed(Path::new(r"\\?\UNC\\allowed\file.txt")),
            Err(FsError::PolicyDenied(_))
        ));
        assert!(matches!(
            unc_policy.check_path_allowed(Path::new("//?/UNC//allowed/file.txt")),
            Err(FsError::PolicyDenied(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn policy_context_rejects_nt_namespaces_drive_prefixed_ads_escapes_and_junction_ads() {
        use std::path::{Component, Prefix};

        let cwd = std::env::current_dir().unwrap();
        let cwd_policy = PolicyContext {
            allowed_roots: vec![cwd.clone()],
            ..PolicyContext::allow_mutating(false, true)
        };

        // 1. Explicit NT object-manager / kernel namespace rejections (case-insensitive, mixed slashes)
        let nt_inputs = [
            r"\??\C:\Windows\System32\cmd.exe",
            "/??/C:/Windows/System32/cmd.exe",
            r"\??\C:",
            r"\??",
            r"\Device\HarddiskVolume1\Windows\System32\cmd.exe",
            r"\device\harddiskvolume1\secret.txt",
            "/Device/HarddiskVolume1/secret.txt",
            r"\DosDevices\C:\Windows\System32\cmd.exe",
            r"\dosdevices\c:\secret.txt",
            "/DosDevices/C:/secret.txt",
            r"\Global??\C:\Windows\System32\cmd.exe",
            r"\global??\c:\secret.txt",
            "/Global??/C:/secret.txt",
            r"\foo\C:\bar",
            r"\\?\UNC\\allowed\file.txt",
        ];
        for raw in nt_inputs {
            assert!(
                matches!(
                    cwd_policy.check_path_allowed(Path::new(raw)),
                    Err(FsError::PolicyDenied(_))
                ),
                "expected PolicyDenied for '{raw}'"
            );
        }

        // 2. Drive-prefixed segment in lexical normalization (PathBuf::push regression)
        let resolver = |drive: char| -> Result<PathBuf, FsError> {
            match drive.to_ascii_uppercase() {
                'C' => Ok(PathBuf::from(r"C:\allowed\sub")),
                other => Err(FsError::PolicyDenied(format!("unmounted drive '{other}:'"))),
            }
        };
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new(r"C:\outside\C:secret"), &resolver).unwrap(),
            PathBuf::from(r"c:\outside\c:secret")
        );
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new(r"C:\allowed\C:secret"), &resolver).unwrap(),
            PathBuf::from(r"c:\allowed\c:secret")
        );
        assert_eq!(
            normalize_policy_path_with_drive_cwd(Path::new(r"\foo\C:\bar"), &resolver).unwrap(),
            PathBuf::from(format!(
                "{}foo\\c:\\bar",
                extract_path_root(&PathBuf::from(strip_windows_verbatim(&cwd.to_string_lossy())))
                    .to_string_lossy()
                    .to_lowercase()
            ))
        );

        // 3. Real NTFS ADS on <drive>:secret (in-root vs out-of-root) & junction:evil_stream
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().join("allowed");
        let allowed_sub = allowed.join("sub");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&allowed_sub).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let drive_char = match cwd.components().next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(b) | Prefix::VerbatimDisk(b) => b as char,
                _ => 'C',
            },
            _ => 'C',
        };

        let in_root_ads = PathBuf::from(format!(r"{}\{drive_char}:secret", allowed.display()));
        let out_root_ads = PathBuf::from(format!(r"{}\{drive_char}:secret", outside.display()));
        std::fs::write(&in_root_ads, b"inside_ads").unwrap();
        std::fs::write(&out_root_ads, b"outside_ads").unwrap();

        let ads_policy = PolicyContext {
            allowed_roots: vec![allowed.clone()],
            ..PolicyContext::allow_mutating(false, true)
        };
        // Both cwd_policy (where cwd is on the same drive) and ads_policy must reject out_root_ads
        assert!(matches!(
            cwd_policy.check_path_allowed(&out_root_ads),
            Err(FsError::PolicyDenied(_))
        ));
        assert!(matches!(
            ads_policy.check_path_allowed(&out_root_ads),
            Err(FsError::PolicyDenied(_))
        ));
        // Legitimate in-root ADS remains allowed
        assert!(ads_policy.check_path_allowed(&in_root_ads).is_ok());

        // Junction pointing outside with ADS suffix `escape_link:evil_stream`
        let escape_link = allowed.join("escape_link");
        let link_created = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &escape_link.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        if link_created {
            let junction_ads = PathBuf::from(format!("{}:evil_stream", escape_link.display()));
            assert!(matches!(
                ads_policy.check_path_allowed(&junction_ads),
                Err(FsError::PolicyDenied(_))
            ));
            let _ = std::fs::remove_dir(&escape_link);
        }

        // Junction pointing inside allowed with ADS suffix `inside_link:ok_stream`
        let inside_link = allowed.join("inside_link");
        let inside_created = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &inside_link.to_string_lossy(),
                &allowed_sub.to_string_lossy(),
            ])
            .output()
            .is_ok_and(|o| o.status.success());
        if inside_created {
            let inside_ads = PathBuf::from(format!("{}:ok_stream", inside_link.display()));
            assert!(ads_policy.check_path_allowed(&inside_ads).is_ok());
            let _ = std::fs::remove_dir(&inside_link);
        }
    }
}
