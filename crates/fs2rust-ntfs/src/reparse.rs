#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{decode_utf16le, decode_utf16le_nul, format_guid_le, read_u16_le, read_u32_le};
use fs2rust_core::{FsError, PolicyContext};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

pub const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
pub const IO_REPARSE_TAG_LX_SYMLINK: u32 = 0xA000_001D;
pub const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001B;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReparseKind {
    SymbolicLinkFile,
    SymbolicLinkDir,
    Junction,
    AppExecLink,
    LxSymlink,
    Cloud,
    OtherReparse,
    HardLink,
}

impl ReparseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SymbolicLinkFile => "SymlinkFile",
            Self::SymbolicLinkDir => "SymlinkDir",
            Self::Junction => "Junction",
            Self::AppExecLink => "AppExecLink",
            Self::LxSymlink => "LxSymlink",
            Self::Cloud => "Cloud",
            Self::OtherReparse => "OtherReparse",
            Self::HardLink => "HardLink",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedReparsePoint {
    pub tag: u32,
    pub kind: ReparseKind,
    pub substitute_name: String,
    pub print_name: String,
    pub resolved_target: String,
    pub is_relative: bool,
    pub guid: Option<String>,
    pub app_exec_package_id: Option<String>,
    pub app_exec_aumid: Option<String>,
}

fn strip_nt_prefix(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix(r"\??\") {
        if let Some(unc) = rest.strip_prefix(r"UNC\") {
            return format!(r"\\{unc}");
        }
        return rest.to_string();
    }
    raw.to_string()
}

/// Parse raw bytes returned by `FSCTL_GET_REPARSE_POINT` in pure Rust (zero `unsafe`).
pub fn parse_reparse_data_buffer(bytes: &[u8], is_dir: bool) -> Result<ParsedReparsePoint, FsError> {
    if bytes.len() < 8 {
        return Err(FsError::Parse(format!(
            "REPARSE_DATA_BUFFER too short: {} bytes (need >= 8)",
            bytes.len()
        )));
    }
    let tag = read_u32_le(bytes, 0)?;
    let data_len = usize::from(read_u16_le(bytes, 4)?);
    let is_microsoft = (tag & 0x8000_0000) != 0;
    let header_size = if is_microsoft { 8usize } else { 24usize };

    if bytes.len() < header_size {
        return Err(FsError::Parse(format!(
            "REPARSE_GUID_DATA_BUFFER too short: {} bytes (need >= {header_size})",
            bytes.len()
        )));
    }
    let total_end = header_size
        .checked_add(data_len)
        .filter(|&end| end <= bytes.len())
        .ok_or_else(|| {
            FsError::Parse(format!(
                "reparse buffer truncated: header {header_size} + data_len {data_len} > {}",
                bytes.len()
            ))
        })?;

    let guid = if !is_microsoft {
        let mut g = [0u8; 16];
        g.copy_from_slice(&bytes[8..24]);
        Some(format_guid_le(&g))
    } else {
        None
    };

    if tag == IO_REPARSE_TAG_SYMLINK {
        if data_len < 12 {
            return Err(FsError::Parse(format!("SYMLINK reparse data_len {data_len} < 12")));
        }
        let sub_off = usize::from(read_u16_le(bytes, 8)?);
        let sub_len = usize::from(read_u16_le(bytes, 10)?);
        let print_off = usize::from(read_u16_le(bytes, 12)?);
        let print_len = usize::from(read_u16_le(bytes, 14)?);
        let flags = read_u32_le(bytes, 16)?;
        let path_base = 20usize;
        let sub_start = path_base
            .checked_add(sub_off)
            .ok_or_else(|| FsError::Parse("symlink sub_off overflow".to_string()))?;
        let sub_end = sub_start
            .checked_add(sub_len)
            .filter(|&e| e <= total_end)
            .ok_or_else(|| FsError::Parse("symlink SubstituteName out of bounds".to_string()))?;
        let print_start = path_base
            .checked_add(print_off)
            .ok_or_else(|| FsError::Parse("symlink print_off overflow".to_string()))?;
        let print_end = print_start
            .checked_add(print_len)
            .filter(|&e| e <= total_end)
            .ok_or_else(|| FsError::Parse("symlink PrintName out of bounds".to_string()))?;

        let substitute_name = decode_utf16le(&bytes[sub_start..sub_end]);
        let print_name = decode_utf16le(&bytes[print_start..print_end]);
        let resolved_target = if !print_name.is_empty() {
            print_name.clone()
        } else {
            strip_nt_prefix(&substitute_name)
        };
        let kind = if is_dir {
            ReparseKind::SymbolicLinkDir
        } else {
            ReparseKind::SymbolicLinkFile
        };
        return Ok(ParsedReparsePoint {
            tag,
            kind,
            substitute_name,
            print_name,
            resolved_target,
            is_relative: (flags & 0x0000_0001) != 0,
            guid,
            app_exec_package_id: None,
            app_exec_aumid: None,
        });
    }

    if tag == IO_REPARSE_TAG_MOUNT_POINT {
        if data_len < 8 {
            return Err(FsError::Parse(format!("MOUNT_POINT reparse data_len {data_len} < 8")));
        }
        let sub_off = usize::from(read_u16_le(bytes, 8)?);
        let sub_len = usize::from(read_u16_le(bytes, 10)?);
        let print_off = usize::from(read_u16_le(bytes, 12)?);
        let print_len = usize::from(read_u16_le(bytes, 14)?);
        // Note: IO_REPARSE_TAG_MOUNT_POINT has NO Flags field; PathBuffer begins at offset 16.
        let path_base = 16usize;
        let sub_start = path_base
            .checked_add(sub_off)
            .ok_or_else(|| FsError::Parse("mount point sub_off overflow".to_string()))?;
        let sub_end = sub_start
            .checked_add(sub_len)
            .filter(|&e| e <= total_end)
            .ok_or_else(|| FsError::Parse("mount point SubstituteName out of bounds".to_string()))?;
        let print_start = path_base
            .checked_add(print_off)
            .ok_or_else(|| FsError::Parse("mount point print_off overflow".to_string()))?;
        let print_end = print_start
            .checked_add(print_len)
            .filter(|&e| e <= total_end)
            .ok_or_else(|| FsError::Parse("mount point PrintName out of bounds".to_string()))?;

        let substitute_name = decode_utf16le(&bytes[sub_start..sub_end]);
        let print_name = decode_utf16le(&bytes[print_start..print_end]);
        let resolved_target = if !print_name.is_empty() {
            print_name.clone()
        } else {
            strip_nt_prefix(&substitute_name)
        };
        return Ok(ParsedReparsePoint {
            tag,
            kind: ReparseKind::Junction,
            substitute_name,
            print_name,
            resolved_target,
            is_relative: false,
            guid,
            app_exec_package_id: None,
            app_exec_aumid: None,
        });
    }

    if tag == IO_REPARSE_TAG_APPEXECLINK {
        if data_len < 4 {
            return Err(FsError::Parse("APPEXECLINK reparse data_len < 4".to_string()));
        }
        let payload = &bytes[12..total_end];
        let mut strings = Vec::new();
        let mut cursor = 0usize;
        while cursor + 2 <= payload.len() && strings.len() < 4 {
            let s = decode_utf16le_nul(&payload[cursor..]);
            let step = (s.encode_utf16().count() + 1) * 2;
            strings.push(s);
            cursor = cursor.saturating_add(step);
        }
        let pkg = strings.first().cloned().unwrap_or_default();
        let aumid = strings.get(1).cloned().unwrap_or_default();
        let target_exe = strings.get(2).cloned().unwrap_or_default();
        return Ok(ParsedReparsePoint {
            tag,
            kind: ReparseKind::AppExecLink,
            substitute_name: target_exe.clone(),
            print_name: target_exe.clone(),
            resolved_target: target_exe,
            is_relative: false,
            guid,
            app_exec_package_id: if pkg.is_empty() { None } else { Some(pkg) },
            app_exec_aumid: if aumid.is_empty() { None } else { Some(aumid) },
        });
    }

    if tag == IO_REPARSE_TAG_LX_SYMLINK {
        if data_len < 4 {
            return Err(FsError::Parse("LX_SYMLINK reparse data_len < 4".to_string()));
        }
        let target = String::from_utf8_lossy(&bytes[12..total_end])
            .trim_end_matches('\0')
            .to_string();
        return Ok(ParsedReparsePoint {
            tag,
            kind: ReparseKind::LxSymlink,
            substitute_name: target.clone(),
            print_name: target.clone(),
            resolved_target: target,
            is_relative: true,
            guid,
            app_exec_package_id: None,
            app_exec_aumid: None,
        });
    }

    let kind = if (tag & 0xFFFF_0FFF) == 0x9000_001A {
        ReparseKind::Cloud
    } else {
        ReparseKind::OtherReparse
    };

    Ok(ParsedReparsePoint {
        tag,
        kind,
        substitute_name: String::new(),
        print_name: String::new(),
        resolved_target: String::new(),
        is_relative: false,
        guid,
        app_exec_package_id: None,
        app_exec_aumid: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtfsLinkEntry {
    pub link_path: String,
    pub link_type: String,
    pub target_path: String,
    pub substitute_name: String,
    pub print_name: String,
    pub is_relative: bool,
    pub target_exists: bool,
    pub hard_link_count: u32,
    pub file_id: u64,
    pub reparse_tag: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct NtfsLinksConfig {
    pub target_paths: Vec<PathBuf>,
    pub recursive: bool,
    pub include_hardlinks: bool,
    pub policy: PolicyContext,
    pub offline_entries: Option<Vec<NtfsLinkEntry>>,
}

pub fn ntfs_links_schema() -> TableSchema {
    TableSchema::new(
        "ntfs_links_view",
        "NTFSLinksView - NTFS Symbolic Links, Junctions, AppExecLinks & Hard Links",
        vec![
            ColumnDef::new("link_path", "Link Path", ColumnType::Text).with_width_hint(260),
            ColumnDef::new("link_type", "Link Type", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("target_path", "Target Path", ColumnType::Text).with_width_hint(280),
            ColumnDef::new("substitute_name", "Substitute Name", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("print_name", "Print Name", ColumnType::Text).with_width_hint(240),
            ColumnDef::new("is_relative", "Relative", ColumnType::Bool).with_width_hint(80),
            ColumnDef::new("target_exists", "Target Exists", ColumnType::Bool).with_width_hint(90),
            ColumnDef::new("hard_link_count", "Hard Links", ColumnType::Uint).with_width_hint(90),
            ColumnDef::new("file_id", "File ID", ColumnType::Uint).with_width_hint(115),
            ColumnDef::new("reparse_tag", "Reparse Tag", ColumnType::Hex).with_width_hint(95),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

pub struct NtfsLinksViewProvider {
    config: NtfsLinksConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl NtfsLinksViewProvider {
    pub fn new(config: NtfsLinksConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for NtfsLinksViewProvider {
    fn tool_id(&self) -> &'static str {
        "ntfs_links_view"
    }

    fn description(&self) -> &'static str {
        "Inspect NTFS symbolic links, directory junctions, reparse points, and hardlinks"
    }

    fn schema(&self) -> TableSchema {
        ntfs_links_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let entries = if let Some(offline) = &self.config.offline_entries {
            offline.clone()
        } else {
            for p in &self.config.target_paths {
                self.config.policy.check_path_allowed(p).map_err(TableError::from)?;
            }
            self.backend
                .inspect_ntfs_links(
                    &self.config.target_paths,
                    self.config.recursive,
                    self.config.include_hardlinks,
                )
                .map_err(TableError::from)?
        };

        let rows: Vec<Row> = entries
            .iter()
            .enumerate()
            .map(|(idx, e)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(e.link_path.clone()),
                        CellValue::Text(e.link_type.clone()),
                        CellValue::Text(e.target_path.clone()),
                        CellValue::Text(e.substitute_name.clone()),
                        CellValue::Text(e.print_name.clone()),
                        CellValue::Bool(e.is_relative),
                        CellValue::Bool(e.target_exists),
                        CellValue::Uint(u64::from(e.hard_link_count)),
                        CellValue::Uint(e.file_id),
                        CellValue::Hex(e.reparse_tag.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
