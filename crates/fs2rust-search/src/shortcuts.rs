use chrono::{DateTime, Utc};
use fs2rust_core::{
    FileSystemOps, FsError, OsFileSystem, PolicyContext, datetime_to_windows_filetime, windows_filetime_to_datetime,
};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpToolError};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SHELL_LINK_HEADER_SIZE: u32 = 0x4C;
pub const SHELL_LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

pub mod link_flags {
    pub const HAS_LINK_TARGET_ID_LIST: u32 = 0x0000_0001;
    pub const HAS_LINK_INFO: u32 = 0x0000_0002;
    pub const HAS_NAME: u32 = 0x0000_0004;
    pub const HAS_RELATIVE_PATH: u32 = 0x0000_0008;
    pub const HAS_WORKING_DIR: u32 = 0x0000_0010;
    pub const HAS_ARGUMENTS: u32 = 0x0000_0020;
    pub const HAS_ICON_LOCATION: u32 = 0x0000_0040;
    pub const IS_UNICODE: u32 = 0x0000_0080;
    pub const FORCE_NO_LINK_INFO: u32 = 0x0000_0100;
    pub const HAS_EXP_STRING: u32 = 0x0000_0200;
    pub const HAS_DARWIN_ID: u32 = 0x0000_1000;
    pub const RUN_AS_USER: u32 = 0x0000_2000;
    pub const HAS_EXP_ICON: u32 = 0x0000_4000;
}

pub mod extra_sig {
    pub const ENVIRONMENT_VARIABLE: u32 = 0xA000_0001;
    pub const CONSOLE_PROPS: u32 = 0xA000_0002;
    pub const TRACKER: u32 = 0xA000_0003;
    pub const CONSOLE_FE_PROPS: u32 = 0xA000_0004;
    pub const SPECIAL_FOLDER: u32 = 0xA000_0005;
    pub const DARWIN: u32 = 0xA000_0006;
    pub const ICON_ENVIRONMENT: u32 = 0xA000_0007;
    pub const SHIM: u32 = 0xA000_0008;
    pub const PROPERTY_STORE: u32 = 0xA000_0009;
    pub const KNOWN_FOLDER: u32 = 0xA000_000B;
    pub const VISTA_AND_ABOVE_ID_LIST: u32 = 0xA000_000C;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ShowCommand {
    #[default]
    Normal = 1,
    Maximized = 3,
    Minimized = 7,
}

impl ShowCommand {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            3 => Self::Maximized,
            7 => Self::Minimized,
            _ => Self::Normal,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Maximized => "Maximized",
            Self::Minimized => "Minimized",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellLinkHeader {
    pub link_flags: u32,
    pub file_attributes: u32,
    pub creation_time: Option<DateTime<Utc>>,
    pub access_time: Option<DateTime<Utc>>,
    pub write_time: Option<DateTime<Utc>>,
    pub file_size: u32,
    pub icon_index: i32,
    pub show_command: ShowCommand,
    pub hot_key: u16,
}

impl Default for ShellLinkHeader {
    fn default() -> Self {
        Self {
            link_flags: link_flags::IS_UNICODE,
            file_attributes: 0,
            creation_time: None,
            access_time: None,
            write_time: None,
            file_size: 0,
            icon_index: 0,
            show_command: ShowCommand::Normal,
            hot_key: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkTargetIdList {
    pub raw_id_list: Vec<u8>,
    pub items: Vec<Vec<u8>>,
    pub pidl_path_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LinkInfo {
    pub flags: u32,
    pub drive_type: Option<u32>,
    pub drive_serial: Option<u32>,
    pub volume_label: Option<String>,
    pub local_base_path: Option<String>,
    pub network_share_name: Option<String>,
    pub common_path_suffix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StringData {
    pub name: Option<String>,
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub cmd_args: Option<String>,
    pub icon_location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtraDataBlock {
    EnvironmentVariable {
        target_ansi: String,
        target_unicode: String,
    },
    Tracker {
        machine_id: String,
        droid: [[u8; 16]; 2],
        droid_birth: [[u8; 16]; 2],
    },
    Darwin {
        data_ansi: String,
        data_unicode: String,
    },
    IconEnvironment {
        target_ansi: String,
        target_unicode: String,
    },
    SpecialFolder {
        folder_id: u32,
        offset: u32,
    },
    KnownFolder {
        folder_guid: [u8; 16],
        offset: u32,
    },
    Unknown {
        signature: u32,
        payload: Vec<u8>,
    },
}

/// Complete parsed `[MS-SHLLINK]` `.lnk` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellLinkFile {
    pub header: ShellLinkHeader,
    pub id_list: Option<LinkTargetIdList>,
    pub link_info: Option<LinkInfo>,
    pub string_data: StringData,
    pub extra_data: Vec<ExtraDataBlock>,
}

impl ShellLinkFile {
    /// Parse a binary `[MS-SHLLINK]` byte slice.
    pub fn parse(bytes: &[u8]) -> Result<Self, FsError> {
        if bytes.len() < SHELL_LINK_HEADER_SIZE as usize {
            return Err(FsError::Parse(format!(
                "lnk file truncated: expected at least 76 bytes, got {}",
                bytes.len()
            )));
        }
        let header_size = read_u32_le(bytes, 0)?;
        if header_size != SHELL_LINK_HEADER_SIZE {
            return Err(FsError::Parse(format!(
                "invalid ShellLinkHeader size 0x{header_size:08x} (expected 0x0000004C)"
            )));
        }
        if bytes[4..20] != SHELL_LINK_CLSID {
            return Err(FsError::Parse("invalid ShellLink CLSID".to_string()));
        }

        let link_flags_val = read_u32_le(bytes, 20)?;
        let header = ShellLinkHeader {
            link_flags: link_flags_val,
            file_attributes: read_u32_le(bytes, 24)?,
            creation_time: windows_filetime_to_datetime(read_u64_le(bytes, 28)?),
            access_time: windows_filetime_to_datetime(read_u64_le(bytes, 36)?),
            write_time: windows_filetime_to_datetime(read_u64_le(bytes, 44)?),
            file_size: read_u32_le(bytes, 52)?,
            icon_index: read_i32_le(bytes, 56)?,
            show_command: ShowCommand::from_raw(read_u32_le(bytes, 60)?),
            hot_key: read_u16_le(bytes, 64)?,
        };

        let mut cursor = SHELL_LINK_HEADER_SIZE as usize;

        // 1. LinkTargetIDList
        let id_list = if (link_flags_val & link_flags::HAS_LINK_TARGET_ID_LIST) != 0 {
            if cursor + 2 > bytes.len() {
                return Err(FsError::Parse("truncated LinkTargetIDList size".to_string()));
            }
            let id_list_size = read_u16_le(bytes, cursor)? as usize;
            cursor += 2;
            if cursor + id_list_size > bytes.len() {
                return Err(FsError::Parse("truncated LinkTargetIDList payload".to_string()));
            }
            let raw = bytes[cursor..cursor + id_list_size].to_vec();
            cursor += id_list_size;
            Some(parse_id_list(&raw))
        } else {
            None
        };

        // 2. LinkInfo
        let link_info = if (link_flags_val & link_flags::HAS_LINK_INFO) != 0
            && (link_flags_val & link_flags::FORCE_NO_LINK_INFO) == 0
        {
            if cursor + 4 > bytes.len() {
                return Err(FsError::Parse("truncated LinkInfo size".to_string()));
            }
            let info_size = read_u32_le(bytes, cursor)? as usize;
            if info_size < 0x1C || cursor + info_size > bytes.len() {
                return Err(FsError::Parse(format!("invalid LinkInfo size {info_size}")));
            }
            let slice = &bytes[cursor..cursor + info_size];
            cursor += info_size;
            Some(parse_link_info(slice)?)
        } else {
            None
        };

        // 3. StringData
        let is_unicode = (link_flags_val & link_flags::IS_UNICODE) != 0;
        let mut string_data = StringData::default();
        if (link_flags_val & link_flags::HAS_NAME) != 0 {
            string_data.name = Some(read_string_data(bytes, &mut cursor, is_unicode)?);
        }
        if (link_flags_val & link_flags::HAS_RELATIVE_PATH) != 0 {
            string_data.relative_path = Some(read_string_data(bytes, &mut cursor, is_unicode)?);
        }
        if (link_flags_val & link_flags::HAS_WORKING_DIR) != 0 {
            string_data.working_dir = Some(read_string_data(bytes, &mut cursor, is_unicode)?);
        }
        if (link_flags_val & link_flags::HAS_ARGUMENTS) != 0 {
            string_data.cmd_args = Some(read_string_data(bytes, &mut cursor, is_unicode)?);
        }
        if (link_flags_val & link_flags::HAS_ICON_LOCATION) != 0 {
            string_data.icon_location = Some(read_string_data(bytes, &mut cursor, is_unicode)?);
        }

        // 4. ExtraData
        let mut extra_data = Vec::new();
        while cursor + 4 <= bytes.len() {
            let block_size = read_u32_le(bytes, cursor)? as usize;
            if block_size < 4 {
                break;
            }
            if block_size < 8 || cursor + block_size > bytes.len() {
                return Err(FsError::Parse(format!(
                    "invalid ExtraData block size {block_size} at offset {cursor}"
                )));
            }
            let sig = read_u32_le(bytes, cursor + 4)?;
            let payload = &bytes[cursor + 8..cursor + block_size];
            extra_data.push(parse_extra_block(sig, payload)?);
            cursor += block_size;
        }

        Ok(Self {
            header,
            id_list,
            link_info,
            string_data,
            extra_data,
        })
    }

    /// Resolve effective target path (expanded env vars -> LinkInfo -> RelativePath -> PIDL/Darwin hint).
    pub fn resolve_target(&self, lnk_path: &Path, env_overrides: Option<&BTreeMap<String, String>>) -> ResolvedTarget {
        for block in &self.extra_data {
            if let ExtraDataBlock::EnvironmentVariable {
                target_ansi,
                target_unicode,
            } = block
            {
                let raw = if !target_unicode.is_empty() {
                    target_unicode
                } else {
                    target_ansi
                };
                if !raw.is_empty() {
                    let expanded = expand_env_vars(raw, env_overrides);
                    return ResolvedTarget {
                        target_path: expanded,
                        kind: "EnvironmentVariable",
                        virtual_target: false,
                    };
                }
            }
        }

        if let Some(info) = &self.link_info {
            if let Some(local) = &info.local_base_path
                && !local.is_empty()
            {
                let combined = match &info.common_path_suffix {
                    Some(suffix) if !suffix.is_empty() => join_win_path(local, suffix),
                    _ => local.clone(),
                };
                return ResolvedTarget {
                    target_path: combined,
                    kind: "LocalPath",
                    virtual_target: false,
                };
            }
            if let Some(net) = &info.network_share_name
                && !net.is_empty()
            {
                let combined = match &info.common_path_suffix {
                    Some(suffix) if !suffix.is_empty() => join_win_path(net, suffix),
                    _ => net.clone(),
                };
                return ResolvedTarget {
                    target_path: combined,
                    kind: "NetworkUNC",
                    virtual_target: false,
                };
            }
        }

        if let Some(rel) = &self.string_data.relative_path
            && !rel.is_empty()
        {
            let resolved = lnk_path
                .parent()
                .map(|p| p.join(rel))
                .unwrap_or_else(|| PathBuf::from(rel));
            return ResolvedTarget {
                target_path: resolved.to_string_lossy().into_owned(),
                kind: "RelativePath",
                virtual_target: false,
            };
        }

        for block in &self.extra_data {
            if let ExtraDataBlock::Darwin {
                data_ansi,
                data_unicode,
            } = block
            {
                let val = if !data_unicode.is_empty() {
                    data_unicode
                } else {
                    data_ansi
                };
                if !val.is_empty() {
                    return ResolvedTarget {
                        target_path: format!("msi:{val}"),
                        kind: "DarwinMSI",
                        virtual_target: true,
                    };
                }
            }
        }

        if let Some(id_list) = &self.id_list
            && let Some(hint) = &id_list.pidl_path_hint
        {
            return ResolvedTarget {
                target_path: hint.clone(),
                kind: "LinkTargetIDList",
                virtual_target: hint.starts_with("::{"),
            };
        }

        ResolvedTarget {
            target_path: String::new(),
            kind: "Unknown",
            virtual_target: false,
        }
    }

    /// Format hot key (`VK` + `Ctrl`/`Shift`/`Alt`) as human-readable text.
    pub fn format_hot_key(&self) -> String {
        if self.header.hot_key == 0 {
            return String::new();
        }
        let vk = (self.header.hot_key & 0x00FF) as u8;
        let mods = ((self.header.hot_key >> 8) & 0x00FF) as u8;
        let mut parts = Vec::new();
        if (mods & 0x02) != 0 {
            parts.push("Ctrl".to_string());
        }
        if (mods & 0x01) != 0 {
            parts.push("Shift".to_string());
        }
        if (mods & 0x04) != 0 {
            parts.push("Alt".to_string());
        }
        let key_name = match vk {
            b'0'..=b'9' | b'A'..=b'Z' => (vk as char).to_string(),
            0x70..=0x87 => format!("F{}", vk - 0x6F),
            _ => format!("0x{vk:02X}"),
        };
        parts.push(key_name);
        parts.join("+")
    }

    /// Produce an updated `.lnk` pointing to `new_target` (clearing stale IDList/Tracker/Env blocks).
    pub fn with_updated_target(
        &self,
        new_target: &str,
        new_working_dir: Option<&str>,
        new_arguments: Option<&str>,
    ) -> Self {
        let mut next = self.clone();
        next.id_list = None;
        next.extra_data.retain(|b| {
            !matches!(
                b,
                ExtraDataBlock::Tracker { .. } | ExtraDataBlock::EnvironmentVariable { .. }
            )
        });
        next.string_data.relative_path = None;
        if let Some(wd) = new_working_dir {
            next.string_data.working_dir = Some(wd.to_string());
        }
        if let Some(args) = new_arguments {
            next.string_data.cmd_args = Some(args.to_string());
        }

        if new_target.contains('%') {
            next.link_info = None;
            next.extra_data.push(ExtraDataBlock::EnvironmentVariable {
                target_ansi: new_target.to_string(),
                target_unicode: new_target.to_string(),
            });
        } else if new_target.starts_with("\\\\") {
            let trimmed = new_target.trim_start_matches('\\');
            let mut parts = trimmed.splitn(3, '\\');
            let share = match (parts.next(), parts.next()) {
                (Some(srv), Some(sh)) => format!("\\\\{srv}\\{sh}"),
                _ => new_target.to_string(),
            };
            let suffix = parts.next().map(ToOwned::to_owned);
            next.link_info = Some(LinkInfo {
                flags: 0x02,
                drive_type: None,
                drive_serial: None,
                volume_label: None,
                local_base_path: None,
                network_share_name: Some(share),
                common_path_suffix: suffix,
            });
        } else {
            next.link_info = Some(LinkInfo {
                flags: 0x01,
                drive_type: Some(3),
                drive_serial: Some(0),
                volume_label: Some(String::new()),
                local_base_path: Some(new_target.to_string()),
                network_share_name: None,
                common_path_suffix: Some(String::new()),
            });
        }

        next.recompute_link_flags();
        next
    }

    fn recompute_link_flags(&mut self) {
        let mut flags = link_flags::IS_UNICODE;
        if self.id_list.is_some() {
            flags |= link_flags::HAS_LINK_TARGET_ID_LIST;
        }
        if self.link_info.is_some() {
            flags |= link_flags::HAS_LINK_INFO;
        } else {
            flags |= link_flags::FORCE_NO_LINK_INFO;
        }
        if self.string_data.name.is_some() {
            flags |= link_flags::HAS_NAME;
        }
        if self.string_data.relative_path.is_some() {
            flags |= link_flags::HAS_RELATIVE_PATH;
        }
        if self.string_data.working_dir.is_some() {
            flags |= link_flags::HAS_WORKING_DIR;
        }
        if self.string_data.cmd_args.is_some() {
            flags |= link_flags::HAS_ARGUMENTS;
        }
        if self.string_data.icon_location.is_some() {
            flags |= link_flags::HAS_ICON_LOCATION;
        }
        if self
            .extra_data
            .iter()
            .any(|b| matches!(b, ExtraDataBlock::EnvironmentVariable { .. }))
        {
            flags |= link_flags::HAS_EXP_STRING;
        }
        if self
            .extra_data
            .iter()
            .any(|b| matches!(b, ExtraDataBlock::Darwin { .. }))
        {
            flags |= link_flags::HAS_DARWIN_ID;
        }
        if self
            .extra_data
            .iter()
            .any(|b| matches!(b, ExtraDataBlock::IconEnvironment { .. }))
        {
            flags |= link_flags::HAS_EXP_ICON;
        }
        if (self.header.link_flags & link_flags::RUN_AS_USER) != 0 {
            flags |= link_flags::RUN_AS_USER;
        }
        self.header.link_flags = flags;
    }

    /// Serialize the `ShellLinkFile` into a valid `[MS-SHLLINK]` binary stream.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FsError> {
        let mut normalized = self.clone();
        normalized.recompute_link_flags();
        let flags = normalized.header.link_flags;

        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&SHELL_LINK_HEADER_SIZE.to_le_bytes());
        out.extend_from_slice(&SHELL_LINK_CLSID);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&normalized.header.file_attributes.to_le_bytes());
        out.extend_from_slice(&opt_dt_to_filetime_u64(normalized.header.creation_time)?.to_le_bytes());
        out.extend_from_slice(&opt_dt_to_filetime_u64(normalized.header.access_time)?.to_le_bytes());
        out.extend_from_slice(&opt_dt_to_filetime_u64(normalized.header.write_time)?.to_le_bytes());
        out.extend_from_slice(&normalized.header.file_size.to_le_bytes());
        out.extend_from_slice(&normalized.header.icon_index.to_le_bytes());
        out.extend_from_slice(&(normalized.header.show_command as u32).to_le_bytes());
        out.extend_from_slice(&normalized.header.hot_key.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());

        if let Some(id_list) = &normalized.id_list {
            let len = u16::try_from(id_list.raw_id_list.len())
                .map_err(|_| FsError::InvalidArgument("IDList exceeds u16::MAX".to_string()))?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&id_list.raw_id_list);
        }

        if let Some(info) = &normalized.link_info {
            out.extend_from_slice(&serialize_link_info(info));
        }

        if let Some(s) = &normalized.string_data.name {
            write_string_data_unicode(&mut out, s);
        }
        if let Some(s) = &normalized.string_data.relative_path {
            write_string_data_unicode(&mut out, s);
        }
        if let Some(s) = &normalized.string_data.working_dir {
            write_string_data_unicode(&mut out, s);
        }
        if let Some(s) = &normalized.string_data.cmd_args {
            write_string_data_unicode(&mut out, s);
        }
        if let Some(s) = &normalized.string_data.icon_location {
            write_string_data_unicode(&mut out, s);
        }

        for block in &normalized.extra_data {
            serialize_extra_block(&mut out, block);
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub target_path: String,
    pub kind: &'static str,
    pub virtual_target: bool,
}

fn opt_dt_to_filetime_u64(dt: Option<DateTime<Utc>>) -> Result<u64, FsError> {
    match dt {
        Some(v) => datetime_to_windows_filetime(v),
        None => Ok(0),
    }
}

fn read_u16_le(bytes: &[u8], off: usize) -> Result<u16, FsError> {
    let slice = bytes
        .get(off..off + 2)
        .ok_or_else(|| FsError::Parse(format!("unexpected EOF reading u16 at {off}")))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32, FsError> {
    let slice = bytes
        .get(off..off + 4)
        .ok_or_else(|| FsError::Parse(format!("unexpected EOF reading u32 at {off}")))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i32_le(bytes: &[u8], off: usize) -> Result<i32, FsError> {
    let slice = bytes
        .get(off..off + 4)
        .ok_or_else(|| FsError::Parse(format!("unexpected EOF reading i32 at {off}")))?;
    Ok(i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(bytes: &[u8], off: usize) -> Result<u64, FsError> {
    let slice = bytes
        .get(off..off + 8)
        .ok_or_else(|| FsError::Parse(format!("unexpected EOF reading u64 at {off}")))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_cstr(bytes: &[u8], start: usize) -> String {
    let Some(slice) = bytes.get(start..) else {
        return String::new();
    };
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn read_cwstr(bytes: &[u8], start: usize) -> String {
    let Some(slice) = bytes.get(start..) else {
        return String::new();
    };
    let mut units = Vec::new();
    for pair in slice.as_chunks::<2>().0 {
        let u = u16::from_le_bytes(*pair);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

fn read_string_data(bytes: &[u8], cursor: &mut usize, is_unicode: bool) -> Result<String, FsError> {
    let char_count = read_u16_le(bytes, *cursor)? as usize;
    *cursor += 2;
    if is_unicode {
        let byte_len = char_count
            .checked_mul(2)
            .ok_or_else(|| FsError::Parse("StringData overflow".to_string()))?;
        if *cursor + byte_len > bytes.len() {
            return Err(FsError::Parse("truncated UTF-16 StringData".to_string()));
        }
        let units: Vec<u16> = bytes[*cursor..*cursor + byte_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes(*p))
            .collect();
        *cursor += byte_len;
        Ok(String::from_utf16_lossy(&units))
    } else {
        if *cursor + char_count > bytes.len() {
            return Err(FsError::Parse("truncated ANSI StringData".to_string()));
        }
        let s = String::from_utf8_lossy(&bytes[*cursor..*cursor + char_count]).into_owned();
        *cursor += char_count;
        Ok(s)
    }
}

fn write_string_data_unicode(out: &mut Vec<u8>, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    let count = units.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&count.to_le_bytes());
    for u in units.into_iter().take(count as usize) {
        out.extend_from_slice(&u.to_le_bytes());
    }
}

fn parse_id_list(raw: &[u8]) -> LinkTargetIdList {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos + 2 <= raw.len() {
        let item_size = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
        if item_size < 2 || pos + item_size > raw.len() {
            break;
        }
        items.push(raw[pos + 2..pos + item_size].to_vec());
        pos += item_size;
    }

    let mut path_segments = Vec::new();
    for item in &items {
        if let Some(first_byte) = item.first().copied() {
            if matches!(first_byte, 0x2F) && item.len() > 3 {
                let drive = read_cstr(item, 1);
                if !drive.is_empty() {
                    path_segments.push(drive.trim_end_matches('\\').to_string());
                }
            } else if matches!(first_byte, 0x31 | 0x32) && item.len() > 14 {
                let name = read_cstr(item, 12);
                if !name.is_empty() && name.is_ascii() {
                    path_segments.push(name);
                }
            }
        }
    }
    let pidl_path_hint = if !path_segments.is_empty() {
        Some(path_segments.join("\\"))
    } else {
        None
    };

    LinkTargetIdList {
        raw_id_list: raw.to_vec(),
        items,
        pidl_path_hint,
    }
}

fn parse_link_info(slice: &[u8]) -> Result<LinkInfo, FsError> {
    let header_size = read_u32_le(slice, 4)? as usize;
    let flags = read_u32_le(slice, 8)?;
    let vol_off = read_u32_le(slice, 12)? as usize;
    let local_base_off = read_u32_le(slice, 16)? as usize;
    let net_off = read_u32_le(slice, 20)? as usize;
    let suffix_off = read_u32_le(slice, 24)? as usize;

    let local_base_unicode_off = if header_size >= 0x24 && slice.len() >= 32 {
        Some(read_u32_le(slice, 28)? as usize)
    } else {
        None
    };
    let suffix_unicode_off = if header_size >= 0x24 && slice.len() >= 36 {
        Some(read_u32_le(slice, 32)? as usize)
    } else {
        None
    };

    let mut info = LinkInfo {
        flags,
        ..LinkInfo::default()
    };

    if (flags & 0x01) != 0 {
        if vol_off > 0 && vol_off + 16 <= slice.len() {
            info.drive_type = Some(read_u32_le(slice, vol_off + 4)?);
            info.drive_serial = Some(read_u32_le(slice, vol_off + 8)?);
            let label_off = read_u32_le(slice, vol_off + 12)? as usize;
            if label_off == 0x14 && vol_off + 20 <= slice.len() {
                let label_u_off = read_u32_le(slice, vol_off + 16)? as usize;
                info.volume_label = Some(read_cwstr(slice, vol_off + label_u_off));
            } else if vol_off + label_off < slice.len() {
                info.volume_label = Some(read_cstr(slice, vol_off + label_off));
            }
        }
        if let Some(uoff) = local_base_unicode_off
            && uoff > 0
            && uoff < slice.len()
        {
            info.local_base_path = Some(read_cwstr(slice, uoff));
        } else if local_base_off > 0 && local_base_off < slice.len() {
            info.local_base_path = Some(read_cstr(slice, local_base_off));
        }
    }

    if (flags & 0x02) != 0 && net_off > 0 && net_off + 20 <= slice.len() {
        let net_name_off = read_u32_le(slice, net_off + 8)? as usize;
        if net_name_off > 0x14 && net_off + 24 <= slice.len() {
            let net_name_u_off = read_u32_le(slice, net_off + 20)? as usize;
            if net_name_u_off > 0 && net_off + net_name_u_off < slice.len() {
                info.network_share_name = Some(read_cwstr(slice, net_off + net_name_u_off));
            } else if net_off + net_name_off < slice.len() {
                info.network_share_name = Some(read_cstr(slice, net_off + net_name_off));
            }
        } else if net_off + net_name_off < slice.len() {
            info.network_share_name = Some(read_cstr(slice, net_off + net_name_off));
        }
    }

    if let Some(uoff) = suffix_unicode_off
        && uoff > 0
        && uoff < slice.len()
    {
        info.common_path_suffix = Some(read_cwstr(slice, uoff));
    } else if suffix_off > 0 && suffix_off < slice.len() {
        info.common_path_suffix = Some(read_cstr(slice, suffix_off));
    }

    Ok(info)
}

fn serialize_link_info(info: &LinkInfo) -> Vec<u8> {
    let header_size: u32 = 0x24;
    let mut body = Vec::new();
    let mut vol_off = 0u32;
    let mut local_ansi_off = 0u32;
    let mut local_uni_off = 0u32;
    let mut net_off = 0u32;

    if (info.flags & 0x01) != 0 {
        vol_off = header_size + body.len() as u32;
        let label = info.volume_label.as_deref().unwrap_or("");
        let label_bytes = label.as_bytes();
        let vol_size = 16u32 + label_bytes.len() as u32 + 1;
        body.extend_from_slice(&vol_size.to_le_bytes());
        body.extend_from_slice(&info.drive_type.unwrap_or(3).to_le_bytes());
        body.extend_from_slice(&info.drive_serial.unwrap_or(0).to_le_bytes());
        body.extend_from_slice(&16u32.to_le_bytes());
        body.extend_from_slice(label_bytes);
        body.push(0);

        let local = info.local_base_path.as_deref().unwrap_or("");
        local_ansi_off = header_size + body.len() as u32;
        body.extend_from_slice(local.as_bytes());
        body.push(0);

        local_uni_off = header_size + body.len() as u32;
        for u in local.encode_utf16() {
            body.extend_from_slice(&u.to_le_bytes());
        }
        body.extend_from_slice(&0u16.to_le_bytes());
    }

    if (info.flags & 0x02) != 0 {
        net_off = header_size + body.len() as u32;
        let net = info.network_share_name.as_deref().unwrap_or("");
        let net_size = 20u32 + net.len() as u32 + 1;
        body.extend_from_slice(&net_size.to_le_bytes());
        body.extend_from_slice(&0x0000_0002u32.to_le_bytes());
        body.extend_from_slice(&20u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        body.extend_from_slice(net.as_bytes());
        body.push(0);
    }

    let suffix = info.common_path_suffix.as_deref().unwrap_or("");
    let suffix_ansi_off = header_size + body.len() as u32;
    body.extend_from_slice(suffix.as_bytes());
    body.push(0);

    let suffix_uni_off = header_size + body.len() as u32;
    for u in suffix.encode_utf16() {
        body.extend_from_slice(&u.to_le_bytes());
    }
    body.extend_from_slice(&0u16.to_le_bytes());

    let total_size = header_size + body.len() as u32;
    let mut out = Vec::with_capacity(total_size as usize);
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&info.flags.to_le_bytes());
    out.extend_from_slice(&vol_off.to_le_bytes());
    out.extend_from_slice(&local_ansi_off.to_le_bytes());
    out.extend_from_slice(&net_off.to_le_bytes());
    out.extend_from_slice(&suffix_ansi_off.to_le_bytes());
    out.extend_from_slice(&local_uni_off.to_le_bytes());
    out.extend_from_slice(&suffix_uni_off.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

fn parse_extra_block(sig: u32, payload: &[u8]) -> Result<ExtraDataBlock, FsError> {
    match sig {
        extra_sig::ENVIRONMENT_VARIABLE if payload.len() >= 780 => Ok(ExtraDataBlock::EnvironmentVariable {
            target_ansi: read_cstr(&payload[..260], 0),
            target_unicode: read_cwstr(&payload[260..780], 0),
        }),
        extra_sig::DARWIN if payload.len() >= 780 => Ok(ExtraDataBlock::Darwin {
            data_ansi: read_cstr(&payload[..260], 0),
            data_unicode: read_cwstr(&payload[260..780], 0),
        }),
        extra_sig::ICON_ENVIRONMENT if payload.len() >= 780 => Ok(ExtraDataBlock::IconEnvironment {
            target_ansi: read_cstr(&payload[..260], 0),
            target_unicode: read_cwstr(&payload[260..780], 0),
        }),
        extra_sig::TRACKER if payload.len() >= 88 => {
            let machine_id = read_cstr(&payload[8..24], 0);
            let mut droid = [[0u8; 16]; 2];
            let mut droid_birth = [[0u8; 16]; 2];
            droid[0].copy_from_slice(&payload[24..40]);
            droid[1].copy_from_slice(&payload[40..56]);
            droid_birth[0].copy_from_slice(&payload[56..72]);
            droid_birth[1].copy_from_slice(&payload[72..88]);
            Ok(ExtraDataBlock::Tracker {
                machine_id,
                droid,
                droid_birth,
            })
        }
        extra_sig::SPECIAL_FOLDER if payload.len() >= 8 => Ok(ExtraDataBlock::SpecialFolder {
            folder_id: read_u32_le(payload, 0)?,
            offset: read_u32_le(payload, 4)?,
        }),
        extra_sig::KNOWN_FOLDER if payload.len() >= 20 => {
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&payload[..16]);
            Ok(ExtraDataBlock::KnownFolder {
                folder_guid: guid,
                offset: read_u32_le(payload, 16)?,
            })
        }
        _ => Ok(ExtraDataBlock::Unknown {
            signature: sig,
            payload: payload.to_vec(),
        }),
    }
}

fn serialize_fixed_ansi_unicode_block(out: &mut Vec<u8>, sig: u32, ansi: &str, unicode: &str) {
    out.extend_from_slice(&788u32.to_le_bytes());
    out.extend_from_slice(&sig.to_le_bytes());
    let mut ansi_buf = [0u8; 260];
    let raw = ansi.as_bytes();
    let copy_len = raw.len().min(259);
    ansi_buf[..copy_len].copy_from_slice(&raw[..copy_len]);
    out.extend_from_slice(&ansi_buf);

    let mut uni_buf = [0u8; 520];
    let mut pos = 0usize;
    for u in unicode.encode_utf16().take(259) {
        let le = u.to_le_bytes();
        uni_buf[pos] = le[0];
        uni_buf[pos + 1] = le[1];
        pos += 2;
    }
    out.extend_from_slice(&uni_buf);
}

fn serialize_extra_block(out: &mut Vec<u8>, block: &ExtraDataBlock) {
    match block {
        ExtraDataBlock::EnvironmentVariable {
            target_ansi,
            target_unicode,
        } => serialize_fixed_ansi_unicode_block(out, extra_sig::ENVIRONMENT_VARIABLE, target_ansi, target_unicode),
        ExtraDataBlock::Darwin {
            data_ansi,
            data_unicode,
        } => serialize_fixed_ansi_unicode_block(out, extra_sig::DARWIN, data_ansi, data_unicode),
        ExtraDataBlock::IconEnvironment {
            target_ansi,
            target_unicode,
        } => serialize_fixed_ansi_unicode_block(out, extra_sig::ICON_ENVIRONMENT, target_ansi, target_unicode),
        ExtraDataBlock::Tracker {
            machine_id,
            droid,
            droid_birth,
        } => {
            out.extend_from_slice(&96u32.to_le_bytes());
            out.extend_from_slice(&extra_sig::TRACKER.to_le_bytes());
            out.extend_from_slice(&88u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            let mut m = [0u8; 16];
            let mb = machine_id.as_bytes();
            let cl = mb.len().min(15);
            m[..cl].copy_from_slice(&mb[..cl]);
            out.extend_from_slice(&m);
            out.extend_from_slice(&droid[0]);
            out.extend_from_slice(&droid[1]);
            out.extend_from_slice(&droid_birth[0]);
            out.extend_from_slice(&droid_birth[1]);
        }
        ExtraDataBlock::SpecialFolder { folder_id, offset } => {
            out.extend_from_slice(&16u32.to_le_bytes());
            out.extend_from_slice(&extra_sig::SPECIAL_FOLDER.to_le_bytes());
            out.extend_from_slice(&folder_id.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
        }
        ExtraDataBlock::KnownFolder { folder_guid, offset } => {
            out.extend_from_slice(&28u32.to_le_bytes());
            out.extend_from_slice(&extra_sig::KNOWN_FOLDER.to_le_bytes());
            out.extend_from_slice(folder_guid);
            out.extend_from_slice(&offset.to_le_bytes());
        }
        ExtraDataBlock::Unknown { signature, payload } => {
            let block_size = (8 + payload.len()) as u32;
            out.extend_from_slice(&block_size.to_le_bytes());
            out.extend_from_slice(&signature.to_le_bytes());
            out.extend_from_slice(payload);
        }
    }
}

fn join_win_path(base: &str, suffix: &str) -> String {
    let b = base.trim_end_matches(['\\', '/']);
    let s = suffix.trim_start_matches(['\\', '/']);
    if b.is_empty() {
        s.to_string()
    } else if s.is_empty() {
        b.to_string()
    } else {
        format!("{b}\\{s}")
    }
}

fn expand_env_vars(input: &str, overrides: Option<&BTreeMap<String, String>>) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '%'
            && let Some(end_rel) = chars[i + 1..].iter().position(|&c| c == '%')
        {
            let name: String = chars[i + 1..i + 1 + end_rel].iter().collect();
            if !name.is_empty() {
                if let Some(ov) = overrides.and_then(|m| m.get(&name).or_else(|| m.get(&name.to_ascii_uppercase()))) {
                    out.push_str(ov);
                    i += end_rel + 2;
                    continue;
                }
                if let Ok(val) = std::env::var(&name) {
                    out.push_str(&val);
                    i += end_rel + 2;
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Configuration for shortcut inspection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShortcutsConfig {
    pub scan_roots: Vec<PathBuf>,
    pub include_recent: bool,
    pub env_overrides: BTreeMap<String, String>,
}

impl ShortcutsConfig {
    /// Discover standard Windows user/system shortcut directories when `scan_roots` is empty.
    pub fn effective_roots(&self) -> Vec<PathBuf> {
        if !self.scan_roots.is_empty() {
            return self.scan_roots.clone();
        }
        let mut roots = Vec::new();
        if let Some(desktop) = dirs::desktop_dir() {
            roots.push(desktop);
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            let base = PathBuf::from(&appdata).join("Microsoft").join("Windows");
            roots.push(base.join("Start Menu"));
            roots.push(
                PathBuf::from(&appdata)
                    .join("Microsoft")
                    .join("Internet Explorer")
                    .join("Quick Launch"),
            );
            if self.include_recent {
                roots.push(base.join("Recent"));
            }
        }
        if let Ok(program_data) = std::env::var("ProgramData") {
            roots.push(
                PathBuf::from(program_data)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu"),
            );
        }
        if let Ok(public_dir) = std::env::var("PUBLIC") {
            roots.push(PathBuf::from(public_dir).join("Desktop"));
        }
        roots.into_iter().filter(|p| p.exists()).collect()
    }
}

/// Read-only `.lnk` shortcut `TableProvider`.
pub struct ShortcutsProvider {
    config: ShortcutsConfig,
    backend: Arc<dyn FileSystemOps>,
}

impl ShortcutsProvider {
    pub fn new(config: ShortcutsConfig) -> Self {
        Self {
            config,
            backend: Arc::new(OsFileSystem),
        }
    }

    pub fn with_backend(config: ShortcutsConfig, backend: Arc<dyn FileSystemOps>) -> Self {
        Self { config, backend }
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "shortcuts_view",
            "Windows .lnk Shortcut Inspector",
            vec![
                ColumnDef::new("shortcut_path", "Shortcut Path", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("target_path", "Target Path", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("target_exists", "Target Exists", ColumnType::Bool).with_width_hint(90),
                ColumnDef::new("arguments", "Arguments", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("working_dir", "Working Dir", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("icon_location", "Icon Location", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("hot_key", "Hot Key", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("show_cmd", "Show Command", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("modified", "Modified", ColumnType::Timestamp).with_width_hint(180),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    pub fn execute(&self) -> Result<Vec<Row>, FsError> {
        let roots = self.config.effective_roots();
        let mut lnk_files = Vec::new();
        for root in roots {
            if !self.backend.exists(&root) {
                continue;
            }
            collect_lnk_files(&root, self.backend.as_ref(), &mut lnk_files);
        }
        lnk_files.sort();
        lnk_files.dedup();

        let env_map = if self.config.env_overrides.is_empty() {
            None
        } else {
            Some(&self.config.env_overrides)
        };

        let mut rows = Vec::with_capacity(lnk_files.len());
        for (idx, path) in lnk_files.into_iter().enumerate() {
            let bytes = match self.backend.read_bytes(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let meta = self.backend.metadata(&path).ok();
            let parsed = match ShellLinkFile::parse(&bytes) {
                Ok(lnk) => lnk,
                Err(err) => {
                    rows.push(
                        Row::new(
                            idx as u64,
                            vec![
                                CellValue::Text(path.to_string_lossy().into_owned()),
                                CellValue::Text(String::new()),
                                CellValue::Bool(false),
                                CellValue::Null,
                                CellValue::Null,
                                CellValue::Null,
                                CellValue::Null,
                                CellValue::Null,
                                meta.as_ref()
                                    .and_then(|m| m.timestamps.modified)
                                    .map_or(CellValue::Null, CellValue::Timestamp),
                            ],
                        )
                        .with_detail_json(json!({ "parse_error": err.to_string() }))
                        .with_raw_bytes(bytes.iter().copied().take(4096).collect()),
                    );
                    continue;
                }
            };

            let resolved = parsed.resolve_target(&path, env_map);
            let target_exists = if resolved.virtual_target {
                true
            } else if resolved.target_path.is_empty() {
                false
            } else {
                self.backend.exists(Path::new(&resolved.target_path))
            };

            let tracker_machine = parsed.extra_data.iter().find_map(|b| match b {
                ExtraDataBlock::Tracker { machine_id, .. } => Some(machine_id.clone()),
                _ => None,
            });
            let darwin_id = parsed.extra_data.iter().find_map(|b| match b {
                ExtraDataBlock::Darwin {
                    data_ansi,
                    data_unicode,
                } => Some(if !data_unicode.is_empty() {
                    data_unicode.clone()
                } else {
                    data_ansi.clone()
                }),
                _ => None,
            });
            let env_target = parsed.extra_data.iter().find_map(|b| match b {
                ExtraDataBlock::EnvironmentVariable {
                    target_ansi,
                    target_unicode,
                } => Some(if !target_unicode.is_empty() {
                    target_unicode.clone()
                } else {
                    target_ansi.clone()
                }),
                _ => None,
            });

            let detail = json!({
                "link_flags": parsed.header.link_flags,
                "target_kind": resolved.kind,
                "target_status": if target_exists { "valid" } else { "broken" },
                "description": parsed.string_data.name,
                "relative_path": parsed.string_data.relative_path,
                "network_path": parsed.link_info.as_ref().and_then(|l| l.network_share_name.clone()),
                "env_target": env_target,
                "tracker_machine_id": tracker_machine,
                "darwin_id": darwin_id,
                "extra_blocks_count": parsed.extra_data.len(),
            });

            rows.push(
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(path.to_string_lossy().into_owned()),
                        CellValue::Text(resolved.target_path),
                        CellValue::Bool(target_exists),
                        parsed
                            .string_data
                            .cmd_args
                            .as_ref()
                            .map_or(CellValue::Null, |s| CellValue::Text(s.clone())),
                        parsed
                            .string_data
                            .working_dir
                            .as_ref()
                            .map_or(CellValue::Null, |s| CellValue::Text(s.clone())),
                        parsed
                            .string_data
                            .icon_location
                            .as_ref()
                            .map_or(CellValue::Null, |s| CellValue::Text(s.clone())),
                        CellValue::Text(parsed.format_hot_key()),
                        CellValue::Text(parsed.header.show_command.label().to_string()),
                        meta.as_ref()
                            .and_then(|m| m.timestamps.modified)
                            .map_or(CellValue::Null, CellValue::Timestamp),
                    ],
                )
                .with_detail_json(detail)
                .with_raw_bytes(bytes.into_iter().take(4096).collect()),
            );
        }

        Ok(rows)
    }
}

fn collect_lnk_files(path: &Path, backend: &dyn FileSystemOps, out: &mut Vec<PathBuf>) {
    let Ok(meta) = backend.metadata(path) else {
        return;
    };
    if meta.is_symlink {
        return;
    }
    if !meta.is_dir {
        if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) {
            out.push(path.to_path_buf());
        }
        return;
    }
    let Ok(children) = backend.read_dir(path) else {
        return;
    };
    for child in children {
        if child.is_symlink {
            continue;
        }
        if child.is_dir {
            collect_lnk_files(&child.path, backend, out);
        } else if child.path.extension().is_some_and(|e| e.eq_ignore_ascii_case("lnk")) {
            out.push(child.path);
        }
    }
}

impl TableProvider for ShortcutsProvider {
    fn tool_id(&self) -> &'static str {
        "shortcuts_view"
    }

    fn description(&self) -> &'static str {
        "Parse Windows [MS-SHLLINK] .lnk shortcuts and detect broken targets"
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

/// Mutating `ActionCommand` rewriting a `.lnk` target path.
pub struct ShortcutsFixAction {
    backend: Arc<dyn FileSystemOps>,
    policy: PolicyContext,
}

impl ShortcutsFixAction {
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

impl ActionCommand for ShortcutsFixAction {
    fn command_id(&self) -> &'static str {
        "shortcuts_fix_target"
    }

    fn description(&self) -> &'static str {
        "Update the target path, working directory, or arguments inside a Windows .lnk shortcut"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["shortcut_path", "new_target"],
            "properties": {
                "shortcut_path": { "type": "string" },
                "new_target": { "type": "string" },
                "new_working_dir": { "type": "string" },
                "new_arguments": { "type": "string" }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let shortcut_path_str = args
            .get("shortcut_path")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'shortcut_path'".to_string()))?;
        let new_target = args
            .get("new_target")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'new_target'".to_string()))?;
        let new_working_dir = args.get("new_working_dir").and_then(Value::as_str);
        let new_arguments = args.get("new_arguments").and_then(Value::as_str);

        let shortcut_path = Path::new(shortcut_path_str);
        self.policy
            .check_path_allowed(shortcut_path)
            .map_err(McpToolError::from)?;
        let bytes = self.backend.read_bytes(shortcut_path).map_err(McpToolError::from)?;
        let parsed = ShellLinkFile::parse(&bytes).map_err(McpToolError::from)?;
        let old_resolved = parsed.resolve_target(shortcut_path, None);
        let updated = parsed.with_updated_target(new_target, new_working_dir, new_arguments);
        let serialized = updated.to_bytes().map_err(McpToolError::from)?;

        if dry_run {
            return Ok(json!({
                "mode": "dry_run",
                "shortcut_path": shortcut_path_str,
                "old_target": old_resolved.target_path,
                "new_target": new_target,
                "new_bytes_len": serialized.len(),
            }));
        }

        self.backend
            .write_bytes(shortcut_path, &serialized)
            .map_err(McpToolError::from)?;

        Ok(json!({
            "mode": "applied",
            "shortcut_path": shortcut_path_str,
            "old_target": old_resolved.target_path,
            "new_target": new_target,
            "bytes_written": serialized.len(),
        }))
    }
}

/// Mutating `ActionCommand` deleting `.lnk` files (with `only_if_broken` safety guard).
pub struct ShortcutsDeleteAction {
    backend: Arc<dyn FileSystemOps>,
    policy: PolicyContext,
}

impl ShortcutsDeleteAction {
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

impl ActionCommand for ShortcutsDeleteAction {
    fn command_id(&self) -> &'static str {
        "shortcuts_delete"
    }

    fn description(&self) -> &'static str {
        "Delete Windows .lnk shortcuts (guarded by only_if_broken = true by default)"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["shortcut_paths"],
            "properties": {
                "shortcut_paths": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "only_if_broken": { "type": "boolean", "default": true }
            }
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let paths_arr = args
            .get("shortcut_paths")
            .and_then(Value::as_array)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'shortcut_paths' array".to_string()))?;
        let only_if_broken = args.get("only_if_broken").and_then(Value::as_bool).unwrap_or(true);

        let mut target_paths = Vec::with_capacity(paths_arr.len());
        for item in paths_arr {
            let p_str = item
                .as_str()
                .ok_or_else(|| McpToolError::InvalidParams("shortcut_paths entries must be strings".to_string()))?;
            self.policy
                .check_path_allowed(Path::new(p_str))
                .map_err(McpToolError::from)?;
            target_paths.push(p_str);
        }

        let mut deleted = 0usize;
        let mut skipped = 0usize;
        let mut results = Vec::with_capacity(target_paths.len());

        for p_str in target_paths {
            let path = Path::new(p_str);
            let bytes = self.backend.read_bytes(path).map_err(McpToolError::from)?;
            let parsed = ShellLinkFile::parse(&bytes).map_err(McpToolError::from)?;
            let resolved = parsed.resolve_target(path, None);
            let target_exists = if resolved.virtual_target {
                true
            } else if resolved.target_path.is_empty() {
                false
            } else {
                self.backend.exists(Path::new(&resolved.target_path))
            };

            if only_if_broken && target_exists {
                skipped += 1;
                results.push(json!({
                    "shortcut_path": p_str,
                    "action": "skipped_valid_target",
                    "target_path": resolved.target_path,
                }));
                continue;
            }

            if dry_run {
                results.push(json!({
                    "shortcut_path": p_str,
                    "action": "would_delete",
                    "target_path": resolved.target_path,
                    "target_exists": target_exists,
                }));
                continue;
            }

            self.backend.remove_file(path).map_err(McpToolError::from)?;
            deleted += 1;
            results.push(json!({
                "shortcut_path": p_str,
                "action": "deleted",
                "target_path": resolved.target_path,
            }));
        }

        Ok(json!({
            "mode": if dry_run { "dry_run" } else { "applied" },
            "deleted": deleted,
            "skipped": skipped,
            "results": results,
        }))
    }
}
