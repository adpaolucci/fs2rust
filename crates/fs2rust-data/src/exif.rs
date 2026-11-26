use crate::error::DataError;
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_IFD_DEPTH: usize = 16;
const MAX_ENTRIES_PER_IFD: usize = 4096;
const MAX_TOTAL_ENTRIES: usize = 16_384;
const MAX_VALUE_BYTES: usize = 1_048_576;

/// Byte order of the TIFF container inside EXIF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TiffEndianness {
    Little,
    Big,
}

/// EXIF Image File Directory category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IfdKind {
    Ifd0,
    ExifIfd,
    GpsInfoIfd,
    InteropIfd,
    Ifd1,
}

impl IfdKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ifd0 => "IFD0",
            Self::ExifIfd => "ExifIFD",
            Self::GpsInfoIfd => "GPSInfoIFD",
            Self::InteropIfd => "InteropIFD",
            Self::Ifd1 => "IFD1",
        }
    }
}

/// All 12 standard TIFF / EXIF field types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TiffFieldType {
    Byte = 1,
    Ascii = 2,
    Short = 3,
    Long = 4,
    Rational = 5,
    SByte = 6,
    Undefined = 7,
    SShort = 8,
    SLong = 9,
    SRational = 10,
    Float = 11,
    Double = 12,
}

impl TiffFieldType {
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::Byte),
            2 => Some(Self::Ascii),
            3 => Some(Self::Short),
            4 => Some(Self::Long),
            5 => Some(Self::Rational),
            6 => Some(Self::SByte),
            7 => Some(Self::Undefined),
            8 => Some(Self::SShort),
            9 => Some(Self::SLong),
            10 => Some(Self::SRational),
            11 => Some(Self::Float),
            12 => Some(Self::Double),
            _ => None,
        }
    }

    pub fn unit_size(self) -> usize {
        match self {
            Self::Byte | Self::Ascii | Self::SByte | Self::Undefined => 1,
            Self::Short | Self::SShort => 2,
            Self::Long | Self::SLong | Self::Float => 4,
            Self::Rational | Self::SRational | Self::Double => 8,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Byte => "BYTE",
            Self::Ascii => "ASCII",
            Self::Short => "SHORT",
            Self::Long => "LONG",
            Self::Rational => "RATIONAL",
            Self::SByte => "SBYTE",
            Self::Undefined => "UNDEFINED",
            Self::SShort => "SSHORT",
            Self::SLong => "SLONG",
            Self::SRational => "SRATIONAL",
            Self::Float => "FLOAT",
            Self::Double => "DOUBLE",
        }
    }
}

/// Single parsed EXIF tag entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExifEntry {
    pub ifd: IfdKind,
    pub tag_id: u16,
    pub tag_name: String,
    pub field_type_code: u16,
    pub data_type: String,
    pub count: u32,
    pub value: String,
    pub parsed_values: Value,
    pub raw_bytes: Vec<u8>,
}

/// Parsed EXIF document containing entries, computed GPS decimal coordinates, and warnings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExifDocument {
    pub source_label: String,
    pub endianness: TiffEndianness,
    pub entries: Vec<ExifEntry>,
    pub gps_latitude_deg: Option<f64>,
    pub gps_longitude_deg: Option<f64>,
    pub warnings: Vec<String>,
}

/// Pure-Rust JPEG `APP1` / TIFF EXIF parser.
pub fn parse_exif(source_label: &str, bytes: &[u8]) -> Result<ExifDocument, DataError> {
    let tiff = extract_tiff_slice(bytes)?;
    if tiff.len() < 8 {
        return Err(DataError::InvalidExif("TIFF header shorter than 8 bytes".to_string()));
    }

    let endianness = match &tiff[0..2] {
        b"II" => TiffEndianness::Little,
        b"MM" => TiffEndianness::Big,
        _ => {
            return Err(DataError::InvalidExif(
                "invalid TIFF byte-order marker (expected II or MM)".to_string(),
            ));
        }
    };

    let magic = read_u16(tiff, 2, endianness)?;
    if magic == 0x002B {
        return Err(DataError::InvalidExif("BigTIFF (0x002B) is not supported".to_string()));
    }
    if magic != 0x002A {
        return Err(DataError::InvalidExif(format!(
            "invalid TIFF magic 0x{magic:04X} (expected 0x002A)"
        )));
    }

    let ifd0_offset = read_u32(tiff, 4, endianness)?;
    if ifd0_offset < 8 || (ifd0_offset as usize) >= tiff.len() {
        return Err(DataError::InvalidExif(format!(
            "IFD0 offset 0x{ifd0_offset:08X} is out of bounds"
        )));
    }

    let mut ctx = ParseCtx {
        tiff,
        endianness,
        visited_ifd_offsets: BTreeSet::new(),
        entries: Vec::new(),
        warnings: Vec::new(),
    };

    ctx.parse_ifd(IfdKind::Ifd0, ifd0_offset, 0)?;

    let (gps_lat, gps_lon) = compute_gps_decimal_degrees(&ctx.entries);

    Ok(ExifDocument {
        source_label: source_label.to_string(),
        endianness,
        entries: ctx.entries,
        gps_latitude_deg: gps_lat,
        gps_longitude_deg: gps_lon,
        warnings: ctx.warnings,
    })
}

fn extract_tiff_slice(bytes: &[u8]) -> Result<&[u8], DataError> {
    if bytes.starts_with(b"II\x2A\x00") || bytes.starts_with(b"MM\x00\x2A") {
        return Ok(bytes);
    }
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        let mut pos = 2usize;
        while pos < bytes.len() {
            while pos < bytes.len() && bytes[pos] == 0xFF {
                pos += 1;
            }
            if pos >= bytes.len() {
                break;
            }
            let marker = bytes[pos];
            pos += 1;
            if marker == 0xD9 || marker == 0xDA {
                break;
            }
            if marker == 0x00 || marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
                continue;
            }
            if pos + 2 > bytes.len() {
                return Err(DataError::InvalidExif("truncated JPEG marker length".to_string()));
            }
            let seg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            if seg_len < 2 {
                return Err(DataError::InvalidExif(format!(
                    "invalid JPEG segment length {seg_len} for marker 0x{marker:02X}"
                )));
            }
            let payload_start = pos + 2;
            let payload_len = seg_len - 2;
            let payload_end = payload_start
                .checked_add(payload_len)
                .ok_or_else(|| DataError::InvalidExif("JPEG segment length overflow".to_string()))?;
            if payload_end > bytes.len() {
                return Err(DataError::InvalidExif(format!(
                    "truncated JPEG marker 0x{marker:02X} payload"
                )));
            }
            let payload = &bytes[payload_start..payload_end];
            if marker == 0xE1 && payload.starts_with(b"Exif\0\0") {
                return Ok(&payload[6..]);
            }
            pos = payload_end;
        }
        return Err(DataError::InvalidExif(
            "JPEG image contains no APP1 Exif segment".to_string(),
        ));
    }
    Err(DataError::InvalidExif(
        "input is neither a JPEG SOI stream nor a raw TIFF II/MM stream".to_string(),
    ))
}

struct ParseCtx<'a> {
    tiff: &'a [u8],
    endianness: TiffEndianness,
    visited_ifd_offsets: BTreeSet<u32>,
    entries: Vec<ExifEntry>,
    warnings: Vec<String>,
}

impl<'a> ParseCtx<'a> {
    fn parse_ifd(&mut self, kind: IfdKind, offset: u32, depth: usize) -> Result<(), DataError> {
        if depth >= MAX_IFD_DEPTH {
            self.warnings.push(format!(
                "stopped recursion at {} (depth limit {MAX_IFD_DEPTH})",
                kind.label()
            ));
            return Ok(());
        }
        if !self.visited_ifd_offsets.insert(offset) {
            self.warnings.push(format!(
                "detected cyclic IFD pointer at offset 0x{offset:08X} in {}",
                kind.label()
            ));
            return Ok(());
        }
        let off = offset as usize;
        if off + 2 > self.tiff.len() {
            self.warnings.push(format!(
                "{} offset 0x{offset:08X} is truncated before entry count",
                kind.label()
            ));
            return Ok(());
        }

        let count = read_u16(self.tiff, off, self.endianness)? as usize;
        if count > MAX_ENTRIES_PER_IFD {
            self.warnings.push(format!(
                "{} entry count {count} exceeds cap {MAX_ENTRIES_PER_IFD}; truncating",
                kind.label()
            ));
        }
        let capped_count = count.min(MAX_ENTRIES_PER_IFD);

        let mut sub_ifds: Vec<(IfdKind, u32)> = Vec::new();
        let entries_start = off + 2;

        for idx in 0..capped_count {
            if self.entries.len() >= MAX_TOTAL_ENTRIES {
                self.warnings
                    .push(format!("reached total EXIF entry cap ({MAX_TOTAL_ENTRIES})"));
                return Ok(());
            }
            let entry_off = match entries_start.checked_add(idx * 12) {
                Some(v) if v + 12 <= self.tiff.len() => v,
                _ => {
                    self.warnings
                        .push(format!("{} entry {idx} truncated at EOF", kind.label()));
                    break;
                }
            };

            let tag_id = read_u16(self.tiff, entry_off, self.endianness)?;
            let type_code = read_u16(self.tiff, entry_off + 2, self.endianness)?;
            let val_count = read_u32(self.tiff, entry_off + 4, self.endianness)?;
            let value_or_off = &self.tiff[entry_off + 8..entry_off + 12];

            let Some(field_type) = TiffFieldType::from_code(type_code) else {
                self.warnings.push(format!(
                    "{} tag 0x{tag_id:04X} has unknown field type {type_code}",
                    kind.label()
                ));
                self.entries.push(ExifEntry {
                    ifd: kind,
                    tag_id,
                    tag_name: tag_name(kind, tag_id).to_string(),
                    field_type_code: type_code,
                    data_type: format!("UNKNOWN({type_code})"),
                    count: val_count,
                    value: format!("[unknown type {type_code}]"),
                    parsed_values: Value::Null,
                    raw_bytes: value_or_off.to_vec(),
                });
                continue;
            };

            let total_bytes = (val_count as usize).checked_mul(field_type.unit_size());
            let raw_slice: Option<&[u8]> = match total_bytes {
                Some(tb) if tb <= 4 => Some(&value_or_off[..tb]),
                Some(tb) if tb <= MAX_VALUE_BYTES => {
                    let val_off = read_u32(self.tiff, entry_off + 8, self.endianness)? as usize;
                    match val_off.checked_add(tb) {
                        Some(end) if end <= self.tiff.len() => Some(&self.tiff[val_off..end]),
                        _ => {
                            self.warnings.push(format!(
                                "{} tag 0x{tag_id:04X} value slice [0x{val_off:X}..+{tb}] out of bounds",
                                kind.label()
                            ));
                            None
                        }
                    }
                }
                Some(tb) => {
                    self.warnings.push(format!(
                        "{} tag 0x{tag_id:04X} payload ({tb} bytes) exceeds 1 MiB OOM guard",
                        kind.label()
                    ));
                    None
                }
                None => {
                    self.warnings
                        .push(format!("{} tag 0x{tag_id:04X} byte count overflow", kind.label()));
                    None
                }
            };

            let (formatted, parsed_values, raw_bytes) = match raw_slice {
                Some(slice) => {
                    let (fmt, json_val) = decode_tag_value(kind, tag_id, field_type, val_count, slice, self.endianness);
                    (fmt, json_val, slice.to_vec())
                }
                None => (
                    format!("[out-of-bounds offset/count {}]", val_count),
                    Value::Null,
                    value_or_off.to_vec(),
                ),
            };

            // Detect sub-IFD pointers
            if matches!(field_type, TiffFieldType::Long | TiffFieldType::Short)
                && val_count == 1
                && let Some(ptr) = raw_slice.and_then(|s| read_scalar_u32(s, field_type, self.endianness))
                && ptr > 0
            {
                match (kind, tag_id) {
                    (IfdKind::Ifd0, 0x8769) => sub_ifds.push((IfdKind::ExifIfd, ptr)),
                    (IfdKind::Ifd0, 0x8825) => sub_ifds.push((IfdKind::GpsInfoIfd, ptr)),
                    (IfdKind::Ifd0 | IfdKind::ExifIfd, 0xA005) => sub_ifds.push((IfdKind::InteropIfd, ptr)),
                    _ => {}
                }
            }

            self.entries.push(ExifEntry {
                ifd: kind,
                tag_id,
                tag_name: tag_name(kind, tag_id).to_string(),
                field_type_code: type_code,
                data_type: field_type.name().to_string(),
                count: val_count,
                value: formatted,
                parsed_values,
                raw_bytes,
            });
        }

        let next_ifd_pos = entries_start.checked_add(capped_count * 12);
        let next_ifd_offset = match next_ifd_pos {
            Some(p) if p + 4 <= self.tiff.len() => read_u32(self.tiff, p, self.endianness)?,
            _ => 0,
        };

        for (sub_kind, ptr) in sub_ifds {
            self.parse_ifd(sub_kind, ptr, depth + 1)?;
        }

        if kind == IfdKind::Ifd0 && next_ifd_offset != 0 {
            self.parse_ifd(IfdKind::Ifd1, next_ifd_offset, depth + 1)?;
        }

        Ok(())
    }
}

fn read_scalar_u32(slice: &[u8], field_type: TiffFieldType, endian: TiffEndianness) -> Option<u32> {
    match field_type {
        TiffFieldType::Short if slice.len() >= 2 => read_u16(slice, 0, endian).ok().map(u32::from),
        TiffFieldType::Long if slice.len() >= 4 => read_u32(slice, 0, endian).ok(),
        _ => None,
    }
}

fn decode_tag_value(
    kind: IfdKind,
    tag_id: u16,
    field_type: TiffFieldType,
    count: u32,
    slice: &[u8],
    endian: TiffEndianness,
) -> (String, Value) {
    match field_type {
        TiffFieldType::Byte => {
            let vals: Vec<u8> = slice.to_vec();
            let text = vals.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::SByte => {
            let vals: Vec<i8> = slice.iter().map(|&b| b as i8).collect();
            let text = vals.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::Ascii => {
            let trimmed = slice.strip_suffix(&[0]).unwrap_or(slice);
            let trimmed = trimmed.split(|&b| b == 0).next().unwrap_or(trimmed);
            let s = String::from_utf8_lossy(trimmed).into_owned();
            (s.clone(), Value::String(s))
        }
        TiffFieldType::Short => {
            let vals: Vec<u16> = slice
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| match endian {
                    TiffEndianness::Little => u16::from_le_bytes(*c),
                    TiffEndianness::Big => u16::from_be_bytes(*c),
                })
                .collect();
            let text = vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::SShort => {
            let vals: Vec<i16> = slice
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| match endian {
                    TiffEndianness::Little => i16::from_le_bytes(*c),
                    TiffEndianness::Big => i16::from_be_bytes(*c),
                })
                .collect();
            let text = vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::Long => {
            let vals: Vec<u32> = slice
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| match endian {
                    TiffEndianness::Little => u32::from_le_bytes(*c),
                    TiffEndianness::Big => u32::from_be_bytes(*c),
                })
                .collect();
            let text = vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::SLong => {
            let vals: Vec<i32> = slice
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| match endian {
                    TiffEndianness::Little => i32::from_le_bytes(*c),
                    TiffEndianness::Big => i32::from_be_bytes(*c),
                })
                .collect();
            let text = vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::Rational => {
            let mut parts = Vec::new();
            let mut json_parts = Vec::new();
            for chunk in slice.as_chunks::<8>().0 {
                let (num, den) = match endian {
                    TiffEndianness::Little => (
                        u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                        u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                    ),
                    TiffEndianness::Big => (
                        u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                        u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                    ),
                };
                if den == 0 {
                    parts.push("undef".to_string());
                    json_parts.push(json!({ "num": num, "den": den, "value": Value::Null }));
                } else {
                    let float_val = num as f64 / den as f64;
                    if num == 0 {
                        parts.push("0".to_string());
                    } else if num < den {
                        parts.push(format!("{num}/{den}"));
                    } else if num % den == 0 {
                        parts.push(format!("{}", num / den));
                    } else {
                        parts.push(format!("{float_val:.4} ({num}/{den})"));
                    }
                    json_parts.push(json!({ "num": num, "den": den, "value": float_val }));
                }
            }
            (parts.join(", "), Value::Array(json_parts))
        }
        TiffFieldType::SRational => {
            let mut parts = Vec::new();
            let mut json_parts = Vec::new();
            for chunk in slice.as_chunks::<8>().0 {
                let (num, den) = match endian {
                    TiffEndianness::Little => (
                        i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                        i32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                    ),
                    TiffEndianness::Big => (
                        i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                        i32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                    ),
                };
                if den == 0 {
                    parts.push("undef".to_string());
                    json_parts.push(json!({ "num": num, "den": den, "value": Value::Null }));
                } else {
                    let float_val = num as f64 / den as f64;
                    parts.push(format!("{float_val:.4} ({num}/{den})"));
                    json_parts.push(json!({ "num": num, "den": den, "value": float_val }));
                }
            }
            (parts.join(", "), Value::Array(json_parts))
        }
        TiffFieldType::Float => {
            let vals: Vec<f32> = slice
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| {
                    let bits = match endian {
                        TiffEndianness::Little => u32::from_le_bytes(*c),
                        TiffEndianness::Big => u32::from_be_bytes(*c),
                    };
                    f32::from_bits(bits)
                })
                .collect();
            let text = vals.iter().map(|v| format!("{v}")).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::Double => {
            let vals: Vec<f64> = slice
                .as_chunks::<8>()
                .0
                .iter()
                .map(|c| {
                    let bits = match endian {
                        TiffEndianness::Little => u64::from_le_bytes(*c),
                        TiffEndianness::Big => u64::from_be_bytes(*c),
                    };
                    f64::from_bits(bits)
                })
                .collect();
            let text = vals.iter().map(|v| format!("{v}")).collect::<Vec<_>>().join(", ");
            (text, json!(vals))
        }
        TiffFieldType::Undefined => decode_undefined_tag(kind, tag_id, count, slice, endian),
    }
}

fn decode_undefined_tag(
    kind: IfdKind,
    tag_id: u16,
    count: u32,
    slice: &[u8],
    endian: TiffEndianness,
) -> (String, Value) {
    if kind == IfdKind::ExifIfd && tag_id == 0x9000 {
        let ver = String::from_utf8_lossy(slice).into_owned();
        return (ver.clone(), Value::String(ver));
    }
    if kind == IfdKind::ExifIfd && tag_id == 0x9101 {
        let mapped: Vec<&str> = slice
            .iter()
            .map(|&b| match b {
                1 => "Y",
                2 => "Cb",
                3 => "Cr",
                4 => "R",
                5 => "G",
                6 => "B",
                _ => "-",
            })
            .collect();
        let text = mapped.join("");
        return (text.clone(), Value::String(text));
    }
    if kind == IfdKind::ExifIfd && tag_id == 0x9286 && slice.len() >= 8 {
        let prefix = &slice[..8];
        let body = &slice[8..];
        let text = if prefix == b"ASCII\0\0\0" {
            String::from_utf8_lossy(body).trim_end_matches('\0').to_string()
        } else if prefix == b"UNICODE\0" {
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| match endian {
                    TiffEndianness::Little => u16::from_le_bytes(*c),
                    TiffEndianness::Big => u16::from_be_bytes(*c),
                })
                .take_while(|&u| u != 0)
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(body).trim_end_matches('\0').to_string()
        };
        return (text.clone(), Value::String(text));
    }
    if kind == IfdKind::ExifIfd && tag_id == 0x927C {
        let summary = format!("<MakerNote: {} bytes>", slice.len());
        return (
            summary,
            json!({ "maker_note_bytes": slice.len(), "preview_hex": encode_hex_lower(&slice[..slice.len().min(32)]) }),
        );
    }
    let hex = encode_hex_lower(&slice[..slice.len().min(64)]);
    (
        format!("<{} bytes: {hex}>", count),
        json!({ "bytes": slice.len(), "hex": hex }),
    )
}

fn compute_gps_decimal_degrees(entries: &[ExifEntry]) -> (Option<f64>, Option<f64>) {
    let mut lat_ref: Option<String> = None;
    let mut lon_ref: Option<String> = None;
    let mut lat_dms: Option<Vec<f64>> = None;
    let mut lon_dms: Option<Vec<f64>> = None;

    for e in entries {
        if e.ifd != IfdKind::GpsInfoIfd {
            continue;
        }
        match e.tag_id {
            0x0001 => lat_ref = e.parsed_values.as_str().map(|s| s.trim().to_ascii_uppercase()),
            0x0002 => lat_dms = extract_rational_floats(&e.parsed_values),
            0x0003 => lon_ref = e.parsed_values.as_str().map(|s| s.trim().to_ascii_uppercase()),
            0x0004 => lon_dms = extract_rational_floats(&e.parsed_values),
            _ => {}
        }
    }

    let lat = lat_dms.and_then(|v| dms_to_decimal(&v, lat_ref.as_deref() == Some("S")));
    let lon = lon_dms.and_then(|v| dms_to_decimal(&v, lon_ref.as_deref() == Some("W")));
    (lat, lon)
}

fn extract_rational_floats(val: &Value) -> Option<Vec<f64>> {
    let arr = val.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        out.push(item.get("value")?.as_f64()?);
    }
    Some(out)
}

fn dms_to_decimal(dms: &[f64], negate: bool) -> Option<f64> {
    if dms.len() < 3 {
        return None;
    }
    let deg = dms[0] + dms[1] / 60.0 + dms[2] / 3600.0;
    Some(if negate { -deg } else { deg })
}

fn read_u16(bytes: &[u8], off: usize, endian: TiffEndianness) -> Result<u16, DataError> {
    let slice = bytes
        .get(off..off + 2)
        .ok_or_else(|| DataError::InvalidExif(format!("unexpected EOF reading u16 at 0x{off:X}")))?;
    Ok(match endian {
        TiffEndianness::Little => u16::from_le_bytes([slice[0], slice[1]]),
        TiffEndianness::Big => u16::from_be_bytes([slice[0], slice[1]]),
    })
}

fn read_u32(bytes: &[u8], off: usize, endian: TiffEndianness) -> Result<u32, DataError> {
    let slice = bytes
        .get(off..off + 4)
        .ok_or_else(|| DataError::InvalidExif(format!("unexpected EOF reading u32 at 0x{off:X}")))?;
    Ok(match endian {
        TiffEndianness::Little => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
        TiffEndianness::Big => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]),
    })
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Map standard EXIF/TIFF tag IDs to human-readable tag names.
pub fn tag_name(ifd: IfdKind, tag_id: u16) -> &'static str {
    match ifd {
        IfdKind::Ifd0 | IfdKind::Ifd1 => match tag_id {
            0x0100 => "ImageWidth",
            0x0101 => "ImageLength",
            0x0102 => "BitsPerSample",
            0x0103 => "Compression",
            0x0106 => "PhotometricInterpretation",
            0x010E => "ImageDescription",
            0x010F => "Make",
            0x0110 => "Model",
            0x0112 => "Orientation",
            0x011A => "XResolution",
            0x011B => "YResolution",
            0x0128 => "ResolutionUnit",
            0x0131 => "Software",
            0x0132 => "DateTime",
            0x013B => "Artist",
            0x0201 => "JPEGInterchangeFormat",
            0x0202 => "JPEGInterchangeFormatLength",
            0x0213 => "YCbCrPositioning",
            0x8298 => "Copyright",
            0x8769 => "ExifIFDPointer",
            0x8825 => "GPSInfoIFDPointer",
            _ => "UnknownTag",
        },
        IfdKind::ExifIfd => match tag_id {
            0x829A => "ExposureTime",
            0x829D => "FNumber",
            0x8822 => "ExposureProgram",
            0x8827 => "ISOSpeedRatings",
            0x9000 => "ExifVersion",
            0x9003 => "DateTimeOriginal",
            0x9004 => "DateTimeDigitized",
            0x9101 => "ComponentsConfiguration",
            0x9201 => "ShutterSpeedValue",
            0x9202 => "ApertureValue",
            0x9204 => "ExposureBiasValue",
            0x9207 => "MeteringMode",
            0x9209 => "Flash",
            0x920A => "FocalLength",
            0x927C => "MakerNote",
            0x9286 => "UserComment",
            0xA001 => "ColorSpace",
            0xA002 => "PixelXDimension",
            0xA003 => "PixelYDimension",
            0xA005 => "InteroperabilityIFDPointer",
            0xA405 => "FocalLengthIn35mmFilm",
            0xA430 => "CameraOwnerName",
            0xA431 => "BodySerialNumber",
            0xA433 => "LensMake",
            0xA434 => "LensModel",
            0xA435 => "LensSerialNumber",
            _ => "UnknownExifTag",
        },
        IfdKind::GpsInfoIfd => match tag_id {
            0x0000 => "GPSVersionID",
            0x0001 => "GPSLatitudeRef",
            0x0002 => "GPSLatitude",
            0x0003 => "GPSLongitudeRef",
            0x0004 => "GPSLongitude",
            0x0005 => "GPSAltitudeRef",
            0x0006 => "GPSAltitude",
            0x0007 => "GPSTimeStamp",
            0x001D => "GPSDateStamp",
            0x001F => "GPSHPositioningError",
            _ => "UnknownGPSTag",
        },
        IfdKind::InteropIfd => match tag_id {
            0x0001 => "InteroperabilityIndex",
            0x0002 => "InteroperabilityVersion",
            0x1000 => "RelatedImageFileFormat",
            0x1001 => "RelatedImageWidth",
            0x1002 => "RelatedImageLength",
            _ => "UnknownInteropTag",
        },
    }
}

/// `TableProvider` reading EXIF tags from one or more JPEG/TIFF files or in-memory buffers.
pub struct ExifDataViewProvider {
    sources: Vec<(String, Vec<u8>)>,
    paths: Vec<PathBuf>,
}

impl ExifDataViewProvider {
    pub fn from_paths(paths: Vec<PathBuf>) -> Self {
        Self {
            sources: Vec::new(),
            paths,
        }
    }

    pub fn from_bytes(label: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            sources: vec![(label.into(), bytes)],
            paths: Vec::new(),
        }
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "fs2rust.data.exif_data_view",
            "JPEG/TIFF EXIF Metadata",
            vec![
                ColumnDef::new("file_path", "File Path", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("ifd", "IFD", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("tag_id", "Tag ID", ColumnType::Text).with_width_hint(80),
                ColumnDef::new("tag_name", "Tag Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("data_type", "Type", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("count", "Count", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("value", "Value", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("hex_bytes", "Raw Hex", ColumnType::Hex).with_width_hint(200),
            ],
        )
    }

    pub fn parse_all(&self) -> Result<Vec<ExifDocument>, DataError> {
        let mut docs = Vec::new();
        for (label, bytes) in &self.sources {
            docs.push(parse_exif(label, bytes)?);
        }
        for path in &self.paths {
            let bytes = std::fs::read(path)?;
            docs.push(parse_exif(&path.to_string_lossy(), &bytes)?);
        }
        Ok(docs)
    }
}

impl TableProvider for ExifDataViewProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.exif_data_view"
    }

    fn description(&self) -> &'static str {
        "Pure-Rust JPEG APP1 and TIFF IFD0/Exif/GPS/Interop/IFD1 EXIF metadata parser"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let docs = self.parse_all().map_err(TableError::from)?;
        let mut rows = Vec::new();
        for doc in docs {
            let gps_map: Option<BTreeMap<&str, f64>> = match (doc.gps_latitude_deg, doc.gps_longitude_deg) {
                (Some(lat), Some(lon)) => {
                    let mut m = BTreeMap::new();
                    m.insert("lat", lat);
                    m.insert("lon", lon);
                    Some(m)
                }
                _ => None,
            };
            let endian_str = match doc.endianness {
                TiffEndianness::Little => "II (Little-Endian)",
                TiffEndianness::Big => "MM (Big-Endian)",
            };
            for entry in doc.entries {
                let id = rows.len() as u64;
                let detail = json!({
                    "endianness": endian_str,
                    "ifd": entry.ifd.label(),
                    "tag_id_u16": entry.tag_id,
                    "raw_count": entry.count,
                    "parsed_values": entry.parsed_values,
                    "gps_decimal_deg": gps_map,
                    "warnings": doc.warnings,
                });
                rows.push(
                    Row::new(
                        id,
                        vec![
                            CellValue::Text(doc.source_label.clone()),
                            CellValue::Text(entry.ifd.label().to_string()),
                            CellValue::Text(format!("0x{:04X}", entry.tag_id)),
                            CellValue::Text(entry.tag_name),
                            CellValue::Text(entry.data_type),
                            CellValue::Uint(u64::from(entry.count)),
                            CellValue::Text(entry.value),
                            CellValue::Hex(entry.raw_bytes.clone()),
                        ],
                    )
                    .with_detail_json(detail)
                    .with_raw_bytes(entry.raw_bytes),
                );
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}

/// Convenience helper for reading EXIF directly from a file path.
pub fn parse_exif_file(path: &Path) -> Result<ExifDocument, DataError> {
    let bytes = std::fs::read(path)?;
    parse_exif(&path.to_string_lossy(), &bytes)
}
