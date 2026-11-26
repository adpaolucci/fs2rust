#![forbid(unsafe_code)]

use fs2rust_core::FsError;

pub fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, FsError> {
    bytes.get(offset).copied().ok_or_else(|| {
        FsError::Parse(format!(
            "unexpected EOF reading u8 at offset {offset} (len={})",
            bytes.len()
        ))
    })
}

pub fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, FsError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| FsError::Parse(format!("offset overflow reading u16 at {offset}")))?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        FsError::Parse(format!(
            "unexpected EOF reading u16 at {offset}..{end} (len={})",
            bytes.len()
        ))
    })?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, FsError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| FsError::Parse(format!("offset overflow reading u32 at {offset}")))?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        FsError::Parse(format!(
            "unexpected EOF reading u32 at {offset}..{end} (len={})",
            bytes.len()
        ))
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32, FsError> {
    Ok(read_u32_le(bytes, offset)? as i32)
}

pub fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, FsError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| FsError::Parse(format!("offset overflow reading u64 at {offset}")))?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        FsError::Parse(format!(
            "unexpected EOF reading u64 at {offset}..{end} (len={})",
            bytes.len()
        ))
    })?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub fn read_i64_le(bytes: &[u8], offset: usize) -> Result<i64, FsError> {
    Ok(read_u64_le(bytes, offset)? as i64)
}

pub fn read_u128_le(bytes: &[u8], offset: usize) -> Result<u128, FsError> {
    let end = offset
        .checked_add(16)
        .ok_or_else(|| FsError::Parse(format!("offset overflow reading u128 at {offset}")))?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        FsError::Parse(format!(
            "unexpected EOF reading u128 at {offset}..{end} (len={})",
            bytes.len()
        ))
    })?;
    let mut arr = [0u8; 16];
    arr.copy_from_slice(slice);
    Ok(u128::from_le_bytes(arr))
}

pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn decode_utf16le_nul(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn format_guid_le(bytes: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        d1, d2, d3, bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub fn validate_volume_guid_path(vol: &str) -> Result<String, FsError> {
    let trimmed = vol.trim();
    let body = trimmed
        .strip_prefix(r"\\?\Volume{")
        .and_then(|s| s.strip_suffix(r"}\"))
        .ok_or_else(|| {
            FsError::InvalidArgument(format!(
                "invalid volume GUID path '{trimmed}': expected format '\\\\?\\Volume{{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}}\\'"
            ))
        })?;
    let parts: Vec<&str> = body.split('-').collect();
    let expected_lens = [8usize, 4, 4, 4, 12];
    if parts.len() != 5
        || parts
            .iter()
            .zip(expected_lens.iter())
            .any(|(p, &len)| p.len() != len || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(FsError::InvalidArgument(format!(
            "invalid volume GUID syntax in '{trimmed}'"
        )));
    }
    Ok(trimmed.to_string())
}

pub fn normalize_volume_device_path(input: &str) -> Result<String, FsError> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(FsError::InvalidArgument("volume specifier cannot be empty".to_string()));
    }
    let clean = trimmed.trim_end_matches(['\\', '/']);
    if clean.len() == 1 && clean.as_bytes()[0].is_ascii_alphabetic() {
        return Ok(format!(r"\\.\{}:", clean.to_ascii_uppercase()));
    }
    if clean.len() == 2 && clean.as_bytes()[0].is_ascii_alphabetic() && clean.as_bytes()[1] == b':' {
        return Ok(format!(r"\\.\{}:", (clean.as_bytes()[0] as char).to_ascii_uppercase()));
    }
    if let Some(rest) = clean.strip_prefix(r"\\.\")
        && rest.len() == 2
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest.as_bytes()[1] == b':'
    {
        return Ok(format!(r"\\.\{}:", (rest.as_bytes()[0] as char).to_ascii_uppercase()));
    }
    if let Some(rest) = clean.strip_prefix(r"\\.\PhysicalDrive")
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(clean.to_string());
    }
    Err(FsError::InvalidArgument(format!(
        "unsupported volume/device specifier '{input}': expected drive letter (e.g. 'C:') or '\\\\.\\PhysicalDriveN'"
    )))
}

pub fn ensure_trailing_backslash(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.ends_with('\\') || trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!(r"{trimmed}\")
    }
}
