use crate::csv_view::{CsvTableProvider, CsvViewOptions};
use crate::encoding::{decode_bytes, decode_windows_1252};
use crate::error::DataError;
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;

/// Detected contact file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactFormat {
    VCard,
    Ldif,
    Csv,
}

impl ContactFormat {
    pub fn label(self) -> &'static str {
        match self {
            Self::VCard => "vCard",
            Self::Ldif => "LDIF",
            Self::Csv => "CSV",
        }
    }
}

/// Canonical normalized contact record parsed by `AddrView`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRecord {
    pub source_path: String,
    pub source_format: String,
    pub full_name: String,
    pub email: String,
    pub phone: String,
    pub mobile: String,
    pub company: String,
    pub title: String,
    pub address: String,
    pub notes: String,
    pub uid: Option<String>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub addresses: Vec<String>,
    pub extra: BTreeMap<String, String>,
}

/// `AddrView` contact book `TableProvider` reading `.vcf`, `.ldif`, and `.csv` contacts.
pub struct AddrViewProvider {
    records: Vec<ContactRecord>,
}

impl AddrViewProvider {
    pub fn from_records(records: Vec<ContactRecord>) -> Self {
        Self { records }
    }

    pub fn from_path(path: &Path) -> Result<Self, DataError> {
        let bytes = std::fs::read(path)?;
        let label = path.to_string_lossy().into_owned();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let format = match ext.as_str() {
            "vcf" | "vcard" => ContactFormat::VCard,
            "ldif" => ContactFormat::Ldif,
            "csv" | "tsv" => ContactFormat::Csv,
            _ => detect_contact_format(&bytes),
        };
        Self::from_bytes(&label, &bytes, format)
    }

    pub fn from_bytes(source_label: &str, bytes: &[u8], format: ContactFormat) -> Result<Self, DataError> {
        let records = match format {
            ContactFormat::VCard => parse_vcards(source_label, bytes)?,
            ContactFormat::Ldif => parse_ldif(source_label, bytes)?,
            ContactFormat::Csv => parse_contact_csv(source_label, bytes)?,
        };
        Ok(Self { records })
    }

    pub fn records(&self) -> &[ContactRecord] {
        &self.records
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "fs2rust.data.addr_view",
            "AddrView — Address Book & Contacts",
            vec![
                ColumnDef::new("full_name", "Full Name", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("email", "Email", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("phone", "Phone", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("mobile", "Mobile", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("company", "Company", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("address", "Address", ColumnType::Text).with_width_hint(260),
                ColumnDef::new("notes", "Notes", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("source_format", "Format", ColumnType::Text).with_width_hint(80),
            ],
        )
    }
}

impl TableProvider for AddrViewProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.addr_view"
    }

    fn description(&self) -> &'static str {
        "Pure-Rust contact book reader for vCard (.vcf), LDIF (.ldif), and contact CSV files"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let rows: Vec<Row> = self
            .records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let detail = json!({
                    "source_path": r.source_path,
                    "emails": r.emails,
                    "phones": r.phones,
                    "addresses": r.addresses,
                    "uid": r.uid,
                    "extra": r.extra,
                });
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(r.full_name.clone()),
                        CellValue::Text(r.email.clone()),
                        CellValue::Text(r.phone.clone()),
                        CellValue::Text(r.mobile.clone()),
                        CellValue::Text(r.company.clone()),
                        CellValue::Text(r.title.clone()),
                        CellValue::Text(r.address.clone()),
                        CellValue::Text(r.notes.clone()),
                        CellValue::Text(r.source_format.clone()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

fn detect_contact_format(bytes: &[u8]) -> ContactFormat {
    let decoded = decode_bytes(bytes);
    let upper = decoded.text.to_ascii_uppercase();
    if upper.contains("BEGIN:VCARD") {
        ContactFormat::VCard
    } else if decoded
        .text
        .lines()
        .any(|l| l.starts_with("dn:") || l.starts_with("dn::"))
    {
        ContactFormat::Ldif
    } else {
        ContactFormat::Csv
    }
}

/// Pure-Rust vCard 2.1 / 3.0 / 4.0 parser supporting line unfolding and Quoted-Printable.
pub fn parse_vcards(source_label: &str, bytes: &[u8]) -> Result<Vec<ContactRecord>, DataError> {
    let decoded = decode_bytes(bytes);
    let logical_lines = unfold_vcard_lines(&decoded.text);

    let mut records = Vec::new();
    let mut current: Option<ContactRecord> = None;
    let mut structured_name: Option<String> = None;

    for line in logical_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("BEGIN:VCARD") {
            if let Some(mut prev) = current.take() {
                if prev.full_name.is_empty()
                    && let Some(sn) = structured_name.take()
                {
                    prev.full_name = sn;
                }
                records.push(prev);
            }
            current = Some(ContactRecord {
                source_path: source_label.to_string(),
                source_format: "vCard".to_string(),
                ..ContactRecord::default()
            });
            structured_name = None;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("END:VCARD") {
            if let Some(mut rec) = current.take() {
                if rec.full_name.is_empty()
                    && let Some(sn) = structured_name.take()
                {
                    rec.full_name = sn;
                }
                records.push(rec);
            }
            continue;
        }
        let Some(rec) = current.as_mut() else {
            continue;
        };

        let Some((lhs, raw_val)) = split_unquoted_once(trimmed, ':') else {
            continue;
        };
        let mut lhs_parts = split_unquoted_all(lhs, ';');
        if lhs_parts.is_empty() {
            continue;
        }
        let raw_name = lhs_parts.remove(0);
        let prop_name = raw_name
            .rsplit('.')
            .next()
            .unwrap_or(&raw_name)
            .trim()
            .to_ascii_uppercase();

        let mut is_qp = false;
        let mut charset = String::from("UTF-8");
        let mut types = Vec::new();
        for param in lhs_parts {
            let p_trim = param.trim();
            let p_upper = p_trim.to_ascii_uppercase();
            if p_upper == "QUOTED-PRINTABLE" {
                is_qp = true;
            } else if let Some((pk, pv)) = p_trim.split_once('=') {
                let pk_up = pk.trim().to_ascii_uppercase();
                let pv_clean = pv.trim().trim_matches('"');
                match pk_up.as_str() {
                    "ENCODING" if pv_clean.eq_ignore_ascii_case("QUOTED-PRINTABLE") => is_qp = true,
                    "CHARSET" => charset = pv_clean.to_ascii_uppercase(),
                    "TYPE" => {
                        for t in pv_clean.split(',') {
                            types.push(t.trim().to_ascii_uppercase());
                        }
                    }
                    _ => {}
                }
            } else if !p_upper.is_empty() {
                types.push(p_upper);
            }
        }

        let val = if is_qp {
            decode_quoted_printable(raw_val, &charset)
        } else {
            unescape_vcard_text(raw_val)
        };

        match prop_name.as_str() {
            "VERSION" => {
                rec.source_format = format!("vCard {}", val.trim());
            }
            "FN" => {
                rec.full_name = val.trim().to_string();
            }
            "N" => {
                let parts = split_unescaped(raw_val, ';');
                let family = parts
                    .first()
                    .map(|s| decode_if_qp(s, is_qp, &charset))
                    .unwrap_or_default();
                let given = parts
                    .get(1)
                    .map(|s| decode_if_qp(s, is_qp, &charset))
                    .unwrap_or_default();
                let joined = [given.trim(), family.trim()]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                if !joined.is_empty() {
                    structured_name = Some(joined);
                }
            }
            "EMAIL" => {
                let e = val.trim().to_string();
                if !e.is_empty() {
                    if rec.email.is_empty() {
                        rec.email = e.clone();
                    }
                    rec.emails.push(e);
                }
            }
            "TEL" => {
                let p = val.trim().to_string();
                if !p.is_empty() {
                    let is_mobile = types.iter().any(|t| t == "CELL" || t == "MOBILE");
                    if is_mobile && rec.mobile.is_empty() {
                        rec.mobile = p.clone();
                    } else if rec.phone.is_empty() {
                        rec.phone = p.clone();
                    }
                    rec.phones.push(p);
                }
            }
            "ORG" => {
                let org = split_unescaped(raw_val, ';')
                    .into_iter()
                    .map(|s| decode_if_qp(s, is_qp, &charset).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" / ");
                rec.company = org;
            }
            "TITLE" => {
                rec.title = val.trim().to_string();
            }
            "ADR" => {
                let addr = split_unescaped(raw_val, ';')
                    .into_iter()
                    .map(|s| decode_if_qp(s, is_qp, &charset).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");
                if !addr.is_empty() {
                    if rec.address.is_empty() {
                        rec.address = addr.clone();
                    }
                    rec.addresses.push(addr);
                }
            }
            "NOTE" => {
                rec.notes = val.trim().to_string();
            }
            "UID" => {
                rec.uid = Some(val.trim().to_string());
            }
            other => {
                if !val.trim().is_empty() {
                    rec.extra.insert(other.to_string(), val.trim().to_string());
                }
            }
        }
    }

    if let Some(mut rec) = current.take() {
        if rec.full_name.is_empty()
            && let Some(sn) = structured_name.take()
        {
            rec.full_name = sn;
        }
        records.push(rec);
    }

    Ok(records)
}

fn split_unescaped(s: &str, delim: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
        } else if ch == delim {
            out.push(&s[start..idx]);
            start = idx + ch.len_utf8();
        }
    }
    out.push(&s[start..]);
    out
}

fn decode_if_qp(raw: &str, is_qp: bool, charset: &str) -> String {
    if is_qp {
        decode_quoted_printable(raw, charset)
    } else {
        unescape_vcard_text(raw)
    }
}

fn unfold_vcard_lines(text: &str) -> Vec<String> {
    let raw_lines: Vec<&str> = text.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let mut out: Vec<String> = Vec::new();
    let mut prev_was_qp_soft_break = false;

    for line in raw_lines {
        if prev_was_qp_soft_break {
            if let Some(last) = out.last_mut() {
                if last.ends_with('=') {
                    last.pop();
                }
                last.push_str(line);
                prev_was_qp_soft_break = last.ends_with('=');
                continue;
            }
            prev_was_qp_soft_break = false;
        }

        if let Some(rest) = line.strip_prefix(' ').or_else(|| line.strip_prefix('\t'))
            && let Some(last) = out.last_mut()
        {
            last.push_str(rest);
            continue;
        }

        let upper = line.to_ascii_uppercase();
        let has_qp = upper.contains("QUOTED-PRINTABLE");
        prev_was_qp_soft_break = has_qp && line.ends_with('=');
        out.push(line.to_string());
    }

    out
}

fn decode_quoted_printable(input: &str, charset: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let raw = input.as_bytes();
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'=' && i + 2 < raw.len() {
            if raw[i + 1] == b'\r' && raw[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if let (Some(hi), Some(lo)) = (hex_nibble(raw[i + 1]), hex_nibble(raw[i + 2])) {
                bytes.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        if raw[i] == b'=' && i + 1 < raw.len() && raw[i + 1] == b'\n' {
            i += 2;
            continue;
        }
        bytes.push(raw[i]);
        i += 1;
    }

    if charset.contains("1252") || charset.contains("ISO-8859-1") {
        decode_windows_1252(&bytes)
    } else {
        String::from_utf8(bytes).unwrap_or_else(|e| decode_windows_1252(e.as_bytes()))
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn unescape_vcard_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('N') => out.push('\n'),
                Some(',') => out.push(','),
                Some(';') => out.push(';'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn split_unquoted_once(s: &str, delim: char) -> Option<(&str, &str)> {
    let mut in_quotes = false;
    for (idx, ch) in s.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == delim && !in_quotes {
            return Some((&s[..idx], &s[idx + ch.len_utf8()..]));
        }
    }
    None
}

fn split_unquoted_all(s: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    for (idx, ch) in s.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == delim && !in_quotes {
            out.push(s[start..idx].to_string());
            start = idx + ch.len_utf8();
        }
    }
    out.push(s[start..].to_string());
    out
}

/// Pure-Rust RFC 2849 LDIF parser with line unfolding and `::` Base64 decoding.
pub fn parse_ldif(source_label: &str, bytes: &[u8]) -> Result<Vec<ContactRecord>, DataError> {
    let decoded = decode_bytes(bytes);
    let mut unfolded: Vec<String> = Vec::new();
    for raw_line in decoded.text.split('\n').map(|l| l.trim_end_matches('\r')) {
        if let Some(rest) = raw_line.strip_prefix(' ')
            && let Some(last) = unfolded.last_mut()
            && !last.is_empty()
            && !last.starts_with('#')
        {
            last.push_str(rest);
            continue;
        }
        unfolded.push(raw_line.to_string());
    }

    let mut records = Vec::new();
    let mut block: Vec<String> = Vec::new();

    for line in unfolded.into_iter().chain(std::iter::once(String::new())) {
        if line.trim().is_empty() {
            if !block.is_empty() {
                if let Some(rec) = parse_ldif_entry(source_label, &block)? {
                    records.push(rec);
                }
                block.clear();
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        block.push(line);
    }

    Ok(records)
}

fn parse_ldif_entry(source_label: &str, lines: &[String]) -> Result<Option<ContactRecord>, DataError> {
    let mut attrs: Vec<(String, String)> = Vec::new();
    for line in lines {
        let Some((attr_raw, rest)) = line.split_once(':') else {
            continue;
        };
        let attr = attr_raw.trim().to_ascii_lowercase();
        if let Some(b64) = rest.strip_prefix(':') {
            let trimmed_b64 = b64.trim();
            match decode_base64(trimmed_b64) {
                Ok(decoded_bytes) => {
                    let val = String::from_utf8(decoded_bytes).unwrap_or_else(|e| decode_windows_1252(e.as_bytes()));
                    attrs.push((attr, val));
                }
                Err(_) => {
                    if !trimmed_b64.is_empty() {
                        attrs.push((attr, trimmed_b64.to_string()));
                    }
                }
            }
        } else if let Some(url) = rest.strip_prefix('<') {
            attrs.push((attr, url.trim().to_string()));
        } else {
            let clean = rest.strip_prefix(' ').unwrap_or(rest).to_string();
            attrs.push((attr, clean));
        }
    }

    if attrs.is_empty() {
        return Ok(None);
    }
    if attrs.len() == 1 && attrs[0].0 == "version" {
        return Ok(None);
    }

    let mut rec = ContactRecord {
        source_path: source_label.to_string(),
        source_format: "LDIF".to_string(),
        ..ContactRecord::default()
    };
    let mut given_name = String::new();
    let mut surname = String::new();
    let mut street = String::new();
    let mut city = String::new();
    let mut state = String::new();
    let mut postal = String::new();
    let mut country = String::new();

    for (k, v) in attrs {
        match k.as_str() {
            "cn" | "displayname" => {
                if rec.full_name.is_empty() {
                    rec.full_name = v;
                }
            }
            "givenname" => given_name = v,
            "sn" => surname = v,
            "mail" | "mozillasecondemail" => {
                if !v.is_empty() {
                    if rec.email.is_empty() {
                        rec.email = v.clone();
                    }
                    rec.emails.push(v);
                }
            }
            "telephonenumber" | "homephone" => {
                if !v.is_empty() {
                    if rec.phone.is_empty() {
                        rec.phone = v.clone();
                    }
                    rec.phones.push(v);
                }
            }
            "mobile" => {
                if !v.is_empty() {
                    if rec.mobile.is_empty() {
                        rec.mobile = v.clone();
                    }
                    rec.phones.push(v);
                }
            }
            "o" | "company" => rec.company = v,
            "title" => rec.title = v,
            "postaladdress" => {
                if rec.address.is_empty() {
                    rec.address = v.clone();
                }
                rec.addresses.push(v);
            }
            "street" | "mozillahomestreet" => street = v,
            "l" | "mozillahomelocalityname" => city = v,
            "st" | "mozillahomestate" => state = v,
            "postalcode" | "mozillahomepostalcode" => postal = v,
            "c" | "mozillahomecountryname" => country = v,
            "description" | "notes" => rec.notes = v,
            "dn" => rec.uid = Some(v),
            other => {
                rec.extra.insert(other.to_string(), v);
            }
        }
    }

    if rec.full_name.is_empty() {
        let joined = [given_name.trim(), surname.trim()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        rec.full_name = joined;
    }
    if rec.address.is_empty() {
        let composed = [street, city, state, postal, country]
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        if !composed.is_empty() {
            rec.addresses.push(composed.clone());
            rec.address = composed;
        }
    }

    Ok(Some(rec))
}

/// Pure-Rust RFC 4648 Base64 decoder (ignores ASCII whitespace).
pub fn decode_base64(input: &str) -> Result<Vec<u8>, DataError> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err(DataError::ContactParse(
            "invalid base64 length in LDIF attribute".to_string(),
        ));
    }
    let num_chunks = clean.len() / 4;
    let mut out = Vec::with_capacity(num_chunks * 3);
    for (idx, chunk) in clean.as_chunks::<4>().0.iter().enumerate() {
        let is_last = idx + 1 == num_chunks;
        if !is_last && chunk.contains(&b'=') {
            return Err(DataError::ContactParse(
                "unexpected base64 padding '=' before final quartet".to_string(),
            ));
        }
        if chunk[2] == b'=' && chunk[3] != b'=' {
            return Err(DataError::ContactParse(
                "invalid base64 padding: '=' at byte 2 requires '=' at byte 3".to_string(),
            ));
        }
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c = if chunk[2] == b'=' {
            None
        } else {
            Some(b64_val(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            None
        } else {
            Some(b64_val(chunk[3])?)
        };

        out.push((a << 2) | (b >> 4));
        if let Some(c_val) = c {
            out.push((b << 4) | (c_val >> 2));
            if let Some(d_val) = d {
                out.push((c_val << 6) | d_val);
            }
        }
    }
    Ok(out)
}

fn b64_val(b: u8) -> Result<u8, DataError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(DataError::ContactParse(format!("invalid base64 byte 0x{b:02X}"))),
    }
}

/// Contact CSV parser mapping Outlook/Thunderbird/Google/NirSoft contact column aliases.
pub fn parse_contact_csv(source_label: &str, bytes: &[u8]) -> Result<Vec<ContactRecord>, DataError> {
    let csv = CsvTableProvider::from_bytes(source_label, bytes, CsvViewOptions::default())?;
    let td = csv.into_table_data();
    let headers: Vec<String> = td
        .schema
        .columns
        .iter()
        .map(|c| c.label.trim().to_ascii_lowercase())
        .collect();

    let mut records = Vec::with_capacity(td.rows.len());
    for row in &td.rows {
        let mut rec = ContactRecord {
            source_path: source_label.to_string(),
            source_format: "CSV".to_string(),
            ..ContactRecord::default()
        };
        let mut first_name = String::new();
        let mut last_name = String::new();

        for (idx, header) in headers.iter().enumerate() {
            let val = row
                .cells
                .get(idx)
                .zip(td.schema.columns.get(idx))
                .map(|(c, col)| {
                    if c.is_null() {
                        String::new()
                    } else {
                        c.format_human(col.col_type)
                    }
                })
                .unwrap_or_default()
                .trim()
                .to_string();
            if val.is_empty() {
                continue;
            }
            match header.as_str() {
                "full name" | "display name" | "name" | "full_name" => rec.full_name = val,
                "first name" | "given name" | "first_name" => first_name = val,
                "last name" | "family name" | "surname" | "last_name" => last_name = val,
                "e-mail address" | "email" | "email address" | "e-mail 1 - value" | "primary email" => {
                    if rec.email.is_empty() {
                        rec.email = val.clone();
                    }
                    rec.emails.push(val);
                }
                "phone" | "business phone" | "home phone" | "work phone" | "phone 1 - value" => {
                    if rec.phone.is_empty() {
                        rec.phone = val.clone();
                    }
                    rec.phones.push(val);
                }
                "mobile" | "mobile phone" | "cell" | "mobile number" => {
                    if rec.mobile.is_empty() {
                        rec.mobile = val.clone();
                    }
                    rec.phones.push(val);
                }
                "company" | "organization" | "org" | "organization 1 - name" => rec.company = val,
                "job title" | "title" | "organization 1 - title" => rec.title = val,
                "address" | "business address" | "home address" | "address 1 - formatted" => {
                    if rec.address.is_empty() {
                        rec.address = val.clone();
                    }
                    rec.addresses.push(val);
                }
                "notes" | "note" | "comments" => rec.notes = val,
                other => {
                    rec.extra.insert(other.to_string(), val);
                }
            }
        }

        if rec.full_name.is_empty() {
            rec.full_name = [first_name.as_str(), last_name.as_str()]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }
        records.push(rec);
    }

    Ok(records)
}
