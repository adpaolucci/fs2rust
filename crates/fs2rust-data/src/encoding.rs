/// Detected byte encoding of a decoded text payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Windows1252,
}

/// Decoded UTF-8 string paired with its detected source encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedText {
    pub text: String,
    pub encoding: TextEncoding,
    pub had_bom: bool,
}

const WIN1252_C1: [char; 32] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}', '\u{02C6}',
    '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}', '\u{0090}', '\u{2018}',
    '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}',
    '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
];

/// Decode raw bytes using BOM detection, BOM-less UTF-16 heuristics, UTF-8 validation,
/// and lossless Windows-1252 fallback.
pub fn decode_bytes(bytes: &[u8]) -> DecodedText {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        if let Ok(s) = std::str::from_utf8(rest) {
            return DecodedText {
                text: s.to_string(),
                encoding: TextEncoding::Utf8Bom,
                had_bom: true,
            };
        }
        return DecodedText {
            text: decode_windows_1252(rest),
            encoding: TextEncoding::Windows1252,
            had_bom: true,
        };
    }

    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return DecodedText {
            text: decode_utf16(rest, true),
            encoding: TextEncoding::Utf16Le,
            had_bom: true,
        };
    }

    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return DecodedText {
            text: decode_utf16(rest, false),
            encoding: TextEncoding::Utf16Be,
            had_bom: true,
        };
    }

    if bytes.len() >= 4 && bytes.len().is_multiple_of(2) {
        let sample = &bytes[..bytes.len().min(512)];
        let pairs = sample.len() / 2;
        let mut even_zeros = 0usize;
        let mut odd_zeros = 0usize;
        for chunk in sample.as_chunks::<2>().0 {
            if chunk[0] == 0 {
                even_zeros += 1;
            }
            if chunk[1] == 0 {
                odd_zeros += 1;
            }
        }
        if odd_zeros * 3 > pairs && even_zeros * 10 <= pairs {
            return DecodedText {
                text: decode_utf16(bytes, true),
                encoding: TextEncoding::Utf16Le,
                had_bom: false,
            };
        }
        if even_zeros * 3 > pairs && odd_zeros * 10 <= pairs {
            return DecodedText {
                text: decode_utf16(bytes, false),
                encoding: TextEncoding::Utf16Be,
                had_bom: false,
            };
        }
    }

    if let Ok(s) = std::str::from_utf8(bytes) {
        return DecodedText {
            text: s.to_string(),
            encoding: TextEncoding::Utf8,
            had_bom: false,
        };
    }

    DecodedText {
        text: decode_windows_1252(bytes),
        encoding: TextEncoding::Windows1252,
        had_bom: false,
    }
}

/// Decode a Windows-1252 byte slice into a UTF-8 `String`.
pub fn decode_windows_1252(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            0x80..=0x9F => out.push(WIN1252_C1[(b - 0x80) as usize]),
            other => out.push(other as char),
        }
    }
    out
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let iter = bytes.as_chunks::<2>().0.iter().map(|pair| {
        if little_endian {
            u16::from_le_bytes(*pair)
        } else {
            u16::from_be_bytes(*pair)
        }
    });
    char::decode_utf16(iter)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}
