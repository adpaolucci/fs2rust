#![forbid(unsafe_code)]

pub mod addr;
pub mod codegen;
pub mod compare;
pub mod csv_view;
pub mod encoding;
pub mod error;
pub mod exif;
pub mod getnir;
pub mod html2text;

use guap_mcp::McpServerRegistry;
use guap_table::TableProvider;
use std::sync::Arc;

pub use addr::{AddrViewProvider, ContactFormat, ContactRecord};
pub use codegen::{
    CodegenInput, CodegenResult, CodegenTarget, CodegenTemplate, EscapeMode, SimpleCodeGeneratorProvider, generate_code,
};
pub use compare::{CompareKeyMode, TableCompareOptions, TableCompareProvider, TableCompareResult, TableInput};
pub use csv_view::{CsvTableProvider, CsvViewOptions, HeaderMode};
pub use encoding::{DecodedText, TextEncoding, decode_bytes, decode_windows_1252};
pub use error::DataError;
pub use exif::{ExifDataViewProvider, ExifDocument, ExifEntry, IfdKind, TiffEndianness, TiffFieldType, parse_exif};
pub use getnir::{GetNirOutputFormat, GetNirRequest, GetNirSource, GetNirTableProvider, evaluate_getnir};
pub use html2text::{
    HeadingStyle, HtmlAsTextOptions, HtmlAsTextOutput, HtmlAsTextProvider, HtmlBlock, HtmlLink, HtmlLinksProvider,
    html_to_text,
};

/// Return static descriptor metadata (`(tool_id, description)`) for all 7 `fs2rust-data` tools.
pub fn provider_descriptors() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "fs2rust.data.csv_file_view",
            "Dynamic CSV/TSV viewer with auto-delimiter, encoding detection, and typed column inference",
        ),
        (
            "fs2rust.data.table_text_compare",
            "Compare two CSV/TSV/JSONL/TableData inputs by key columns or row position",
        ),
        (
            "fs2rust.data.getnir",
            "Evaluate NirSoft-style tabular queries (columns, where, sort, top) and format outputs",
        ),
        (
            "fs2rust.data.exif_data_view",
            "Pure-Rust JPEG APP1 and TIFF IFD0/Exif/GPS/Interop/IFD1 EXIF metadata parser",
        ),
        (
            "fs2rust.data.simple_code_generator",
            "Template-based snippet generator from regex captures, CSV, JSON, or TableData",
        ),
        (
            "fs2rust.data.html_as_text",
            "Pure-Rust HTML-to-text extractor preserving headings, lists, tables, preformatted blocks, and link footnotes",
        ),
        (
            "fs2rust.data.addr_view",
            "Pure-Rust contact book reader for vCard (.vcf), LDIF (.ldif), and contact CSV files",
        ),
    ]
}

/// Register any caller-supplied `fs2rust-data` `TableProvider` instances on an `McpServerRegistry`.
pub fn register_data_tools(registry: &mut McpServerRegistry, providers: Vec<Arc<dyn TableProvider>>) {
    for provider in providers {
        registry.register_table(provider);
    }
}
