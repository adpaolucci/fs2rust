use fs2rust_data::addr::{AddrViewProvider, ContactFormat, decode_base64};
use fs2rust_data::codegen::{
    CodegenInput, CodegenTarget, CodegenTemplate, EscapeMode, SimpleCodeGeneratorProvider, generate_code,
};
use fs2rust_data::compare::{CompareKeyMode, TableCompareOptions, TableCompareProvider, TableInput};
use fs2rust_data::csv_view::{CsvTableProvider, CsvViewOptions};
use fs2rust_data::encoding::{TextEncoding, decode_bytes};
use fs2rust_data::exif::{ExifDataViewProvider, IfdKind, TiffEndianness, parse_exif};
use fs2rust_data::getnir::{GetNirOutputFormat, GetNirRequest, GetNirSource, evaluate_getnir};
use fs2rust_data::html2text::{HtmlAsTextOptions, HtmlAsTextProvider, HtmlLinksProvider, html_to_text};
use fs2rust_data::register_data_tools;
use guap_export::{ExportFormat, ExportOptions};
use guap_mcp::{McpServerRegistry, PolicyMode};
use guap_table::{
    CellValue, ColumnDef, ColumnType, FilterExpr, Row, SortDirection, TableData, TableProvider, TableQuery, TableSchema,
};
use std::sync::Arc;

#[test]
fn csv_file_view_utf16le_win1252_leading_zeros_and_export() {
    // 1. UTF-16LE BOM + semicolon delimiter + leading-zero ZIP codes
    let csv_text = "zip;city;population;active\r\n00123;Boston;654776;true\r\n90210;Beverly Hills;32701;false\r\n";
    let mut utf16_bytes = vec![0xFFu8, 0xFEu8];
    for u in csv_text.encode_utf16() {
        utf16_bytes.extend_from_slice(&u.to_le_bytes());
    }

    let provider = CsvTableProvider::from_bytes("cities.csv", &utf16_bytes, CsvViewOptions::default()).unwrap();
    assert_eq!(provider.detected_delimiter(), b';');
    assert_eq!(provider.detected_encoding(), TextEncoding::Utf16Le);
    assert!(provider.has_header());

    let schema = provider.schema();
    assert_eq!(schema.columns[0].col_type, ColumnType::Text); // leading zero guard preserved "00123"
    assert_eq!(schema.columns[2].col_type, ColumnType::Uint);
    assert_eq!(schema.columns[3].col_type, ColumnType::Bool);

    let filtered = provider
        .query(&TableQuery {
            filter: Some(FilterExpr::Regex {
                column: Some("city".to_string()),
                pattern: "^B.*".to_string(),
            }),
            sort: vec![(2, SortDirection::Asc)],
            ..TableQuery::default()
        })
        .unwrap();
    assert_eq!(filtered.total_rows, 2);
    assert_eq!(filtered.rows[0].cells[0], CellValue::Text("90210".to_string()));

    let md = provider
        .export(
            &TableQuery::default(),
            ExportFormat::Markdown,
            &ExportOptions::default(),
        )
        .unwrap();
    let md_str = String::from_utf8(md).unwrap();
    assert!(md_str.contains("00123"));
    assert!(md_str.contains("Beverly Hills"));

    // 2. Windows-1252 Euro sign 0x80 decoding
    let win1252 = b"item|price\nWidget|\x8012.50\n";
    let dec = decode_bytes(win1252);
    assert_eq!(dec.encoding, TextEncoding::Windows1252);
    assert!(dec.text.contains("€12.50"));
}

#[test]
fn table_text_compare_keyed_and_positional_with_union_columns() {
    let tmp = tempfile::tempdir().unwrap();
    let left_csv = tmp.path().join("left.csv");
    let right_jsonl = tmp.path().join("right.jsonl");

    std::fs::write(&left_csv, "id,name,role\n1,Alice,Admin\n2,Bob,User\n").unwrap();
    std::fs::write(
        &right_jsonl,
        "{\"id\":1,\"name\":\"Alice\",\"role\":\"Owner\",\"dept\":\"Sec\"}\n{\"id\":3,\"name\":\"Cara\",\"role\":\"User\",\"dept\":\"Ops\"}\n",
    )
    .unwrap();

    let cmp = TableCompareProvider::compare(
        TableInput::Csv {
            path: left_csv.clone(),
            options: CsvViewOptions::default(),
        },
        TableInput::Jsonl { path: right_jsonl },
        TableCompareOptions {
            key_mode: CompareKeyMode::Columns(vec!["id".to_string()]),
            align_union_columns: true,
            include_unchanged: true,
        },
    )
    .unwrap();

    assert_eq!(cmp.summary().modified, 1);
    assert_eq!(cmp.summary().removed, 1);
    assert_eq!(cmp.summary().added, 1);

    let data = cmp.query(&TableQuery::default()).unwrap();
    assert_eq!(data.total_rows, 3);
    assert!(data.rows.iter().all(|r| r.detail_json.is_some()));

    // Positional comparison
    let right_csv = tmp.path().join("right.csv");
    std::fs::write(&right_csv, "id,name,role\n1,Alice,Admin\n2,Bobby,User\n").unwrap();
    let pos_cmp = TableCompareProvider::compare(
        TableInput::Csv {
            path: left_csv,
            options: CsvViewOptions::default(),
        },
        TableInput::Csv {
            path: right_csv,
            options: CsvViewOptions::default(),
        },
        TableCompareOptions {
            key_mode: CompareKeyMode::Positional,
            align_union_columns: true,
            include_unchanged: false,
        },
    )
    .unwrap();
    assert_eq!(pos_cmp.summary().modified, 1);
    assert_eq!(pos_cmp.query(&TableQuery::default()).unwrap().total_rows, 1);
}

#[test]
fn getnir_evaluates_stdin_jsonl_and_formats_outputs() {
    let jsonl =
        b"{\"name\":\"alpha\",\"score\":10}\n{\"name\":\"beta\",\"score\":42}\n{\"name\":\"gamma\",\"score\":7}\n";
    let eval = evaluate_getnir(
        GetNirSource::StdinBytes(jsonl.to_vec()),
        &GetNirRequest {
            columns: Some(vec!["name".to_string(), "score".to_string()]),
            where_expr: Some("score >= 10".to_string()),
            sort: Some("score:desc".to_string()),
            offset: 0,
            top: Some(1),
            format: GetNirOutputFormat::NirAlignedText,
        },
    )
    .unwrap();

    assert_eq!(eval.table.rows.len(), 1);
    assert_eq!(eval.table.rows[0].cells[0], CellValue::Text("beta".to_string()));
    let aligned = String::from_utf8(eval.formatted_bytes.unwrap()).unwrap();
    assert!(aligned.contains("beta"));
    assert!(aligned.contains("42"));
}

fn build_synthetic_jpeg_with_exif() -> Vec<u8> {
    // Little-endian TIFF payload placed inside JPEG APP1 Exif\0\0
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II\x2A\x00");
    tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at offset 8

    // IFD0: 4 entries (Make, ExifIFD ptr, GPSInfoIFD ptr, FloatTest) + NextIFD=IFD1
    // Reserve IFD0 header+entries+next_ifd: 2 + 4*12 + 4 = 54 bytes (at 8..62)
    let ifd0_len = 2 + 4 * 12 + 4;
    let ifd0_end = 8 + ifd0_len;
    tiff.resize(ifd0_end, 0);

    // ExifIFD at ifd0_end: 3 entries (ExposureTime RATIONAL, UserComment UNDEFINED, MakerNote UNDEFINED)
    let exif_ifd_off = tiff.len() as u32;
    let exif_ifd_len = 2 + 3 * 12 + 4;
    tiff.resize(tiff.len() + exif_ifd_len, 0);

    // GPSInfoIFD: 4 entries (LatRef, Lat RATIONAL[3], LonRef, Lon RATIONAL[3])
    let gps_ifd_off = tiff.len() as u32;
    let gps_ifd_len = 2 + 4 * 12 + 4;
    tiff.resize(tiff.len() + gps_ifd_len, 0);

    // IFD1: 1 entry (Compression SHORT = 6)
    let ifd1_off = tiff.len() as u32;
    let ifd1_len = 2 + 12 + 4;
    tiff.resize(tiff.len() + ifd1_len, 0);

    // Heap values
    let make_off = tiff.len() as u32;
    tiff.extend_from_slice(b"Canon\0");

    let exp_off = tiff.len() as u32;
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&125u32.to_le_bytes());

    let comment_off = tiff.len() as u32;
    let comment_bytes = b"ASCII\0\0\0Sunset";
    tiff.extend_from_slice(comment_bytes);

    let maker_off = tiff.len() as u32;
    tiff.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02]);

    // Lat 37 deg, 46 min, 29.64 sec -> 37 + 46/60 + 2964/360000 = 37.7749
    let lat_off = tiff.len() as u32;
    for (n, d) in [(37u32, 1u32), (46, 1), (2964, 100)] {
        tiff.extend_from_slice(&n.to_le_bytes());
        tiff.extend_from_slice(&d.to_le_bytes());
    }
    // Lon 122 deg, 25 min, 9.84 sec W -> -122.4194
    let lon_off = tiff.len() as u32;
    for (n, d) in [(122u32, 1u32), (25, 1), (984, 100)] {
        tiff.extend_from_slice(&n.to_le_bytes());
        tiff.extend_from_slice(&d.to_le_bytes());
    }

    let write_entry = |buf: &mut [u8], pos: usize, tag: u16, ftype: u16, count: u32, val_bytes: [u8; 4]| {
        buf[pos..pos + 2].copy_from_slice(&tag.to_le_bytes());
        buf[pos + 2..pos + 4].copy_from_slice(&ftype.to_le_bytes());
        buf[pos + 4..pos + 8].copy_from_slice(&count.to_le_bytes());
        buf[pos + 8..pos + 12].copy_from_slice(&val_bytes);
    };

    // Populate IFD0
    tiff[8..10].copy_from_slice(&4u16.to_le_bytes());
    write_entry(&mut tiff, 10, 0x010F, 2, 6, make_off.to_le_bytes());
    write_entry(&mut tiff, 22, 0x8769, 4, 1, exif_ifd_off.to_le_bytes());
    write_entry(&mut tiff, 34, 0x8825, 4, 1, gps_ifd_off.to_le_bytes());
    write_entry(&mut tiff, 46, 0x0112, 3, 1, [1, 0, 0, 0]); // Orientation SHORT = 1
    tiff[58..62].copy_from_slice(&ifd1_off.to_le_bytes());

    // Populate ExifIFD
    let e_base = exif_ifd_off as usize;
    tiff[e_base..e_base + 2].copy_from_slice(&3u16.to_le_bytes());
    write_entry(&mut tiff, e_base + 2, 0x829A, 5, 1, exp_off.to_le_bytes());
    write_entry(
        &mut tiff,
        e_base + 14,
        0x9286,
        7,
        comment_bytes.len() as u32,
        comment_off.to_le_bytes(),
    );
    write_entry(&mut tiff, e_base + 26, 0x927C, 7, 6, maker_off.to_le_bytes());

    // Populate GPSInfoIFD
    let g_base = gps_ifd_off as usize;
    tiff[g_base..g_base + 2].copy_from_slice(&4u16.to_le_bytes());
    write_entry(&mut tiff, g_base + 2, 0x0001, 2, 2, *b"N\0\0\0");
    write_entry(&mut tiff, g_base + 14, 0x0002, 5, 3, lat_off.to_le_bytes());
    write_entry(&mut tiff, g_base + 26, 0x0003, 2, 2, *b"W\0\0\0");
    write_entry(&mut tiff, g_base + 38, 0x0004, 5, 3, lon_off.to_le_bytes());

    // Populate IFD1
    let i1_base = ifd1_off as usize;
    tiff[i1_base..i1_base + 2].copy_from_slice(&1u16.to_le_bytes());
    write_entry(&mut tiff, i1_base + 2, 0x0103, 3, 1, [6, 0, 0, 0]);

    // Wrap inside JPEG SOI + APP1
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
    let seg_len = (2 + 6 + tiff.len()) as u16;
    jpeg.extend_from_slice(&seg_len.to_be_bytes());
    jpeg.extend_from_slice(b"Exif\0\0");
    jpeg.extend_from_slice(&tiff);
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    jpeg
}

#[test]
fn exif_parses_jpeg_app1_gps_ifd1_and_guards_cyclic_and_malformed_tiff() {
    let jpeg = build_synthetic_jpeg_with_exif();
    let doc = parse_exif("photo.jpg", &jpeg).unwrap();
    assert_eq!(doc.endianness, TiffEndianness::Little);
    assert!(
        doc.entries
            .iter()
            .any(|e| e.ifd == IfdKind::Ifd0 && e.tag_name == "Make" && e.value == "Canon")
    );
    assert!(
        doc.entries
            .iter()
            .any(|e| e.ifd == IfdKind::ExifIfd && e.tag_name == "ExposureTime" && e.value == "1/125")
    );
    assert!(
        doc.entries
            .iter()
            .any(|e| e.ifd == IfdKind::ExifIfd && e.tag_name == "UserComment" && e.value == "Sunset")
    );
    assert!(
        doc.entries
            .iter()
            .any(|e| e.ifd == IfdKind::Ifd1 && e.tag_name == "Compression")
    );
    assert!((doc.gps_latitude_deg.unwrap() - 37.7749).abs() < 1e-4);
    assert!((doc.gps_longitude_deg.unwrap() + 122.4194).abs() < 1e-4);

    let provider = ExifDataViewProvider::from_bytes("photo.jpg", jpeg);
    let table = provider.query(&TableQuery::default()).unwrap();
    assert!(!table.rows.is_empty());
    assert!(table.rows[0].raw_bytes.is_some());

    // Self-referential IFD cycle loop (next_ifd points back to offset 8)
    let mut cyclic_tiff = Vec::new();
    cyclic_tiff.extend_from_slice(b"MM\x00\x2A"); // Big-endian TIFF
    cyclic_tiff.extend_from_slice(&8u32.to_be_bytes());
    cyclic_tiff.extend_from_slice(&1u16.to_be_bytes());
    cyclic_tiff.extend_from_slice(&0x0100u16.to_be_bytes()); // ImageWidth
    cyclic_tiff.extend_from_slice(&4u16.to_be_bytes()); // LONG
    cyclic_tiff.extend_from_slice(&1u32.to_be_bytes());
    cyclic_tiff.extend_from_slice(&1920u32.to_be_bytes());
    cyclic_tiff.extend_from_slice(&8u32.to_be_bytes()); // Cycle back to IFD0!

    let cyc_doc = parse_exif("cycle.tif", &cyclic_tiff).unwrap();
    assert_eq!(cyc_doc.endianness, TiffEndianness::Big);
    assert!(cyc_doc.warnings.iter().any(|w| w.contains("cyclic")));

    // Out-of-bounds value offset should warn cleanly without panic/OOM
    let mut oob_tiff = b"II\x2A\x00\x08\x00\x00\x00".to_vec();
    oob_tiff.extend_from_slice(&1u16.to_le_bytes());
    oob_tiff.extend_from_slice(&0x010Eu16.to_le_bytes());
    oob_tiff.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    oob_tiff.extend_from_slice(&500u32.to_le_bytes()); // > EOF
    oob_tiff.extend_from_slice(&0x1000u32.to_le_bytes());
    oob_tiff.extend_from_slice(&0u32.to_le_bytes());
    let oob_doc = parse_exif("oob.tif", &oob_tiff).unwrap();
    assert!(!oob_doc.warnings.is_empty());

    // BigTIFF must be rejected cleanly
    assert!(parse_exif("big.tif", b"II\x2B\x00\x08\x00\x00\x00").is_err());
}

#[test]
fn simple_code_generator_escapes_sql_and_prevents_recursive_expansion() {
    let sql_res = generate_code(
        &CodegenInput::RegexCapture {
            text: "user: O'Reilly\nuser: {{2}}".to_string(),
            pattern: r"user:\s*(?P<name>.+)".to_string(),
            line_by_line: true,
        },
        &CodegenTemplate {
            rule_name: "insert_users".to_string(),
            target: CodegenTarget::Sql,
            header_template: "BEGIN;".to_string(),
            body_template: "INSERT INTO users (id, name) VALUES ({{row_number}}, '{{name}}');".to_string(),
            footer_template: "COMMIT; -- {{row_count}}".to_string(),
            separator: "\n".to_string(),
            escape_mode: EscapeMode::Auto,
            strict_placeholders: false,
        },
    )
    .unwrap();

    assert_eq!(sql_res.matched_count, 2);
    assert_eq!(
        sql_res.snippets[0],
        "INSERT INTO users (id, name) VALUES (1, 'O''Reilly');"
    );
    // Single-pass: literal `{{2}}` in input data is preserved without secondary expansion!
    assert_eq!(sql_res.snippets[1], "INSERT INTO users (id, name) VALUES (2, '{{2}}');");

    let json_res = SimpleCodeGeneratorProvider::from_input(
        &CodegenInput::Json {
            json_text: r#"[{"field":"1st item","kind":"String"}]"#.to_string(),
        },
        &CodegenTemplate {
            rule_name: "rust_fields".to_string(),
            target: CodegenTarget::Rust,
            body_template: "pub {{field|rust_ident|lower}}: {{kind|raw}},".to_string(),
            ..CodegenTemplate::default()
        },
    )
    .unwrap();
    let tbl = json_res.query(&TableQuery::default()).unwrap();
    assert_eq!(
        tbl.rows[0].cells[3],
        CellValue::Text("pub _1st_item: String,".to_string())
    );
}

#[test]
fn html_as_text_suppresses_scripts_renders_tables_lists_and_dedup_links() {
    let html = br#"<!doctype html>
<html>
<head>
  <title>Report &amp; Summary</title>
  <style>.hidden { display: none; }</style>
  <script>alert("secret");</script>
  <noscript>Enable JS</noscript>
  <template><p>Template hidden</p></template>
</head>
<body>
  <h1>Overview &#x20AC;100</h1>
  <p>Visit <a href="https://example.com">Example</a> and <a href="https://example.com">Mirror</a> or <a href="javascript:void(0)">Skip</a>.</p>
  <ul>
    <li>First item</li>
    <li>Second item
      <ol><li>Sub step</li></ol>
    </li>
  </ul>
  <table>
    <tr><th>Name</th><th>Value</th></tr>
    <tr><td>Alpha</td><td>42</td></tr>
  </table>
  <pre>let x = 1;
let y = 2;</pre>
</body>
</html>"#;

    let out = html_to_text(html, &HtmlAsTextOptions::default());
    assert_eq!(out.title, "Report & Summary");
    assert!(!out.text.contains("alert("));
    assert!(!out.text.contains("display: none"));
    assert!(!out.text.contains("Enable JS"));
    assert!(!out.text.contains("Template hidden"));
    assert!(!out.text.contains("javascript:"));
    assert!(out.text.contains("# Overview €100"));
    assert!(out.text.contains("Example[1] and Mirror[1]"));
    assert!(out.text.contains("- First item"));
    assert!(out.text.contains("1. Sub step"));
    assert!(out.text.contains("| Name"));
    assert!(out.text.contains("let x = 1;\nlet y = 2;"));
    assert_eq!(out.links.len(), 1);

    let p1 = HtmlAsTextProvider::from_bytes("index.html", html, &HtmlAsTextOptions::default());
    assert_eq!(p1.query(&TableQuery::default()).unwrap().total_rows, 1);

    let p2 = HtmlLinksProvider::from_bytes("index.html", html, &HtmlAsTextOptions::default());
    assert_eq!(p2.query(&TableQuery::default()).unwrap().total_rows, 1);
}

#[test]
fn addr_view_parses_vcard_qp_ldif_base64_and_csv_and_registers_in_mcp() {
    // 1. vCard 2.1 with Quoted-Printable UTF-8 + soft break & vCard 3.0 escaped chars
    let vcf = b"BEGIN:VCARD\r\n\
VERSION:2.1\r\n\
FN;ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:Ren=C3=A9 =\r\nDupont\r\n\
EMAIL:rene@example.org\r\n\
TEL;CELL:+1-555-0101\r\n\
ORG:Acme Corp;R&D\r\n\
NOTE;ENCODING=QUOTED-PRINTABLE;CHARSET=WINDOWS-1252:Budget =80500\r\n\
END:VCARD\r\n\
BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
FN:Smith\\, Jane\r\n\
EMAIL:jane@example.org\r\n\
END:VCARD\r\n";

    let vcf_provider = AddrViewProvider::from_bytes("contacts.vcf", vcf, ContactFormat::VCard).unwrap();
    assert_eq!(vcf_provider.records().len(), 2);
    assert_eq!(vcf_provider.records()[0].full_name, "René Dupont");
    assert_eq!(vcf_provider.records()[0].mobile, "+1-555-0101");
    assert_eq!(vcf_provider.records()[0].company, "Acme Corp / R&D");
    assert_eq!(vcf_provider.records()[0].notes, "Budget €500");
    assert_eq!(vcf_provider.records()[1].full_name, "Smith, Jane");

    // 2. LDIF (RFC 2849) with folded lines and `::` Base64 UTF-8
    // "José García" base64 = "Sm9zw6kgR2FyY8OtYQ=="
    let ldif = concat!(
        "version: 1\n",
        "dn: cn=Jose,dc=example,dc=org\n",
        "cn:: Sm9zw6kgR2FyY8OtYQ==\n",
        "mail: jose@example.org\n",
        "telephoneNumber: +1-555-0200\n",
        "description: First part\n",
        "  continued note\n\n",
    )
    .as_bytes();
    let ldif_provider = AddrViewProvider::from_bytes("dir.ldif", ldif, ContactFormat::Ldif).unwrap();
    assert_eq!(ldif_provider.records().len(), 1);
    assert_eq!(ldif_provider.records()[0].full_name, "José García");
    assert_eq!(ldif_provider.records()[0].notes, "First part continued note");

    // 3. CSV contact aliases
    let csv = b"First Name,Last Name,E-mail Address,Mobile Phone,Organization\nAda,Lovelace,ada@analytical.org,+44-123,Engine Labs\n";
    let csv_provider = AddrViewProvider::from_bytes("contacts.csv", csv, ContactFormat::Csv).unwrap();
    assert_eq!(csv_provider.records()[0].full_name, "Ada Lovelace");
    assert_eq!(csv_provider.records()[0].email, "ada@analytical.org");
    assert_eq!(csv_provider.records()[0].mobile, "+44-123");

    // Verify McpServerRegistry registration works cleanly
    let mut reg = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
    register_data_tools(
        &mut reg,
        vec![Arc::new(vcf_provider), Arc::new(ldif_provider), Arc::new(csv_provider)],
    );
    let tools = reg.list_tools();
    assert!(tools.as_array().is_some_and(|a| !a.is_empty()));
}

#[test]
fn exif_covers_all_12_tiff_types_and_interop_ifd() {
    // Build a raw little-endian TIFF exercising BYTE(1), SBYTE(6), SSHORT(8), SLONG(9), SRATIONAL(10), FLOAT(11), DOUBLE(12),
    // plus ExifIFD -> ExifVersion(0x9000), ComponentsConfiguration(0x9101), InteropIFD(0xA005).
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II\x2A\x00");
    tiff.extend_from_slice(&8u32.to_le_bytes());

    // IFD0: 9 entries (7 scalar/extended types + ExifIFD ptr + Interop pointer)
    let ifd0_count = 8usize;
    let ifd0_len = 2 + ifd0_count * 12 + 4;
    tiff.resize(8 + ifd0_len, 0);

    let exif_off = tiff.len() as u32;
    let exif_len = 2 + 3 * 12 + 4;
    tiff.resize(tiff.len() + exif_len, 0);

    let interop_off = tiff.len() as u32;
    let interop_len = 2 + 12 + 4;
    tiff.resize(tiff.len() + interop_len, 0);

    let srat_off = tiff.len() as u32;
    tiff.extend_from_slice(&(-5i32).to_le_bytes());
    tiff.extend_from_slice(&2i32.to_le_bytes());

    let dbl_off = tiff.len() as u32;
    tiff.extend_from_slice(&3.25f64.to_le_bytes());

    let write_entry = |buf: &mut [u8], pos: usize, tag: u16, ftype: u16, count: u32, val_bytes: [u8; 4]| {
        buf[pos..pos + 2].copy_from_slice(&tag.to_le_bytes());
        buf[pos + 2..pos + 4].copy_from_slice(&ftype.to_le_bytes());
        buf[pos + 4..pos + 8].copy_from_slice(&count.to_le_bytes());
        buf[pos + 8..pos + 12].copy_from_slice(&val_bytes);
    };

    tiff[8..10].copy_from_slice(&(ifd0_count as u16).to_le_bytes());
    write_entry(&mut tiff, 10, 0x0100, 1, 2, [10, 20, 0, 0]); // BYTE[2]
    write_entry(&mut tiff, 22, 0x0101, 6, 2, [(-5i8) as u8, 7, 0, 0]); // SBYTE[2]
    write_entry(
        &mut tiff,
        34,
        0x0102,
        8,
        1,
        [(-120i16).to_le_bytes()[0], (-120i16).to_le_bytes()[1], 0, 0],
    ); // SSHORT
    write_entry(&mut tiff, 46, 0x0103, 9, 1, (-42_000i32).to_le_bytes()); // SLONG
    write_entry(&mut tiff, 58, 0x0106, 10, 1, srat_off.to_le_bytes()); // SRATIONAL
    write_entry(&mut tiff, 70, 0x011A, 11, 1, 1.5f32.to_le_bytes()); // FLOAT
    write_entry(&mut tiff, 82, 0x011B, 12, 1, dbl_off.to_le_bytes()); // DOUBLE
    write_entry(&mut tiff, 94, 0x8769, 4, 1, exif_off.to_le_bytes()); // ExifIFD ptr

    let e_base = exif_off as usize;
    tiff[e_base..e_base + 2].copy_from_slice(&3u16.to_le_bytes());
    write_entry(&mut tiff, e_base + 2, 0x9000, 7, 4, *b"0232"); // ExifVersion
    write_entry(&mut tiff, e_base + 14, 0x9101, 7, 4, [1, 2, 3, 0]); // YCbCr-
    write_entry(&mut tiff, e_base + 26, 0xA005, 4, 1, interop_off.to_le_bytes()); // InteropIFD

    let i_base = interop_off as usize;
    tiff[i_base..i_base + 2].copy_from_slice(&1u16.to_le_bytes());
    write_entry(&mut tiff, i_base + 2, 0x0001, 2, 4, *b"R98\0"); // inline 4-byte ASCII

    let doc = parse_exif("types12.tif", &tiff).unwrap();
    assert!(doc.entries.iter().any(|e| e.data_type == "BYTE" && e.value == "10, 20"));
    assert!(doc.entries.iter().any(|e| e.data_type == "SBYTE" && e.value == "-5, 7"));
    assert!(doc.entries.iter().any(|e| e.data_type == "SSHORT" && e.value == "-120"));
    assert!(
        doc.entries
            .iter()
            .any(|e| e.data_type == "SLONG" && e.value == "-42000")
    );
    assert!(
        doc.entries
            .iter()
            .any(|e| e.data_type == "SRATIONAL" && e.value.contains("-2.5000"))
    );
    assert!(doc.entries.iter().any(|e| e.data_type == "FLOAT" && e.value == "1.5"));
    assert!(doc.entries.iter().any(|e| e.data_type == "DOUBLE" && e.value == "3.25"));
    assert!(
        doc.entries
            .iter()
            .any(|e| e.tag_name == "ExifVersion" && e.value == "0232")
    );
    assert!(
        doc.entries
            .iter()
            .any(|e| e.tag_name == "ComponentsConfiguration" && e.value == "YCbCr-")
    );
    assert!(
        doc.entries
            .iter()
            .any(|e| e.ifd == IfdKind::InteropIfd && e.tag_name == "InteroperabilityIndex" && e.value == "R98")
    );
}

#[test]
fn html_as_text_blocks_entity_encoded_js_flushes_eof_and_nests_template() {
    let opts = HtmlAsTextOptions::default();

    // 1. Entity-encoded & control-char-obfuscated javascript:/vbscript: links are blocked, while &amp; in normal URLs is decoded
    let js_html = br#"<a href="&#106;avascript:alert(1)">J1</a> <a href="&#x6A;avascript:alert(2)">J2</a> <a href="&#106;a&#9;vascript:alert(3)">J3</a> <a href="vbscript:msgbox(1)">V1</a> <a href="https://example.com/search?a=1&amp;b=2">Good</a>"#;
    let js_out = html_to_text(js_html, &opts);
    assert_eq!(js_out.links.len(), 1);
    assert_eq!(js_out.links[0].href, "https://example.com/search?a=1&b=2");

    // 2. Unclosed heading, table, pre, and link flush cleanly at EOF
    let h_out = html_to_text(b"<h1>Unclosed Heading", &opts);
    assert_eq!(h_out.text, "# Unclosed Heading");

    let t_out = html_to_text(b"<table><tr><th>H1</th><th>H2</th></tr><tr><td>A</td><td>B", &opts);
    assert!(t_out.text.contains("| H1"));
    assert!(t_out.text.contains("| A"));
    assert!(t_out.text.contains("B   |"));

    let pre_out = html_to_text(b"<pre>line1\nline2", &opts);
    assert_eq!(pre_out.text, "line1\nline2");

    let link_out = html_to_text(b"<p>See <a href=\"https://eof.test\">EOF link", &opts);
    assert_eq!(link_out.links.len(), 1);
    assert!(link_out.text.contains("EOF link[1]"));

    // 3. Nested <template> and <noscript> do not leak inner content
    let tpl_out = html_to_text(
        b"<template><template><p>inner</p></template><p>still inside outer template</p></template><noscript><noscript>hidden</noscript>outer hidden</noscript><p>Visible</p>",
        &opts,
    );
    assert_eq!(tpl_out.text, "Visible");

    // 4. Unclosed comment / declaration at EOF do not leak raw markup
    let cmt_out = html_to_text(b"<p>Clean</p><!-- unclosed secret", &opts);
    assert_eq!(cmt_out.text, "Clean");
    let decl_out = html_to_text(b"<p>Clean</p><!DOCTYPE unclosed", &opts);
    assert_eq!(decl_out.text, "Clean");
}

#[test]
fn table_text_compare_reconciles_uint_vs_int_and_numeric_types() {
    let tmp = tempfile::tempdir().unwrap();
    let left_csv = tmp.path().join("left_u.csv");
    let right_csv = tmp.path().join("right_i.csv");
    std::fs::write(&left_csv, "id,val\n1,same\n2,x\n").unwrap();
    std::fs::write(&right_csv, "id,val\n1,same\n-1,y\n").unwrap();

    let cmp = TableCompareProvider::compare(
        TableInput::Csv {
            path: left_csv.clone(),
            options: CsvViewOptions::default(),
        },
        TableInput::Csv {
            path: right_csv.clone(),
            options: CsvViewOptions::default(),
        },
        TableCompareOptions {
            key_mode: CompareKeyMode::Columns(vec!["id".to_string()]),
            align_union_columns: true,
            include_unchanged: true,
        },
    )
    .unwrap();
    assert_eq!(cmp.summary().unchanged, 1);
    assert_eq!(cmp.summary().removed, 1);
    assert_eq!(cmp.summary().added, 1);

    let cmp_no_union = TableCompareProvider::compare(
        TableInput::Csv {
            path: left_csv,
            options: CsvViewOptions::default(),
        },
        TableInput::Csv {
            path: right_csv,
            options: CsvViewOptions::default(),
        },
        TableCompareOptions {
            key_mode: CompareKeyMode::Columns(vec!["id".to_string()]),
            align_union_columns: false,
            include_unchanged: true,
        },
    )
    .unwrap();
    assert_eq!(cmp_no_union.summary().unchanged, 1);
}

#[test]
fn addr_view_ldif_colon_recovery_base64_padding_and_vcard_escapes() {
    // 1. LDIF normal value containing `::` and `:<`
    let ldif_cpp = b"dn: cn=Dev,dc=example,dc=org\ncn: Alice\ndescription: Uses std::vector and template:<T>\n\n";
    let cpp_provider = AddrViewProvider::from_bytes("cpp.ldif", ldif_cpp, ContactFormat::Ldif).unwrap();
    assert_eq!(cpp_provider.records().len(), 1);
    assert_eq!(cpp_provider.records()[0].notes, "Uses std::vector and template:<T>");

    // 2. Base64 rejects invalid padding positions
    assert!(decode_base64("YWJj=ZGVm").is_err());
    assert!(decode_base64("YWI=A").is_err());
    assert_eq!(decode_base64("Sm9z").unwrap(), b"Jos");

    // 3. Malformed LDIF Base64 attribute recovers instead of aborting entire file
    let ldif_bad =
        b"dn: cn=First,dc=org\ncn: First\nbadAttr:: !!!not_base64!!!\n\ndn: cn=Second,dc=org\ncn: Second\n\n";
    let bad_provider = AddrViewProvider::from_bytes("bad.ldif", ldif_bad, ContactFormat::Ldif).unwrap();
    assert_eq!(bad_provider.records().len(), 2);
    assert_eq!(bad_provider.records()[0].full_name, "First");
    assert_eq!(bad_provider.records()[1].full_name, "Second");

    // 4. vCard N, ORG, ADR respect escaped `\;` and missing END:VCARD flushes at EOF
    let vcf_esc = b"BEGIN:VCARD\r\nVERSION:3.0\r\nN:Van\\;Der;Bob\r\nORG:Acme\\;Corp;R\\&D\r\nADR:;;123 Main\\;Apt 4;NYC\r\nEND:VCARD\r\nBEGIN:VCARD\r\nFN:Truncated Survivor\r\n";
    let vcf_provider = AddrViewProvider::from_bytes("esc.vcf", vcf_esc, ContactFormat::VCard).unwrap();
    assert_eq!(vcf_provider.records().len(), 2);
    assert_eq!(vcf_provider.records()[0].full_name, "Bob Van;Der");
    assert_eq!(vcf_provider.records()[0].company, "Acme;Corp / R\\&D");
    assert_eq!(vcf_provider.records()[0].address, "123 Main;Apt 4, NYC");
    assert_eq!(vcf_provider.records()[1].full_name, "Truncated Survivor");
}

#[test]
fn csv_file_view_unique_column_ids_and_leading_zero_decimals() {
    let csv_dups = b"foo_2,foo,foo\n1,2,3\n";
    let dup_provider = CsvTableProvider::from_bytes("dups.csv", csv_dups, CsvViewOptions::default()).unwrap();
    let ids: Vec<String> = dup_provider.schema().columns.into_iter().map(|c| c.id).collect();
    assert_eq!(ids, vec!["foo_2", "foo", "foo_3"]);

    // Verify passing to TableTextCompare succeeds without duplicate column id error
    let dup_provider2 = CsvTableProvider::from_bytes("dups2.csv", csv_dups, CsvViewOptions::default()).unwrap();
    let cmp = TableCompareProvider::compare(
        TableInput::Provider(Arc::new(dup_provider)),
        TableInput::Provider(Arc::new(dup_provider2)),
        TableCompareOptions::default(),
    )
    .unwrap();
    assert_eq!(cmp.summary().unchanged, 1);

    // Dotted leading-zero IDs stay Text, while 0.25 / -0.5 remain Float
    let csv_zeros = b"code,ratio\n00123.45,0.25\n00987.65,-0.5\n";
    let zero_provider = CsvTableProvider::from_bytes("codes.csv", csv_zeros, CsvViewOptions::default()).unwrap();
    let z_schema = zero_provider.schema();
    assert_eq!(z_schema.columns[0].col_type, ColumnType::Text);
    assert_eq!(z_schema.columns[1].col_type, ColumnType::Float);
}

#[test]
fn simple_code_generator_preserves_sql_like_wildcards() {
    let input = CodegenInput::Json {
        json_text: r#"[{"col":"name"}]"#.to_string(),
    };
    let tpl = CodegenTemplate {
        rule_name: "sql_like".to_string(),
        target: CodegenTarget::Sql,
        body_template:
            "SELECT * FROM users WHERE {{col}} LIKE '%admin%' AND x LIKE '%foo' AND y = '%col%' AND z = '%%lit%%';"
                .to_string(),
        strict_placeholders: false,
        ..CodegenTemplate::default()
    };
    let res = generate_code(&input, &tpl).unwrap();
    assert_eq!(
        res.snippets[0],
        "SELECT * FROM users WHERE name LIKE '%admin%' AND x LIKE '%foo' AND y = 'name' AND z = '%lit%';"
    );

    let strict_tpl = CodegenTemplate {
        body_template: "SELECT * FROM users WHERE {{col}} LIKE '%admin%';".to_string(),
        strict_placeholders: true,
        ..tpl
    };
    assert!(generate_code(&input, &strict_tpl).is_err());
}

#[test]
fn html_as_text_decodes_zero_padded_numeric_entities_and_blocks_js_bypass() {
    let opts = HtmlAsTextOptions::default();

    let html = br#"<html>
<head><title>Title &#00000000008364;100 &amp; &#x000000000041;</title></head>
<body>
  <p>Dec: &#00000000008364;50 Hex: &#x00000000006A; &#X00000000004B; Null: &#00000000000;</p>
  <p>Invalid: &#; &#x; &#99999999999999999999; &#0000000000106abc;</p>
  <a href="&#0000000000106;avascript:alert(1)">ZeroPadDec</a>
  <a href="&#x00000000006a;avascript:alert(2)">ZeroPadHex</a>
  <a href="&#X000000000076;b&#00000000009;script:msgbox(1)">ZeroPadVbs</a>
  <a href="https://example.com/?x=&#000000000049;&#x000000000026;y=2">SafeLink</a>
</body>
</html>"#;

    let out = html_to_text(html, &opts);
    assert_eq!(out.title, "Title €100 & A");
    assert!(out.text.contains("Dec: €50 Hex: j K Null: \u{FFFD}"));
    assert!(
        out.text
            .contains("Invalid: &#; &#x; &#99999999999999999999; &#0000000000106abc;")
    );
    assert_eq!(out.links.len(), 1);
    assert_eq!(out.links[0].text, "SafeLink");
    assert_eq!(out.links[0].href, "https://example.com/?x=1&y=2");
}

#[test]
fn table_text_compare_reconciles_bytes_size_vs_int_and_uint() {
    let make_table = |title: &str, col_type: ColumnType, rows: Vec<Row>| TableData {
        schema: TableSchema::new(
            "test",
            title,
            vec![
                ColumnDef::new("sz", "Size", col_type),
                ColumnDef::new("tag", "Tag", ColumnType::Text),
            ],
        ),
        total_rows: rows.len(),
        rows,
    };

    // 1. BytesSize(100, 200) vs Int(100, -5) -> Int reconciliation in both union & non-union modes
    let left_bytes = make_table(
        "left_bytes",
        ColumnType::BytesSize,
        vec![
            Row::new(0, vec![CellValue::Bytes(100), CellValue::Text("same".to_string())]),
            Row::new(1, vec![CellValue::Bytes(200), CellValue::Text("only_left".to_string())]),
        ],
    );
    let right_int = make_table(
        "right_int",
        ColumnType::Int,
        vec![
            Row::new(0, vec![CellValue::Int(100), CellValue::Text("same".to_string())]),
            Row::new(1, vec![CellValue::Int(-5), CellValue::Text("only_right".to_string())]),
        ],
    );

    for union_mode in [true, false] {
        let cmp = TableCompareProvider::compare(
            TableInput::TableData(left_bytes.clone()),
            TableInput::TableData(right_int.clone()),
            TableCompareOptions {
                key_mode: CompareKeyMode::Columns(vec!["sz".to_string()]),
                align_union_columns: union_mode,
                include_unchanged: true,
            },
        )
        .unwrap();
        assert_eq!(cmp.summary().unchanged, 1);
        assert_eq!(cmp.summary().removed, 1);
        assert_eq!(cmp.summary().added, 1);
    }

    // 2. BytesSize with u64::MAX vs Int(-5) falls back to Text cleanly without overflow
    let left_max = make_table(
        "left_max",
        ColumnType::BytesSize,
        vec![
            Row::new(0, vec![CellValue::Bytes(100), CellValue::Text("same".to_string())]),
            Row::new(1, vec![CellValue::Bytes(u64::MAX), CellValue::Text("huge".to_string())]),
        ],
    );
    for union_mode in [true, false] {
        let cmp = TableCompareProvider::compare(
            TableInput::TableData(left_max.clone()),
            TableInput::TableData(right_int.clone()),
            TableCompareOptions {
                key_mode: CompareKeyMode::Columns(vec!["sz".to_string()]),
                align_union_columns: union_mode,
                include_unchanged: true,
            },
        )
        .unwrap();
        assert_eq!(cmp.summary().unchanged, 1);
        assert_eq!(cmp.summary().removed, 1);
        assert_eq!(cmp.summary().added, 1);
    }

    // 3. BytesSize(100) vs Uint(100) continues joining cleanly
    let right_uint = make_table(
        "right_uint",
        ColumnType::Uint,
        vec![Row::new(
            0,
            vec![CellValue::Uint(100), CellValue::Text("same".to_string())],
        )],
    );
    let cmp_bu = TableCompareProvider::compare(
        TableInput::TableData(left_bytes),
        TableInput::TableData(right_uint),
        TableCompareOptions {
            key_mode: CompareKeyMode::Columns(vec!["sz".to_string()]),
            align_union_columns: true,
            include_unchanged: true,
        },
    )
    .unwrap();
    assert_eq!(cmp_bu.summary().unchanged, 1);
    assert_eq!(cmp_bu.summary().removed, 1);
}

#[test]
fn table_text_compare_prevents_64bit_int_vs_float_key_collision() {
    let make_table = |title: &str, col_type: ColumnType, keys: Vec<CellValue>| {
        let rows: Vec<Row> = keys
            .into_iter()
            .enumerate()
            .map(|(i, k)| Row::new(i as u64, vec![k, CellValue::Text(format!("v{i}"))]))
            .collect();
        TableData {
            schema: TableSchema::new(
                "test",
                title,
                vec![
                    ColumnDef::new("id", "ID", col_type),
                    ColumnDef::new("val", "Val", ColumnType::Text),
                ],
            ),
            total_rows: rows.len(),
            rows,
        }
    };

    let right_float = make_table("right_f", ColumnType::Float, vec![CellValue::Float(1.5)]);

    // 1. Uint 2^53 and 2^53 + 1 vs Float(1.5) must stay 3 distinct diff keys
    let left_uint = make_table(
        "left_u64",
        ColumnType::Uint,
        vec![
            CellValue::Uint(9_007_199_254_740_992),
            CellValue::Uint(9_007_199_254_740_993),
        ],
    );
    for union_mode in [true, false] {
        let cmp = TableCompareProvider::compare(
            TableInput::TableData(left_uint.clone()),
            TableInput::TableData(right_float.clone()),
            TableCompareOptions {
                key_mode: CompareKeyMode::Columns(vec!["id".to_string()]),
                align_union_columns: union_mode,
                include_unchanged: true,
            },
        )
        .unwrap();
        assert_eq!(cmp.result().diff.rows.len(), 3);
        assert_eq!(cmp.summary().removed, 2);
        assert_eq!(cmp.summary().added, 1);
    }

    // 2. Negative Int -(2^53) and -(2^53 + 1) vs Float(1.5) must stay 3 distinct diff keys
    let left_int = make_table(
        "left_i64",
        ColumnType::Int,
        vec![
            CellValue::Int(-9_007_199_254_740_992),
            CellValue::Int(-9_007_199_254_740_993),
        ],
    );
    for union_mode in [true, false] {
        let cmp = TableCompareProvider::compare(
            TableInput::TableData(left_int.clone()),
            TableInput::TableData(right_float.clone()),
            TableCompareOptions {
                key_mode: CompareKeyMode::Columns(vec!["id".to_string()]),
                align_union_columns: union_mode,
                include_unchanged: true,
            },
        )
        .unwrap();
        assert_eq!(cmp.result().diff.rows.len(), 3);
        assert_eq!(cmp.summary().removed, 2);
        assert_eq!(cmp.summary().added, 1);
    }

    // 3. BytesSize > 2^53 vs Float(1.5) must stay 3 distinct diff keys
    let left_bytes = make_table(
        "left_bytes64",
        ColumnType::BytesSize,
        vec![
            CellValue::Bytes(9_007_199_254_740_992),
            CellValue::Bytes(9_007_199_254_740_993),
        ],
    );
    for union_mode in [true, false] {
        let cmp = TableCompareProvider::compare(
            TableInput::TableData(left_bytes.clone()),
            TableInput::TableData(right_float.clone()),
            TableCompareOptions {
                key_mode: CompareKeyMode::Columns(vec!["id".to_string()]),
                align_union_columns: union_mode,
                include_unchanged: true,
            },
        )
        .unwrap();
        assert_eq!(cmp.result().diff.rows.len(), 3);
        assert_eq!(cmp.summary().removed, 2);
        assert_eq!(cmp.summary().added, 1);
    }

    // 4. Exact small integers <= 2^53 still join with Float(42.0)
    let left_small = make_table("left_small", ColumnType::Uint, vec![CellValue::Uint(42)]);
    let right_small = make_table("right_small", ColumnType::Float, vec![CellValue::Float(42.0)]);
    let cmp_small = TableCompareProvider::compare(
        TableInput::TableData(left_small),
        TableInput::TableData(right_small),
        TableCompareOptions {
            key_mode: CompareKeyMode::Columns(vec!["id".to_string()]),
            align_union_columns: true,
            include_unchanged: true,
        },
    )
    .unwrap();
    assert_eq!(cmp_small.summary().unchanged, 1);
}

#[test]
fn html_as_text_does_not_double_decode_title_entities() {
    let out = html_to_text(
        b"<html><head><title>A &amp;lt; B &amp;amp; C &amp;#106;avascript</title></head><body><p>A &amp;lt; B</p></body></html>",
        &HtmlAsTextOptions::default(),
    );
    assert_eq!(out.title, "A &lt; B &amp; C &#106;avascript");
}

#[test]
fn html_as_text_closes_unclosed_title_at_head_end_or_body_start() {
    let head_end = html_to_text(
        b"<html><head><title>Unclosed</head><body><p>Body</p></body></html>",
        &HtmlAsTextOptions::default(),
    );
    assert_eq!(head_end.title, "Unclosed");
    assert!(head_end.text.contains("Body"));

    let body_start = html_to_text(
        b"<html><head><title>Unclosed<body><p>Body</p></body></html>",
        &HtmlAsTextOptions::default(),
    );
    assert_eq!(body_start.title, "Unclosed");
    assert!(body_start.text.contains("Body"));
}

#[test]
fn html_as_text_ignores_nested_state_mutating_tags_inside_title() {
    let opts = HtmlAsTextOptions::default();

    // Closed </title> with <a>, <h1>, <blockquote>, <table><tr><td>, <ul><li>, <pre>, <code>, <b>, <span>, <!-- -->, <script>
    let closed_a = html_to_text(
        br#"<html><head><title>Foo <a href="https://evil.test">Bar</a> Baz</title></head><body><p>Body</p></body></html>"#,
        &opts,
    );
    assert_eq!(closed_a.title, "Foo Bar Baz");
    assert!(closed_a.links.is_empty());
    assert_eq!(closed_a.text, "Body");

    let closed_mixed = html_to_text(
        b"<html><head><title><b>Bold</b> <span>Span</span><!-- c --><script>bad()</script><h1>H</h1><blockquote>Q</blockquote><table><tr><td>C</td></tr></table><ul><li>L</li></ul><pre>P</pre><code>X</code></title></head><body><p>Body</p></body></html>",
        &opts,
    );
    assert_eq!(closed_mixed.title, "Bold SpanHQCLPX");
    assert!(closed_mixed.links.is_empty());
    assert_eq!(closed_mixed.text, "Body");
    assert_eq!(closed_mixed.blocks.len(), 1);
    assert_eq!(closed_mixed.blocks[0].kind, "paragraph");

    // Unclosed <title> closed by </head> or <body> with state-mutating tags inside
    let cases: &[(&[u8], &str, &str)] = &[
        (
            b"<html><head><title>Foo <h1>UnclosedH1</head><body><p>Body</p></body></html>",
            "Foo UnclosedH1",
            "Body",
        ),
        (
            b"<html><head><title>Foo <h1>UnclosedH1<body><p>Body</p></body></html>",
            "Foo UnclosedH1",
            "Body",
        ),
        (
            b"<html><head><title>Foo <blockquote>UnclosedBQ</head><body><p>Body</p></body></html>",
            "Foo UnclosedBQ",
            "Body",
        ),
        (
            b"<html><head><title>Foo <blockquote>UnclosedBQ<body><p>Body</p></body></html>",
            "Foo UnclosedBQ",
            "Body",
        ),
        (
            b"<html><head><title>Foo <table><tr><td>UnclosedTbl</head><body>BodyText</body></html>",
            "Foo UnclosedTbl",
            "BodyText",
        ),
        (
            b"<html><head><title>Foo <table><tr><td>UnclosedTbl<body>BodyText</body></html>",
            "Foo UnclosedTbl",
            "BodyText",
        ),
        (
            b"<html><head><title>Foo <ul><li>UnclosedLi</head><body>BodyText</body></html>",
            "Foo UnclosedLi",
            "BodyText",
        ),
        (
            b"<html><head><title>Foo <ul><li>UnclosedLi<body>BodyText</body></html>",
            "Foo UnclosedLi",
            "BodyText",
        ),
        (
            b"<html><head><title>Foo <pre>UnclosedPre</head><body>Line1<br>Line2</body></html>",
            "Foo UnclosedPre",
            "Line1\n\nLine2",
        ),
        (
            b"<html><head><title>Foo <pre>UnclosedPre<body>Line1<br>Line2</body></html>",
            "Foo UnclosedPre",
            "Line1\n\nLine2",
        ),
        (
            br#"<html><head><title>Foo <a href="https://evil.test">UnclosedA</head><body><p>Body</p></body></html>"#,
            "Foo UnclosedA",
            "Body",
        ),
        (
            br#"<html><head><title>Foo <a href="https://evil.test">UnclosedA<body><p>Body</p></body></html>"#,
            "Foo UnclosedA",
            "Body",
        ),
    ];

    for (html, expected_title, expected_text) in cases {
        let out = html_to_text(html, &opts);
        assert_eq!(out.title, *expected_title);
        assert_eq!(out.text, *expected_text);
        assert!(out.links.is_empty());
        assert!(
            out.blocks.iter().all(|b| b.kind == "paragraph"),
            "unexpected non-paragraph block {:?} for {:?}",
            out.blocks,
            String::from_utf8_lossy(html)
        );
    }
}
