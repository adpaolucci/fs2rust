use crate::encoding::{decode_bytes, decode_windows_1252};
use crate::error::DataError;
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, TableData, TableError, TableProvider, TableQuery, TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;

/// Heading formatting style for `HTMLAsText`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HeadingStyle {
    #[default]
    Markdown,
    Underline,
    Plain,
}

/// Configuration options for `HTMLAsText`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtmlAsTextOptions {
    pub heading_style: HeadingStyle,
    pub include_link_footnotes: bool,
    pub include_alt_text: bool,
    pub ignore_javascript_links: bool,
    pub table_cell_separator: String,
}

impl Default for HtmlAsTextOptions {
    fn default() -> Self {
        Self {
            heading_style: HeadingStyle::Markdown,
            include_link_footnotes: true,
            include_alt_text: true,
            ignore_javascript_links: true,
            table_cell_separator: " | ".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtmlLink {
    pub index: usize,
    pub text: String,
    pub href: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtmlBlock {
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtmlAsTextOutput {
    pub title: String,
    pub text: String,
    pub links: Vec<HtmlLink>,
    pub blocks: Vec<HtmlBlock>,
    pub word_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Unordered,
    Ordered(usize),
}

enum HtmlToken {
    Text(String),
    StartTag { name: String, attrs: Vec<(String, String)> },
    EndTag(String),
}

/// Convert raw HTML bytes into structured plain text, blocks, and deduplicated link footnotes.
pub fn html_to_text(bytes: &[u8], opts: &HtmlAsTextOptions) -> HtmlAsTextOutput {
    let decoded = decode_bytes(bytes);
    let tokens = tokenize_html(&decoded.text);

    let mut title = String::new();
    let mut blocks: Vec<HtmlBlock> = Vec::new();
    let mut links: Vec<HtmlLink> = Vec::new();
    let mut link_index_by_href: HashMap<String, usize> = HashMap::new();

    let mut in_title = false;
    let mut in_pre = false;
    let mut in_code = false;
    let mut blockquote_depth = 0usize;
    let mut heading_level: Option<usize> = None;
    let mut heading_buf = String::new();

    let mut list_stack: Vec<ListKind> = Vec::new();
    let mut active_list_item: Option<(usize, String, String)> = None; // (depth, prefix, text)

    let mut in_table = false;
    let mut current_table_rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Option<Vec<String>> = None;
    let mut current_cell: Option<String> = None;

    let mut active_link: Option<(String, String)> = None; // (href, text)
    let mut para_buf = String::new();
    let mut out_sections: Vec<String> = Vec::new();

    let flush_paragraph = |buf: &mut String, out: &mut Vec<String>, blks: &mut Vec<HtmlBlock>, bq_depth: usize| {
        let trimmed = collapse_inline_whitespace(buf);
        buf.clear();
        if !trimmed.is_empty() {
            let line = if bq_depth > 0 {
                format!("{}{trimmed}", "> ".repeat(bq_depth))
            } else {
                trimmed
            };
            blks.push(HtmlBlock {
                kind: "paragraph".to_string(),
                text: line.clone(),
            });
            out.push(line);
        }
    };

    let flush_list_item =
        |item: &mut Option<(usize, String, String)>, out: &mut Vec<String>, blks: &mut Vec<HtmlBlock>| {
            if let Some((depth, prefix, text)) = item.take() {
                let trimmed = collapse_inline_whitespace(&text);
                if !trimmed.is_empty() {
                    let indent = "  ".repeat(depth.saturating_sub(1));
                    let line = format!("{indent}{prefix}{trimmed}");
                    blks.push(HtmlBlock {
                        kind: "list_item".to_string(),
                        text: line.clone(),
                    });
                    out.push(line);
                }
            }
        };

    let push_text = |chunk: &str,
                     in_title: bool,
                     title: &mut String,
                     heading_level: Option<usize>,
                     heading_buf: &mut String,
                     active_link: &mut Option<(String, String)>,
                     current_cell: &mut Option<String>,
                     active_list_item: &mut Option<(usize, String, String)>,
                     para_buf: &mut String| {
        if in_title {
            title.push_str(chunk);
            return;
        }
        if let Some((_, link_text)) = active_link.as_mut() {
            link_text.push_str(chunk);
        }
        if let Some(cell) = current_cell.as_mut() {
            cell.push_str(chunk);
            return;
        }
        if heading_level.is_some() {
            heading_buf.push_str(chunk);
            return;
        }
        if let Some((_, _, li_text)) = active_list_item.as_mut() {
            li_text.push_str(chunk);
            return;
        }
        para_buf.push_str(chunk);
    };

    for tok in tokens {
        match tok {
            HtmlToken::Text(raw) => {
                let decoded_text = decode_html_entities(&raw);
                push_text(
                    &decoded_text,
                    in_title,
                    &mut title,
                    heading_level,
                    &mut heading_buf,
                    &mut active_link,
                    &mut current_cell,
                    &mut active_list_item,
                    &mut para_buf,
                );
            }
            HtmlToken::StartTag { name, attrs } => {
                if in_title {
                    if name == "body" {
                        in_title = false;
                    }
                    continue;
                }
                match name.as_str() {
                    "title" => {
                        in_title = true;
                    }
                    "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        let lvl = name[1..].parse::<usize>().unwrap_or(1);
                        heading_level = Some(lvl);
                        heading_buf.clear();
                    }
                    "p" | "div" | "section" | "article" | "header" | "footer" | "main" | "nav" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                    }
                    "blockquote" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        blockquote_depth += 1;
                    }
                    "br" => {
                        if current_cell.is_some() {
                            if let Some(c) = current_cell.as_mut() {
                                c.push(' ');
                            }
                        } else if in_pre {
                            para_buf.push('\n');
                        } else {
                            flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        }
                    }
                    "hr" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        out_sections.push("---".to_string());
                    }
                    "ul" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        list_stack.push(ListKind::Unordered);
                    }
                    "ol" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        list_stack.push(ListKind::Ordered(1));
                    }
                    "li" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        let depth = list_stack.len().max(1);
                        let prefix = match list_stack.last_mut() {
                            Some(ListKind::Unordered) | None => "- ".to_string(),
                            Some(ListKind::Ordered(n)) => {
                                let cur = *n;
                                *n += 1;
                                format!("{cur}. ")
                            }
                        };
                        active_list_item = Some((depth, prefix, String::new()));
                    }
                    "table" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        in_table = true;
                        current_table_rows.clear();
                    }
                    "tr" if in_table => {
                        current_row = Some(Vec::new());
                    }
                    "th" | "td" if in_table => {
                        current_cell = Some(String::new());
                    }
                    "pre" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        in_pre = true;
                    }
                    "code" => {
                        if !in_pre {
                            in_code = true;
                            push_text(
                                "`",
                                in_title,
                                &mut title,
                                heading_level,
                                &mut heading_buf,
                                &mut active_link,
                                &mut current_cell,
                                &mut active_list_item,
                                &mut para_buf,
                            );
                        }
                    }
                    "a" => {
                        if let Some(href) = attrs
                            .iter()
                            .find(|(k, _)| k == "href")
                            .map(|(_, v)| v.trim().to_string())
                        {
                            let scheme_check: String = href
                                .chars()
                                .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
                                .collect::<String>()
                                .to_ascii_lowercase();
                            let ignore = opts.ignore_javascript_links
                                && (scheme_check.starts_with("javascript:") || scheme_check.starts_with("vbscript:"));
                            if !href.is_empty() && !ignore {
                                active_link = Some((href, String::new()));
                            }
                        }
                    }
                    "img" if opts.include_alt_text => {
                        if let Some(alt) = attrs
                            .iter()
                            .find(|(k, _)| k == "alt")
                            .map(|(_, v)| v.trim().to_string())
                            && !alt.is_empty()
                        {
                            let tag = format!("[img: {alt}]");
                            push_text(
                                &tag,
                                in_title,
                                &mut title,
                                heading_level,
                                &mut heading_buf,
                                &mut active_link,
                                &mut current_cell,
                                &mut active_list_item,
                                &mut para_buf,
                            );
                        }
                    }
                    "body" => {
                        in_title = false;
                    }
                    _ => {}
                }
            }
            HtmlToken::EndTag(name) => {
                if in_title {
                    if matches!(name.as_str(), "title" | "head") {
                        in_title = false;
                    }
                    continue;
                }
                match name.as_str() {
                    "title" => {
                        in_title = false;
                    }
                    "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                        if let Some(lvl) = heading_level.take() {
                            let text = collapse_inline_whitespace(&heading_buf);
                            heading_buf.clear();
                            if !text.is_empty() {
                                let rendered = match opts.heading_style {
                                    HeadingStyle::Markdown => format!("{} {text}", "#".repeat(lvl)),
                                    HeadingStyle::Underline => {
                                        let ch = if lvl == 1 { '=' } else { '-' };
                                        format!("{text}\n{}", ch.to_string().repeat(text.chars().count().max(3)))
                                    }
                                    HeadingStyle::Plain => text,
                                };
                                blocks.push(HtmlBlock {
                                    kind: "heading".to_string(),
                                    text: rendered.clone(),
                                });
                                out_sections.push(rendered);
                            }
                        }
                    }
                    "p" | "div" | "section" | "article" | "header" | "footer" | "main" | "nav" => {
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                    }
                    "blockquote" => {
                        flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);
                        blockquote_depth = blockquote_depth.saturating_sub(1);
                    }
                    "ul" | "ol" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                        list_stack.pop();
                    }
                    "li" => {
                        flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
                    }
                    "th" | "td" if in_table => {
                        if let Some(cell) = current_cell.take()
                            && let Some(row) = current_row.as_mut()
                        {
                            row.push(collapse_inline_whitespace(&cell));
                        }
                    }
                    "tr" if in_table => {
                        if let Some(row) = current_row.take()
                            && !row.is_empty()
                        {
                            current_table_rows.push(row);
                        }
                    }
                    "table" if in_table => {
                        in_table = false;
                        if let Some(row) = current_row.take()
                            && !row.is_empty()
                        {
                            current_table_rows.push(row);
                        }
                        if !current_table_rows.is_empty() {
                            let rendered = render_pipe_table(&current_table_rows, &opts.table_cell_separator);
                            blocks.push(HtmlBlock {
                                kind: "table".to_string(),
                                text: rendered.clone(),
                            });
                            out_sections.push(rendered);
                            current_table_rows.clear();
                        }
                    }
                    "pre" => {
                        in_pre = false;
                        let raw_pre = para_buf.trim_matches('\n').to_string();
                        para_buf.clear();
                        if !raw_pre.is_empty() {
                            blocks.push(HtmlBlock {
                                kind: "pre".to_string(),
                                text: raw_pre.clone(),
                            });
                            out_sections.push(raw_pre);
                        }
                    }
                    "code" => {
                        if in_code {
                            in_code = false;
                            push_text(
                                "`",
                                in_title,
                                &mut title,
                                heading_level,
                                &mut heading_buf,
                                &mut active_link,
                                &mut current_cell,
                                &mut active_list_item,
                                &mut para_buf,
                            );
                        }
                    }
                    "a" => {
                        if let Some((href, link_text)) = active_link.take() {
                            let idx = if let Some(&existing) = link_index_by_href.get(&href) {
                                existing
                            } else {
                                let next = links.len() + 1;
                                link_index_by_href.insert(href.clone(), next);
                                links.push(HtmlLink {
                                    index: next,
                                    text: collapse_inline_whitespace(&link_text),
                                    href,
                                });
                                next
                            };
                            if opts.include_link_footnotes {
                                let marker = format!("[{idx}]");
                                push_text(
                                    &marker,
                                    in_title,
                                    &mut title,
                                    heading_level,
                                    &mut heading_buf,
                                    &mut None,
                                    &mut current_cell,
                                    &mut active_list_item,
                                    &mut para_buf,
                                );
                            }
                        }
                    }
                    "head" => {
                        in_title = false;
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some((href, link_text)) = active_link.take() {
        let idx = if let Some(&existing) = link_index_by_href.get(&href) {
            existing
        } else {
            let next = links.len() + 1;
            link_index_by_href.insert(href.clone(), next);
            links.push(HtmlLink {
                index: next,
                text: collapse_inline_whitespace(&link_text),
                href,
            });
            next
        };
        if opts.include_link_footnotes {
            let marker = format!("[{idx}]");
            push_text(
                &marker,
                in_title,
                &mut title,
                heading_level,
                &mut heading_buf,
                &mut None,
                &mut current_cell,
                &mut active_list_item,
                &mut para_buf,
            );
        }
    }

    if in_table {
        if let Some(cell) = current_cell.take() {
            let text = collapse_inline_whitespace(&cell);
            if let Some(row) = current_row.as_mut() {
                row.push(text);
            } else {
                current_row = Some(vec![text]);
            }
        }
        if let Some(row) = current_row.take()
            && !row.is_empty()
        {
            current_table_rows.push(row);
        }
        if !current_table_rows.is_empty() {
            let rendered = render_pipe_table(&current_table_rows, &opts.table_cell_separator);
            blocks.push(HtmlBlock {
                kind: "table".to_string(),
                text: rendered.clone(),
            });
            out_sections.push(rendered);
            current_table_rows.clear();
        }
    }

    if let Some(lvl) = heading_level.take() {
        let text = collapse_inline_whitespace(&heading_buf);
        heading_buf.clear();
        if !text.is_empty() {
            let rendered = match opts.heading_style {
                HeadingStyle::Markdown => format!("{} {text}", "#".repeat(lvl)),
                HeadingStyle::Underline => {
                    let ch = if lvl == 1 { '=' } else { '-' };
                    format!("{text}\n{}", ch.to_string().repeat(text.chars().count().max(3)))
                }
                HeadingStyle::Plain => text,
            };
            blocks.push(HtmlBlock {
                kind: "heading".to_string(),
                text: rendered.clone(),
            });
            out_sections.push(rendered);
        }
    }

    if in_pre {
        let raw_pre = para_buf.trim_matches('\n').to_string();
        para_buf.clear();
        if !raw_pre.is_empty() {
            blocks.push(HtmlBlock {
                kind: "pre".to_string(),
                text: raw_pre.clone(),
            });
            out_sections.push(raw_pre);
        }
    }

    flush_list_item(&mut active_list_item, &mut out_sections, &mut blocks);
    flush_paragraph(&mut para_buf, &mut out_sections, &mut blocks, blockquote_depth);

    if opts.include_link_footnotes && !links.is_empty() {
        let mut refs = String::from("References:\n");
        for l in &links {
            refs.push_str(&format!("[{}] {}\n", l.index, l.href));
        }
        out_sections.push(refs.trim_end().to_string());
    }

    let text = out_sections.join("\n\n");
    let word_count = text.split_whitespace().count();
    let title = collapse_inline_whitespace(&title);

    HtmlAsTextOutput {
        title,
        text,
        links,
        blocks,
        word_count,
    }
}

fn render_pipe_table(rows: &[Vec<String>], sep: &str) -> String {
    let col_count = rows.iter().map(Vec::len).max().unwrap_or(0);
    if col_count == 0 {
        return String::new();
    }
    let mut widths = vec![3usize; col_count];
    for r in rows {
        for (i, cell) in r.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    let mut lines = Vec::with_capacity(rows.len() + 1);
    for (row_idx, r) in rows.iter().enumerate() {
        let mut cells = Vec::with_capacity(col_count);
        for (i, &w) in widths.iter().enumerate() {
            let val = r.get(i).map(String::as_str).unwrap_or("");
            cells.push(format!("{:<width$}", val, width = w));
        }
        lines.push(format!("| {} |", cells.join(sep)));
        if row_idx == 0 {
            let dashes: Vec<String> = widths.iter().map(|&w| "-".repeat(w)).collect();
            lines.push(format!("| {} |", dashes.join(sep)));
        }
    }
    lines.join("\n")
}

fn collapse_inline_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn tokenize_html(input: &str) -> Vec<HtmlToken> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut text_start = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }

        if i > text_start {
            tokens.push(HtmlToken::Text(input[text_start..i].to_string()));
        }

        // Comment <!-- ... -->
        if input[i..].starts_with("<!--") {
            if let Some(end_rel) = input[i + 4..].find("-->") {
                i = i + 4 + end_rel + 3;
                text_start = i;
                continue;
            } else {
                text_start = bytes.len();
                break;
            }
        }

        // DOCTYPE / declaration <! ... >
        if input[i..].starts_with("<!") || input[i..].starts_with("<?") {
            if let Some(end_rel) = input[i + 2..].find('>') {
                i = i + 2 + end_rel + 1;
                text_start = i;
                continue;
            } else {
                text_start = bytes.len();
                break;
            }
        }

        // Scan tag end respecting quoted attributes
        let Some(tag_end) = find_tag_close(input, i + 1) else {
            tokens.push(HtmlToken::Text(input[i..].to_string()));
            text_start = bytes.len();
            break;
        };

        let inner = input[i + 1..tag_end].trim();
        i = tag_end + 1;
        text_start = i;

        if inner.is_empty() {
            continue;
        }
        if let Some(rest) = inner.strip_prefix('/') {
            let name = rest.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if !name.is_empty() {
                tokens.push(HtmlToken::EndTag(name));
            }
            continue;
        }

        let (name, attrs, self_closing) = parse_start_tag(inner);
        if name.is_empty() {
            continue;
        }

        // Suppress raw text content inside <script>, <style>, <noscript>, <template>
        if !self_closing && matches!(name.as_str(), "script" | "style" | "noscript" | "template") {
            if matches!(name.as_str(), "template" | "noscript") {
                i = skip_nested_raw_element(input, i, &name);
            } else {
                let close_pat = format!("</{name}");
                let lower_tail = input[i..].to_ascii_lowercase();
                if let Some(close_rel) = lower_tail.find(&close_pat) {
                    let after_name = i + close_rel + close_pat.len();
                    if let Some(gt_rel) = input[after_name..].find('>') {
                        i = after_name + gt_rel + 1;
                    } else {
                        i = bytes.len();
                    }
                } else {
                    i = bytes.len();
                }
            }
            text_start = i;
            continue;
        }

        let end_name = if self_closing && !matches!(name.as_str(), "br" | "hr" | "img") {
            Some(name.clone())
        } else {
            None
        };
        tokens.push(HtmlToken::StartTag { name, attrs });
        if let Some(end) = end_name {
            tokens.push(HtmlToken::EndTag(end));
        }
    }

    if text_start < bytes.len() {
        tokens.push(HtmlToken::Text(input[text_start..].to_string()));
    }

    tokens
}

fn skip_nested_raw_element(input: &str, mut pos: usize, tag: &str) -> usize {
    let bytes = input.as_bytes();
    let tag_bytes = tag.as_bytes();
    let mut depth = 1usize;
    while pos < bytes.len() {
        if bytes[pos] != b'<' {
            pos += 1;
            continue;
        }
        if input[pos..].starts_with("<!--") {
            if let Some(end_rel) = input[pos + 4..].find("-->") {
                pos = pos + 4 + end_rel + 3;
                continue;
            } else {
                return bytes.len();
            }
        }
        if bytes.get(pos + 1) == Some(&b'/') {
            let name_start = pos + 2;
            let name_end = name_start + tag_bytes.len();
            if name_end <= bytes.len()
                && bytes[name_start..name_end].eq_ignore_ascii_case(tag_bytes)
                && bytes
                    .get(name_end)
                    .is_some_and(|&b| b == b'>' || b.is_ascii_whitespace())
            {
                if let Some(gt) = find_tag_close(input, pos + 1) {
                    pos = gt + 1;
                } else {
                    return bytes.len();
                }
                depth -= 1;
                if depth == 0 {
                    return pos;
                }
                continue;
            }
        } else {
            let name_start = pos + 1;
            let name_end = name_start + tag_bytes.len();
            if name_end <= bytes.len()
                && bytes[name_start..name_end].eq_ignore_ascii_case(tag_bytes)
                && bytes
                    .get(name_end)
                    .is_some_and(|&b| b == b'>' || b == b'/' || b.is_ascii_whitespace())
            {
                if let Some(gt) = find_tag_close(input, pos + 1) {
                    let self_closing = input[pos + 1..gt].trim_end().ends_with('/');
                    pos = gt + 1;
                    if !self_closing {
                        depth += 1;
                    }
                    continue;
                } else {
                    return bytes.len();
                }
            }
        }
        pos += 1;
    }
    bytes.len()
}

fn find_tag_close(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i),
            None => {}
        }
        i += 1;
    }
    None
}

fn parse_start_tag(inner: &str) -> (String, Vec<(String, String)>, bool) {
    let trimmed = inner.trim();
    let (body, self_closing) = if let Some(s) = trimmed.strip_suffix('/') {
        (s.trim_end(), true)
    } else {
        (trimmed, false)
    };

    let mut chars = body.char_indices().peekable();
    let mut name_end = body.len();
    for (idx, ch) in chars.by_ref() {
        if ch.is_whitespace() {
            name_end = idx;
            break;
        }
    }
    let name = body[..name_end].to_ascii_lowercase();
    let mut attrs = Vec::new();
    let rest = body[name_end..].trim_start();
    let rbytes = rest.as_bytes();
    let mut pos = 0usize;

    while pos < rbytes.len() {
        while pos < rbytes.len() && rbytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= rbytes.len() {
            break;
        }
        let key_start = pos;
        while pos < rbytes.len() && !rbytes[pos].is_ascii_whitespace() && rbytes[pos] != b'=' {
            pos += 1;
        }
        let key = rest[key_start..pos].to_ascii_lowercase();
        while pos < rbytes.len() && rbytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let mut val = String::new();
        if pos < rbytes.len() && rbytes[pos] == b'=' {
            pos += 1;
            while pos < rbytes.len() && rbytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            if pos < rbytes.len() && (rbytes[pos] == b'"' || rbytes[pos] == b'\'') {
                let q = rbytes[pos];
                pos += 1;
                let v_start = pos;
                while pos < rbytes.len() && rbytes[pos] != q {
                    pos += 1;
                }
                val = rest[v_start..pos].to_string();
                if pos < rbytes.len() {
                    pos += 1;
                }
            } else {
                let v_start = pos;
                while pos < rbytes.len() && !rbytes[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                val = rest[v_start..pos].to_string();
            }
        }
        if !key.is_empty() {
            attrs.push((key, decode_html_entities(&val)));
        }
    }

    (name, attrs, self_closing)
}

/// Decode numeric (`&#123;`, `&#x1F;`, arbitrarily zero-padded HTML5 numeric refs) and common HTML named entities.
pub fn decode_html_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pos = 0usize;
    let bytes = s.as_bytes();

    while pos < bytes.len() {
        if bytes[pos] == b'&' {
            if bytes.get(pos + 1) == Some(&b'#') {
                if let Some((ch, end_pos)) = parse_numeric_entity(bytes, pos + 2) {
                    out.push(ch);
                    pos = end_pos;
                    continue;
                }
            } else {
                let search_end = (pos + 14).min(bytes.len());
                if let Some(semi_rel) = bytes[pos + 1..search_end].iter().position(|&b| b == b';')
                    && semi_rel > 0
                {
                    let entity = &s[pos + 1..pos + 1 + semi_rel];
                    if let Some(ch) = resolve_named_entity(entity) {
                        out.push(ch);
                        pos += semi_rel + 2;
                        continue;
                    }
                }
            }
        }
        let ch = s[pos..].chars().next().unwrap();
        out.push(ch);
        pos += ch.len_utf8();
    }
    out
}

fn parse_numeric_entity(bytes: &[u8], start: usize) -> Option<(char, usize)> {
    let (is_hex, digit_start) = match bytes.get(start) {
        Some(b'x' | b'X') => (true, start + 1),
        Some(_) => (false, start),
        None => return None,
    };

    let mut scan = digit_start;
    if is_hex {
        while scan < bytes.len() && bytes[scan].is_ascii_hexdigit() {
            scan += 1;
        }
    } else {
        while scan < bytes.len() && bytes[scan].is_ascii_digit() {
            scan += 1;
        }
    }

    if scan == digit_start || bytes.get(scan) != Some(&b';') {
        return None;
    }

    let digits = &bytes[digit_start..scan];
    let code = match digits.iter().position(|&b| b != b'0') {
        None => 0u32,
        Some(sig_idx) => {
            let sig = std::str::from_utf8(&digits[sig_idx..]).ok()?;
            if is_hex {
                if sig.len() > 6 {
                    return None;
                }
                u32::from_str_radix(sig, 16).ok()?
            } else {
                if sig.len() > 7 {
                    return None;
                }
                sig.parse::<u32>().ok()?
            }
        }
    };

    let ch = decode_numeric_char(code)?;
    Some((ch, scan + 1))
}

fn resolve_named_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some('\u{00A0}'),
        "ndash" => Some('\u{2013}'),
        "mdash" => Some('\u{2014}'),
        "lsquo" => Some('\u{2018}'),
        "rsquo" => Some('\u{2019}'),
        "ldquo" => Some('\u{201C}'),
        "rdquo" => Some('\u{201D}'),
        "bull" => Some('\u{2022}'),
        "hellip" => Some('\u{2026}'),
        "copy" => Some('\u{00A9}'),
        "reg" => Some('\u{00AE}'),
        "trade" => Some('\u{2122}'),
        "euro" => Some('\u{20AC}'),
        "pound" => Some('\u{00A3}'),
        "yen" => Some('\u{00A5}'),
        "cent" => Some('\u{00A2}'),
        "sect" => Some('\u{00A7}'),
        "deg" => Some('\u{00B0}'),
        "plusmn" => Some('\u{00B1}'),
        "times" => Some('\u{00D7}'),
        "divide" => Some('\u{00F7}'),
        "laquo" => Some('\u{00AB}'),
        "raquo" => Some('\u{00BB}'),
        "middot" => Some('\u{00B7}'),
        "rarr" => Some('\u{2192}'),
        "larr" => Some('\u{2190}'),
        "uarr" => Some('\u{2191}'),
        "darr" => Some('\u{2193}'),
        "check" => Some('\u{2713}'),
        _ => None,
    }
}

fn decode_numeric_char(code: u32) -> Option<char> {
    if code == 0 {
        return Some(char::REPLACEMENT_CHARACTER);
    }
    if (0x80..=0x9F).contains(&code) {
        let decoded = decode_windows_1252(&[code as u8]);
        return decoded.chars().next();
    }
    char::from_u32(code)
}

/// Primary `TableProvider` for `HTMLAsText`.
pub struct HtmlAsTextProvider {
    items: Vec<(String, HtmlAsTextOutput)>,
}

impl HtmlAsTextProvider {
    pub fn from_bytes(source_path: impl Into<String>, bytes: &[u8], opts: &HtmlAsTextOptions) -> Self {
        let out = html_to_text(bytes, opts);
        Self {
            items: vec![(source_path.into(), out)],
        }
    }

    pub fn from_paths(paths: &[PathBuf], opts: &HtmlAsTextOptions) -> Result<Self, DataError> {
        let mut items = Vec::with_capacity(paths.len());
        for p in paths {
            let bytes = std::fs::read(p)?;
            items.push((p.to_string_lossy().into_owned(), html_to_text(&bytes, opts)));
        }
        Ok(Self { items })
    }

    pub fn outputs(&self) -> &[(String, HtmlAsTextOutput)] {
        &self.items
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "fs2rust.data.html_as_text",
            "HTMLAsText — HTML Text & Structure Extractor",
            vec![
                ColumnDef::new("source_path", "Source Path", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("links_count", "Links", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("word_count", "Words", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("extracted_text", "Extracted Text", ColumnType::Text).with_width_hint(420),
            ],
        )
    }
}

impl TableProvider for HtmlAsTextProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.html_as_text"
    }

    fn description(&self) -> &'static str {
        "Pure-Rust HTML-to-text extractor preserving headings, lists, tables, preformatted blocks, and link footnotes"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let rows: Vec<Row> = self
            .items
            .iter()
            .enumerate()
            .map(|(idx, (src, out))| {
                let detail = json!({
                    "links": out.links,
                    "blocks": out.blocks,
                });
                Row::new(
                    idx as u64,
                    vec![
                        CellValue::Text(src.clone()),
                        CellValue::Text(out.title.clone()),
                        CellValue::Uint(out.links.len() as u64),
                        CellValue::Uint(out.word_count as u64),
                        CellValue::Text(out.text.clone()),
                    ],
                )
                .with_detail_json(detail)
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}

/// Companion `TableProvider` exposing extracted hyperlinks as individual rows.
pub struct HtmlLinksProvider {
    items: Vec<(String, HtmlAsTextOutput)>,
}

impl HtmlLinksProvider {
    pub fn from_bytes(source_path: impl Into<String>, bytes: &[u8], opts: &HtmlAsTextOptions) -> Self {
        Self {
            items: vec![(source_path.into(), html_to_text(bytes, opts))],
        }
    }

    pub fn schema_def() -> TableSchema {
        TableSchema::new(
            "fs2rust.data.html_links",
            "HTMLAsText — Extracted Links",
            vec![
                ColumnDef::new("source_path", "Source Path", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("index", "Index", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("link_text", "Link Text", ColumnType::Text).with_width_hint(200),
                ColumnDef::new("href", "Href", ColumnType::Text).with_width_hint(300),
            ],
        )
    }
}

impl TableProvider for HtmlLinksProvider {
    fn tool_id(&self) -> &'static str {
        "fs2rust.data.html_links"
    }

    fn description(&self) -> &'static str {
        "Extracted hyperlink footnotes from HTML documents"
    }

    fn schema(&self) -> TableSchema {
        Self::schema_def()
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let mut rows = Vec::new();
        for (src, out) in &self.items {
            for link in &out.links {
                let id = rows.len() as u64;
                rows.push(Row::new(
                    id,
                    vec![
                        CellValue::Text(src.clone()),
                        CellValue::Uint(link.index as u64),
                        CellValue::Text(link.text.clone()),
                        CellValue::Text(link.href.clone()),
                    ],
                ));
            }
        }
        apply_query(&self.schema(), &rows, req)
    }
}
