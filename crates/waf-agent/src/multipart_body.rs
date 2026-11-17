//! Multipart body parsing, installed at start into
//! engine-rules' `MULTIPART_PARSE_HOOK` hook (custom rules reading a multipart body; without
//! it such a request panics and fails open). Uses the domain crate's multipart parser.

use wafio_domain::multipart::{
    BodyPart, MultipartParser, ReadError, first_header_value, split_media_type,
};
use wafio_engine_rules::{
    FILE_PREVIEW_LIMIT_BYTES, MULTIPART_PART_LIMIT, MultipartPart, PART_VALUE_LIMIT_BYTES,
    ParsedBody, collect_multipart_part_names,
};

/// Reads a part's content, at most `limit` bytes.
fn read_limited(r: &mut MultipartParser<'_>, limit: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while out.len() < limit {
        let want = (limit - out.len()).min(buf.len());
        let (n, err) = r.part_read(&mut buf[..want]);
        out.extend_from_slice(&buf[..n]);
        if err.is_some() || n == 0 {
            break;
        }
    }
    out
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Duplicate field values are comma-joined.
fn append_map_entry(m: &mut std::collections::BTreeMap<String, String>, key: &str, value: &str) {
    match m.get_mut(key) {
        Some(prev) if !prev.is_empty() => {
            prev.push(',');
            prev.push_str(value);
        }
        _ => {
            m.insert(key.to_string(), value.to_string());
        }
    }
}

/// `parseMultipartBody(fullContentType, raw, p)`.
pub fn extract_multipart_fields(full_content_type: &[u8], raw: &[u8], p: &mut ParsedBody) {
    let boundary = match split_media_type(full_content_type) {
        Some((_, params)) => params.get(&b"boundary"[..]).cloned().unwrap_or_default(),
        None => Vec::new(),
    };
    if boundary.is_empty() {
        p.parse_error = "multipart boundary missing".into();
        return;
    }
    let mut reader = MultipartParser::new(raw, &boundary);
    p.multipart.clear();
    p.multipart_filenames.clear();
    p.multipart_content_types.clear();
    for _ in 0..MULTIPART_PART_LIMIT {
        let mut part: BodyPart = match reader.next_decoded_part() {
            Ok(part) => part,
            Err(ReadError::Eof) => break,
            Err(_) => {
                p.parse_error = "malformed multipart body".into();
                return;
            }
        };
        let cds: Vec<Vec<u8>> = part
            .header
            .get(&b"Content-Disposition"[..])
            .cloned()
            .unwrap_or_default();
        let names = collect_multipart_part_names(&part.form_field_name(), &cds);
        let Some(name) = names.last().map(|n| s(n)) else {
            reader.part_close();
            continue;
        };
        let content_type = first_header_value(&part.header, b"Content-Type").to_vec();
        let filename = part.client_file_name();
        p.multipart_content_types
            .insert(name.clone(), s(&content_type));
        let value = if !filename.is_empty() {
            p.files_count += 1;
            p.multipart_filenames.insert(name.clone(), s(&filename));
            read_limited(&mut reader, FILE_PREVIEW_LIMIT_BYTES)
        } else {
            read_limited(&mut reader, PART_VALUE_LIMIT_BYTES)
        };
        append_map_entry(&mut p.multipart, &name, &s(&value));
        p.multipart_parts.push(MultipartPart {
            names,
            value,
            filename,
            content_type,
        });
        reader.part_close();
    }
}

/// Installs the hooks engine-rules expects from the agent wiring.
pub fn install_engine_hooks() {
    let _ = wafio_engine_rules::MULTIPART_PARSE_HOOK.set(extract_multipart_fields);
    let _ =
        wafio_engine_rules::TRANSFORMS_HOOK.set(wafio_bytetext::transforms::apply_known_transforms);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_and_files_into_map_entries() {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n2\r\n--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"/x/shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php\r\n--b--\r\n";
        let mut p = ParsedBody::default();
        extract_multipart_fields(b"multipart/form-data; boundary=b", body, &mut p);
        assert_eq!(p.parse_error, "");
        assert_eq!(p.multipart["a"], "1,2");
        assert_eq!(p.multipart_filenames["f"], "shell.php");
        assert_eq!(p.multipart_content_types["f"], "application/x-php");
        assert_eq!(p.files_count, 1);
        assert_eq!(p.multipart_parts.len(), 3);
        let mut q = ParsedBody::default();
        extract_multipart_fields(b"multipart/form-data", body, &mut q);
        assert_eq!(q.parse_error, "multipart boundary missing");
    }
}
