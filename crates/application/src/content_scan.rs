//! The upload scan (`scan_uploaded_files`, `render_scan_results`, the default malware engine handle). The
//! hash database itself is crate `wafio-malware`; `deps::engine` re-exports these items.

use std::collections::BTreeSet;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use wafio_bytetext::strings::{eq_ignore_case, trim_whitespace};
use wafio_domain::json_text::append_quoted_string;
use wafio_domain::multipart::{MultipartParser, ReadError, first_header_value, split_media_type};
use wafio_engine_rules::{ContentScanConfig, content_scan_reason_label};
pub use wafio_malware::{HashMatcher, SnapshotStatus, Timestamp};

/// The default malware engine with no extra paths: the process-wide database every executor shares (builtin
/// EICAR signature plus the first existing local malware corpus). Set `AnalyzeConfig.malware_hash_engine`
/// to this for every app: `AnalyzeConfig { malware_hash_engine: Some(default_malware_engine()), .. }`.
pub fn default_malware_engine() -> Arc<HashMatcher> {
    wafio_malware::default_engine(&[])
}

/// The scan result of one file (attacker-controlled labels as byte strings).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileScanResult {
    pub database: Option<SnapshotStatus>,
    pub status: String,
    pub reason: String,
    pub source: String,
    pub field_name: Vec<u8>,
    pub filename: Vec<u8>,
    pub size: i64,
    pub content_type: Vec<u8>,
    pub sha256: [u8; 32],
    pub sha256_hex: String,
    pub is_malware: bool,
    pub threat_name: Vec<u8>,
}

fn incomplete(status: &str, reason: &str) -> (Vec<FileScanResult>, Option<FileScanResult>) {
    (
        vec![FileScanResult {
            status: status.into(),
            reason: reason.into(),
            ..Default::default()
        }],
        None,
    )
}

/// Hashes complete objects only; no match is not a safety verdict.
pub fn scan_uploaded_files(
    content_type: &[u8],
    body: &[u8],
    cfg: &ContentScanConfig,
    database: Option<&HashMatcher>,
) -> (Vec<FileScanResult>, Option<FileScanResult>) {
    if !cfg.enabled || cfg.mode == "disabled" || (!cfg.scan_multipart && !cfg.scan_raw_body) {
        return (Vec::new(), None);
    }
    if body.is_empty() && content_type.is_empty() {
        return (Vec::new(), None);
    }
    let Some(database) = database else {
        return incomplete("not_scanned", "database_unavailable");
    };
    let max_size = if cfg.max_scan_size_bytes <= 0 {
        10 * 1024 * 1024
    } else {
        cfg.max_scan_size_bytes
    };
    let Some((media_type, params)) = split_media_type(content_type) else {
        return incomplete("error", "invalid_content_type");
    };
    if media_type.starts_with(b"multipart/") {
        if !cfg.scan_multipart {
            return (Vec::new(), None);
        }
        let boundary = params
            .get(&b"boundary"[..])
            .map(Vec::as_slice)
            .unwrap_or_default();
        if boundary.is_empty() {
            return incomplete("error", "missing_boundary");
        }
        return scan_form_upload_parts(boundary, body, max_size, cfg, database);
    }
    if !cfg.scan_raw_body {
        return (Vec::new(), None);
    }
    let mut file = FileScanResult {
        field_name: b"raw_body".to_vec(),
        filename: b"raw_payload".to_vec(),
        size: body.len() as i64,
        content_type: media_type,
        ..Default::default()
    };
    if body.len() as i64 > max_size {
        (file.status, file.reason) = ("not_scanned".into(), "size_limit".into());
    } else {
        file.sha256 = Sha256::digest(body).into();
        lookup_content_hash(&mut file, cfg, database);
    }
    let matched = file.is_malware.then(|| file.clone());
    (vec![file], matched)
}

/// Bytes copied and the first non-EOF read error. `chunk` is the read size (32 KiB scratch when hashing, 8
/// KiB otherwise), which decides whether a read error arrives with the last bytes.
fn copy_part(
    mr: &mut MultipartParser<'_>,
    limit: i64,
    chunk: usize,
    mut hasher: Option<&mut Sha256>,
) -> (i64, bool) {
    let mut buf = vec![0u8; chunk];
    let mut left = limit;
    let mut written = 0i64;
    loop {
        if left <= 0 {
            return (written, false);
        }
        let want = chunk.min(usize::try_from(left).unwrap_or(usize::MAX));
        let (n, err) = mr.part_read(&mut buf[..want]);
        left -= n as i64;
        written += n as i64;
        if let Some(h) = hasher.as_deref_mut() {
            h.update(&buf[..n]);
        }
        match err {
            None => {}
            Some(ReadError::Eof) => return (written, false),
            Some(_) => return (written, true),
        }
    }
}

fn scan_form_upload_parts(
    boundary: &[u8],
    body: &[u8],
    max_size: i64,
    cfg: &ContentScanConfig,
    database: &HashMatcher,
) -> (Vec<FileScanResult>, Option<FileScanResult>) {
    let mut mr = MultipartParser::new(body, boundary);
    let mut scanned: Vec<FileScanResult> = Vec::new();
    // Bound parsing work as well as hashing, including non-file fields.
    let mut remaining = max_size;
    let mut parts = 0;
    loop {
        // NextRawPart: a quoted-printable part keeps its header and is reported unsupported.
        let mut part = match mr.next_undecoded_part() {
            Ok(p) => p,
            Err(ReadError::Eof) => break,
            Err(_) => {
                scanned.push(FileScanResult {
                    status: "error".into(),
                    reason: "malformed_multipart".into(),
                    ..Default::default()
                });
                return (scanned, None);
            }
        };
        if parts >= 128 {
            scanned.push(FileScanResult {
                status: "not_scanned".into(),
                reason: "part_limit".into(),
                ..Default::default()
            });
            return (scanned, None);
        }
        parts += 1;
        let mut file = FileScanResult {
            field_name: content_scan_reason_label(&part.form_field_name()).to_vec(),
            filename: content_scan_reason_label(&part.client_file_name()).to_vec(),
            content_type: content_scan_reason_label(first_header_value(
                &part.header,
                b"Content-Type",
            ))
            .to_vec(),
            ..Default::default()
        };
        if !first_header_value(&part.header, b"Content-Transfer-Encoding").is_empty() {
            (file.status, file.reason) =
                ("not_scanned".into(), "unsupported_transfer_encoding".into());
            scanned.push(file);
            return (scanned, None);
        }
        let is_file = !file.filename.is_empty() || !file.content_type.is_empty();
        let mut hasher = Sha256::new();
        let (written, read_err) = if is_file {
            copy_part(&mut mr, remaining + 1, 32 * 1024, Some(&mut hasher))
        } else {
            copy_part(&mut mr, remaining + 1, 8 * 1024, None)
        };
        file.size = written;
        if read_err {
            (file.status, file.reason) = ("error".into(), "incomplete_part".into());
            scanned.push(file);
            return (scanned, None);
        }
        if written > remaining {
            (file.status, file.reason) = ("not_scanned".into(), "size_limit".into());
            scanned.push(file);
            return (scanned, None);
        }
        remaining -= written;
        if !is_file {
            continue;
        }
        file.sha256 = hasher.finalize().into();
        lookup_content_hash(&mut file, cfg, database);
        let malware = file.is_malware;
        scanned.push(file);
        if malware {
            let m = scanned.last().cloned();
            return (scanned, m);
        }
    }
    (scanned, None)
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The string list is used only when the compiled set is empty (config not prepared); a prepared set is
/// never empty while its strings are not.
fn hash_is_listed(
    sum: &[u8; 32],
    encoded: &str,
    compiled: &BTreeSet<[u8; 32]>,
    hashes: &[String],
) -> bool {
    if !compiled.is_empty() || hashes.is_empty() {
        return compiled.contains(sum);
    }
    hashes
        .iter()
        .any(|h| eq_ignore_case(trim_whitespace(h.as_bytes()), encoded.as_bytes()))
}

fn lookup_content_hash(file: &mut FileScanResult, cfg: &ContentScanConfig, database: &HashMatcher) {
    file.sha256_hex = hex_lower(&file.sha256);
    file.status = "no_match".into();
    // Project exceptions never mutate the shared threat database.
    if hash_is_listed(
        &file.sha256,
        &file.sha256_hex,
        &cfg.allow_hashes,
        &cfg.custom_allowlist_hashes,
    ) {
        file.status = "allowlisted".into();
        return;
    }
    if hash_is_listed(
        &file.sha256,
        &file.sha256_hex,
        &cfg.block_hashes,
        &cfg.custom_blocklist_hashes,
    ) {
        (file.is_malware, file.threat_name, file.source) =
            (true, b"Custom.Project.Blocklist".to_vec(), "project".into());
    } else {
        let (m, name, status) = database.lookup(&file.sha256);
        (
            file.is_malware,
            file.threat_name,
            file.source,
            file.database,
        ) = (m, name, "database".into(), Some(status));
    }
    if file.is_malware {
        file.status = "match".into();
    }
}

/// The files as a JSON array, fields in struct order with their omitempty rules; None
/// where encoding fails (a database timestamp RFC 3339 cannot carry).
fn encode_scanned_files_json(files: &[FileScanResult]) -> Option<Vec<u8>> {
    let mut o = Vec::new();
    let s = |o: &mut Vec<u8>, key: &str, v: &[u8]| {
        o.extend_from_slice(format!(",\"{key}\":").as_bytes());
        append_quoted_string(o, v);
    };
    o.push(b'[');
    for (i, f) in files.iter().enumerate() {
        if i > 0 {
            o.push(b',');
        }
        o.push(b'{');
        if let Some(d) = &f.database {
            o.extend_from_slice(b"\"database\":{");
            if !d.version.is_empty() {
                o.extend_from_slice(b"\"version\":");
                append_quoted_string(&mut o, d.version.as_bytes());
                o.push(b',');
            }
            if !d.source.is_empty() {
                o.extend_from_slice(b"\"source\":");
                append_quoted_string(&mut o, d.source.as_bytes());
                o.push(b',');
            }
            o.extend_from_slice(
                format!(
                    r#""updated_at":"{}","items":{},"stale":{},"degraded":{}}},"#,
                    d.updated_at.to_json().ok()?,
                    d.items,
                    d.stale,
                    d.degraded
                )
                .as_bytes(),
            );
        }
        o.extend_from_slice(b"\"status\":");
        append_quoted_string(&mut o, f.status.as_bytes());
        for (key, v) in [
            ("reason", f.reason.as_bytes()),
            ("source", f.source.as_bytes()),
            ("field", &f.field_name),
            ("filename", &f.filename),
        ] {
            if !v.is_empty() {
                s(&mut o, key, v);
            }
        }
        o.extend_from_slice(format!(",\"bytes_read\":{}", f.size).as_bytes());
        for (key, v) in [
            ("content_type", &f.content_type[..]),
            ("sha256", f.sha256_hex.as_bytes()),
        ] {
            if !v.is_empty() {
                s(&mut o, key, v);
            }
        }
        if f.is_malware {
            o.extend_from_slice(b",\"matched\":true");
        }
        if !f.threat_name.is_empty() {
            s(&mut o, "signature", &f.threat_name);
        }
        o.push(b'}');
    }
    o.push(b']');
    Some(o)
}

pub fn render_scan_results(files: &[FileScanResult]) -> Vec<u8> {
    let mut out = b"content_scan:".to_vec();
    if files.is_empty() {
        out.extend_from_slice(b"null"); // no files encode as null
    } else {
        // An encoding error is ignored: the detail is then just the prefix.
        out.extend_from_slice(&encode_scanned_files_json(files).unwrap_or_default());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wafio_engine_rules::standard_content_scan_config;

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const B: &str = "b0undary";

    fn sum(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    /// A multipart body with one file part per `(field, filename, data)`, as (content type, body).
    fn multipart(parts: &[(&str, &str, &[u8])]) -> (Vec<u8>, Vec<u8>) {
        let mut body = Vec::new();
        for (i, (field, filename, data)) in parts.iter().enumerate() {
            let sep = if i == 0 { "" } else { "\r\n" };
            body.extend_from_slice(
                format!("{sep}--{B}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n")
                    .as_bytes(),
            );
            body.extend_from_slice(data);
        }
        body.extend_from_slice(format!("\r\n--{B}--\r\n").as_bytes());
        (
            format!("multipart/form-data; boundary={B}").into_bytes(),
            body,
        )
    }

    fn engine(payload: &[u8], name: &str) -> HashMatcher {
        let e = HashMatcher::new(10, 0.01);
        e.insert_hash(sum(payload), name.as_bytes());
        e
    }

    // TestExtractAndScanUploads_MultipartCleanAndMalware
    #[test]
    fn multipart_clean_and_malware() {
        let e = engine(EICAR, "EICAR.Standard.Test");
        let cfg = standard_content_scan_config();
        let (ct, body) = multipart(&[(
            "avatar",
            "profile.jpg",
            b"fake image header JPEG\xFF\xD8\xFF\xE0 and clean content",
        )]);
        let (files, m) = scan_uploaded_files(&ct, &body, &cfg, Some(&e));
        assert!(m.is_none());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, b"profile.jpg");
        assert_eq!(files[0].status, "no_match");

        let (ct, body) = multipart(&[
            ("doc", "notes.txt", b"clean notes content"),
            ("attachment", "eicar.com", EICAR),
        ]);
        let (files, m) = scan_uploaded_files(&ct, &body, &cfg, Some(&e));
        let m = m.expect("malware");
        assert_eq!(
            (m.threat_name.as_slice(), m.filename.as_slice(), m.size),
            (&b"EICAR.Standard.Test"[..], &b"eicar.com"[..], 68)
        );
        assert_eq!(files.len(), 2);
    }

    // TestExtractAndScanUploads_RawBinary + TestContentScanRawDoesNotTrustMIME
    #[test]
    fn raw_binary() {
        let e = engine(b"malicious-binary-payload-test", "Trojan.Linux.Generic");
        let mut cfg = standard_content_scan_config();
        cfg.scan_raw_body = true;
        let (files, m) = scan_uploaded_files(
            b"application/octet-stream",
            b"innocent binary bytes",
            &cfg,
            Some(&e),
        );
        assert!(m.is_none() && files.len() == 1);
        for ct in [
            "text/plain",
            "application/json",
            "image/png",
            "application/octet-stream",
        ] {
            let (_, m) = scan_uploaded_files(
                ct.as_bytes(),
                b"malicious-binary-payload-test",
                &cfg,
                Some(&e),
            );
            assert_eq!(m.expect(ct).threat_name, b"Trojan.Linux.Generic");
        }
    }

    // TestContentScanContracts
    #[test]
    fn contracts() {
        let payload = b"known-hash-fixture";
        let hex = hex_lower(&sum(payload));
        let e = engine(payload, "fixture");
        let mut cfg = standard_content_scan_config();
        cfg.scan_multipart = false;
        let (ct, body) = multipart(&[("file", "fixture.bin", payload)]);
        assert_eq!(
            scan_uploaded_files(&ct, &body, &cfg, Some(&e)),
            (Vec::new(), None)
        );

        let mut cfg = standard_content_scan_config();
        cfg.scan_raw_body = true;
        cfg.custom_allowlist_hashes = vec![hex.to_uppercase()];
        let (files, m) = scan_uploaded_files(b"application/octet-stream", payload, &cfg, Some(&e));
        assert!(m.is_none());
        assert_eq!(files[0].status, "allowlisted");
        cfg.prepare().unwrap();
        assert!(
            scan_uploaded_files(b"application/octet-stream", payload, &cfg, Some(&e))
                .1
                .is_none()
        );

        let mut cfg = standard_content_scan_config();
        cfg.scan_raw_body = true;
        cfg.custom_blocklist_hashes = vec![hex.clone()];
        cfg.prepare().unwrap();
        let m = scan_uploaded_files(
            b"application/octet-stream",
            payload,
            &cfg,
            Some(&HashMatcher::new(10, 0.01)),
        )
        .1;
        assert_eq!(
            m.expect("blocklist").threat_name,
            b"Custom.Project.Blocklist"
        );

        for multipart_body in [false, true] {
            let mut cfg = standard_content_scan_config();
            cfg.scan_raw_body = true;
            cfg.max_scan_size_bytes = payload.len() as i64;
            let mut body = payload.to_vec();
            body.extend_from_slice(b"-different-complete-file");
            let (ct, body) = if multipart_body {
                multipart(&[("file", "fixture.bin", &body)])
            } else {
                (b"application/octet-stream".to_vec(), body)
            };
            assert!(scan_uploaded_files(&ct, &body, &cfg, Some(&e)).1.is_none());
        }
    }

    // TestContentScanIncompleteNeverHasDigest
    #[test]
    fn incomplete_never_has_digest() {
        let e = HashMatcher::new(10, 0.01);
        let mut cfg = standard_content_scan_config();
        cfg.scan_raw_body = true;
        cfg.max_scan_size_bytes = 4;
        for (ct, body, status, reason) in [
            (
                "application/octet-stream",
                "12345",
                "not_scanned",
                "size_limit",
            ),
            ("multipart/form-data", "broken", "error", "missing_boundary"),
            (
                "invalid content type",
                "hello",
                "error",
                "invalid_content_type",
            ),
        ] {
            let (files, m) = scan_uploaded_files(ct.as_bytes(), body.as_bytes(), &cfg, Some(&e));
            assert!(m.is_none() && files.len() == 1);
            assert_eq!(
                (
                    files[0].status.as_str(),
                    files[0].reason.as_str(),
                    files[0].sha256_hex.as_str()
                ),
                (status, reason, "")
            );
        }
        // No database: incomplete before any parsing (the review's fail-open case).
        let (ct, body) = multipart(&[("file", "a.bin", b"x")]);
        let (files, _) = scan_uploaded_files(&ct, &body, &standard_content_scan_config(), None);
        assert_eq!(
            (files[0].status.as_str(), files[0].reason.as_str()),
            ("not_scanned", "database_unavailable")
        );
    }

    // TestContentScanMultipartBounds
    #[test]
    fn multipart_bounds() {
        let e = HashMatcher::new(10, 0.01);
        for (parts, size, budget, want) in [
            (1, 16, 16, "no_match"),
            (1, 17, 16, "not_scanned"),
            (2, 9, 16, "not_scanned"),
            (129, 1, 1024, "not_scanned"),
        ] {
            let data = vec![b'x'; size];
            let list: Vec<(&str, &str, &[u8])> = (0..parts)
                .map(|_| ("file", "file.bin", &data[..]))
                .collect();
            let (ct, body) = multipart(&list);
            let mut cfg = standard_content_scan_config();
            cfg.max_scan_size_bytes = budget;
            let (files, m) = scan_uploaded_files(&ct, &body, &cfg, Some(&e));
            let last = files.last().expect("files");
            assert!(m.is_none() && last.status == want, "{files:?}");
            if want == "not_scanned" {
                assert_eq!(last.sha256_hex, "");
            }
        }
    }

    // TestContentScanBoundsMetadata
    #[test]
    fn bounds_metadata() {
        let field = "f".repeat(1000);
        let filename = format!("{}.bin", "x".repeat(1000));
        let (ct, body) = multipart(&[(&field, &filename, b"ok")]);
        let (files, _) = scan_uploaded_files(
            &ct,
            &body,
            &standard_content_scan_config(),
            Some(&HashMatcher::new(10, 0.01)),
        );
        assert!(
            files.len() == 1 && files[0].filename.len() == 256 && files[0].field_name.len() == 256
        );
    }

    #[test]
    fn transfer_encoding_and_malformed() {
        let e = HashMatcher::new(10, 0.01);
        let cfg = standard_content_scan_config();
        let ct = format!("multipart/form-data; boundary={B}").into_bytes();
        let body = format!(
            "--{B}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\"\r\nContent-Transfer-Encoding: base64\r\n\r\neA==\r\n--{B}--\r\n"
        );
        let (files, _) = scan_uploaded_files(&ct, body.as_bytes(), &cfg, Some(&e));
        assert_eq!(
            (files[0].reason.as_str(), files[0].size),
            ("unsupported_transfer_encoding", 0)
        );
        let body =
            format!("--{B}\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nvalue-without-end");
        let (files, _) = scan_uploaded_files(&ct, body.as_bytes(), &cfg, Some(&e));
        let last = files.last().unwrap();
        assert_eq!(
            (last.reason.as_str(), last.field_name.as_slice(), last.size),
            ("incomplete_part", &b"f"[..], 17)
        );
    }

    // NextRawPart: a quoted-printable part is not decoded, it is reported like any other
    // transfer encoding (the part is never hashed).
    #[test]
    fn quoted_printable_part_is_unsupported() {
        let e = engine(b"qp-payload", "fixture");
        let cfg = standard_content_scan_config();
        let ct = format!("multipart/form-data; boundary={B}").into_bytes();
        for cte in ["quoted-printable", "Quoted-Printable", "base64", "7bit"] {
            let body = format!(
                "--{B}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\r\nContent-Transfer-Encoding: {cte}\r\n\r\nqp-payload\r\n--{B}--\r\n"
            );
            let (files, m) = scan_uploaded_files(&ct, body.as_bytes(), &cfg, Some(&e));
            assert!(m.is_none() && files.len() == 1, "{cte}: {files:?}");
            assert_eq!(
                (
                    files[0].status.as_str(),
                    files[0].reason.as_str(),
                    files[0].size
                ),
                ("not_scanned", "unsupported_transfer_encoding", 0),
                "{cte}"
            );
            assert_eq!(
                (files[0].filename.as_slice(), files[0].sha256_hex.as_str()),
                (&b"a.bin"[..], ""),
                "{cte}"
            );
        }
    }

    // Encoding fails for a snapshot timestamp with a zone hour of 24 or more; the error is dropped.
    #[test]
    fn unmarshalable_database_timestamp_empties_the_detail() {
        let e = HashMatcher::new(10, 0.01);
        let text = format!(
            "# Updated: 2020-01-02T10:00:00+24:00\n{} fixture\n",
            "11".repeat(32)
        );
        e.replace_with_text(&mut text.as_bytes(), "fixture", Timestamp::ZERO)
            .unwrap();
        let (ct, body) = multipart(&[("f", "a.bin", b"clean")]);
        let (files, _) = scan_uploaded_files(&ct, &body, &standard_content_scan_config(), Some(&e));
        assert_eq!(files[0].status, "no_match");
        assert_eq!(render_scan_results(&files), b"content_scan:");
        // a database loaded with an ordinary offset keeps it in the detail
        let text = format!(
            "# Updated: 2020-01-02T10:00:00.5+07:00\n{} fixture\n",
            "11".repeat(32)
        );
        e.replace_with_text(&mut text.as_bytes(), "fixture", Timestamp::ZERO)
            .unwrap();
        let (files, _) = scan_uploaded_files(&ct, &body, &standard_content_scan_config(), Some(&e));
        let got = String::from_utf8(render_scan_results(&files)).unwrap();
        assert!(got.contains(r#""source":"fixture","updated_at":"2020-01-02T10:00:00.5+07:00","items":1,"stale":true,"degraded":false}"#), "{got}");
    }

    #[test]
    fn render_matches_recorded_json() {
        let e = engine(EICAR, "EICAR.Standard.Test");
        let (ct, body) = multipart(&[("a<b", "e\u{2028}.com", EICAR)]);
        let (files, _) = scan_uploaded_files(&ct, &body, &standard_content_scan_config(), Some(&e));
        let got = String::from_utf8(render_scan_results(&files)).unwrap();
        let want = [
            r#"content_scan:[{"database":{"updated_at":"0001-01-01T00:00:00Z","items":1,"stale":true,"degraded":false},"#,
            r#""status":"match","source":"database","field":"a\u003cb","filename":"e\u2028.com","bytes_read":68,"#,
            r#""content_type":"application/octet-stream","sha256":""#,
            &hex_lower(&sum(EICAR)),
            r#"","matched":true,"signature":"EICAR.Standard.Test"}]"#,
        ]
        .concat();
        assert_eq!(got, want);
        assert_eq!(
            render_scan_results(&[FileScanResult { status: "not_scanned".into(), reason: "database_unavailable".into(), ..Default::default() }]),
            br#"content_scan:[{"status":"not_scanned","reason":"database_unavailable","bytes_read":0}]"#
        );
    }
}
