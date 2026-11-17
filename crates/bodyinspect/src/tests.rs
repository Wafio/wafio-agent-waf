//! Tests for body inspection, the decode budget and brotli decoding. Fixtures come from
//! flate2/brotli encoders (the decoders must accept any conforming stream).

use std::io::Write;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};

use super::budget::{ByteBudget, parse_budget_env, parse_size_with_suffix, shared_budget};
use super::decode::{
    brotli_window_bits_for, fit_layer_budget, rewrite_brotli_window_header, worst_case_reservation,
};
use super::*;

/// Tests that change the process-wide budget run one at a time.
static BUDGET_LOCK: Mutex<()> = Mutex::new(());

struct BudgetGuard {
    prev: i64,
    _g: MutexGuard<'static, ()>,
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        set_inflight_decode_bytes(self.prev);
    }
}

fn with_decode_budget(n: i64) -> BudgetGuard {
    let g = BUDGET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev = inflight_decode_bytes_limit();
    set_inflight_decode_bytes(n);
    BudgetGuard { prev, _g: g }
}

/// Takes the lock and leaves the limit as it is. The limit is read under the lock: read before it, the value
/// could be the one another test had set for itself and has put back since.
fn lock_budget() -> BudgetGuard {
    let g = BUDGET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    BudgetGuard {
        prev: inflight_decode_bytes_limit(),
        _g: g,
    }
}

struct Hold(i64);

impl Drop for Hold {
    fn drop(&mut self) {
        shared_budget().release(self.0);
    }
}

fn hold_budget(n: i64) -> Hold {
    assert!(
        shared_budget().try_acquire(n),
        "could not reserve {n} bytes"
    );
    Hold(n)
}

fn benign_json_body() -> Vec<u8> {
    br#"{"name":"alice","city":"Bandung","items":[1,2,3],"note":"see you tomorrow"}"#.to_vec()
}

/// Deterministic high-entropy bytes behind a PNG signature.
fn binary_blob(n: usize) -> Vec<u8> {
    let mut x: u64 = 42;
    let mut b: Vec<u8> = (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    let sig = b"\x89PNG\r\n\x1a\n";
    let k = sig.len().min(n);
    b[..k].copy_from_slice(&sig[..k]);
    b
}

fn gzip_bytes(p: &[u8]) -> Vec<u8> {
    let mut w = GzEncoder::new(Vec::new(), Compression::default());
    w.write_all(p).unwrap();
    w.finish().unwrap()
}

fn zlib_bytes(p: &[u8]) -> Vec<u8> {
    let mut w = ZlibEncoder::new(Vec::new(), Compression::default());
    w.write_all(p).unwrap();
    w.finish().unwrap()
}

fn raw_deflate_bytes(p: &[u8]) -> Vec<u8> {
    let mut w = DeflateEncoder::new(Vec::new(), Compression::default());
    w.write_all(p).unwrap();
    w.finish().unwrap()
}

fn brotli_bytes_window(p: &[u8], lgwin: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, lgwin);
        w.write_all(p).unwrap();
    }
    out
}

fn brotli_bytes(p: &[u8]) -> Vec<u8> {
    brotli_bytes_window(p, 22)
}

fn hdrs(pairs: &[(&str, &str)]) -> Headers {
    let mut h = Headers::new();
    for (k, v) in pairs {
        h.entry(k.as_bytes().to_vec())
            .or_default()
            .push(v.as_bytes().to_vec());
    }
    h
}

fn dec(body: &[u8], codings: &[&str], limit: i64) -> (Option<Vec<u8>>, String) {
    let (out, skipped) = decode(body, codings, limit);
    (out.map(|c| c.into_owned()), skipped)
}

#[test]
fn sniff_text_table() {
    let mut large = br#"{"k":""#.to_vec();
    large.extend(vec![b'a'; SNIFF_WINDOW_BYTES]);
    large.extend(binary_blob(4096));
    let cat = |a: &[u8], b: Vec<u8>| [a.to_vec(), b].concat();
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("json object", benign_json_body(), "json"),
        (
            "json array after whitespace",
            b" \r\n\t[1,2,3]".to_vec(),
            "json",
        ),
        (
            "json after utf8 bom",
            cat(b"\xef\xbb\xbf", benign_json_body()),
            "json",
        ),
        (
            "json with non-ascii text",
            r#"{"kota":"Bandung – Jawa Barat","catatan":"日本語のテキストです","emoji":"🙂🙂🙂"}"#
                .as_bytes()
                .to_vec(),
            "json",
        ),
        (
            "form pairs",
            b"name=alice&city=paris&remember=1".to_vec(),
            "form",
        ),
        ("single form pair", b"a=1".to_vec(), "form"),
        (
            "form with raw spaces",
            b"note=see you tomorrow&x=1".to_vec(),
            "form",
        ),
        ("large text head", large, "json"),
        (
            "semicolon separated pair",
            b"some words here;lang=en".to_vec(),
            "form",
        ),
        (
            "pair after spaced junk",
            b"some words & lang=en".to_vec(),
            "form",
        ),
        ("newline inside key", b"title\nlang=en".to_vec(), ""),
        (
            "prose with equals",
            b"the total for this invoice = 42 dollars".to_vec(),
            "",
        ),
        (
            "plain text",
            b"hello world, nothing structured here".to_vec(),
            "",
        ),
        ("empty key only", b"=value".to_vec(), ""),
        ("whitespace only", b" \n\t ".to_vec(), ""),
        ("empty", Vec::new(), ""),
        ("png upload", binary_blob(8192), ""),
        ("binary after brace", cat(b"{", binary_blob(8192)), ""),
        (
            "binary after form shape",
            cat(b"a=b&", binary_blob(8192)),
            "",
        ),
    ];
    for (name, body, want) in cases {
        assert_eq!(detect_text_payload(&body), want, "{name}");
    }
}

#[test]
fn is_declared_binary_content_type_table() {
    for (ct, want) in [
        ("application/octet-stream", true),
        ("image/png", true),
        ("video/mp4", true),
        ("audio/mpeg", true),
        ("font/woff2", true),
        ("application/zip", true),
        ("application/pdf", true),
        ("application/x-tar", true),
        ("application/x-gzip", true),
        ("application/json", false),
        ("multipart/form-data; boundary=x", false),
        ("text/plain", false),
        ("", false),
    ] {
        assert_eq!(declares_binary_content(ct.as_bytes()), want, "{ct}");
    }
}

#[test]
fn declared_label_table() {
    let long = format!("image/<x>\x00{}", "a".repeat(99));
    let want_long = format!("image/x{}", "a".repeat(57));
    for (ct, want) in [
        ("application/octet-stream", "binary"),
        ("application/octet-stream; charset=x", "binary"),
        ("image/png", "image/png"),
        ("image/png; name=\"a b\"", "image/png"),
        (long.as_str(), want_long.as_str()),
        ("", "unknown"),
    ] {
        assert_eq!(content_type_label(ct.as_bytes()), want, "{ct:?}");
    }
}

#[test]
fn content_codings_table() {
    let cases: Vec<(&str, Headers, Vec<&str>)> = vec![
        ("no header", Headers::new(), vec![]),
        (
            "identity only",
            hdrs(&[("Content-Encoding", "identity")]),
            vec![],
        ),
        (
            "single",
            hdrs(&[("Content-Encoding", "gzip")]),
            vec!["gzip"],
        ),
        (
            "case and list",
            hdrs(&[("content-encoding", " GZIP , identity,br ")]),
            vec!["gzip", "br"],
        ),
        (
            "repeated fields",
            hdrs(&[("Content-Encoding", "gzip"), ("Content-Encoding", "br")]),
            vec!["gzip", "br"],
        ),
        (
            "empty tokens",
            hdrs(&[("Content-Encoding", ",, ,")]),
            vec![],
        ),
        (
            "stops past cap",
            hdrs(&[("Content-Encoding", "gzip,gzip,gzip,gzip,gzip,gzip")]),
            vec!["gzip"; 4],
        ),
        // Lowercasing is Unicode: U+0130 lowers to 'i'.
        (
            "unicode lower",
            hdrs(&[("Content-Encoding", "GZ\u{130}P")]),
            vec!["gzip"],
        ),
    ];
    for (name, h, want) in cases {
        let got: Vec<String> = declared_codings(&h)
            .into_iter()
            .map(|t| String::from_utf8(t).unwrap())
            .collect();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn decoded_limit_table() {
    for (route_max, want) in [
        (0, DECODED_BODY_LIMIT_BYTES),
        (-1, DECODED_BODY_LIMIT_BYTES),
        (64 << 20, DECODED_BODY_LIMIT_BYTES),
        (1 << 20, 1 << 20),
        (4096, 4096),
    ] {
        assert_eq!(decoded_size_cap(route_max), want, "{route_max}");
    }
}

#[test]
fn decode_round_trips() {
    let _g = lock_budget();
    let plain = benign_json_body();
    let cases: Vec<(&str, Vec<u8>, Vec<&str>)> = vec![
        ("identity", plain.clone(), vec![]),
        ("gzip", gzip_bytes(&plain), vec!["gzip"]),
        ("x-gzip alias", gzip_bytes(&plain), vec!["x-gzip"]),
        ("deflate zlib-wrapped", zlib_bytes(&plain), vec!["deflate"]),
        ("deflate raw", raw_deflate_bytes(&plain), vec!["deflate"]),
        ("br", brotli_bytes(&plain), vec!["br"]),
        (
            "gzip then br",
            brotli_bytes(&gzip_bytes(&plain)),
            vec!["gzip", "br"],
        ),
        (
            "gzip multi-member",
            [gzip_bytes(&plain[..10]), gzip_bytes(&plain[10..])].concat(),
            vec!["gzip"],
        ),
    ];
    for (name, body, codings) in cases {
        let orig = body.clone();
        let (got, skipped) = dec(&body, &codings, DECODED_BODY_LIMIT_BYTES);
        assert_eq!(skipped, "", "{name}");
        assert_eq!(got.as_deref(), Some(plain.as_slice()), "{name}");
        assert_eq!(body, orig, "{name}: input modified");
        assert_eq!(
            inflight_decode_bytes_used(),
            0,
            "{name}: reservation leaked"
        );
    }
}

#[test]
fn decode_failures() {
    let _g = lock_budget();
    let plain = benign_json_body();
    let gz = gzip_bytes(&plain);
    let mut corrupt = gz.clone();
    let n = corrupt.len();
    for b in &mut corrupt[12..n - 8] {
        *b ^= 0x5a;
    }
    let mut bad_crc = gz.clone();
    bad_crc[n - 8] ^= 0xff;
    let tail = |mut v: Vec<u8>| {
        v.extend_from_slice(b"trailing");
        v
    };
    let form = b"name=alice&city=paris".to_vec();
    let cases: Vec<(&str, Vec<u8>, Vec<&str>, &str)> = vec![
        (
            "unsupported coding",
            plain.clone(),
            vec!["zstd"],
            "content_encoding:zstd",
        ),
        (
            "unsupported with junk chars",
            plain.clone(),
            vec!["x\x01<y>"],
            "content_encoding:xy",
        ),
        (
            "unsupported anywhere in stack",
            gz.clone(),
            vec!["gzip", "compress"],
            "content_encoding:compress",
        ),
        (
            "too many codings",
            plain.clone(),
            vec!["gzip", "gzip", "gzip", "gzip"],
            SKIP_REASON_DECOMPRESS_LIMIT,
        ),
        (
            "plaintext labelled gzip",
            plain.clone(),
            vec!["gzip"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "plaintext labelled br",
            form.clone(),
            vec!["br"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "plaintext labelled deflate",
            form.clone(),
            vec!["deflate"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "corrupt gzip",
            corrupt,
            vec!["gzip"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "gzip checksum mismatch",
            bad_crc,
            vec!["gzip"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "truncated gzip",
            gz[..n - 8].to_vec(),
            vec!["gzip"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "gzip trailing garbage",
            tail(gz.clone()),
            vec!["gzip"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "raw deflate trailing data",
            tail(raw_deflate_bytes(&plain)),
            vec!["deflate"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "zlib trailing data",
            tail(zlib_bytes(&plain)),
            vec!["deflate"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "br trailing data",
            tail(brotli_bytes(&plain)),
            vec!["br"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "empty gzip",
            Vec::new(),
            vec!["gzip"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
        (
            "empty deflate",
            Vec::new(),
            vec!["deflate"],
            SKIP_REASON_DECOMPRESS_ERROR,
        ),
    ];
    for (name, body, codings, want) in cases {
        let (got, skipped) = dec(&body, &codings, DECODED_BODY_LIMIT_BYTES);
        assert_eq!(skipped, want, "{name}");
        assert!(got.is_none(), "{name}: expected None");
        assert_eq!(
            inflight_decode_bytes_used(),
            0,
            "{name}: reservation leaked"
        );
    }
    // The brotli reader fails on an empty body.
    let (got, skipped) = dec(b"", &["br"], DECODED_BODY_LIMIT_BYTES);
    assert!(got.is_none() && skipped == SKIP_REASON_DECOMPRESS_ERROR);
}

#[test]
fn decode_bomb_guards() {
    let _g = lock_budget();
    // Ratio guard.
    let bomb = gzip_bytes(&vec![0u8; 16 << 20]);
    let want = (bomb.len() as i64 * EXPANSION_RATIO_LIMIT).max(RATIO_CHECK_MIN_OUTPUT);
    assert!(
        want < DECODED_BODY_LIMIT_BYTES,
        "fixture too large for a ratio test: {want}"
    );
    let (got, skipped) = dec(&bomb, &["gzip"], DECODED_BODY_LIMIT_BYTES);
    assert_eq!(skipped, SKIP_REASON_DECOMPRESS_LIMIT);
    assert_eq!(got.unwrap().len() as i64, want);

    // Output cap.
    let data = binary_blob(2 << 20);
    let limit = decoded_size_cap(1 << 20);
    let (got, skipped) = dec(&gzip_bytes(&data), &["gzip"], limit);
    assert_eq!(skipped, SKIP_REASON_DECOMPRESS_LIMIT);
    assert_eq!(got.unwrap(), &data[..limit as usize]);

    // Cap on an intermediate layer.
    let body = brotli_bytes(&gzip_bytes(&data));
    let (got, skipped) = dec(&body, &["gzip", "br"], 1 << 20);
    assert!(got.is_none() && skipped == SKIP_REASON_DECOMPRESS_LIMIT);

    // Stacked bomb.
    let body = brotli_bytes(&gzip_bytes(&vec![0u8; 32 << 20]));
    let (got, skipped) = dec(&body, &["gzip", "br"], DECODED_BODY_LIMIT_BYTES);
    assert_eq!(skipped, SKIP_REASON_DECOMPRESS_LIMIT);
    assert!(got.map_or(0, |g| g.len()) as i64 <= DECODED_BODY_LIMIT_BYTES);
}

#[test]
fn inspect_table() {
    let _g = lock_budget();
    let plain_json = benign_json_body();
    let gz_json = gzip_bytes(&plain_json);
    let blob = binary_blob(8192);
    let corrupt_gz = [&gz_json[..10], &blob[..64]].concat();
    let ce = |v: &str| hdrs(&[("Content-Encoding", v)]);
    let mp = b"--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--b--\r\n".to_vec();
    struct Case {
        name: &'static str,
        body: Vec<u8>,
        ct: &'static str,
        headers: Headers,
        kind: &'static str,
        scan: Option<Vec<u8>>,
        decoded: bool,
        sniffed: &'static str,
        skipped: &'static str,
        notes: Vec<&'static str>,
    }
    let c = |name, body, ct, headers, kind, scan, decoded, sniffed, skipped, notes| Case {
        name,
        body,
        ct,
        headers,
        kind,
        scan,
        decoded,
        sniffed,
        skipped,
        notes,
    };
    let none = Headers::new;
    let cases = vec![
        c(
            "json",
            plain_json.clone(),
            "application/json",
            none(),
            BODY_KIND_TEXT,
            Some(plain_json.clone()),
            false,
            "",
            "",
            vec![],
        ),
        c(
            "json declared octet-stream",
            plain_json.clone(),
            "application/octet-stream",
            none(),
            BODY_KIND_TEXT,
            Some(plain_json.clone()),
            false,
            "json",
            "",
            vec!["body_ct_mismatch:binary->json"],
        ),
        c(
            "form declared image",
            b"name=alice&city=paris".to_vec(),
            "image/png",
            none(),
            BODY_KIND_TEXT,
            Some(b"name=alice&city=paris".to_vec()),
            false,
            "form",
            "",
            vec!["body_ct_mismatch:image/png->form"],
        ),
        c(
            "genuine binary upload",
            blob.clone(),
            "image/png",
            none(),
            BODY_KIND_BINARY,
            None,
            false,
            "",
            "",
            vec![],
        ),
        c(
            "gzip json",
            gz_json.clone(),
            "application/json",
            ce("gzip"),
            BODY_KIND_TEXT,
            Some(plain_json.clone()),
            true,
            "",
            "",
            vec!["body_decoded:gzip"],
        ),
        c(
            "gzip json declared octet-stream",
            gz_json.clone(),
            "application/octet-stream",
            ce("gzip"),
            BODY_KIND_TEXT,
            Some(plain_json.clone()),
            true,
            "json",
            "",
            vec!["body_decoded:gzip", "body_ct_mismatch:binary->json"],
        ),
        c(
            "gzip binary upload",
            gzip_bytes(&blob),
            "application/octet-stream",
            ce("gzip"),
            BODY_KIND_BINARY,
            None,
            true,
            "",
            "",
            vec!["body_decoded:gzip"],
        ),
        c(
            "binary bomb clears flag",
            gzip_bytes(&vec![0u8; 16 << 20]),
            "application/octet-stream",
            ce("gzip"),
            BODY_KIND_BINARY,
            None,
            true,
            "",
            "",
            vec!["body_decoded:gzip"],
        ),
        c(
            "unsupported coding keeps raw",
            plain_json.clone(),
            "application/json",
            ce("zstd"),
            BODY_KIND_TEXT,
            Some(plain_json.clone()),
            false,
            "",
            "content_encoding:zstd",
            vec!["body_scan_incomplete:content_encoding:zstd"],
        ),
        c(
            "corrupt gzip keeps raw",
            corrupt_gz.clone(),
            "application/json",
            ce("gzip"),
            BODY_KIND_TEXT,
            Some(corrupt_gz.clone()),
            false,
            "",
            SKIP_REASON_DECOMPRESS_ERROR,
            vec!["body_scan_incomplete:decompress_error"],
        ),
        c(
            "corrupt gzip binary label keeps flag",
            corrupt_gz.clone(),
            "application/octet-stream",
            ce("gzip"),
            BODY_KIND_BINARY,
            None,
            false,
            "",
            SKIP_REASON_DECOMPRESS_ERROR,
            vec!["body_scan_incomplete:decompress_error"],
        ),
        c(
            "gzip multipart",
            gzip_bytes(&mp),
            "multipart/form-data; boundary=b",
            ce("gzip"),
            BODY_KIND_MULTIPART,
            Some(mp.clone()),
            true,
            "",
            "",
            vec!["body_decoded:gzip"],
        ),
    ];
    for tc in cases {
        let orig = tc.body.clone();
        let res = inspect(&tc.body, tc.ct.as_bytes(), &tc.headers, &Options::default());
        assert_eq!(res.kind, tc.kind, "{}", tc.name);
        assert_eq!(res.scan.as_deref(), tc.scan.as_deref(), "{}", tc.name);
        assert_eq!(
            (res.decoded, res.sniffed, res.skipped.as_str()),
            (tc.decoded, tc.sniffed, tc.skipped),
            "{}",
            tc.name
        );
        assert_eq!(res.notes, tc.notes, "{}", tc.name);
        assert_eq!(tc.body, orig, "{}: body modified", tc.name);
    }
}

#[test]
fn inspect_transform_applies_to_decoded_copy_only() {
    let _g = lock_budget();
    let plain = benign_json_body();
    let calls = AtomicI64::new(0);
    let t = |b: Vec<u8>| {
        calls.fetch_add(1, Ordering::SeqCst);
        b.to_ascii_uppercase()
    };
    let opt = Options {
        output_limit: 0,
        transform: Some(&t),
    };
    let gz = gzip_bytes(&plain);
    let res = inspect(
        &gz,
        b"application/json",
        &hdrs(&[("Content-Encoding", "gzip")]),
        &opt,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        res.scan.as_deref(),
        Some(plain.to_ascii_uppercase().as_slice())
    );
    let res = inspect(&plain, b"application/json", &Headers::new(), &opt);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(res.scan.as_deref(), Some(plain.as_slice()));
}

#[test]
fn prepare_request_cases() {
    let _g = lock_budget();
    let plain = benign_json_body();
    let gz = gzip_bytes(&plain);
    let blob = binary_blob(4096);

    let mut req = IncomingRequest {
        headers: hdrs(&[
            ("content-encoding", "gzip"),
            ("Content-Type", "application/json"),
        ]),
        body: gz.clone(),
        ..Default::default()
    };
    let notes = prepare_body_for_engines(&mut req);
    assert_eq!(req.body, plain);
    assert_eq!(req.content_scan_body.as_deref(), Some(gz.as_slice()));
    assert_eq!(req.body_size, gz.len() as i64);
    assert_eq!(req.body_scan_skipped, "");
    assert_eq!(req.content_type, b"application/json");
    assert_eq!(notes, ["body_decoded:gzip"]);

    let mut req = IncomingRequest {
        headers: hdrs(&[("Content-Encoding", "zstd")]),
        body: plain.clone(),
        body_size: 9999,
        ..Default::default()
    };
    prepare_body_for_engines(&mut req);
    assert!(req.body == plain && req.content_scan_body.is_none() && req.body_size == 9999);
    assert_eq!(req.body_scan_skipped, "content_encoding:zstd");

    let mut req = IncomingRequest {
        headers: hdrs(&[("Content-Type", "application/json")]),
        body: plain.clone(),
        ..Default::default()
    };
    prepare_body_for_engines(&mut req);
    assert!(
        req.body == plain
            && req.content_scan_body.is_none()
            && req.body_size == 0
            && req.body_scan_skipped.is_empty()
    );

    let mut req = IncomingRequest {
        content_type: b"application/octet-stream".to_vec(),
        body: plain.clone(),
        ..Default::default()
    };
    let notes = prepare_body_for_engines(&mut req);
    assert!(req.body == plain && req.content_scan_body.is_none());
    assert_eq!(notes, ["body_ct_mismatch:binary->json"]);

    let mut req = IncomingRequest {
        content_type: b"image/png".to_vec(),
        body: blob.clone(),
        ..Default::default()
    };
    prepare_body_for_engines(&mut req);
    assert!(req.body.is_empty() && req.content_scan_body.as_deref() == Some(blob.as_slice()));
    assert!(req.body_size == blob.len() as i64 && req.body_scan_skipped.is_empty());

    let full = [blob.clone(), blob.clone()].concat();
    let mut req = IncomingRequest {
        content_type: b"image/png".to_vec(),
        body: blob.clone(),
        body_size: full.len() as i64,
        content_scan_body: Some(full.clone()),
        ..Default::default()
    };
    prepare_body_for_engines(&mut req);
    assert!(
        req.body.is_empty()
            && req.body_size == full.len() as i64
            && req.content_scan_body == Some(full)
    );

    let mut req = IncomingRequest {
        headers: hdrs(&[("Content-Type", "text/plain"), ("Content-Encoding", "gzip")]),
        ..Default::default()
    };
    assert!(prepare_body_for_engines(&mut req).is_empty());
    assert!(
        req.body.is_empty()
            && req.body_scan_skipped.is_empty()
            && req.content_type == b"text/plain"
    );
}

#[test]
fn annotate_result_table() {
    let notes = vec![
        "body_decoded:gzip".to_string(),
        "body_ct_mismatch:binary->json".to_string(),
    ];
    use wafio_domain::request::*;
    for (action, method, detail, want) in [
        (
            "block",
            ANALYZE_METHOD_SEMANTIC,
            "xss:tag",
            "xss:tag; body_decoded:gzip; body_ct_mismatch:binary->json",
        ),
        (
            "log",
            ANALYZE_METHOD_SEMANTIC,
            "",
            "body_decoded:gzip; body_ct_mismatch:binary->json",
        ),
        ("allow", ANALYZE_METHOD_SEMANTIC, "", ""),
        (
            "block",
            ANALYZE_METHOD_CUSTOM_RULE,
            "custom_gui_rule:r1",
            "custom_gui_rule:r1",
        ),
        (
            "block",
            ANALYZE_METHOD_CONTENT_SCAN,
            "body_scan_incomplete:decompress_error",
            "body_scan_incomplete:decompress_error",
        ),
        ("block", ANALYZE_METHOD_POLICY, "", ""),
    ] {
        let mut res = AnalysisResult {
            action: action.into(),
            analyze_method: method.into(),
            match_detail: detail.as_bytes().to_vec(),
            ..Default::default()
        };
        attach_notes(&mut res, &notes);
        assert_eq!(res.match_detail, want.as_bytes(), "{action}/{method}");
    }
    let mut res = AnalysisResult {
        action: "block".into(),
        analyze_method: ANALYZE_METHOD_SEMANTIC.into(),
        match_detail: b"x".to_vec(),
        ..Default::default()
    };
    attach_notes(&mut res, &[]);
    assert_eq!(res.match_detail, b"x");
}

#[test]
fn decode_budget_exhausted_skips_decoding() {
    let _g = with_decode_budget(1 << 20);
    let plain = benign_json_body();
    let gz = gzip_bytes(&plain);
    let hold = hold_budget(1 << 20);
    let before = skipped_decode_count();
    let (got, skipped) = dec(&gz, &["gzip"], DECODED_BODY_LIMIT_BYTES);
    assert!(got.is_none() && skipped == SKIP_REASON_DECOMPRESS_BUDGET);
    assert_eq!(skipped_decode_count(), before + 1);

    let mut req = IncomingRequest {
        content_type: b"application/json".to_vec(),
        headers: hdrs(&[("Content-Encoding", "gzip")]),
        body: gz.clone(),
        ..Default::default()
    };
    let notes = prepare_body_for_engines(&mut req);
    assert!(
        req.body == gz
            && req.body_scan_skipped == SKIP_REASON_DECOMPRESS_BUDGET
            && req.content_scan_body.is_none()
    );
    assert_eq!(notes, ["body_scan_incomplete:decompress_budget"]);

    drop(hold);
    let (got, skipped) = dec(&gz, &["gzip"], DECODED_BODY_LIMIT_BYTES);
    assert!(skipped.is_empty() && got.as_deref() == Some(plain.as_slice()));
    assert_eq!(inflight_decode_bytes_used(), 0);
}

#[test]
fn decode_budget_partially_held() {
    let gz = gzip_bytes(&benign_json_body());
    let single = worst_case_reservation(&["gzip"], RATIO_CHECK_MIN_OUTPUT);
    let stacked = worst_case_reservation(&["gzip", "br"], RATIO_CHECK_MIN_OUTPUT);
    assert!(stacked > single);
    let capacity = stacked + single;
    let _g = with_decode_budget(capacity);
    let _hold = hold_budget(capacity - single);
    assert_eq!(dec(&gz, &["gzip"], DECODED_BODY_LIMIT_BYTES).1, "");
    assert_eq!(
        dec(
            &brotli_bytes(&gz),
            &["gzip", "br"],
            DECODED_BODY_LIMIT_BYTES
        )
        .1,
        SKIP_REASON_DECOMPRESS_BUDGET
    );
}

#[test]
fn decode_budget_shrinks_oversized_decode() {
    let plain = benign_json_body().repeat(20000);
    let body = brotli_bytes(&gzip_bytes(&plain));
    let codings = ["gzip", "br"];
    let layer_budget = RATIO_CHECK_MIN_OUTPUT.max(body.len() as i64 * EXPANSION_RATIO_LIMIT);
    let full = worst_case_reservation(&codings, layer_budget);
    let capacity = full - (256 << 10);
    let want = fit_layer_budget(&codings, layer_budget, capacity);
    assert!(want > 0 && want < layer_budget && worst_case_reservation(&codings, want) <= capacity);
    let _g = with_decode_budget(capacity);
    let (got, skipped) = dec(&body, &codings, DECODED_BODY_LIMIT_BYTES);
    assert_eq!(skipped, SKIP_REASON_DECOMPRESS_LIMIT);
    let got = got.unwrap();
    assert_eq!(got.len() as i64, want);
    assert_eq!(got, &plain[..want as usize]);
    assert_eq!(inflight_decode_bytes_used(), 0);
}

#[test]
fn decode_budget_below_decoder_state() {
    let capacity = worst_case_reservation(&["gzip"], RATIO_CHECK_MIN_OUTPUT);
    let _g = with_decode_budget(capacity);
    let plain = benign_json_body();
    let (got, skipped) = dec(&brotli_bytes(&plain), &["br"], DECODED_BODY_LIMIT_BYTES);
    assert!(got.is_none() && skipped == SKIP_REASON_DECOMPRESS_LIMIT);
    let (got, skipped) = dec(&gzip_bytes(&plain), &["gzip"], DECODED_BODY_LIMIT_BYTES);
    assert!(skipped.is_empty() && got.as_deref() == Some(plain.as_slice()));
    assert_eq!(inflight_decode_bytes_used(), 0);
}

#[test]
fn decode_budget_disabled() {
    let _g = with_decode_budget(0);
    let gz = gzip_bytes(&benign_json_body());
    let _hold = hold_budget(1 << 40);
    assert_eq!(dec(&gz, &["gzip"], DECODED_BODY_LIMIT_BYTES).1, "");
}

#[test]
fn decode_budget_concurrent() {
    let capacity = 2 * worst_case_reservation(&["gzip", "br"], RATIO_CHECK_MIN_OUTPUT);
    let _g = with_decode_budget(capacity);
    let plain = Arc::new(benign_json_body());
    let gz = Arc::new(gzip_bytes(&plain));
    let stacked = Arc::new(brotli_bytes(&gz));
    let decoded = Arc::new(AtomicI64::new(0));
    let skipped_n = Arc::new(AtomicI64::new(0));
    let threads: Vec<_> = (0..32)
        .map(|g| {
            let (plain, gz, stacked, decoded, skipped_n) = (
                plain.clone(),
                gz.clone(),
                stacked.clone(),
                decoded.clone(),
                skipped_n.clone(),
            );
            std::thread::spawn(move || {
                for i in 0..50 {
                    let (body, codings): (&[u8], &[&str]) = if (g + i) % 3 == 0 {
                        (&stacked, &["gzip", "br"])
                    } else {
                        (&gz, &["gzip"])
                    };
                    let (got, skipped) = dec(body, codings, DECODED_BODY_LIMIT_BYTES);
                    if skipped.is_empty() && got.as_deref() == Some(plain.as_slice()) {
                        decoded.fetch_add(1, Ordering::SeqCst);
                    } else if skipped == SKIP_REASON_DECOMPRESS_BUDGET && got.is_none() {
                        skipped_n.fetch_add(1, Ordering::SeqCst);
                    } else {
                        panic!("unexpected result: skipped {skipped:?}");
                    }
                    assert!(inflight_decode_bytes_used() <= capacity);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(
        decoded.load(Ordering::SeqCst) + skipped_n.load(Ordering::SeqCst),
        32 * 50
    );
    assert!(decoded.load(Ordering::SeqCst) > 0);
    assert_eq!(inflight_decode_bytes_used(), 0);
}

#[test]
fn mem_budget_acquire_release_concurrent() {
    const CAPACITY: i64 = 1000;
    let b = Arc::new(ByteBudget {
        capacity: AtomicI64::new(CAPACITY),
        in_use: AtomicI64::new(0),
        skips: std::sync::atomic::AtomicU64::new(0),
    });
    let held = Arc::new(AtomicI64::new(0));
    let peak = Arc::new(AtomicI64::new(0));
    let threads: Vec<_> = (0..16i64)
        .map(|g| {
            let (b, held, peak) = (b.clone(), held.clone(), peak.clone());
            std::thread::spawn(move || {
                for i in 0..2000i64 {
                    let n = (g * 31 + i * 7) % 300 + 1;
                    if !b.try_acquire(n) {
                        continue;
                    }
                    let cur = held.fetch_add(n, Ordering::SeqCst) + n;
                    peak.fetch_max(cur, Ordering::SeqCst);
                    held.fetch_sub(n, Ordering::SeqCst);
                    b.release(n);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert!(peak.load(Ordering::SeqCst) <= CAPACITY);
    assert_eq!(b.in_use.load(Ordering::SeqCst), 0);
    assert!(b.try_acquire(CAPACITY) && !b.try_acquire(1));
    b.release(CAPACITY);
}

#[test]
fn budget_from_env_table() {
    for (v, want) in [
        ("", DEFAULT_INFLIGHT_DECODE_BYTES),
        ("0", 0),
        ("1048576", 1 << 20),
        ("32MiB", 32 << 20),
        (" 512kib ", 512 << 10),
        ("2G", 2 << 30),
        ("100b", 100),
        ("-5", DEFAULT_INFLIGHT_DECODE_BYTES),
        ("lots", DEFAULT_INFLIGHT_DECODE_BYTES),
        ("1.5MiB", DEFAULT_INFLIGHT_DECODE_BYTES),
        ("99999GiB9", DEFAULT_INFLIGHT_DECODE_BYTES),
        ("+7", 7),
    ] {
        assert_eq!(parse_budget_env(v.as_bytes()), want, "{v:?}");
    }
    assert!(parse_size_with_suffix(b"9223372036854775807GiB").is_none());
}

#[test]
fn set_decode_memory_budget_values() {
    let _g = lock_budget();
    set_inflight_decode_bytes(-1);
    assert_eq!(inflight_decode_bytes_limit(), DEFAULT_INFLIGHT_DECODE_BYTES);
    set_inflight_decode_bytes(5 << 20);
    assert_eq!(inflight_decode_bytes_limit(), 5 << 20);
}

#[test]
fn decode_brotli_declared_window_truncated() {
    // Only the verdict is checked: a large-window header plus zeros is corrupt.
    let _g = with_decode_budget(DEFAULT_INFLIGHT_DECODE_BYTES);
    let body = [&[0xCF, 0xFF, 0xFF, 0xFF][..], &[0u8; 100][..]].concat();
    let orig = body.clone();
    let (got, skipped) = dec(&body, &["br"], DECODED_BODY_LIMIT_BYTES);
    assert!(
        got.is_none() && skipped == SKIP_REASON_DECOMPRESS_ERROR,
        "skipped {skipped:?}"
    );
    assert_eq!(body, orig);
    assert_eq!(inflight_decode_bytes_used(), 0);
}

#[test]
fn decode_brotli_window_cap_keeps_output() {
    let _g = with_decode_budget(DEFAULT_INFLIGHT_DECODE_BYTES);
    let block = binary_blob(30 << 10);
    let plain = block.repeat(4);
    let body = brotli_bytes_window(&plain, 24);
    assert_eq!(
        body[0] & 0x0F,
        0x0F,
        "encoder did not declare WBITS 24: {:#x}",
        body[0]
    );
    let (got, skipped) = dec(&body, &["br"], DECODED_BODY_LIMIT_BYTES);
    assert!(skipped.is_empty() && got.as_deref() == Some(plain.as_slice()));
    const LIMIT: i64 = 64 << 10;
    let (got, skipped) = dec(&body, &["br"], LIMIT);
    assert_eq!(skipped, SKIP_REASON_DECOMPRESS_LIMIT);
    assert_eq!(got.unwrap(), &plain[..LIMIT as usize]);
    let (got, skipped) = dec(
        &gzip_bytes(&body),
        &["br", "gzip"],
        DECODED_BODY_LIMIT_BYTES,
    );
    assert!(skipped.is_empty() && got.as_deref() == Some(plain.as_slice()));
}

#[test]
fn brotli_window_for_table() {
    for (budget, want) in [
        (0, 18),
        (64 << 10, 18),
        ((1 << 18) - 16 - 1, 18),
        ((1 << 18) - 16, 19),
        (RATIO_CHECK_MIN_OUTPUT, 19),
        (4 << 20, 23),
        (DECODED_BODY_LIMIT_BYTES, 24),
        (1 << 30, 24),
    ] {
        let (got, ring) = brotli_window_bits_for(budget);
        assert_eq!(got, want, "{budget}");
        assert!(
            !(got < 24 && (1i64 << got) - 16 < budget + 1),
            "{budget}: does not cover"
        );
        assert!(ring >= 1i64 << got);
    }
}

#[test]
fn brotli_source_header_rewrite() {
    let (cap_bits, _) = brotli_window_bits_for(RATIO_CHECK_MIN_OUTPUT);
    for (name, b0, want) in [
        ("WBITS 16 kept", 0x00u8, 0x00u8),
        ("WBITS 17 (7-bit form) kept", 0x01, 0x01),
        ("WBITS 18 kept", 0x03, 0x03),
        ("WBITS 19 kept", 0x05, 0x05),
        ("WBITS 22 capped", 0x0B, ((cap_bits - 17) as u8) << 1 | 1),
        (
            "WBITS 24 capped, upper bits kept",
            0xCF,
            0xC0 | ((cap_bits - 17) as u8) << 1 | 1,
        ),
    ] {
        let data = [b0, 0xAA, 0xBB];
        let got = rewrite_brotli_window_header(&data, RATIO_CHECK_MIN_OUTPUT).unwrap_or(b0);
        assert_eq!(got, want, "{name}");
    }
}

/// Replays a dump of encoded streams and their mutations; skipped unless
/// GODUMP_DECODE=<file> is set.
#[test]
fn decode_differential() {
    let Ok(path) = std::env::var("GODUMP_DECODE") else {
        return;
    };
    let _g = with_decode_budget(0);
    let data = std::fs::read_to_string(path).unwrap();
    let b64 = |s: &str| -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
        for c in s.bytes() {
            let Some(v) = T.iter().position(|&t| t == c) else {
                continue;
            };
            acc = (acc << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    };
    let (mut n, mut bad) = (0, 0);
    for line in data.lines() {
        let r: serde_json::Value = serde_json::from_str(line).unwrap();
        let body = b64(r["body"].as_str().unwrap());
        let codings: Vec<String> = r["codings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();
        let limit = r["limit"].as_i64().unwrap();
        let (got, skipped) = dec(
            &body,
            &codings.iter().map(String::as_str).collect::<Vec<_>>(),
            limit,
        );
        let want = if r["nil"].as_bool().unwrap() {
            None
        } else {
            Some((
                r["len"].as_u64().unwrap() as usize,
                r["crc"].as_u64().unwrap() as u32,
            ))
        };
        let got = got.map(|g| {
            let mut c = flate2::Crc::new();
            c.update(&g);
            (g.len(), c.sum())
        });
        n += 1;
        if got != want || skipped != r["skipped"].as_str().unwrap() {
            bad += 1;
            if let Ok(fp) = std::env::var("GODUMP_DECODE_FAIL") {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(fp)
                    .unwrap();
                writeln!(
                    f,
                    "{} {} {}",
                    codings.join(","),
                    limit,
                    r["body"].as_str().unwrap()
                )
                .unwrap();
            }
            if bad <= 10 {
                eprintln!(
                    "MISMATCH codings={codings:?} limit={limit} body[..16]={:02x?} len={}: got {:?}/{skipped}, want {:?}/{}",
                    &body[..body.len().min(16)],
                    body.len(),
                    got,
                    want,
                    r["skipped"]
                );
            }
        }
    }
    assert_eq!(
        bad, 0,
        "{bad} of {n} decode cases differ from the recorded reference"
    );
    eprintln!("decode reference: {n} cases identical");
}

/// Verdicts pinned for bodies that decoders driven in a plain way judge differently.
#[test]
fn decode_matches_reference_on_former_divergences() {
    let _g = lock_budget();
    let hex = |h: &str| -> Vec<u8> {
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };
    // zlib stream of zeros with one byte mutated: its dynamic block defines an
    // incomplete Huffman code, which is rejected before anything is decoded.
    let mut zl = hex("789cecc0010d000000c220fba7b6c70701");
    zl.extend(vec![0u8; 289]);
    zl.extend(hex("8090070000ffff941c0001"));
    assert_eq!(
        dec(&zl, &["deflate"], DECODED_BODY_LIMIT_BYTES),
        (None, SKIP_REASON_DECOMPRESS_ERROR.to_string())
    );
    // brotli streams whose MLEN exceeds what they encode: the pending output (up to the
    // budget) is delivered after the input ran out.
    for h in [
        "5bdff0044002201e0b24739100",
        "5fee93044002201e0b24739100",
        "5fdf93044002201e0b24639100",
    ] {
        let (got, skipped) = dec(&hex(h), &["br"], DECODED_BODY_LIMIT_BYTES);
        assert_eq!(skipped, SKIP_REASON_DECOMPRESS_LIMIT, "{h}");
        assert_eq!(
            got.map(|g| g.len()),
            Some(RATIO_CHECK_MIN_OUTPUT as usize),
            "{h}"
        );
    }
    // WBITS 1000001 is the large-window marker: the decoder refuses it.
    assert_eq!(
        dec(&hex("11d1"), &["br"], DECODED_BODY_LIMIT_BYTES),
        (None, SKIP_REASON_DECOMPRESS_ERROR.to_string())
    );
}

/// `cargo test --release -p wafio-bodyinspect inflate_throughput -- --ignored --nocapture`
#[test]
#[ignore]
fn inflate_throughput() {
    let _g = lock_budget();
    let mut text = Vec::new();
    let mut i = 0u32;
    while text.len() < 8 << 20 {
        text.extend_from_slice(
            format!(
                "{{\"id\":{i},\"name\":\"item{}\",\"tags\":[\"a\",\"b\"]}},",
                i % 97
            )
            .as_bytes(),
        );
        i += 1;
    }
    // below the ratio guard (100x) the body decodes whole
    text.truncate((8 << 20) - 1);
    let plain = text;
    let body = gzip_bytes(&plain);
    let start = std::time::Instant::now();
    let (got, skipped) = dec(&body, &["gzip"], DECODED_BODY_LIMIT_BYTES);
    let secs = start.elapsed().as_secs_f64();
    assert_eq!(skipped, "");
    assert_eq!(got.map(|g| g.len()), Some(plain.len()));
    eprintln!(
        "json 8 MiB: {} -> {} bytes, {:.0} MiB/s",
        body.len(),
        plain.len(),
        plain.len() as f64 / secs / (1 << 20) as f64
    );
}

fn from_hex(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn fnv1a(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf29ce484222325u64, |h, &c| {
        (h ^ u64::from(c)).wrapping_mul(0x100000001b3)
    })
}

/// A fixed-seed generator for the stream tests.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Streams and verdicts recorded from the decoders this crate had before it called
/// `miniz_oxide` and the brotli stream decoder directly: fixed-seed mutations of encoder output
/// at assorted limits, one `coding limit body => result` line each.
#[test]
fn decode_matches_recorded_vectors() {
    let _g = with_decode_budget(0);
    let mut n = 0;
    for (i, line) in include_str!("../testdata/decode_vectors.txt")
        .lines()
        .enumerate()
    {
        let (head, want) = line.split_once(" => ").unwrap();
        let mut f = head.split(' ');
        let codings: Vec<&str> = f.next().unwrap().split(',').collect();
        let limit: i64 = f.next().unwrap().parse().unwrap();
        let body = from_hex(f.next().unwrap());
        let (got, skipped) = dec(&body, &codings, limit);
        let got = match got {
            None => format!("none {skipped}"),
            Some(o) => format!("some {} {:016x} {skipped}", o.len(), fnv1a(&o)),
        };
        assert_eq!(got.trim_end(), want.trim_end(), "vector {i}: {head}");
        n += 1;
    }
    assert!(n > 300, "{n} vectors");
}

/// LSB-first bit writer for hand-built deflate streams.
#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitWriter {
    fn put(&mut self, v: u32, n: u32) {
        for i in 0..n {
            self.acc |= ((v >> i) & 1) << self.n;
            self.n += 1;
            if self.n == 8 {
                self.bytes.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }

    /// Huffman codes go out most significant bit first.
    fn put_code(&mut self, code: u32, len: u32) {
        for i in (0..len).rev() {
            self.put((code >> i) & 1, 1);
        }
    }

    fn bits(&self) -> usize {
        self.bytes.len() * 8 + self.n as usize
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.bytes.push(self.acc as u8);
        }
        self.bytes
    }
}

/// Canonical code of each symbol for the code lengths `lens`.
fn canonical_codes(lens: &[u8]) -> Vec<u32> {
    let mut codes = vec![0u32; lens.len()];
    let mut code = 0u32;
    for len in 1..=15u8 {
        for (s, &l) in lens.iter().enumerate() {
            if l == len {
                codes[s] = code;
                code += 1;
            }
        }
        code <<= 1;
    }
    codes
}

/// Writes a final dynamic block header whose literal/length code gives `(symbol, length)`
/// entries (lengths 1 or 2) and whose distance code is `dist` (lengths 0..=2), and returns the
/// literal/length codes. Code lengths 0, 1 and 2 are coded with the code 0, 10, 11.
fn dynamic_header(w: &mut BitWriter, lit: &[(usize, u8)], dist: &[u8]) -> Vec<(u32, u8)> {
    let mut lens = vec![0u8; 257];
    for &(s, l) in lit {
        if s >= lens.len() {
            lens.resize(s + 1, 0);
        }
        lens[s] = l;
    }
    w.put(1, 1);
    w.put(2, 2);
    w.put(lens.len() as u32 - 257, 5);
    w.put(dist.len() as u32 - 1, 5);
    w.put(18 - 4, 4);
    // Code-length code: symbol 0 has length 1, symbols 1 and 2 have length 2.
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    for &sym in &ORDER[..18] {
        w.put(
            match sym {
                0 => 1,
                1 | 2 => 2,
                _ => 0,
            },
            3,
        );
    }
    for &l in lens.iter().chain(dist) {
        match l {
            0 => w.put_code(0, 1),
            1 => w.put_code(0b10, 2),
            _ => w.put_code(0b11, 2),
        }
    }
    let codes = canonical_codes(&lens);
    lens.iter().zip(codes).map(|(&l, c)| (c, l)).collect()
}

/// What `dec` returns: the decoded bytes and the `body_scan_skipped` value.
type Verdict = (Option<Vec<u8>>, String);

fn raw_dec(data: &[u8], limit: i64) -> Verdict {
    dec(data, &["deflate"], limit)
}

#[test]
fn deflate_single_one_bit_code_is_valid() {
    let _g = lock_budget();
    let mut w = BitWriter::default();
    let codes = dynamic_header(&mut w, &[(256, 1)], &[0]);
    w.put_code(codes[256].0, 1);
    assert_eq!(raw_dec(&w.finish(), 100), (Some(vec![]), String::new()));

    let mut w = BitWriter::default();
    dynamic_header(&mut w, &[(256, 1)], &[0]);
    w.put(1, 1); // the code nothing is assigned to
    assert_eq!(
        raw_dec(&w.finish(), 100),
        (None, SKIP_REASON_DECOMPRESS_ERROR.to_string())
    );
}

#[test]
fn deflate_incomplete_and_oversubscribed_codes_are_corrupt() {
    let _g = lock_budget();
    for (lit, complete) in [
        (vec![(256usize, 1u8), (65, 2)], false),
        (vec![(256, 1), (65, 2), (66, 2)], true),
        (vec![(256, 1), (65, 1), (66, 2)], false),
        (vec![(256, 2), (65, 2), (66, 2), (67, 2)], true),
        (vec![(256, 2), (65, 2), (66, 2)], false),
    ] {
        let mut w = BitWriter::default();
        let codes = dynamic_header(&mut w, &lit, &[0]);
        let (code, len) = codes[256];
        w.put_code(code, u32::from(len));
        let got = raw_dec(&w.finish(), 100);
        if complete {
            assert_eq!(got, (Some(vec![]), String::new()), "{lit:?}");
        } else {
            assert_eq!(
                got,
                (None, SKIP_REASON_DECOMPRESS_ERROR.to_string()),
                "{lit:?}"
            );
        }
    }
}

#[test]
fn deflate_empty_distance_code_allows_literals_only() {
    let _g = lock_budget();
    let lit = [(65usize, 1u8), (256, 1)];
    let mut w = BitWriter::default();
    let codes = dynamic_header(&mut w, &lit, &[0]);
    for _ in 0..3 {
        w.put_code(codes[65].0, 1);
    }
    w.put_code(codes[256].0, 1);
    assert_eq!(
        raw_dec(&w.finish(), 100),
        (Some(b"AAA".to_vec()), String::new())
    );

    // A match needs a distance code.
    let mut w = BitWriter::default();
    let codes = dynamic_header(&mut w, &[(256, 1), (257, 1)], &[0]);
    w.put_code(codes[257].0, 1);
    assert_eq!(
        raw_dec(&w.finish(), 100),
        (None, SKIP_REASON_DECOMPRESS_ERROR.to_string())
    );
}

#[test]
fn deflate_distance_past_the_history_is_corrupt() {
    let _g = lock_budget();
    // Length 3 at distance 1 before any literal.
    let mut w = BitWriter::default();
    let codes = dynamic_header(&mut w, &[(256, 1), (257, 1)], &[1]);
    w.put_code(codes[257].0, 1);
    w.put(0, 1);
    assert_eq!(
        raw_dec(&w.finish(), 100),
        (None, SKIP_REASON_DECOMPRESS_ERROR.to_string())
    );

    // After one literal the same match copies it three times.
    let mut w = BitWriter::default();
    let codes = dynamic_header(&mut w, &[(65, 2), (256, 2), (257, 1)], &[1]);
    w.put_code(codes[65].0, 2);
    w.put_code(codes[257].0, 1);
    w.put(0, 1);
    w.put_code(codes[256].0, 2);
    assert_eq!(
        raw_dec(&w.finish(), 100),
        (Some(b"AAAA".to_vec()), String::new())
    );
}

#[test]
fn deflate_stored_blocks() {
    let _g = lock_budget();
    let corrupt = (None, SKIP_REASON_DECOMPRESS_ERROR.to_string());
    let stored = |n: u16, nn: u16, body: &[u8]| {
        let mut v = vec![0x01];
        v.extend_from_slice(&n.to_le_bytes());
        v.extend_from_slice(&nn.to_le_bytes());
        v.extend_from_slice(body);
        v
    };
    assert_eq!(
        raw_dec(&stored(5, !5, b"abcde"), 100),
        (Some(b"abcde".to_vec()), String::new())
    );
    assert_eq!(raw_dec(&stored(5, !5, b"abc"), 100), corrupt, "short body");
    assert_eq!(
        raw_dec(&stored(5, 0, b"abcde"), 100),
        corrupt,
        "length check"
    );
    assert_eq!(raw_dec(&[0x01, 5, 0], 100), corrupt, "cut header");
    assert_eq!(
        raw_dec(&stored(5, !5, b"abcdefg"), 100),
        corrupt,
        "bytes after the stream"
    );
    // The limit falls inside the block: budget 3 keeps three bytes, 5 and 6 do not stop it.
    assert_eq!(
        raw_dec(&stored(5, !5, b"abcde"), 3),
        (
            Some(b"abc".to_vec()),
            SKIP_REASON_DECOMPRESS_LIMIT.to_string()
        )
    );
    assert_eq!(
        raw_dec(&stored(5, !5, b"abcde"), 5),
        (Some(b"abcde".to_vec()), String::new())
    );
}

#[test]
fn deflate_reserved_block_type_and_oversized_tables_are_corrupt() {
    let _g = lock_budget();
    let corrupt = (None, SKIP_REASON_DECOMPRESS_ERROR.to_string());
    assert_eq!(raw_dec(&[0x07], 10), corrupt, "block type 3");
    for (hlit, hdist) in [(31, 0), (0, 31)] {
        let mut w = BitWriter::default();
        w.put(1, 1);
        w.put(2, 2);
        w.put(hlit, 5);
        w.put(hdist, 5);
        w.put(0, 4);
        assert_eq!(
            raw_dec(&w.finish(), 10),
            corrupt,
            "hlit {hlit} hdist {hdist}"
        );
    }
}

#[test]
fn deflate_long_codes_and_far_matches_round_trip() {
    let _g = lock_budget();
    // Fibonacci symbol counts give codes of 10 to 15 bits.
    let mut shuffled = Vec::new();
    let (mut a, mut b) = (1usize, 1usize);
    for sym in 0..19u8 {
        shuffled.extend(std::iter::repeat_n(40 + sym * 7, a));
        (a, b) = (b, a + b);
    }
    let mut rng = XorShift(12345);
    for i in (1..shuffled.len()).rev() {
        shuffled.swap(i, rng.below(i + 1));
    }
    // A match at the largest distance.
    let mut far: Vec<u8> = (0..32768u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    far.extend_from_within(..);
    for plain in [shuffled, far] {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&plain).unwrap();
        let data = enc.finish().unwrap();
        assert_eq!(
            raw_dec(&data, DECODED_BODY_LIMIT_BYTES),
            (Some(plain), String::new())
        );
    }
}

/// A stream that ends inside its last block still yields what was decoded before it ended, so a
/// limit reached by the final symbols is reported as a limit, not as corruption.
#[test]
fn deflate_truncated_stream_reaching_the_limit_is_a_limit() {
    let _g = lock_budget();
    // 'A' = 0, 'B' = 10, end of block = 11: after the header only 'A's, ending on a byte boundary.
    let mut w = BitWriter::default();
    let codes = dynamic_header(&mut w, &[(65, 1), (66, 2), (256, 2)], &[0]);
    assert_eq!(codes[65], (0, 1));
    let literals = 8 - w.bits() % 8 + 16;
    for _ in 0..literals {
        w.put(0, 1);
    }
    let data = w.finish();
    let plain = vec![b'A'; literals];
    assert_eq!(
        raw_dec(&data, literals as i64 - 1),
        (
            Some(plain[..literals - 1].to_vec()),
            SKIP_REASON_DECOMPRESS_LIMIT.to_string()
        )
    );
    assert_eq!(
        raw_dec(&data, literals as i64 + 100),
        (None, SKIP_REASON_DECOMPRESS_ERROR.to_string())
    );
}

/// gzip member with the given header fields and the deflate data of `plain`.
fn gzip_member(plain: &[u8], flags: u8, fields: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 3];
    v.extend_from_slice(fields);
    v.extend(raw_deflate_bytes(plain));
    let mut crc = flate2::Crc::new();
    crc.update(plain);
    v.extend_from_slice(&crc.sum().to_le_bytes());
    v.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    v
}

#[test]
fn decode_gzip_header_fields() {
    let _g = lock_budget();
    let plain = benign_json_body();
    let ok = (Some(plain.clone()), String::new());
    let bad = (None, SKIP_REASON_DECOMPRESS_ERROR.to_string());
    let text = |n: usize| [vec![b'n'; n], vec![0]].concat();
    let extra = |n: usize| [(n as u16).to_le_bytes().to_vec(), vec![7; n]].concat();
    let header_crc = |flags: u8, fields: &[u8], good: bool| {
        let mut h = vec![0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 3];
        h.extend_from_slice(fields);
        let mut c = flate2::Crc::new();
        c.update(&h);
        let sum = c.sum() as u16 ^ u16::from(!good);
        [fields.to_vec(), sum.to_le_bytes().to_vec()].concat()
    };
    let cases: Vec<(&str, Vec<u8>, Verdict)> = vec![
        ("no fields", gzip_member(&plain, 0, &[]), ok.clone()),
        ("extra", gzip_member(&plain, 4, &extra(300)), ok.clone()),
        (
            "extra beyond the data",
            gzip_member(&plain, 4, &[0xff, 0xff, 1]),
            bad.clone(),
        ),
        (
            "name of 511 bytes",
            gzip_member(&plain, 8, &text(511)),
            ok.clone(),
        ),
        (
            "name of 512 bytes",
            gzip_member(&plain, 8, &text(512)),
            bad.clone(),
        ),
        (
            "name without end",
            gzip_member(&plain, 8, &[b'n'; 4]),
            bad.clone(),
        ),
        (
            "comment of 511 bytes",
            gzip_member(&plain, 16, &text(511)),
            ok.clone(),
        ),
        (
            "comment of 512 bytes",
            gzip_member(&plain, 16, &text(512)),
            bad.clone(),
        ),
        (
            "extra, name and comment",
            gzip_member(&plain, 4 | 8 | 16, &[extra(5), text(9), text(3)].concat()),
            ok.clone(),
        ),
        (
            "header checksum",
            gzip_member(&plain, 2 | 8, &header_crc(2 | 8, &text(4), true)),
            ok.clone(),
        ),
        (
            "wrong header checksum",
            gzip_member(&plain, 2 | 8, &header_crc(2 | 8, &text(4), false)),
            bad.clone(),
        ),
        (
            "reserved flags are ignored",
            gzip_member(&plain, 0xe0, &[]),
            ok.clone(),
        ),
    ];
    for (name, body, want) in cases {
        assert_eq!(
            dec(&body, &["gzip"], DECODED_BODY_LIMIT_BYTES),
            want,
            "{name}"
        );
    }
}

#[test]
fn decode_zlib_header_rules() {
    let _g = lock_budget();
    let plain = benign_json_body();
    let raw = raw_deflate_bytes(&plain);
    let bad = (None, SKIP_REASON_DECOMPRESS_ERROR.to_string());
    let adler = adler2::adler32_slice(&plain);
    let wrap = |cmf: u8, flg: u8, dict: Option<u32>| {
        let mut v = vec![cmf, flg];
        if let Some(d) = dict {
            v.extend_from_slice(&d.to_be_bytes());
        }
        v.extend_from_slice(&raw);
        v.extend_from_slice(&adler.to_be_bytes());
        v
    };
    // The FCHECK bits make (CMF * 256 + FLG) a multiple of 31.
    let flg = |cmf: u8, bits: u8| {
        let base = u16::from(cmf) * 256 + u16::from(bits);
        bits + ((31 - base % 31) % 31) as u8
    };
    let ok = (Some(plain.clone()), String::new());
    assert_eq!(
        dec(&wrap(0x78, flg(0x78, 0), None), &["deflate"], 1 << 20),
        ok
    );
    assert_eq!(
        dec(&wrap(0x48, flg(0x48, 0), None), &["deflate"], 1 << 20),
        ok
    );
    // FDICT with the Adler-32 of no dictionary (1) is accepted.
    assert_eq!(
        dec(&wrap(0x78, flg(0x78, 0x20), Some(1)), &["deflate"], 1 << 20),
        ok
    );
    // Anything else that is not a valid header is read as raw deflate and fails.
    assert_eq!(
        dec(&wrap(0x78, flg(0x78, 0x20), Some(7)), &["deflate"], 1 << 20),
        bad
    );
    assert_eq!(dec(&wrap(0x78, 0x9d, None), &["deflate"], 1 << 20), bad);
    assert_eq!(
        dec(&wrap(0x88, flg(0x88, 0), None), &["deflate"], 1 << 20),
        bad
    );
    assert_eq!(
        dec(&wrap(0x79, flg(0x79, 0), None), &["deflate"], 1 << 20),
        bad
    );
}

#[test]
fn decode_gzip_members_do_not_share_history() {
    let _g = lock_budget();
    // The second member is one fixed-code block: a match of length 3 at distance 5, which
    // would reach back into the first member's output.
    let mut w = BitWriter::default();
    w.put(1, 1);
    w.put(1, 2);
    w.put_code(1, 7); // length symbol 257 = 3
    w.put_code(4, 5); // distance symbol 4 = 5..6
    w.put(0, 1); // distance 5
    w.put_code(0, 7); // end of block
    let mut second = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    second.extend(w.finish());
    let mut crc = flate2::Crc::new();
    crc.update(b"def");
    second.extend_from_slice(&crc.sum().to_le_bytes());
    second.extend_from_slice(&3u32.to_le_bytes());
    let body = [gzip_bytes(b"abcdefgh"), second].concat();
    assert_eq!(
        dec(&body, &["gzip"], DECODED_BODY_LIMIT_BYTES),
        (None, SKIP_REASON_DECOMPRESS_ERROR.to_string())
    );
}

#[test]
fn gunzip_to_vec_decodes_whole_files() {
    let plain = binary_blob(300_000);
    let gz = [gzip_bytes(&plain[..1000]), gzip_bytes(&plain[1000..])].concat();
    assert_eq!(gunzip_to_vec(&gz, 1 << 20).unwrap(), plain);
    assert_eq!(gunzip_to_vec(&gz, plain.len()).unwrap(), plain);
    assert!(gunzip_to_vec(&gz, plain.len() - 1).is_err());
    assert!(gunzip_to_vec(&gz[..gz.len() - 3], 1 << 20).is_err());
    assert!(gunzip_to_vec(&[gz, vec![0]].concat(), 1 << 20).is_err());
}

/// What an independent reader makes of a whole stream (None when it rejects it).
fn reference_decode(coding: &str, body: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    let zlib_like = body.len() >= 2
        && body[0] & 0x0f == 8
        && body[0] >> 4 <= 7
        && (u16::from(body[0]) << 8 | u16::from(body[1])) % 31 == 0
        && body[1] & 0x20 == 0;
    match coding {
        "gzip" => flate2::read::MultiGzDecoder::new(body).read_to_end(&mut out),
        "deflate" if zlib_like => flate2::read::ZlibDecoder::new(body).read_to_end(&mut out),
        "deflate" => flate2::read::DeflateDecoder::new(body).read_to_end(&mut out),
        _ => brotli::Decompressor::new(body, 4096).read_to_end(&mut out),
    }
    .ok()
    .map(|_| out)
}

fn mutate_once(b: &mut Vec<u8>, rng: &mut XorShift) {
    let n = b.len();
    // Half of the edits land in the first bytes (headers), a tenth in the last (trailers).
    let at = match rng.below(10) {
        0..=4 => rng.below(n.min(24)),
        5 => n.saturating_sub(1 + rng.below(n.min(12))),
        _ => rng.below(n),
    };
    match rng.below(7) {
        0 if n > 0 => b[at] ^= 1 << rng.below(8),
        1 if n > 0 => b[at] = rng.next() as u8,
        2 => b.truncate(rng.below(n + 1)),
        3 if n > 0 => {
            b.remove(at);
        }
        4 => b.insert(at.min(n), rng.next() as u8),
        5 if n > 8 => {
            let (from, len) = (rng.below(n - 4), 1 + rng.below(12));
            let piece: Vec<u8> = b[from..(from + len).min(n)].to_vec();
            b.splice(at.min(n)..at.min(n), piece).for_each(drop);
        }
        _ => b.extend((0..1 + rng.below(8)).map(|_| rng.next() as u8)),
    }
}

/// Fixed-seed mutations of encoder output for a bounded time. Every case must keep the rules the
/// limits promise: nothing panics, the reservation is returned, a smaller limit gives a prefix of
/// the complete decode, the exact size still decodes whole, and a stream decoded whole is one an
/// independent reader decodes to the same bytes.
#[test]
fn decode_mutation_fuzz_keeps_the_limit_rules() {
    let _g = with_decode_budget(0);
    let plains = [
        benign_json_body().repeat(40),
        binary_blob(3000),
        vec![0u8; 20_000],
        b"abcabcabd".repeat(500),
        Vec::new(),
    ];
    let mut bases: Vec<(&str, Vec<u8>)> = Vec::new();
    for p in &plains {
        bases.push(("gzip", gzip_bytes(p)));
        bases.push(("deflate", zlib_bytes(p)));
        bases.push(("deflate", raw_deflate_bytes(p)));
        bases.push(("br", brotli_bytes(p)));
    }
    bases.push((
        "gzip",
        [gzip_bytes(&plains[0]), gzip_bytes(&plains[1])].concat(),
    ));
    // WAFIO_DECODE_FUZZ_SECS and WAFIO_DECODE_FUZZ_SEED run a longer session by hand.
    let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    let budget = std::time::Duration::from_secs(env("WAFIO_DECODE_FUZZ_SECS").unwrap_or(3));
    let mut rng = XorShift(env("WAFIO_DECODE_FUZZ_SEED").unwrap_or(0x5eed_1234_abcd_ef01));
    let start = std::time::Instant::now();
    let (mut cases, mut whole, mut cut) = (0u64, 0u64, 0u64);
    'run: for round in 0.. {
        for (coding, base) in &bases {
            if start.elapsed() > budget {
                break 'run;
            }
            let mut body = base.clone();
            if round > 0 {
                for _ in 0..1 + rng.below(3) {
                    mutate_once(&mut body, &mut rng);
                }
            }
            cases += 1;
            let (full, skipped) = dec(&body, &[coding], DECODED_BODY_LIMIT_BYTES);
            assert_eq!(inflight_decode_bytes_used(), 0, "{coding} {body:02x?}");
            let Some(out) = full else {
                assert_ne!(skipped, "", "{coding} {body:02x?}");
                continue;
            };
            if !skipped.is_empty() {
                continue;
            }
            whole += 1;
            for l in [0, 1, out.len() / 2, out.len().saturating_sub(1)] {
                if l >= out.len() {
                    continue;
                }
                cut += 1;
                let (part, skipped) = dec(&body, &[coding], l as i64);
                assert_eq!(
                    skipped, SKIP_REASON_DECOMPRESS_LIMIT,
                    "{coding} {l} {body:02x?}"
                );
                assert_eq!(part.as_deref(), (l > 0).then(|| &out[..l]), "{coding} {l}");
            }
            let exact = dec(&body, &[coding], out.len() as i64);
            assert_eq!(
                exact,
                (Some(out.clone()), String::new()),
                "{coding} {body:02x?}"
            );
            // gzip with reserved flag bits is accepted here and refused by the reference reader.
            let reserved = *coding == "gzip" && body.get(3).is_some_and(|f| f & 0xe0 != 0);
            if !reserved && base != &bases[bases.len() - 1].1 {
                assert_eq!(
                    reference_decode(coding, &body),
                    Some(out),
                    "{coding} {body:02x?}"
                );
            }
        }
    }
    eprintln!("decode fuzz: {cases} cases, {whole} decoded whole, {cut} cut at a smaller limit");
    assert!(
        cases > 2000 && whole > 100 && cut > 100,
        "{cases} {whole} {cut}"
    );
}
