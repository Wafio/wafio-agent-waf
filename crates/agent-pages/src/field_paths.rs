//! Field rules: the JSON, urlencoded and multipart request body rewriters, response
//! decryption, the stored request body masks and the multipart preview.
//! AES-256-GCM, 12-byte random nonce, output base64(nonce ‖ ciphertext ‖ tag).

use crate::crypto::{
    B64, Gcm, decode_base64_partial, encode_base64, fill_random_bytes, hex_decode,
};
use crate::field_names::{
    FormField, collect_multipart_part_names, remap_json_path, split_form_name,
    unescape_form_leniently,
};
use crate::json_tree::{
    DecodeError, JValue, Token, TokenDecoder, scan_value_end_with_depth, serialize_sorted,
};
use crate::multipart;
use wafio_bytetext::strings::{eq_ignore_case, join, split, trim_whitespace};

pub const FIELD_SOURCE_FORM_URLENCODED: &str = "urlencoded";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestFieldRule {
    pub field: String,
    pub source: String,
    pub action: String,
    pub cipher_key_hex: String,
    pub methods: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseFieldTransformRule {
    pub field: String,
    pub action: String,
    pub cipher_key_hex: String,
}

/// Empty list = every method; trimmed, upper-cased compare.
pub fn allows_method(methods: &[String], method: &[u8]) -> bool {
    if methods.is_empty() {
        return true;
    }
    let method = wafio_bytetext::strings::to_uppercase(trim_whitespace(method));
    methods
        .iter()
        .any(|m| wafio_bytetext::strings::to_uppercase(trim_whitespace(m.as_bytes())) == method)
}

/// The method filter for the field rules of a request (the path match is engine-rules').
pub fn filter_field_rules_by_method(
    rules: &[RequestFieldRule],
    method: &[u8],
) -> Vec<RequestFieldRule> {
    rules
        .iter()
        .filter(|r| allows_method(&r.methods, method))
        .cloned()
        .collect()
}

const UTF8_BYTE_ORDER_MARK: &[u8] = b"\xef\xbb\xbf";

// Documents nested deeper than this are decoded and rewritten on a big-stack thread:
// The scanner accepts 10000 levels and the tree code here recurses.
const INLINE_DEPTH: usize = 512;

fn with_stack<T: Send>(depth: usize, f: impl FnOnce() -> T + Send) -> T {
    if depth <= INLINE_DEPTH {
        return f();
    }
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn_scoped(s, f)
            .expect("spawn deep-JSON thread")
            .join()
            .expect("deep-JSON thread")
    })
}

/// The first document after a BOM (numbers exact), the rest
/// forwarded as is, and the nesting depth (for `with_stack`).
pub fn parse_json_document(body: &[u8]) -> Result<(&[u8], &[u8], usize), DecodeError> {
    let body = body.strip_prefix(UTF8_BYTE_ORDER_MARK).unwrap_or(body);
    let (end, depth) = scan_value_end_with_depth(body, 0)?;
    Ok((&body[..end], &body[end..], depth))
}

/// A string as is, anything else as its JSON text.
pub fn leaf_text(v: &JValue) -> Vec<u8> {
    match v {
        JValue::String(s) => s.clone(),
        JValue::Number(n) => n.clone(),
        v => serialize_sorted(v),
    }
}

pub fn form_key_in_rules(fields: &[FormField], name: &[u8]) -> bool {
    let segs = split_form_name(name);
    fields.iter().any(|f| f.matches(name, &segs))
}

/// 64 hex chars → AES-256 key.
pub fn parse_cipher_key_hex(hex_key: &str) -> Result<[u8; 32], String> {
    let k = hex_decode(hex_key.as_bytes()).map_err(|e| format!("invalid AES key hex: {e}"))?;
    let n = k.len();
    k.try_into()
        .map_err(|_| format!("AES-256 key must be 32 bytes, got {n}"))
}

/// Nonce-prefixed AES-256-GCM.
pub fn open_gcm_ciphertext(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let g = Gcm::new(key);
    if ciphertext.len() < g.required_nonce_len() {
        return Err("ciphertext too short".into());
    }
    let (nonce, data) = ciphertext.split_at(g.required_nonce_len());
    g.open(nonce, data)
}

/// One rule with its cipher built once and its failures counted.
pub struct FieldRewriter<'a> {
    rule: &'a RequestFieldRule,
    gcm: Option<Gcm>,
    key_error: Option<String>,
    pub failures: usize,
    pub first_error: Option<String>,
}

impl<'a> FieldRewriter<'a> {
    pub fn new(rule: &'a RequestFieldRule) -> Self {
        let (mut gcm, mut key_err) = (None, None);
        if rule.action == "encrypt_aes" || rule.action == "decrypt_aes" {
            match parse_cipher_key_hex(&rule.cipher_key_hex) {
                Ok(k) => gcm = Some(Gcm::new(&k)),
                Err(e) => key_err = Some(e),
            }
        }
        FieldRewriter {
            rule,
            gcm,
            key_error: key_err,
            failures: 0,
            first_error: None,
        }
    }

    /// The transformed value, or the value and false (counted).
    pub fn apply(&mut self, value: &[u8]) -> (Vec<u8>, bool) {
        match self.run(value) {
            Ok(v) => (v, true),
            Err(e) => {
                self.failures += 1;
                self.first_error.get_or_insert(e);
                (value.to_vec(), false)
            }
        }
    }

    fn run(&self, value: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(e) = &self.key_error {
            return Err(e.clone());
        }
        match self.rule.action.as_str() {
            "encrypt_aes" => {
                let g = self.gcm.as_ref().expect("cipher");
                let mut nonce = vec![0u8; g.required_nonce_len()];
                fill_random_bytes(&mut nonce).map_err(|e| e.to_string())?;
                let n = nonce.clone();
                Ok(encode_base64(B64::Std, &g.seal(nonce, &n, value)))
            }
            "decrypt_aes" => {
                let g = self.gcm.as_ref().expect("cipher");
                let (raw, ok) = decode_base64_partial(B64::Std, value);
                if !ok {
                    return Err("illegal base64 data".into());
                }
                if raw.len() < g.required_nonce_len() {
                    return Err("ciphertext too short".into());
                }
                let (nonce, ct) = raw.split_at(g.required_nonce_len());
                g.open(nonce, ct)
            }
            "mask" => Ok(b"[MASKED]".to_vec()),
            _ => Ok(value.to_vec()),
        }
    }

    /// One line for the values this request left unchanged.
    pub fn report_failures(&self, kind: &str) -> Option<String> {
        (self.failures > 0).then(|| {
            let line = format!(
                "[field-rule] {} on {} field {:?}: {} value(s) left unchanged (first error: {})",
                self.rule.action,
                kind,
                self.rule.field,
                self.failures,
                self.first_error.as_deref().unwrap_or("")
            );
            tracing::warn!("{line}");
            line
        })
    }
}

/// ct_category "form" (urlencoded), "json" or "multipart".
pub fn rule_applies_to_source(rule: &RequestFieldRule, ct_category: &str) -> bool {
    match String::from_utf8_lossy(&wafio_bytetext::strings::to_lowercase(
        rule.source.as_bytes(),
    ))
    .as_ref()
    {
        "any" | "" => true,
        FIELD_SOURCE_FORM_URLENCODED => ct_category == "form",
        "form" => ct_category == "form" || ct_category == "multipart",
        "body.json" | "json" => ct_category == "json",
        "multipart" => ct_category == "multipart",
        _ => false,
    }
}

/// Returns (body, content type) with every non-mask rule applied; mask rules only touch the
/// stored preview.
pub fn transform_request_body(
    body: &[u8],
    raw_content_type: &[u8],
    ct_category: &str,
    rules: &[RequestFieldRule],
) -> (Vec<u8>, Vec<u8>) {
    if body.is_empty() || rules.is_empty() {
        return (body.to_vec(), raw_content_type.to_vec());
    }
    let active: Vec<RequestFieldRule> = rules
        .iter()
        .filter(|r| r.action != "mask")
        .cloned()
        .collect();
    if active.is_empty() {
        return (body.to_vec(), raw_content_type.to_vec());
    }
    match ct_category {
        "form" => transform_form_body(body, raw_content_type, &active),
        "json" => transform_json_body(body, raw_content_type, &active),
        "multipart" => transform_multipart_body(body, raw_content_type, &active),
        _ => (body.to_vec(), raw_content_type.to_vec()),
    }
}

/// Rewrites every value a rule names (one rule per value), names and
/// values read leniently; other pairs and the order kept byte for byte.
pub fn transform_form_body(
    body: &[u8],
    content_type: &[u8],
    rules: &[RequestFieldRule],
) -> (Vec<u8>, Vec<u8>) {
    let mut active: Vec<(FieldRewriter, FormField)> = rules
        .iter()
        .filter(|r| rule_applies_to_source(r, "form"))
        .map(|r| (FieldRewriter::new(r), FormField::new(r.field.as_bytes())))
        .collect();
    if active.is_empty() {
        return (body.to_vec(), content_type.to_vec());
    }
    let mut pairs: Vec<Vec<u8>> = split(body, b"&").into_iter().map(<[u8]>::to_vec).collect();
    let mut modified = false;
    for pair in pairs.iter_mut() {
        let (raw_name, raw_value, _) = wafio_bytetext::strings::cut(pair, b"=");
        let name = unescape_form_leniently(raw_name);
        let segs = split_form_name(&name);
        let mut replaced = None;
        for (t, f) in active.iter_mut() {
            if !f.matches(&name, &segs) {
                continue;
            }
            let (new_val, ok) = t.apply(&unescape_form_leniently(raw_value));
            if ok {
                replaced = Some(
                    [
                        raw_name,
                        b"=",
                        &wafio_bytetext::url::escape_query_component(&new_val),
                    ]
                    .concat(),
                );
            }
            break;
        }
        if let Some(p) = replaced {
            *pair = p;
            modified = true;
        }
    }
    for (t, _) in &active {
        t.report_failures("form");
    }
    if !modified {
        return (body.to_vec(), content_type.to_vec());
    }
    (join(&pairs, b"&"), content_type.to_vec())
}

/// Rewrites every value a rule's dot path names (encrypt_aes takes a named
/// array or object whole, decrypt_aes each element); one rule per path.
pub fn transform_json_body(
    body: &[u8],
    content_type: &[u8],
    rules: &[RequestFieldRule],
) -> (Vec<u8>, Vec<u8>) {
    let Ok((doc, rest, depth)) = parse_json_document(body) else {
        return (body.to_vec(), content_type.to_vec());
    };
    let out = with_stack(depth, || {
        let mut root = crate::json_tree::build(doc);
        let mut modified = false;
        let mut done: Vec<&str> = Vec::new();
        for rule in rules {
            if !rule_applies_to_source(rule, "json")
                || done
                    .iter()
                    .any(|f| eq_ignore_case(f.as_bytes(), rule.field.as_bytes()))
            {
                continue;
            }
            done.push(&rule.field);
            let mut t = FieldRewriter::new(rule);
            remap_json_path(
                &mut root,
                rule.field.as_bytes(),
                rule.action == "encrypt_aes",
                &mut |v| {
                    let (new_val, ok) = t.apply(&leaf_text(&v));
                    if !ok {
                        return v;
                    }
                    modified = true;
                    JValue::String(new_val)
                },
            );
            t.report_failures("json");
        }
        modified.then(|| [serialize_sorted(&root).as_slice(), rest].concat())
    });
    match out {
        Some(b) => (b, content_type.to_vec()),
        None => (body.to_vec(), content_type.to_vec()),
    }
}

/// Rebuilds the body with a new boundary; any parse problem forwards the original.
pub fn transform_multipart_body(
    body: &[u8],
    content_type: &[u8],
    rules: &[RequestFieldRule],
) -> (Vec<u8>, Vec<u8>) {
    let unchanged = || (body.to_vec(), content_type.to_vec());
    let Ok((_, params)) = multipart::split_media_type(content_type) else {
        return unchanged();
    };
    let Some(boundary) = params.get(b"boundary".as_slice()).filter(|b| !b.is_empty()) else {
        return unchanged();
    };
    let mut active: Vec<(FieldRewriter, FormField)> = rules
        .iter()
        .filter(|r| rule_applies_to_source(r, "multipart"))
        .map(|r| (FieldRewriter::new(r), FormField::new(r.field.as_bytes())))
        .collect();
    if active.is_empty() {
        return unchanged();
    }
    let result = (|| {
        let mut mr = multipart::Reader::new(body, boundary);
        let mut mw = multipart::Writer::new().ok()?;
        let mut modified = false;
        loop {
            let part = match mr.next_decoded_part() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(_) => return None,
            };
            let names = collect_multipart_part_names(
                &part.form_field_name(),
                &part.header_field_values(b"Content-Disposition"),
            );
            if part.error.is_some() {
                return None; // reading the part failed: forward the original
            }
            let mut part_body = part.body.clone();
            'rules: for (t, f) in active.iter_mut() {
                for name in &names {
                    if !f.matches(name, &split_form_name(name)) {
                        continue;
                    }
                    let (new_val, ok) = t.apply(&part_body);
                    if ok {
                        part_body = new_val;
                        modified = true;
                    }
                    break 'rules;
                }
            }
            mw.start_part(&part.header);
            mw.write(&part_body);
        }
        if !modified {
            return None;
        }
        let ct = [b"multipart/form-data; boundary=".as_slice(), mw.boundary()].concat();
        Some((mw.close(), ct))
    })();
    for (t, _) in &active {
        t.report_failures("multipart");
    }
    result.unwrap_or_else(unchanged)
}

/// base64(nonce ‖ ciphertext ‖ tag) → plaintext.
pub fn decrypt_response_payload(body: &[u8], hex_key: &str) -> Result<Vec<u8>, String> {
    let key = parse_cipher_key_hex(hex_key)?;
    let (raw, ok) = decode_base64_partial(B64::Std, trim_whitespace(body));
    if !ok {
        return Err("base64 decode: illegal base64 data".into());
    }
    open_gcm_ciphertext(&key, &raw)
}

/// Standard then URL base64.
pub fn decrypt_base64_field(s: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    let s = trim_whitespace(s);
    let (mut raw, ok) = decode_base64_partial(B64::Std, s);
    if !ok {
        let (r, ok) = decode_base64_partial(B64::Url, s);
        if !ok {
            return None;
        }
        raw = r;
    }
    open_gcm_ciphertext(key, &raw).ok()
}

/// Decrypts in place every ciphertext string each rule's dot
/// path names (arrays element by element).
pub fn decrypt_json_response_fields(
    body: &[u8],
    rules: &[ResponseFieldTransformRule],
) -> Result<Vec<u8>, String> {
    let (doc, rest, depth) = parse_json_document(body).map_err(|e| format!("json parse: {e}"))?;
    with_stack(depth, || {
        let mut root = crate::json_tree::build(doc);
        for r in rules {
            let key = parse_cipher_key_hex(&r.cipher_key_hex)
                .map_err(|e| format!("field {:?}: {e}", r.field))?;
            remap_json_path(&mut root, r.field.as_bytes(), false, &mut |v| {
                if let JValue::String(s) = &v
                    && let Some(plain) = decrypt_base64_field(s, &key)
                {
                    return JValue::String(plain);
                }
                v
            });
        }
        Ok([serialize_sorted(&root).as_slice(), rest].concat())
    })
}

/// Matchers of the mask rules for a form or multipart body.
pub fn redact_form_fields(ct_category: &str, rules: &[RequestFieldRule]) -> Vec<FormField> {
    rules
        .iter()
        .filter(|r| r.action == "mask" && rule_applies_to_source(r, ct_category))
        .map(|r| FormField::new(r.field.as_bytes()))
        .collect()
}

pub fn redact_form_preview(preview: &[u8], fields: &[FormField]) -> Vec<u8> {
    let mut pairs: Vec<Vec<u8>> = split(preview, b"&")
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();
    let mut changed = false;
    for pair in pairs.iter_mut() {
        let (raw_name, _, _) = wafio_bytetext::strings::cut(pair, b"=");
        if form_key_in_rules(fields, &unescape_form_leniently(raw_name)) {
            *pair = [raw_name, b"=[MASKED]"].concat();
            changed = true;
        }
    }
    if !changed {
        return preview.to_vec();
    }
    join(&pairs, b"&")
}

/// Masks the named values over the token stream (a cut preview is
/// masked up to the cut; after a syntax error everything is masked).
pub fn redact_json_preview(preview: &[u8], fields: &[&str]) -> Vec<u8> {
    struct Frame {
        object: bool,
        expects_key: bool,
        key: Vec<u8>,
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut spans: Vec<(usize, usize, &[u8])> = Vec::new();
    let named = |stack: &[Frame]| {
        let keys: Vec<&[u8]> = stack
            .iter()
            .filter(|f| f.object)
            .map(|f| f.key.as_slice())
            .collect();
        let path = join(&keys, b".");
        fields.iter().any(|f| eq_ignore_case(&path, f.as_bytes()))
    };
    fn value_completed(stack: &mut [Frame]) {
        if let Some(top) = stack.last_mut()
            && top.object
        {
            top.expects_key = true;
        }
    }
    let base = if preview.starts_with(UTF8_BYTE_ORDER_MARK) {
        UTF8_BYTE_ORDER_MARK.len()
    } else {
        0
    };
    let mut dec = TokenDecoder::new(&preview[base..]);
    loop {
        let tok = match dec.token() {
            Ok(t) => t,
            Err(e) => {
                if e == DecodeError::Syntax {
                    spans.push((base + dec.consumed_offset(), preview.len(), b"[MASKED]"));
                }
                break;
            }
        };
        if let Token::Delim(d) = tok {
            if d == b'{' || d == b'[' {
                stack.push(Frame {
                    object: d == b'{',
                    expects_key: d == b'{',
                    key: Vec::new(),
                });
            } else {
                stack.pop();
                value_completed(&mut stack);
            }
            continue;
        }
        let Some(top) = stack.last_mut().filter(|f| f.object && f.expects_key) else {
            value_completed(&mut stack);
            continue;
        };
        top.key = match tok {
            Token::String(s) => s,
            _ => Vec::new(),
        };
        top.expects_key = false;
        if !named(&stack) {
            continue;
        }
        let start = base + dec.consumed_offset();
        let mut end = preview.len();
        let mut depth = 0i64;
        while let Ok(vt) = dec.token() {
            if let Token::Delim(d) = vt {
                depth += if d == b'{' || d == b'[' { 1 } else { -1 };
            }
            if depth == 0 {
                end = base + dec.consumed_offset();
                break;
            }
        }
        spans.push((start, end, br#":"[MASKED]""#));
        if let Some(top) = stack.last_mut() {
            top.expects_key = true;
        }
        if end == preview.len() {
            break;
        }
    }
    if spans.is_empty() {
        return preview.to_vec();
    }
    let mut b = Vec::with_capacity(preview.len());
    let mut last = 0;
    for (start, end, with) in spans {
        if start < last {
            continue;
        }
        b.extend_from_slice(&preview[last..start]);
        b.extend_from_slice(with);
        last = end;
    }
    b.extend_from_slice(&preview[last..]);
    b
}

/// The stored request body with mask-named values replaced
/// (multipart is masked while its preview is built).
pub fn redact_body_preview(
    preview: &[u8],
    ct_category: &str,
    rules: &[RequestFieldRule],
) -> Vec<u8> {
    if preview.is_empty() {
        return preview.to_vec();
    }
    match ct_category {
        "json" => {
            let fields: Vec<&str> = rules
                .iter()
                .filter(|r| r.action == "mask" && rule_applies_to_source(r, ct_category))
                .map(|r| r.field.as_str())
                .collect();
            if !fields.is_empty() {
                return redact_json_preview(preview, &fields);
            }
        }
        "form" => {
            let fields = redact_form_fields(ct_category, rules);
            if !fields.is_empty() {
                return redact_form_preview(preview, &fields);
            }
        }
        _ => {}
    }
    preview.to_vec()
}

/// "name=value&…" of text fields (≤ 256 bytes each), file names
/// for files, mask-named parts as [MASKED]; at most 20 parts.
pub fn compose_multipart_preview(
    content_type: &[u8],
    body: &[u8],
    rules: &[RequestFieldRule],
) -> Vec<u8> {
    let masked = redact_form_fields("multipart", rules);
    let summary = || format!("[multipart {} bytes]", body.len()).into_bytes();
    let Ok((_, params)) = multipart::split_media_type(content_type) else {
        return summary();
    };
    let Some(boundary) = params.get(b"boundary".as_slice()) else {
        return summary();
    };
    let mut mr = multipart::Reader::new(body, boundary);
    let mut parts: Vec<Vec<u8>> = Vec::new();
    while let Ok(Some(p)) = mr.next_decoded_part() {
        let name = p.form_field_name();
        let filename = p.client_file_name();
        let names =
            collect_multipart_part_names(&name, &p.header_field_values(b"Content-Disposition"));
        if !masked.is_empty()
            && (name.is_empty() || names.iter().any(|n| form_key_in_rules(&masked, n)))
        {
            parts.push([name.as_slice(), b"=[MASKED]"].concat());
        } else if !filename.is_empty() {
            parts.push([name.as_slice(), b"=[file:", &filename, b"]"].concat());
        } else {
            let val = &p.body[..p.body.len().min(256)];
            if p.read_error_within(256).is_none() && !val.is_empty() {
                parts.push([name.as_slice(), b"=", val].concat());
            }
        }
        if parts.len() >= 20 {
            break;
        }
    }
    if parts.is_empty() {
        return summary();
    }
    join(&parts, b"&")
}

pub fn filter_decrypt_rules(rules: &[RequestFieldRule]) -> Vec<RequestFieldRule> {
    rules
        .iter()
        .filter(|r| r.action == "decrypt_aes")
        .cloned()
        .collect()
}

pub fn filter_encrypt_rules(rules: &[RequestFieldRule]) -> Vec<RequestFieldRule> {
    rules
        .iter()
        .filter(|r| r.action == "encrypt_aes")
        .cloned()
        .collect()
}
