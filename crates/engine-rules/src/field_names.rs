//! How apps read form, multipart and JSON field names.

use crate::custom_rules_v2::DynamicJson;
use wafio_domain::text_helpers::eq_ignore_case;

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn hex_digit_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// '+' is a space, valid %XX escapes decoded, invalid kept.
pub fn unescape_form_leniently(s: &[u8]) -> Vec<u8> {
    if !s.contains(&b'%') && !s.contains(&b'+') {
        return s.to_vec();
    }
    let mut b = Vec::with_capacity(s.len());
    push_form_unescaped(&mut b, s);
    b
}

fn push_form_unescaped(b: &mut Vec<u8>, s: &[u8]) {
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'+' {
            b.push(b' ');
        } else if c == b'%' && i + 2 < s.len() && is_hex_digit(s[i + 1]) && is_hex_digit(s[i + 2]) {
            b.push(hex_digit_value(s[i + 1]) << 4 | hex_digit_value(s[i + 2]));
            i += 2;
        } else {
            b.push(c);
        }
        i += 1;
    }
}

/// FormKeyMatcher: whether a form key names a field, the way apps bind it.
#[derive(Clone, Debug)]
pub struct FormKeyMatcher {
    field: Vec<u8>,
    php: Vec<u8>,
    bracket: Option<Vec<u8>>,
    min_len: usize,
    max_len: usize,
}

impl FormKeyMatcher {
    pub fn new(field: &str) -> FormKeyMatcher {
        let f = field.as_bytes().to_vec();
        let php = push_php_form_key(&f);
        let segs: Vec<&str> = field.split('.').collect();
        let bracket = if segs.len() > 1 {
            Some(format!("{}[{}]", segs[0], segs[1..].join("][")).into_bytes())
        } else {
            None
        };
        let min_len = wafio_bytetext::utf8::count_code_points(&f);
        let max_len = 3 * f.len().max(bracket.as_ref().map_or(0, Vec::len)) + 256;
        FormKeyMatcher {
            field: f,
            php,
            bracket,
            min_len,
            max_len,
        }
    }
    pub fn min_len(&self) -> usize {
        self.min_len
    }
    /// `k` is a raw (urlencoded) or decoded key.
    pub fn matches(&self, k: &[u8], urlencoded: bool) -> bool {
        if k.len() < self.min_len || k.len() > self.max_len {
            return false;
        }
        let mut key = Vec::with_capacity(k.len());
        if urlencoded {
            push_form_unescaped(&mut key, k);
        } else {
            key.extend_from_slice(k);
        }
        if let Some(i) = key.iter().position(|&c| c == 0) {
            key.truncate(i);
        }
        if self.matches_name(&key) {
            return true;
        }
        if key.len() > 1 && key[key.len() - 1] == b']' {
            if let Some(i) = key.iter().position(|&c| c == b'[')
                && i > 0
                && self.matches_name(&key[..i])
            {
                return true;
            }
            if let Some(i) = key.iter().rposition(|&c| c == b'[')
                && i > 0
                && self.matches_name(&key[..i])
            {
                return true;
            }
        }
        false
    }
    fn matches_name(&self, k: &[u8]) -> bool {
        if eq_ignore_case(k, &self.field)
            || self.bracket.as_ref().is_some_and(|b| eq_ignore_case(k, b))
        {
            return true;
        }
        eq_ignore_case(&push_php_form_key(k), &self.php)
    }
}

/// PHP's mangling of a form key ('.' and ' ' before the first '['
/// become '_', leading spaces dropped).
fn push_php_form_key(k: &[u8]) -> Vec<u8> {
    let start = k.iter().position(|&c| c != b' ').unwrap_or(k.len());
    let k = &k[start..];
    let end = k.iter().position(|&c| c == b'[').unwrap_or(k.len());
    k.iter()
        .enumerate()
        .map(|(i, &c)| {
            if i < end && (c == b' ' || c == b'.') {
                b'_'
            } else {
                c
            }
        })
        .collect()
}

/// FormField: a configured field name matched against form and multipart names.
#[derive(Clone, Debug)]
pub struct FormField {
    lenient: FormKeyMatcher,
    segments: Vec<Vec<u8>>,
}

impl FormField {
    pub fn new(field: &str) -> FormField {
        FormField {
            lenient: FormKeyMatcher::new(field),
            segments: split_form_name(field.as_bytes()),
        }
    }
    pub fn matches(&self, name: &[u8], name_segs: &[Vec<u8>]) -> bool {
        if self.lenient.matches(name, false) {
            return true;
        }
        if self.segments.len() < 2
            || name_segs.len() < self.segments.len()
            || !eq_ignore_case(&name_segs[0], &self.segments[0])
        {
            return false;
        }
        let mut next = 1;
        for s in &name_segs[1..] {
            if next < self.segments.len() && eq_ignore_case(s, &self.segments[next]) {
                next += 1;
            }
        }
        next == self.segments.len()
    }
}

/// The segments of a bracket/dot name ("" for a plain name).
pub fn split_form_name(name: &[u8]) -> Vec<Vec<u8>> {
    let mut name = name;
    if let Some(i) = name.iter().position(|&c| c == 0) {
        name = &name[..i];
    }
    let start = name.iter().position(|&c| c != b' ').unwrap_or(name.len());
    let name = &name[start..];
    if !name.iter().any(|&c| c == b'[' || c == b'.') {
        return Vec::new();
    }
    // Split on '[', ']' and '.', dropping empty pieces (ASCII separators: byte split is equivalent).
    name.split(|&c| c == b'[' || c == b']' || c == b'.')
        .filter(|s| !s.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// Multipart part names from a part's form name and Content-Disposition header values.
pub fn collect_multipart_part_names(
    form_name: &[u8],
    content_dispositions: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    if !form_name.is_empty() {
        return vec![form_name.to_vec()];
    }
    let mut names = Vec::new();
    for cd in content_dispositions {
        for param in cd.split(|&c| c == b';') {
            if let Some(eq) = param.iter().position(|&c| c == b'=')
                && eq_ignore_case(
                    wafio_bytetext::strings::trim_whitespace(&param[..eq]),
                    b"name",
                )
            {
                let v = wafio_bytetext::strings::trim_whitespace(&param[eq + 1..]);
                names.push(wafio_bytetext::strings::trim_chars(v, b"\"").to_vec());
            }
        }
    }
    names
}

fn field_step<'a>(key: &str, field: &'a str) -> Option<&'a str> {
    let (k, f) = (key.as_bytes(), field.as_bytes());
    if f.len() > k.len() && f[k.len()] == b'.' && eq_ignore_case(&f[..k.len()], k) {
        field.get(k.len() + 1..)
    } else {
        None
    }
}

/// Visits every node a dot path names (keys case-insensitive, arrays walked; map keys in
/// sorted order).
pub fn follow_json_path(node: &DynamicJson, field: &str, visit: &mut dyn FnMut(&DynamicJson)) {
    match node {
        DynamicJson::Object(m) => {
            for (key, child) in m {
                if eq_ignore_case(key.as_bytes(), field.as_bytes()) {
                    visit(child);
                } else if let Some(rest) = field_step(key, field) {
                    follow_json_path(child, rest, visit);
                }
            }
        }
        DynamicJson::Array(a) => {
            for e in a {
                follow_json_path(e, field, visit);
            }
        }
        _ => {}
    }
}

/// Replaces every node a dot path names with fn(node); with whole false
/// an array is rewritten element by element.
pub fn remap_json_path(
    node: &mut DynamicJson,
    field: &str,
    whole: bool,
    f: &mut dyn FnMut(DynamicJson) -> DynamicJson,
) {
    match node {
        DynamicJson::Object(m) => {
            for (key, child) in m.iter_mut() {
                if eq_ignore_case(key.as_bytes(), field.as_bytes()) {
                    let v = std::mem::replace(child, DynamicJson::Null);
                    *child = remap_json_leaf(v, whole, f);
                } else if let Some(rest) = field_step(key, field) {
                    remap_json_path(child, rest, whole, f);
                }
            }
        }
        DynamicJson::Array(a) => {
            for e in a {
                remap_json_path(e, field, whole, f);
            }
        }
        _ => {}
    }
}

fn remap_json_leaf(
    v: DynamicJson,
    whole: bool,
    f: &mut dyn FnMut(DynamicJson) -> DynamicJson,
) -> DynamicJson {
    match v {
        DynamicJson::Array(list) if !whole => DynamicJson::Array(
            list.into_iter()
                .map(|x| remap_json_leaf(x, whole, f))
                .collect(),
        ),
        v => f(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_names_match_reference() {
        let m = FormKeyMatcher::new("user.email");
        assert!(m.matches(b"user[email]", false));
        assert!(m.matches(b"user_email", false));
        assert!(m.matches(b"USER.EMAIL", false));
        assert!(m.matches(b"user%5Bemail%5D", true));
        assert!(!m.matches(b"user", false));
        let f = FormField::new("a.b");
        assert!(f.matches(b"a[x][b]", &split_form_name(b"a[x][b]")));
        assert_eq!(unescape_form_leniently(b"a+b%2"), b"a b%2");
    }
}
