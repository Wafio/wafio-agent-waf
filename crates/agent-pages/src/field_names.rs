//! The form-name, multipart-name and JSON-path helpers field rules use. engine-rules owns the
//! shared copy; this one stays in step with it.

use crate::json_tree::JValue;
use wafio_bytetext::strings::{eq_ignore_case, split, trim_start_chars};
use wafio_bytetext::utf8::count_code_points;

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn hex_digit_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// '+' and valid %XX decoded, anything else kept literally.
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

/// Case-insensitive, PHP-mangled, NUL-cut and array-element spellings.
#[derive(Clone, Debug)]
pub struct FormKeyMatcher {
    field: Vec<u8>,
    php: Vec<u8>,
    bracket: Option<Vec<u8>>,
    min_len: usize,
    max_len: usize,
}

impl FormKeyMatcher {
    pub fn new(field: &[u8]) -> Self {
        let php = push_php_form_key(field);
        let segs = split(field, b".");
        let bracket = (segs.len() > 1).then(|| {
            let mut b = segs[0].to_vec();
            b.push(b'[');
            b.extend_from_slice(&wafio_bytetext::strings::join(&segs[1..], b"]["));
            b.push(b']');
            b
        });
        let min_len = count_code_points(field);
        let max_len = 3 * field.len().max(bracket.as_ref().map_or(0, Vec::len)) + 256;
        FormKeyMatcher {
            field: field.to_vec(),
            php,
            bracket,
            min_len,
            max_len,
        }
    }

    pub fn min_len(&self) -> usize {
        self.min_len
    }

    pub fn matches(&self, k: &[u8], urlencoded: bool) -> bool {
        if k.len() < self.min_len || k.len() > self.max_len {
            return false;
        }
        let mut owned = Vec::new();
        let mut key: &[u8] = if urlencoded {
            push_form_unescaped(&mut owned, k);
            &owned
        } else {
            k
        };
        if let Some(i) = key.iter().position(|&c| c == 0) {
            key = &key[..i];
        }
        if self.matches_name(key) {
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

// Leading spaces dropped, ' ' and '.' before the first '[' → '_'.
fn push_php_form_key(k: &[u8]) -> Vec<u8> {
    let k = trim_start_chars(k, b" ");
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

/// A name or a dot path through bracket names.
#[derive(Clone, Debug)]
pub struct FormField {
    lenient: FormKeyMatcher,
    segs: Vec<Vec<u8>>,
}

impl FormField {
    pub fn new(field: &[u8]) -> Self {
        FormField {
            lenient: FormKeyMatcher::new(field),
            segs: split_form_name(field),
        }
    }

    /// `name_segs` is `split_form_name(name)`.
    pub fn matches(&self, name: &[u8], name_segs: &[Vec<u8>]) -> bool {
        if self.lenient.matches(name, false) {
            return true;
        }
        if self.segs.len() < 2
            || name_segs.len() < self.segs.len()
            || !eq_ignore_case(&name_segs[0], &self.segs[0])
        {
            return false;
        }
        let mut next = 1;
        for s in &name_segs[1..] {
            if next < self.segs.len() && eq_ignore_case(s, &self.segs[next]) {
                next += 1;
            }
        }
        next == self.segs.len()
    }
}

/// Splits at '[', ']' and '.' after a NUL cut and leading spaces;
/// empty for a name without '[' or '.'.
pub fn split_form_name(name: &[u8]) -> Vec<Vec<u8>> {
    let name = match name.iter().position(|&c| c == 0) {
        Some(i) => &name[..i],
        None => name,
    };
    let name = trim_start_chars(name, b" ");
    if !name.iter().any(|&c| c == b'[' || c == b'.') {
        return Vec::new();
    }
    name.split(|&c| c == b'[' || c == b']' || c == b'.')
        .filter(|s| !s.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// The form name, or every `name` parameter of every
/// Content-Disposition when no form name is found.
pub fn collect_multipart_part_names(
    form_name: &[u8],
    content_dispositions: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    if !form_name.is_empty() {
        return vec![form_name.to_vec()];
    }
    let mut names = Vec::new();
    for cd in content_dispositions {
        for param in split(cd, b";") {
            let (k, v, ok) = wafio_bytetext::strings::cut(param, b"=");
            if ok && eq_ignore_case(wafio_bytetext::strings::trim_whitespace(k), b"name") {
                names.push(
                    wafio_bytetext::strings::trim_chars(
                        wafio_bytetext::strings::trim_whitespace(v),
                        b"\"",
                    )
                    .to_vec(),
                );
            }
        }
    }
    names
}

/// Replaces every value the dot path names with fn(value); with
/// whole, a named array is one value, otherwise each element (nested arrays too).
pub fn remap_json_path(
    node: &mut JValue,
    field: &[u8],
    whole: bool,
    f: &mut dyn FnMut(JValue) -> JValue,
) {
    match node {
        JValue::Object(m) => {
            for (key, child) in m.iter_mut() {
                if eq_ignore_case(key, field) {
                    let v = std::mem::replace(child, JValue::Null);
                    *child = remap_json_leaf(v, whole, f);
                } else if field.len() > key.len()
                    && field[key.len()] == b'.'
                    && eq_ignore_case(&field[..key.len()], key)
                {
                    remap_json_path(child, &field[key.len() + 1..], whole, f);
                }
            }
        }
        JValue::Array(a) => {
            for elem in a.iter_mut() {
                remap_json_path(elem, field, whole, f);
            }
        }
        _ => {}
    }
}

fn remap_json_leaf(v: JValue, whole: bool, f: &mut dyn FnMut(JValue) -> JValue) -> JValue {
    match v {
        JValue::Array(list) if !whole => JValue::Array(
            list.into_iter()
                .map(|e| remap_json_leaf(e, whole, f))
                .collect(),
        ),
        v => f(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_field_matches() {
        for (name, field, want) in [
            ("photo", "photo", true),
            ("photos[]", "photos[]", true),
            ("photos[]", "photos", true),
            ("employees[0][photo]", "employees.photo", true),
            ("employees[12][photo]", "employees[][photo]", true),
            ("employees[a][photo]", "employees.photo", true),
            ("Employees[0][Photo]", "employees.photo", true),
            ("user.email", "user.email", true),
            ("user[email]", "user.email", true),
            ("user_email", "user.email", true),
            ("user email", "user.email", true),
            ("ssn\x00x", "ssn", true),
            ("SSN", "ssn", true),
            ("employees[0][photo]", "photo", false),
            ("photography", "photo", false),
            ("employees[0][name]", "employees.photo", false),
        ] {
            let got = FormField::new(field.as_bytes())
                .matches(name.as_bytes(), &split_form_name(name.as_bytes()));
            assert_eq!(got, want, "{field:?} matches {name:?}");
        }
    }
}
