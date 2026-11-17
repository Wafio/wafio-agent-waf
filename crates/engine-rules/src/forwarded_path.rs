//! The path a request is forwarded under (the request target is parsed as a URI and its path
//! normalized, below) and the readings path exceptions match on.

/// The readings of one request's path that path rules match on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestPathReadings {
    /// The decoded, normalized path the upstream receives.
    pub forwarded: Vec<u8>,
    /// The decoded but unresolved path of a non-proxy request ("" when equal to Forwarded
    /// or for a proxy request).
    pub unresolved: Vec<u8>,
    /// The raw path had an invalid percent escape: no exemption applies.
    pub no_exemption: bool,
}

/// Returns (path, ok); ok is false when the raw path holds an invalid escape.
pub fn decode_forwarded_path(raw_uri: &[u8]) -> (Vec<u8>, bool) {
    let (p, _, ok) = split_request_readings(raw_uri);
    (p, ok)
}

pub fn readings_for_proxy_request(forwarded: &[u8]) -> RequestPathReadings {
    RequestPathReadings {
        forwarded: forwarded.to_vec(),
        ..Default::default()
    }
}

/// The readings of a raw request-target.
pub fn readings_for_raw_target(raw_uri: &[u8]) -> RequestPathReadings {
    let (fwd, unresolved, ok) = split_request_readings(raw_uri);
    let mut rp = RequestPathReadings {
        no_exemption: !ok,
        ..Default::default()
    };
    if unresolved != fwd {
        rp.unresolved = unresolved;
    }
    rp.forwarded = fwd;
    rp
}

fn split_request_readings(raw_uri: &[u8]) -> (Vec<u8>, Vec<u8>, bool) {
    let orig = original_path_after_uri_parse(b"wafio.invalid", raw_uri).unwrap_or_default();
    let path = resolve_dot_segments(&orig);
    let path = if path.is_empty() { b"/".to_vec() } else { path };
    // On a parse error the path stays empty, so the forwarded path is "/".
    (
        path,
        decode_path_leniently(&orig),
        !contains_invalid_percent_escape(&orig),
    )
}

/// Decodes every valid %XX escape, keeps an invalid one literally.
fn decode_path_leniently(raw: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(raw.len() + 1);
    if raw.first() != Some(&b'/') {
        b.push(b'/');
    }
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if c == b'%'
            && i + 2 < raw.len()
            && raw[i + 1].is_ascii_hexdigit()
            && raw[i + 2].is_ascii_hexdigit()
        {
            b.push(hex_digit_value(raw[i + 1]) << 4 | hex_digit_value(raw[i + 2]));
            i += 3;
            continue;
        }
        b.push(c);
        i += 1;
    }
    b
}

fn hex_digit_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Whether `p` has a '%' not followed by two hex digits.
pub fn contains_invalid_percent_escape(p: &[u8]) -> bool {
    let mut i = 0;
    while i < p.len() {
        if p[i] != b'%' {
            i += 1;
            continue;
        }
        if i + 2 >= p.len() || !p[i + 1].is_ascii_hexdigit() || !p[i + 2].is_ascii_hexdigit() {
            return true;
        }
        i += 3;
    }
    false
}

// ---- URI parse (path part) ---------------------------------------------------------------

/// The original path that parsing `uri` for `host` stores, or None when the parse fails
/// before setting it.
fn original_path_after_uri_parse(host: &[u8], uri: &[u8]) -> Option<Vec<u8>> {
    if uri.iter().any(|&b| b < b' ' || b == 0x7f) {
        return None;
    }
    let mut host = host.to_vec();
    let mut uri = uri.to_vec();
    if host.is_empty() || contains(&uri, b"://") {
        let (scheme, new_host, new_uri) = split_host_and_uri(&host, &uri);
        if !scheme.is_empty() && !is_valid_scheme(&scheme) {
            return None;
        }
        host = new_host;
        uri = new_uri;
    }
    if let Some(n) = host.iter().rposition(|&c| c == b'@') {
        if !is_valid_userinfo(&host[..n]) {
            return None;
        }
        host = host[n + 1..].to_vec();
    }
    check_host_syntax(&host)?;
    let q = uri.iter().position(|&c| c == b'?');
    let f = uri.iter().position(|&c| c == b'#');
    let q = match (q, f) {
        (Some(q), Some(f)) if q > f => None,
        (q, _) => q,
    };
    Some(match (q, f) {
        (None, None) => uri,
        (Some(q), _) => uri[..q].to_vec(),
        (None, Some(f)) => uri[..f].to_vec(),
    })
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    memchr::memmem::find(h, n).is_some()
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    memchr::memmem::find(h, n)
}

fn split_host_and_uri(host: &[u8], uri: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let Some(n) = find(uri, b"//") else {
        return (b"http".to_vec(), host.to_vec(), uri.to_vec());
    };
    let mut scheme = &uri[..n];
    if scheme.contains(&b'/') {
        return (b"http".to_vec(), host.to_vec(), uri.to_vec());
    }
    if scheme.last() == Some(&b':') {
        scheme = &scheme[..scheme.len() - 1];
    }
    let rest = &uri[n + 2..];
    let mut n = rest.iter().position(|&c| c == b'/');
    if let Some(nq) = rest.iter().position(|&c| c == b'?')
        && n.is_none_or(|n| nq < n)
    {
        n = Some(nq);
    }
    if let Some(nh) = rest.iter().position(|&c| c == b'#')
        && n.is_none_or(|n| nh < n)
    {
        n = Some(nh);
    }
    match n {
        None => (scheme.to_vec(), rest.to_vec(), b"/".to_vec()),
        Some(n) => (scheme.to_vec(), rest[..n].to_vec(), rest[n..].to_vec()),
    }
}

fn is_valid_scheme(s: &[u8]) -> bool {
    if s.is_empty() || !s[0].is_ascii_alphabetic() {
        return false;
    }
    s[1..]
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

fn is_valid_userinfo(u: &[u8]) -> bool {
    u.iter().all(|&c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

fn is_valid_port_suffix(p: &[u8]) -> bool {
    p.is_empty() || (p[0] == b':' && p[1..].iter().all(u8::is_ascii_digit))
}

#[derive(Clone, Copy, PartialEq)]
enum EscapeMode {
    Host,
    Zone,
}

fn needs_escaping(c: u8, mode: EscapeMode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    let _ = mode; // host and zone allow the same set
    if matches!(
        c,
        b'!' | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'"'
    ) {
        return false;
    }
    !matches!(c, b'-' | b'_' | b'.' | b'~')
}

/// Percent-unescape error check (the unescaped bytes are not needed here).
fn unescape_checked(s: &[u8], mode: EscapeMode) -> Option<Vec<u8>> {
    let mut n = 0;
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            n += 1;
            if i + 2 >= s.len() || !s[i + 1].is_ascii_hexdigit() || !s[i + 2].is_ascii_hexdigit() {
                return None;
            }
            if mode == EscapeMode::Host && hex_digit_value(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                return None;
            }
            if mode == EscapeMode::Zone {
                let v = hex_digit_value(s[i + 1]) << 4 | hex_digit_value(s[i + 2]);
                if &s[i..i + 3] != b"%25" && v != b' ' && needs_escaping(v, EscapeMode::Host) {
                    return None;
                }
            }
            i += 3;
        } else {
            if s[i] < 0x80 && needs_escaping(s[i], mode) {
                return None;
            }
            i += 1;
        }
    }
    if n == 0 {
        return Some(s.to_vec());
    }
    let mut t = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            t.push(hex_digit_value(s[i + 1]) << 4 | hex_digit_value(s[i + 2]));
            i += 3;
        } else {
            t.push(s[i]);
            i += 1;
        }
    }
    Some(t)
}

/// Checks the host syntax (Some on success).
fn check_host_syntax(host: &[u8]) -> Option<()> {
    let host = if host.first() == Some(&b'[') {
        let i = host.iter().rposition(|&c| c == b']')?;
        if !is_valid_port_suffix(&host[i + 1..]) {
            return None;
        }
        if let Some(zone) = find(&host[..i], b"%25") {
            unescape_checked(&host[..zone], EscapeMode::Host)?;
            unescape_checked(&host[zone..i], EscapeMode::Zone)?;
            unescape_checked(&host[i..], EscapeMode::Host)?;
            return Some(());
        }
        host
    } else {
        if host.contains(&b'[') || host.contains(&b']') {
            return None;
        }
        if let Some(i) = host.iter().rposition(|&c| c == b':') {
            if host[..i].contains(&b':') {
                return None;
            }
            if !is_valid_port_suffix(&host[i..]) {
                return None;
            }
        }
        host
    };
    let h = unescape_checked(host, EscapeMode::Host)?;
    check_ipv6_literal(&h)
}

fn check_ipv6_literal(host: &[u8]) -> Option<()> {
    if host.first() != Some(&b'[') {
        return Some(());
    }
    let end = host.iter().position(|&c| c == b']')?;
    if end == 1 {
        return None;
    }
    let mut addr = &host[1..end];
    if let Some(zi) = addr.iter().position(|&c| c == b'%') {
        if zi == addr.len() - 1 {
            return None;
        }
        addr = &addr[..zi];
    }
    if !addr.contains(&b':') {
        return None;
    }
    if addr.contains(&b'.') {
        let last_colon = addr.iter().rposition(|&c| c == b':')?;
        if last_colon == addr.len() - 1 || !is_valid_ipv4_literal(&addr[last_colon + 1..]) {
            return None;
        }
        let double_at_split = last_colon > 0 && addr[last_colon - 1] == b':';
        let head = if double_at_split {
            &addr[..last_colon - 1]
        } else {
            &addr[..last_colon]
        };
        let (mut hextets, double_head) = read_ipv6_hextets(head)?;
        if double_head && double_at_split {
            return None;
        }
        hextets += 2;
        let double = double_head || double_at_split;
        if (!double && hextets != 8) || (double && hextets >= 8) {
            return None;
        }
        return Some(());
    }
    let (hextets, double) = read_ipv6_hextets(addr)?;
    if (!double && hextets != 8) || (double && hextets >= 8) {
        return None;
    }
    Some(())
}

fn read_ipv6_hextets(s: &[u8]) -> Option<(usize, bool)> {
    let n = s.len();
    let (mut i, mut groups, mut seen_double, mut just_double) = (0, 0, false, false);
    while i < n {
        if s[i] == b':' {
            if i + 1 < n && s[i + 1] == b':' {
                if seen_double || just_double {
                    return None;
                }
                seen_double = true;
                just_double = true;
                i += 2;
                if i == n {
                    break;
                }
                continue;
            }
            if i == 0 || just_double || i == n - 1 || !s[i + 1].is_ascii_hexdigit() {
                return None;
            }
            i += 1;
            continue;
        }
        just_double = false;
        let mut cnt = 0;
        while cnt < 4 && i < n && s[i].is_ascii_hexdigit() {
            i += 1;
            cnt += 1;
        }
        if cnt == 0 {
            return None;
        }
        groups += 1;
        if i < n && s[i] != b':' {
            return None;
        }
    }
    Some((groups, seen_double))
}

fn is_valid_ipv4_literal(s: &[u8]) -> bool {
    let (n, mut i, mut parts) = (s.len(), 0, 0);
    while parts < 4 {
        if i >= n {
            return false;
        }
        let (start, mut val, mut digits) = (i, 0u32, 0);
        while i < n && s[i].is_ascii_digit() {
            val = val * 10 + u32::from(s[i] - b'0');
            if val > 255 {
                return false;
            }
            i += 1;
            digits += 1;
            if digits > 3 {
                return false;
            }
        }
        if digits == 0 || (digits > 1 && s[start] == b'0') {
            return false;
        }
        parts += 1;
        if parts == 4 {
            return i == n;
        }
        if i >= n || s[i] != b'.' {
            return false;
        }
        i += 1;
    }
    false
}

/// Normalizes a path (unix rules).
pub fn resolve_dot_segments(src: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(src.len() + 1);
    if src.first() != Some(&b'/') {
        dst.push(b'/');
    }
    decode_query_arg_keep_plus(&mut dst, src);
    // remove duplicate slashes
    let mut b = Vec::with_capacity(dst.len());
    for &c in &dst {
        if c == b'/' && b.last() == Some(&b'/') {
            continue;
        }
        b.push(c);
    }
    if !b.contains(&b'.') {
        return b;
    }
    // remove /./ parts
    while let Some(n) = find(&b, b"/./") {
        b.drain(n..n + 2);
    }
    // remove /foo/../ parts
    while let Some(n) = find(&b, b"/../") {
        let nn = b[..n].iter().rposition(|&c| c == b'/').unwrap_or(0);
        b.drain(nn..n + 3);
    }
    // remove trailing /foo/..
    if let Some(n) = rindex(&b, b"/..")
        && n + 3 == b.len()
    {
        match b[..n].iter().rposition(|&c| c == b'/') {
            None => return b"/".to_vec(),
            Some(nn) => b.truncate(nn + 1),
        }
    }
    b
}

fn rindex(h: &[u8], n: &[u8]) -> Option<usize> {
    memchr::memmem::rfind(h, n)
}

fn decode_query_arg_keep_plus(dst: &mut Vec<u8>, src: &[u8]) {
    let Some(idx) = src.iter().position(|&c| c == b'%') else {
        dst.extend_from_slice(src);
        return;
    };
    dst.extend_from_slice(&src[..idx]);
    let mut i = idx;
    while i < src.len() {
        let c = src[i];
        if c == b'%' {
            if i + 3 > src.len() {
                dst.extend_from_slice(&src[i..]);
                return;
            }
            if src[i + 1].is_ascii_hexdigit() && src[i + 2].is_ascii_hexdigit() {
                dst.push(hex_digit_value(src[i + 1]) << 4 | hex_digit_value(src[i + 2]));
                i += 3;
                continue;
            }
            dst.push(b'%');
        } else {
            dst.push(c);
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dot_segments_matches_reference() {
        for (raw, want) in [
            ("//f%20obar/baz/../zzz", "/f obar/zzz"),
            ("/a/./b/", "/a/b/"),
            ("/a/..", "/"),
            ("/a/b/..", "/a/"),
            ("a%2", "/a%2"),
            ("/x/%2e%2e/y", "/y"),
        ] {
            assert_eq!(
                String::from_utf8_lossy(&resolve_dot_segments(raw.as_bytes())),
                want,
                "{raw}"
            );
        }
        let rp = readings_for_raw_target(b"/a/%2e%2e/b?q=1");
        assert_eq!(rp.forwarded, b"/b");
        assert_eq!(rp.unresolved, b"/a/../b");
        assert!(readings_for_raw_target(b"/a%zz").no_exemption);
        assert_eq!(readings_for_raw_target(b"http://h/x/y").forwarded, b"/x/y");
        assert_eq!(readings_for_raw_target(b"http://[bad/x").forwarded, b"/");
        assert_eq!(readings_for_raw_target(b"/a\x01").forwarded, b"/");
    }
}
