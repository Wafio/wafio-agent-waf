//! Private URL parser for the subset this crate reads (scheme, user, host, path, raw query,
//! fragment) and host:port splitting.
//! bytetext has no URL parser yet; move this there when it does.

use wafio_domain::text_helpers::quote;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Host,
    Zone,
    Path,
    UserPassword,
    Fragment,
}

#[allow(dead_code)]
/// The URL fields this crate reads. `user` is `Some((name, password))`
/// when the authority carried userinfo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Url {
    pub scheme: Vec<u8>,
    pub opaque: Vec<u8>,
    pub user: Option<(Vec<u8>, Option<Vec<u8>>)>,
    pub host: Vec<u8>,
    pub path: Vec<u8>,
    pub raw_query: Vec<u8>,
    pub fragment: Vec<u8>,
    pub trailing_question_mark: bool,
}

impl Url {
    pub fn has_scheme(&self) -> bool {
        !self.scheme.is_empty()
    }

    pub fn hostname(&self) -> &[u8] {
        url_split_host_port(&self.host).0
    }

    pub fn port(&self) -> &[u8] {
        url_split_host_port(&self.host).1
    }
}

fn url_split_host_port(hp: &[u8]) -> (&[u8], &[u8]) {
    let mut host = hp;
    let mut port: &[u8] = b"";
    if let Some(colon) = host.iter().rposition(|&c| c == b':')
        && is_valid_port_suffix(&host[colon..])
    {
        port = &host[colon + 1..];
        host = &host[..colon];
    }
    if host.starts_with(b"[") && host.ends_with(b"]") && host.len() >= 2 {
        host = &host[1..host.len() - 1];
    }
    (host, port)
}

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

/// Whether `c` needs escaping in `mode` (only the modes this parser uses).
fn needs_escaping(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if (mode == Mode::Host || mode == Mode::Zone)
        && matches!(
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
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => return c == b'?',
            Mode::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            Mode::Fragment => return false,
            _ => {}
        },
        _ => {}
    }
    if mode == Mode::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

/// Percent-decodes `s` (no `+` handling: no mode here is the query component).
fn unescape(s: &[u8], mode: Mode) -> Result<Vec<u8>, String> {
    let mut n = 0;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                n += 1;
                if i + 2 >= s.len() || !is_hex_digit(s[i + 1]) || !is_hex_digit(s[i + 2]) {
                    let e = &s[i..];
                    return Err(format!(
                        "invalid URL escape {}",
                        quote(&e[..e.len().min(3)])
                    ));
                }
                if mode == Mode::Host && hex_digit_value(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return Err(format!("invalid URL escape {}", quote(&s[i..i + 3])));
                }
                if mode == Mode::Zone {
                    let v = hex_digit_value(s[i + 1]) << 4 | hex_digit_value(s[i + 2]);
                    if &s[i..i + 3] != b"%25" && v != b' ' && needs_escaping(v, Mode::Host) {
                        return Err(format!("invalid URL escape {}", quote(&s[i..i + 3])));
                    }
                }
                i += 3;
            }
            c => {
                if (mode == Mode::Host || mode == Mode::Zone) && c < 0x80 && needs_escaping(c, mode)
                {
                    return Err(format!(
                        "invalid character {} in host name",
                        quote(&s[i..i + 1])
                    ));
                }
                i += 1;
            }
        }
    }
    if n == 0 {
        return Ok(s.to_vec());
    }
    let mut t = Vec::with_capacity(s.len() - 2 * n);
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
    Ok(t)
}

fn split_scheme(raw: &[u8]) -> Result<(&[u8], &[u8]), String> {
    for (i, &c) in raw.iter().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok((b"", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err("missing protocol scheme".into());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok((b"", raw)),
        }
    }
    Ok((b"", raw))
}

fn is_valid_port_suffix(port: &[u8]) -> bool {
    if port.is_empty() {
        return true;
    }
    port[0] == b':' && port[1..].iter().all(u8::is_ascii_digit)
}

fn is_valid_userinfo(s: &[u8]) -> bool {
    // A non-ASCII rune is never valid.
    s.iter().all(|&c| {
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

fn unescape_host(scheme: &[u8], host: &[u8]) -> Result<Vec<u8>, String> {
    let open = host.iter().rposition(|&c| c == b'[');
    if let Some(open) = open {
        if open > 0 {
            return Err("invalid IP-literal".into());
        }
        let Some(close) = host.iter().rposition(|&c| c == b']') else {
            return Err("missing ']' in host".into());
        };
        let colon_port = &host[close + 1..];
        if !is_valid_port_suffix(colon_port) {
            return Err(format!("invalid port {} after host", quote(colon_port)));
        }
        let unescaped_colon_port = unescape(colon_port, Mode::Host)?;
        if close < 1 {
            return Err("invalid host: ParseAddr(\"\"): unable to parse IP".into());
        }
        let hostname = &host[1..close];
        let unescaped = match find(hostname, b"%25") {
            Some(z) => {
                let mut h = unescape(&hostname[..z], Mode::Host)?;
                h.extend(unescape(&hostname[z..], Mode::Zone)?);
                h
            }
            None => unescape(hostname, Mode::Host)?,
        };
        let addr = wafio_domain::ip_address::parse_ip_address(&unescaped)
            .map_err(|e| format!("invalid host: {e}"))?;
        if addr.is_ipv4() {
            return Err("invalid IP-literal".into());
        }
        let mut out = b"[".to_vec();
        out.extend_from_slice(&unescaped);
        out.push(b']');
        out.extend(unescaped_colon_port);
        return Ok(out);
    }
    if let Some(first) = host.iter().position(|&c| c == b':') {
        let last = host.iter().rposition(|&c| c == b':').expect("colon");
        // For http and https the first colon is kept, for other schemes the last.
        let i = if last != first && scheme != b"http" && scheme != b"https" {
            last
        } else {
            first
        };
        let colon_port = &host[i..];
        if !is_valid_port_suffix(colon_port) {
            return Err(format!("invalid port {} after host", quote(colon_port)));
        }
    }
    unescape(host, Mode::Host)
}

fn find(s: &[u8], sub: &[u8]) -> Option<usize> {
    memchr::memmem::find(s, sub)
}

type User = Option<(Vec<u8>, Option<Vec<u8>>)>;

fn split_userinfo_and_host(scheme: &[u8], authority: &[u8]) -> Result<(User, Vec<u8>), String> {
    let at = authority.iter().rposition(|&c| c == b'@');
    let host = match at {
        None => unescape_host(scheme, authority)?,
        Some(i) => unescape_host(scheme, &authority[i + 1..])?,
    };
    let Some(i) = at else { return Ok((None, host)) };
    let userinfo = &authority[..i];
    if !is_valid_userinfo(userinfo) {
        return Err("net/url: invalid userinfo".into());
    }
    let user = match userinfo.iter().position(|&c| c == b':') {
        None => (unescape(userinfo, Mode::UserPassword)?, None),
        Some(c) => (
            unescape(&userinfo[..c], Mode::UserPassword)?,
            Some(unescape(&userinfo[c + 1..], Mode::UserPassword)?),
        ),
    };
    Ok((Some(user), host))
}

fn parse_inner(raw: &[u8]) -> Result<Url, String> {
    if raw.iter().any(|&b| b < b' ' || b == 0x7f) {
        return Err("net/url: invalid control character in URL".into());
    }
    let mut url = Url::default();
    if raw == b"*" {
        url.path = b"*".to_vec();
        return Ok(url);
    }
    let (scheme, mut rest) = split_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    if rest.ends_with(b"?") && rest.iter().filter(|&&c| c == b'?').count() == 1 {
        url.trailing_question_mark = true;
        rest = &rest[..rest.len() - 1];
    } else if let Some(q) = rest.iter().position(|&c| c == b'?') {
        url.raw_query = rest[q + 1..].to_vec();
        rest = &rest[..q];
    }
    if !rest.starts_with(b"/") {
        if !url.scheme.is_empty() {
            url.opaque = rest.to_vec();
            return Ok(url);
        }
        let segment: &[u8] = rest.split(|&c| c == b'/').next().unwrap_or_default();
        if segment.contains(&b':') {
            return Err("first path segment in URL cannot contain colon".into());
        }
    }
    if (!url.scheme.is_empty() || !rest.starts_with(b"///")) && rest.starts_with(b"//") {
        let mut authority = &rest[2..];
        rest = b"";
        if let Some(i) = authority.iter().position(|&c| c == b'/') {
            rest = &authority[i..];
            authority = &authority[..i];
        }
        let (user, host) = split_userinfo_and_host(&url.scheme, authority)?;
        url.user = user;
        url.host = host;
    }
    url.path = unescape(rest, Mode::Path)?;
    Ok(url)
}

/// Parses `raw`. The error text has the form `parse "<url>": <reason>`.
pub(crate) fn parse(raw: &[u8]) -> Result<Url, String> {
    let (u, frag) = match raw.iter().position(|&c| c == b'#') {
        Some(i) => (&raw[..i], &raw[i + 1..]),
        None => (raw, &b""[..]),
    };
    let mut url = parse_inner(u).map_err(|e| format!("parse {}: {e}", quote(u)))?;
    if !frag.is_empty() {
        url.fragment =
            unescape(frag, Mode::Fragment).map_err(|e| format!("parse {}: {e}", quote(raw)))?;
    }
    Ok(url)
}

/// Splits `host:port`. The error text has the form `address <addr>: <reason>`.
pub(crate) fn split_host_and_port(hostport: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let addr_err = |why: &str| {
        if hostport.is_empty() {
            return Err(why.to_string());
        }
        Err(format!(
            "address {}: {why}",
            String::from_utf8_lossy(hostport)
        ))
    };
    let Some(i) = hostport.iter().rposition(|&c| c == b':') else {
        return addr_err("missing port in address");
    };
    let host;
    let j;
    let k;
    if hostport[0] == b'[' {
        let Some(end) = hostport.iter().position(|&c| c == b']') else {
            return addr_err("missing ']' in address");
        };
        if end + 1 == hostport.len() {
            return addr_err("missing port in address");
        } else if end + 1 != i {
            if hostport[end + 1] == b':' {
                return addr_err("too many colons in address");
            }
            return addr_err("missing port in address");
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(&b':') {
            return addr_err("too many colons in address");
        }
        j = 0;
        k = 0;
    }
    if hostport[j..].contains(&b'[') {
        return addr_err("unexpected '[' in address");
    }
    if hostport[k..].contains(&b']') {
        return addr_err("unexpected ']' in address");
    }
    Ok((host.to_vec(), hostport[i + 1..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_matches_reference_cases() {
        let u = parse(b"HTTPS://User:p%40ss@App.Example.com:8443/a%20b?x=1#frag").unwrap();
        assert_eq!(u.scheme, b"https");
        assert_eq!(u.host, b"App.Example.com:8443");
        assert_eq!(u.hostname(), b"App.Example.com");
        assert_eq!(u.port(), b"8443");
        assert_eq!(u.path, b"/a b");
        assert_eq!(u.raw_query, b"x=1");
        assert_eq!(u.fragment, b"frag");
        assert_eq!(u.user, Some((b"User".to_vec(), Some(b"p@ss".to_vec()))));
        let u = parse(b"fcgi://127.0.0.1:9000?root=/var/www").unwrap();
        assert_eq!(
            (u.host.as_slice(), u.raw_query.as_slice()),
            (&b"127.0.0.1:9000"[..], &b"root=/var/www"[..])
        );
        let u = parse(b"https://[::1]:443").unwrap();
        assert_eq!((u.hostname(), u.port()), (&b"::1"[..], &b"443"[..]));
        assert_eq!(parse(b"javascript:alert(1)").unwrap().opaque, b"alert(1)");
        for bad in [
            &b"%zz://not a url"[..],
            b"https://ok.test:bad",
            b"https://a:b:80",
            b"http://[1.2.3.4]/",
            b"x\x01",
            b":foo",
            b"1a:b/c",
            b"http://a b/",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(parse(b"mongodb://a:1,b:2/").is_ok());
        assert!(parse(b"https://ok.test:70000").is_ok());
    }

    #[test]
    fn split_host_and_port_matches_reference_cases() {
        assert_eq!(
            split_host_and_port(b"127.0.0.1:9100").unwrap(),
            (b"127.0.0.1".to_vec(), b"9100".to_vec())
        );
        assert_eq!(
            split_host_and_port(b"[::1]:1").unwrap(),
            (b"::1".to_vec(), b"1".to_vec())
        );
        assert_eq!(
            split_host_and_port(b":9100").unwrap(),
            (b"".to_vec(), b"9100".to_vec())
        );
        for bad in [
            &b"127.0.0.1"[..],
            b"::1:80",
            b"[::1]",
            b"[::1]x:80",
            b"a]:80",
        ] {
            assert!(
                split_host_and_port(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
