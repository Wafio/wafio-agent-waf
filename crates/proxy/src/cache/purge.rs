//! What a purge names: every copy of the app, of an address, or of a path below one, whatever its
//! encoding or `Vary` variant.

use crate::request::{forward_target, split_path_query};
use wafio_engine_rules::decode_forwarded_path;

/// What a `CachePurge` asks to remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeScope<'a> {
    /// The copies of one address: a path with its query (on every host of the app) or an absolute
    /// `http://` or `https://` URL (that host only). The address is read as a request target is
    /// before its copy is keyed (the path decoded, dot segments resolved and escaped again, the
    /// query kept with `"`, `<` and `>` written out), then compared byte for byte with the stored
    /// target.
    Url(&'a str),
    /// The copies whose target path starts with a path (on every host), or with the path of an
    /// absolute URL (on its host), read the same way.
    Prefix(&'a str),
    /// Everything the app has stored.
    App,
}

/// The host and the target of an address. A path has no host: `None`.
fn split(address: &str) -> Option<(Option<Vec<u8>>, Vec<u8>)> {
    if address.starts_with('/') {
        return Some((None, address.as_bytes().to_vec()));
    }
    let rest = address
        .strip_prefix("http://")
        .or_else(|| address.strip_prefix("https://"))?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let host = rest[..end].to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let tail = &rest[end..];
    let target = if tail.starts_with('/') {
        tail.as_bytes().to_vec()
    } else {
        [b"/", tail.as_bytes()].concat()
    };
    Some((Some(host.into_bytes()), target))
}

/// The target a request for `target` is stored under: its path decoded, its dot segments resolved
/// and escaped again, its query with `"`, `<` and `>` written out. `None` when the path holds a
/// `%` that no two hex digits follow, or a space or control byte (which no request line carries).
fn stored_target(target: &[u8]) -> Option<Vec<u8>> {
    let (path, valid) = decode_forwarded_path(target);
    if !valid || target.iter().any(|&c| c <= b' ' || c == 0x7f) {
        return None;
    }
    Some(forward_target(&path, split_path_query(target).1))
}

/// [`PurgeScope`] ready to compare with the host and target of a key.
#[derive(Debug)]
pub(crate) enum Matcher {
    All,
    Url {
        host: Option<Vec<u8>>,
        target: Vec<u8>,
    },
    Prefix {
        host: Option<Vec<u8>>,
        path: Vec<u8>,
    },
}

impl Matcher {
    /// `None` for an address that is not a path or an absolute http(s) URL.
    pub fn new(scope: PurgeScope<'_>) -> Option<Matcher> {
        Some(match scope {
            PurgeScope::App => Matcher::All,
            PurgeScope::Url(address) => {
                let (host, target) = split(address)?;
                let target = stored_target(&target)?;
                Matcher::Url { host, target }
            }
            PurgeScope::Prefix(address) => {
                let (host, target) = split(address)?;
                // A prefix is a path: what follows a `?` is no part of it.
                let end = target
                    .iter()
                    .position(|&c| c == b'?')
                    .unwrap_or(target.len());
                Matcher::Prefix {
                    host,
                    path: stored_target(&target[..end])?,
                }
            }
        })
    }

    pub fn is_all(&self) -> bool {
        matches!(self, Matcher::All)
    }

    /// Whether the key with this host and target is named. A key whose address is not known is
    /// named only by a purge of everything.
    pub fn matches(&self, address: Option<(&[u8], &[u8])>) -> bool {
        let (Matcher::Url { host, .. } | Matcher::Prefix { host, .. }) = self else {
            return true;
        };
        let Some((key_host, target)) = address else {
            return false;
        };
        if host.as_deref().is_some_and(|h| h != key_host) {
            return false;
        }
        match self {
            Matcher::Url { target: want, .. } => target == want.as_slice(),
            Matcher::Prefix { path, .. } => {
                let end = target
                    .iter()
                    .position(|&c| c == b'?')
                    .unwrap_or(target.len());
                target[..end].starts_with(path)
            }
            Matcher::All => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(scope: PurgeScope<'_>, host: &str, target: &str) -> bool {
        Matcher::new(scope)
            .unwrap()
            .matches(Some((host.as_bytes(), target.as_bytes())))
    }

    #[test]
    fn a_path_names_the_target_on_every_host_and_a_url_only_its_host() {
        let url = PurgeScope::Url;
        assert!(named(url("/p/1?a=1"), "a.test", "/p/1?a=1"));
        assert!(named(url("/p/1?a=1"), "b.test", "/p/1?a=1"));
        assert!(
            !named(url("/p/1"), "a.test", "/p/1?a=1"),
            "the query counts"
        );
        assert!(!named(url("/p/1?a=1"), "a.test", "/p/1"));
        assert!(named(url("https://A.test/p/1"), "a.test", "/p/1"));
        assert!(
            named(url("http://a.test/p/1"), "a.test", "/p/1"),
            "either scheme"
        );
        assert!(!named(url("https://a.test/p/1"), "b.test", "/p/1"));
        assert!(named(url("https://a.test:8443/"), "a.test:8443", "/"));
        assert!(!named(url("https://a.test:8443/"), "a.test", "/"));
        assert!(
            named(url("https://a.test"), "a.test", "/"),
            "no path is the root"
        );
        assert!(named(url("https://a.test?x=1"), "a.test", "/?x=1"));
    }

    #[test]
    fn a_prefix_compares_the_path_and_leaves_the_query_out() {
        let prefix = PurgeScope::Prefix;
        assert!(named(prefix("/blog/"), "a.test", "/blog/post?x=1"));
        assert!(named(prefix("/blog/"), "b.test", "/blog/"));
        assert!(!named(prefix("/blog/"), "a.test", "/other/blog/"));
        assert!(
            !named(prefix("/blog/"), "a.test", "/x?p=/blog/"),
            "not in the query"
        );
        assert!(
            named(prefix("/blog"), "a.test", "/blog-2/x"),
            "a text prefix"
        );
        assert!(named(prefix("https://a.test/blog/"), "a.test", "/blog/x"));
        assert!(!named(prefix("https://a.test/blog/"), "b.test", "/blog/x"));
        assert!(
            named(prefix("/"), "a.test", "/"),
            "the root names every path"
        );
    }

    #[test]
    fn an_address_is_read_the_way_a_request_target_is_before_its_copy_is_keyed() {
        let url = PurgeScope::Url;
        // The copy of /x_(y) is stored with its parentheses escaped.
        assert!(named(url("/x_(y)"), "a.test", "/x_%28y%29"));
        assert!(named(url("/x_%28y%29"), "a.test", "/x_%28y%29"));
        assert!(named(url("/a%2db"), "a.test", "/a-b"), "lower-case escape");
        assert!(named(url("/a%2Db"), "a.test", "/a-b"));
        assert!(named(url("/a-b"), "a.test", "/a-b"));
        assert!(named(url("/caf%c3%a9"), "a.test", "/caf%C3%A9"));
        assert!(
            named(url("/caf\u{e9}"), "a.test", "/caf%C3%A9"),
            "raw UTF-8"
        );
        assert!(named(url("/a/./b"), "a.test", "/a/b"), "dot segment");
        assert!(named(url("/a/x/../b"), "a.test", "/a/b"), "dot-dot segment");
        assert!(named(url("/a/%2e%2e/b"), "a.test", "/b"), "escaped dots");
        assert!(named(url("//a///b"), "a.test", "/a/b"), "repeated slash");
        assert!(named(url("https://A.test/x_(y)"), "a.test", "/x_%28y%29"));
        assert!(
            !named(url("/a%2db"), "a.test", "/a%2Db"),
            "stored form only"
        );
        assert!(!named(url("/a%2fb"), "a.test", "/a-b"));
        // The query keeps its bytes, but `"`, `<` and `>` are written out as in the key.
        assert!(named(url("/p?q=\"x\""), "a.test", "/p?q=%22x%22"));
        assert!(named(url("/p?q=<b>"), "a.test", "/p?q=%3Cb%3E"));
        assert!(named(url("/p?q=%22x"), "a.test", "/p?q=%22x"));
        assert!(!named(url("/p?q=%2d"), "a.test", "/p?q=-"), "no decoding");
        assert!(
            !named(url("/p?q=%2d"), "a.test", "/p?q=%2D"),
            "no case change"
        );
        assert!(
            !named(url("/p?b=2&a=1"), "a.test", "/p?a=1&b=2"),
            "no sorting"
        );
        assert!(named(url("/p?"), "a.test", "/p"), "an empty query is none");
    }

    #[test]
    fn a_prefix_is_read_the_same_way_and_keeps_its_text_meaning() {
        let prefix = PurgeScope::Prefix;
        assert!(named(
            prefix("/wiki/Foo_("),
            "a.test",
            "/wiki/Foo_%28bar%29"
        ));
        assert!(named(
            prefix("/wiki/Foo_%28bar"),
            "a.test",
            "/wiki/Foo_%28bar%29"
        ));
        assert!(named(prefix("/a%2d"), "a.test", "/a-b/x"));
        assert!(named(prefix("/a/./b/"), "a.test", "/a/b/c"));
        assert!(named(prefix("/a/x/../"), "a.test", "/a/b"));
        assert!(
            named(prefix("/caf%c3"), "a.test", "/caf%C3%A9"),
            "half a character"
        );
        assert!(
            named(prefix("/p/?ignored=1"), "a.test", "/p/x"),
            "query left out"
        );
        assert!(named(prefix("https://a.test/x_("), "a.test", "/x_%28y%29"));
        assert!(!named(prefix("https://a.test/x_("), "b.test", "/x_%28y%29"));
        assert!(!named(prefix("/a%2d"), "a.test", "/a%2Db"));
    }

    #[test]
    fn an_address_that_cannot_be_read_as_a_request_target_names_nothing() {
        for bad in [
            "/a%zz",
            "/a%4",
            "/a%",
            "/a%2",
            "/a b",
            "/a\x01",
            "/a\x7f",
            "/a\tb",
            "https://a.test/a%zz",
            "http://a.test/a b",
        ] {
            assert!(Matcher::new(PurgeScope::Url(bad)).is_none(), "{bad:?}");
            assert!(Matcher::new(PurgeScope::Prefix(bad)).is_none(), "{bad:?}");
        }
        // A bad escape in the query is no escape of the path: the query is kept as it is.
        assert!(named(PurgeScope::Url("/p?q=%zz"), "a.test", "/p?q=%zz"));
        assert!(Matcher::new(PurgeScope::Prefix("/p?q=%zz")).is_some());
    }

    #[test]
    fn everything_names_every_key_even_one_with_no_known_address() {
        let all = Matcher::new(PurgeScope::App).unwrap();
        assert!(all.is_all() && all.matches(None) && all.matches(Some((b"h", b"/"))));
        let url = Matcher::new(PurgeScope::Url("/a")).unwrap();
        assert!(
            !url.matches(None),
            "an unknown address is not named by an address"
        );
    }

    #[test]
    fn an_address_that_is_neither_a_path_nor_an_http_url_names_nothing() {
        for bad in [
            "",
            "ftp://a.test/",
            "a.test/p",
            "http://",
            "https:///p",
            "p",
        ] {
            assert!(Matcher::new(PurgeScope::Url(bad)).is_none(), "{bad:?}");
            assert!(Matcher::new(PurgeScope::Prefix(bad)).is_none(), "{bad:?}");
        }
    }
}
