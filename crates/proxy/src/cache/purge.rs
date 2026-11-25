//! What a purge names: every copy of the app, of an address, or of a path below one, whatever its
//! encoding or `Vary` variant.

/// What a `CachePurge` asks to remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeScope<'a> {
    /// The copies of one address: a path with its query (on every host of the app) or an absolute
    /// `http://` or `https://` URL (that host only), compared byte for byte with the target.
    Url(&'a str),
    /// The copies whose target path starts with a path (on every host), or with the path of an
    /// absolute URL (on its host).
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
                    path: target[..end].to_vec(),
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
