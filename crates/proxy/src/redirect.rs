//! The main host name of an app, the `Location` of every redirect to HTTPS, and the path prefix
//! an app lives under.

use std::borrow::Cow;
use std::collections::HashSet;

use crate::config::{Route, TlsSite};
use crate::https::host_name;
use crate::request::{InboundRequest, push_escaped_path, push_forward_query};
use crate::response::OutboundResponse;

/// Where the visitors of an app's other host names are sent.
pub(crate) struct MainHost {
    /// The main host name, lower case. It comes from the bundle only, never from the request.
    host: String,
    /// The HTTPS port of the app's listener.
    port: u16,
    /// Every host name of the app, the main one included.
    hosts: HashSet<String>,
}

impl MainHost {
    /// `None` when the site names no main host.
    pub fn new(site: &TlsSite, port: u16) -> Option<MainHost> {
        site.canonical_host.as_ref().map(|host| MainHost {
            host: host.clone(),
            port,
            hosts: site.hosts.iter().cloned().collect(),
        })
    }

    /// The `308` for a request that arrived under another host name of the app: same path and
    /// query, the main host. Nothing for the main host itself and for a host the app does not
    /// serve. `308` keeps the method, so a `POST` is repeated as a `POST`.
    pub fn answer(&self, req: &InboundRequest) -> Option<OutboundResponse> {
        let name = host_name(&req.host);
        if name == self.host.as_bytes()
            || !std::str::from_utf8(name).is_ok_and(|n| self.hosts.contains(n))
        {
            return None;
        }
        let mut response = OutboundResponse::new(308);
        response.set(
            b"Location",
            &https_location(&self.host, self.port, &req.forward_request_target),
        );
        Some(response)
    }
}

/// `https://<host>` (with `:port` unless it is 443) and the request target. A byte that is not
/// visible ASCII (a space, CR, LF, a control or high byte) is written as `%XX`, so nothing
/// can end the header line. `OPTIONS *` and an absolute-form target without a path have no
/// origin-form target: they get `/`.
pub(crate) fn https_location(host: &str, port: u16, target: &[u8]) -> Vec<u8> {
    let mut location = format!("https://{host}").into_bytes();
    if port != 443 {
        location.extend_from_slice(format!(":{port}").as_bytes());
    }
    if !target.starts_with(b"/") {
        location.push(b'/');
    }
    if target.starts_with(b"/") || target.starts_with(b"?") {
        for &byte in target {
            if byte.is_ascii_graphic() {
                location.push(byte);
            } else {
                location.extend_from_slice(format!("%{byte:02X}").as_bytes());
            }
        }
    }
    location
}

/// What follows `prefix` in `path`: `/` when nothing does, the rest when it starts with `/`, and
/// `None` when the path is not under the prefix (`/shopping` is not under `/shop`).
fn below_prefix<'a>(prefix: &[u8], path: &'a [u8]) -> Option<&'a [u8]> {
    match path.strip_prefix(prefix)? {
        [] => Some(b"/"),
        rest if rest.starts_with(b"/") => Some(rest),
        _ => None,
    }
}

/// Whether the route has a path prefix and the request is for a path outside it. Such a request
/// is answered `404` and never reaches the application: it would arrive under a path that no
/// rule written for the public one covers (`/admin` for the page that is public at
/// `/shop/admin`). The path is the one the pipeline inspects, decoded with its dot segments
/// resolved, so `/shop/../admin` is outside `/shop`.
pub(crate) fn outside_prefix(route: &Route, req: &InboundRequest) -> bool {
    let prefix = route.proxy_config.strip_path_prefix.as_bytes();
    !prefix.is_empty() && below_prefix(prefix, &req.forward_path).is_none()
}

/// The decoded path the application sees: the request path with the route's path prefix taken
/// off (as for [`upstream_target`]), else the path as it is.
pub(crate) fn app_path<'a>(route: &Route, req: &'a InboundRequest) -> &'a [u8] {
    let prefix = route.proxy_config.strip_path_prefix.as_bytes();
    if prefix.is_empty() {
        return &req.forward_path;
    }
    below_prefix(prefix, &req.forward_path).unwrap_or(&req.forward_path)
}

/// The request target the upstream gets: the public one, with the route's path prefix taken off
/// when the path equals it or goes on with `/` (`/` when nothing is left). The prefix is matched
/// on the decoded path, dot segments already resolved. A request that asks for an upgrade is not
/// changed. A path outside the prefix never gets here (`outside_prefix`); it is left as it is.
pub(crate) fn upstream_target<'a>(route: &Route, req: &'a InboundRequest) -> Cow<'a, [u8]> {
    let prefix = route.proxy_config.strip_path_prefix.as_bytes();
    if prefix.is_empty() || req.has_upgrade() {
        return Cow::Borrowed(&req.forward_request_target);
    }
    let Some(rest) = below_prefix(prefix, &req.forward_path) else {
        return Cow::Borrowed(&req.forward_request_target);
    };
    let mut target = Vec::with_capacity(req.forward_request_target.len());
    push_escaped_path(&mut target, rest);
    if !req.query.is_empty() {
        target.push(b'?');
        push_forward_query(&mut target, &req.query);
    }
    Cow::Owned(target)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::cert_store::BookChange;
    use crate::config::{AppSpec, build_route};

    fn site(canonical: Option<&str>, listen: &str) -> TlsSite {
        TlsSite {
            listen: listen.into(),
            hosts: vec!["shop.test".into(), "www.shop.test".into()],
            certificate: BookChange::Keep,
            redirect_listen: None,
            canonical_host: canonical.map(str::to_owned),
        }
    }

    fn route(proxy_config: &str, tls: Option<TlsSite>) -> Route {
        build_route(&AppSpec {
            app_id: "a".into(),
            listen_host: String::new(),
            listen_port: 0,
            upstream: "http://127.0.0.1:1".into(),
            mode: "block".into(),
            proxy_config: proxy_config.as_bytes().to_vec(),
            rules_json: Vec::new(),
            fcgi_doc_root: String::new(),
            fcgi_index: String::new(),
            fcgi_keep_conn: false,
            maintenance: Vec::new(),
            analysis: Arc::new(crate::testing::analysis_setup(b"{}")),
            tls,
            compression: None,
            static_files: None,
            cache: None,
            session_cookies: Vec::new(),
        })
        .unwrap()
    }

    fn request(host: &str, target: &str) -> InboundRequest {
        InboundRequest::from_head(
            format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        )
    }

    fn location(main: &MainHost, host: &str, target: &str) -> Option<String> {
        let r = main.answer(&request(host, target))?;
        assert_eq!(r.status, 308, "{host} {target}");
        Some(String::from_utf8(r.peek(b"Location").unwrap().to_vec()).unwrap())
    }

    #[test]
    fn another_host_of_the_app_goes_to_the_main_host_with_its_path_and_query() {
        let main = MainHost::new(&site(Some("shop.test"), "0.0.0.0:443"), 443).unwrap();
        for (host, target, want) in [
            (
                "www.shop.test",
                "/cart?a=1&b=2",
                "https://shop.test/cart?a=1&b=2",
            ),
            ("www.shop.test", "/", "https://shop.test/"),
            ("www.shop.test", "/?x=1", "https://shop.test/?x=1"),
            ("www.shop.test", "/a/../b/./c", "https://shop.test/b/c"),
            (
                "www.shop.test",
                "/a%20b/%e2%82%ac?q=%41",
                "https://shop.test/a%20b/%E2%82%AC?q=%41",
            ),
            (
                "www.shop.test",
                "/%5Cevil.test",
                "https://shop.test/%5Cevil.test",
            ),
            ("WWW.Shop.TEST", "/x", "https://shop.test/x"),
            ("www.shop.test:8443", "/x", "https://shop.test/x"),
            ("www.shop.test.", "/x", "https://shop.test/x"),
        ] {
            assert_eq!(
                location(&main, host, target).as_deref(),
                Some(want),
                "{host} {target}"
            );
        }
    }

    /// Whatever the target looks like, the host of the `Location` is the main host: the part
    /// after it starts with a slash, a query or nothing.
    #[test]
    fn no_target_makes_the_redirect_leave_the_main_host() {
        let main = MainHost::new(&site(Some("shop.test"), "0.0.0.0:443"), 443).unwrap();
        for target in [
            "//evil.test/x",
            "///x",
            "/%2F%2Fevil.test",
            "/%5Cevil.test",
            "/.//evil.test",
            "/@evil.test",
            "/..;/x",
        ] {
            let got = location(&main, "www.shop.test", target).expect(target);
            let rest = got
                .strip_prefix("https://shop.test")
                .unwrap_or_else(|| panic!("{target}: {got}"));
            assert!(rest.starts_with('/'), "{target}: {got}");
        }
    }

    #[test]
    fn the_main_host_and_a_host_the_app_does_not_serve_are_left_alone() {
        let main = MainHost::new(&site(Some("shop.test"), "0.0.0.0:443"), 443).unwrap();
        for host in [
            "shop.test",
            "SHOP.test:443",
            "shop.test.",
            "other.test",
            "evil.test",
            "shop.test.evil.test",
            "",
        ] {
            assert!(main.answer(&request(host, "/x")).is_none(), "{host:?}");
        }
        assert!(MainHost::new(&site(None, "0.0.0.0:443"), 443).is_none());
    }

    #[test]
    fn the_method_is_kept_by_the_status_and_the_port_of_the_listener_is_named() {
        let main = MainHost::new(&site(Some("shop.test"), "0.0.0.0:8443"), 8443).unwrap();
        let post = InboundRequest::from_head(
            b"POST /order HTTP/1.1\r\nHost: www.shop.test\r\nContent-Length: 0\r\n\r\n",
        );
        let r = main.answer(&post).unwrap();
        assert_eq!(r.status, 308, "308 repeats a POST as a POST");
        assert_eq!(
            r.peek(b"Location"),
            Some(&b"https://shop.test:8443/order"[..])
        );
        assert!(r.body.is_empty());
    }

    #[test]
    fn the_location_cannot_carry_a_byte_that_ends_a_header_line_or_names_another_host() {
        for (target, want) in [
            (&b"/a b"[..], "https://h/a%20b"),
            (
                b"/x\r\nSet-Cookie: a=b",
                "https://h/x%0D%0ASet-Cookie:%20a=b",
            ),
            (
                b"/x?q=\xe2\x82\xac\x00\x7f",
                "https://h/x?q=%E2%82%AC%00%7F",
            ),
            (b"/x\ty", "https://h/x%09y"),
            // Already escaped bytes stay as written.
            (b"/a%20b%0d%0a", "https://h/a%20b%0d%0a"),
            // A path that starts with two slashes is a path on the host, not another host.
            (b"//evil.test/x", "https://h//evil.test/x"),
            // No origin-form target: `OPTIONS *`, an absolute-form target without a path.
            (b"*", "https://h/"),
            (b"", "https://h/"),
            (b"?x=1", "https://h/?x=1"),
            (b"x", "https://h/"),
        ] {
            let got = https_location("h", 443, target);
            assert_eq!(String::from_utf8(got.clone()).unwrap(), want, "{target:?}");
            assert!(
                got.iter().all(u8::is_ascii_graphic),
                "{target:?}: {got:?} holds a byte that is not visible ASCII"
            );
        }
        assert_eq!(https_location("h", 8443, b"/x"), b"https://h:8443/x");
        assert_eq!(https_location("h", 443, b"/x"), b"https://h/x");
    }

    fn target(proxy_config: &str, request: &InboundRequest) -> String {
        let r = route(proxy_config, None);
        String::from_utf8(upstream_target(&r, request).into_owned()).unwrap()
    }

    #[test]
    fn the_prefix_comes_off_the_path_it_equals_or_starts_with_before_a_slash() {
        let cfg = r#"{"strip_path_prefix":"/shop"}"#;
        for (path, want) in [
            ("/shop", "/"),
            ("/shop/", "/"),
            ("/shop/cart", "/cart"),
            ("/shop/cart?a=1&b=%20", "/cart?a=1&b=%20"),
            ("/shop?a=1", "/?a=1"),
            ("/shop/?a=1", "/?a=1"),
            ("/shop/a%20b/%e2%82%ac", "/a%20b/%E2%82%AC"),
            ("/shopping", "/shopping"),
            ("/shop2/x", "/shop2/x"),
            ("/Shop/x", "/Shop/x"),
            ("/other/shop/x", "/other/shop/x"),
            ("/", "/"),
            // The path the pipeline reads has its dot segments resolved: this is `/admin`.
            ("/shop/../admin", "/admin"),
            ("/shop/./x", "/x"),
            ("/a/../shop/x", "/x"),
        ] {
            let req = request("a.test", path);
            assert_eq!(target(cfg, &req), want, "{path}");
            // What inspection reads is never the short path.
            assert!(req.forward_path.starts_with(b"/"), "{path}");
        }
        let req = request("a.test", "/shop/cart?x=<b>");
        assert_eq!(target(cfg, &req), "/cart?x=%3Cb%3E");
        assert_eq!(req.forward_path, b"/shop/cart");
        assert_eq!(req.forward_request_target, b"/shop/cart?x=%3Cb%3E");
    }

    #[test]
    fn a_path_outside_the_prefix_is_told_from_one_under_it() {
        let shop = route(r#"{"strip_path_prefix":"/shop"}"#, None);
        for (path, outside) in [
            ("/shop", false),
            ("/shop/", false),
            ("/shop/admin", false),
            ("/shop?a=1", false),
            ("/shop/%2e%2e/shop/x", false),
            ("/admin", true),
            ("/", true),
            ("/shopping", true),
            ("/shop2/x", true),
            ("/Shop/x", true),
            ("/other/shop/x", true),
            // Dot segments are resolved first, so this is `/admin`.
            ("/shop/../admin", true),
            ("/shop/%2e%2e/admin", true),
            ("/a/../shop/x", false),
        ] {
            assert_eq!(
                outside_prefix(&shop, &request("a.test", path)),
                outside,
                "{path}"
            );
        }
        let deeper = route(r#"{"strip_path_prefix":"/a/b"}"#, None);
        assert!(outside_prefix(&deeper, &request("a.test", "/a")));
        assert!(outside_prefix(&deeper, &request("a.test", "/a/bc")));
        assert!(!outside_prefix(&deeper, &request("a.test", "/a/b/c")));
        // No prefix: no path is outside it.
        for cfg in ["{}", r#"{"strip_path_prefix":""}"#] {
            let r = route(cfg, None);
            assert!(!outside_prefix(&r, &request("a.test", "/admin")), "{cfg}");
        }
    }

    #[test]
    fn a_longer_prefix_goes_by_whole_segments() {
        let cfg = r#"{"strip_path_prefix":"/a/b"}"#;
        for (path, want) in [
            ("/a/b", "/"),
            ("/a/b/c", "/c"),
            ("/a/bc", "/a/bc"),
            ("/a", "/a"),
            ("/a/b/c/d?x=1", "/c/d?x=1"),
        ] {
            assert_eq!(target(cfg, &request("a.test", path)), want, "{path}");
        }
    }

    #[test]
    fn no_prefix_and_an_upgrade_request_keep_the_public_target() {
        let plain = request("a.test", "/shop/cart?a=1");
        assert_eq!(target("{}", &plain), "/shop/cart?a=1");
        assert_eq!(
            target(r#"{"strip_path_prefix":""}"#, &plain),
            "/shop/cart?a=1"
        );
        let upgrade = InboundRequest::from_head(
            b"GET /shop/ws HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        );
        assert!(upgrade.has_upgrade() && !plain.has_upgrade());
        assert_eq!(
            target(r#"{"strip_path_prefix":"/shop"}"#, &upgrade),
            "/shop/ws"
        );
    }

    #[test]
    fn a_route_says_whether_it_redirects() {
        assert!(!route("{}", None).redirects());
        assert!(route(r#"{"strip_path_prefix":"/shop"}"#, None).redirects());
        let tls = |canonical| Some(site(canonical, "0.0.0.0:443"));
        assert!(route("{}", tls(Some("shop.test"))).redirects());
        assert!(!route("{}", tls(None)).redirects());
    }

    #[test]
    fn a_route_refuses_a_prefix_that_is_not_valid() {
        for bad in [
            "shop", "/shop/", "/a//b", "/a/../b", "/a b", "/a%2Fb", "/a?b",
        ] {
            let cfg = json_prefix(bad);
            let spec = AppSpec {
                app_id: "a".into(),
                listen_host: String::new(),
                listen_port: 0,
                upstream: "http://127.0.0.1:1".into(),
                mode: "block".into(),
                proxy_config: cfg.into_bytes(),
                rules_json: Vec::new(),
                fcgi_doc_root: String::new(),
                fcgi_index: String::new(),
                fcgi_keep_conn: false,
                maintenance: Vec::new(),
                analysis: Arc::new(crate::testing::analysis_setup(b"{}")),
                tls: None,
                compression: None,
                static_files: None,
                cache: None,
                session_cookies: Vec::new(),
            };
            let e = build_route(&spec).err().expect(bad);
            assert!(e.contains("strip_path_prefix"), "{bad}: {e}");
        }
    }

    /// `{"strip_path_prefix": "<value>"}` with the backslash and quote of the value escaped.
    fn json_prefix(value: &str) -> String {
        format!(
            r#"{{"strip_path_prefix":"{}"}}"#,
            value.replace('\\', "\\\\").replace('"', "\\\"")
        )
    }
}
