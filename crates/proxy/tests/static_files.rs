//! Static files through the public API: an app that answers `GET` and `HEAD` for the files of a
//! folder itself. What is served and how (type, validators, conditions, ranges), what never is
//! (traversal in every spelling, links, hidden and PHP files, the names the host agent never
//! sheds), what happens when the folder's link moves, big files, compression of a small one, and
//! the decision events.

mod common;

use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use wafio_proxy::{AppSpec, CompressionSpec, StaticSpec};

/// A scratch directory, removed at the end of the test.
struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("wafio-static-it-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir.canonicalize().unwrap())
    }

    fn file(&self, rel: &str, content: &[u8]) -> PathBuf {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    fn link(&self, rel: &str, target: impl AsRef<Path>) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(target, path).unwrap();
    }

    fn path(&self, rel: &str) -> String {
        self.0.join(rel).to_str().unwrap().to_owned()
    }

    /// A file of `size` bytes that holds a pattern the test can check, written without keeping it
    /// in memory.
    fn pattern(&self, rel: &str, size: u64) {
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut out = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
        let mut block = [0u8; 1 << 16];
        let mut at = 0u64;
        while at < size {
            let n = block.len().min((size - at) as usize);
            for (i, b) in block[..n].iter_mut().enumerate() {
                *b = byte_at(at + i as u64);
            }
            std::io::Write::write_all(&mut out, &block[..n]).unwrap();
            at += n as u64;
        }
    }

    /// A file of `size` bytes with no data written (a sparse file).
    fn sparse(&self, rel: &str, size: u64) -> PathBuf {
        let path = self.file(rel, b"");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(size)
            .unwrap();
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn byte_at(i: u64) -> u8 {
    ((i * 31 + i / 251) % 251) as u8
}

fn checks_out(body: &[u8], from: u64) -> bool {
    body.iter()
        .enumerate()
        .all(|(i, b)| *b == byte_at(from + i as u64))
}

const FROM_APP: &[u8] = b"from the application";

async fn upstream() -> TestUpstream {
    http_upstream_with("Content-Type: text/plain\r\n", FROM_APP).await
}

fn folder_app(port: u16, up: &TestUpstream, root: &str, missing: &str, max_age: i64) -> AppSpec {
    let mut a = app("shop", port, &format!("http://{}", up.addr));
    a.static_files = Some(StaticSpec::check(root, missing, max_age).expect("the folder passes"));
    a
}

struct Site {
    _h: Harness,
    addr: SocketAddr,
    up: TestUpstream,
    dir: Dir,
}

/// The standard folder `public/` of `dir`, and `secret.txt` beside it.
async fn site(missing: &str) -> Site {
    let dir = Dir::new("site");
    dir.file("public/index.html", b"<h1>home</h1>");
    dir.file("public/hello.txt", b"hello, folder");
    dir.file("public/css/site.css", b"body { color: black }\n");
    dir.file("public/img/logo.png", b"\x89PNG not really");
    dir.file("public/docs/index.html", b"docs");
    dir.file("public/empty/keep.txt", b"no index here");
    dir.file("secret.txt", b"SECRET OUTSIDE THE FOLDER");
    site_of(dir, missing).await
}

async fn site_of(dir: Dir, missing: &str) -> Site {
    let up = upstream().await;
    let port = free_port();
    let a = folder_app(port, &up, &dir.path("public"), missing, 0);
    let (h, addr) = Harness::serve(vec![a]);
    Site {
        _h: h,
        addr,
        up,
        dir,
    }
}

fn request(method: &str, path: &str, extra: &[&str]) -> Vec<u8> {
    let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: app.test\r\n");
    for line in extra {
        raw.push_str(line);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");
    raw.into_bytes()
}

fn with(path: &str, extra: &[&str]) -> Vec<u8> {
    request("GET", path, extra)
}

/// A `HEAD` request and the head that answers it: the status and the headers. Nothing follows.
async fn head_of(c: &mut Client, path: &str, extra: &[&str]) -> ReplyParts {
    c.0.get_mut()
        .write_all(&request("HEAD", path, extra))
        .await
        .unwrap();
    let (first, headers) = read_head(&mut c.0).await.unwrap().unwrap();
    ReplyParts {
        status: first.split(' ').nth(1).unwrap().parse().unwrap(),
        headers,
        body: Vec::new(),
    }
}

#[tokio::test]
async fn a_file_comes_from_the_folder_with_its_type_and_validators_and_the_application_is_not_asked()
 {
    let s = site("").await;
    let mut c = Client::connect(s.addr).await.unwrap();
    for (path, body, ct) in [
        (
            "/hello.txt",
            &b"hello, folder"[..],
            "text/plain; charset=utf-8",
        ),
        (
            "/css/site.css",
            b"body { color: black }\n",
            "text/css; charset=utf-8",
        ),
        ("/img/logo.png", b"\x89PNG not really", "image/png"),
        ("/", b"<h1>home</h1>", "text/html; charset=utf-8"),
        ("/index.html", b"<h1>home</h1>", "text/html; charset=utf-8"),
        ("/docs/", b"docs", "text/html; charset=utf-8"),
        (
            "/hello.txt?cache=bust&x=1",
            b"hello, folder",
            "text/plain; charset=utf-8",
        ),
    ] {
        let r = c.send(&get(path)).await.unwrap();
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.body, body, "{path}");
        assert_eq!(r.header("content-type"), Some(ct), "{path}");
        assert_eq!(
            r.header("content-length"),
            Some(body.len().to_string().as_str()),
            "{path}"
        );
        assert_eq!(
            r.header("x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(r.header("accept-ranges"), Some("bytes"), "{path}");
        assert!(
            r.header("last-modified")
                .is_some_and(|d| d.ends_with(" GMT")),
            "{path}"
        );
        let etag = r.header("etag").unwrap();
        assert!(
            etag.starts_with('"') && etag.ends_with('"') && etag.contains('-'),
            "{etag}"
        );
        assert_eq!(
            r.header("cache-control"),
            None,
            "no browser cache time is set: {path}"
        );
        assert_eq!(
            r.header("x-up"),
            None,
            "{path}: the application did not answer"
        );
    }
    assert_eq!(s.up.count(), 0, "the application was not asked");
}

#[tokio::test]
async fn the_browser_cache_time_is_sent_when_it_is_set_and_not_otherwise() {
    let dir = Dir::new("age");
    dir.file("public/a.txt", b"a");
    let up = upstream().await;
    let a = folder_app(free_port(), &up, &dir.path("public"), "", 3600);
    let (_h, addr) = Harness::serve(vec![a]);
    let r = one(addr, &get("/a.txt")).await;
    assert_eq!(r.header("cache-control"), Some("max-age=3600"));
}

#[tokio::test]
async fn head_gets_the_headers_of_get_and_no_body_for_a_small_and_a_big_file() {
    let s = site("").await;
    s.dir.pattern("public/big.bin", 3 << 20);
    let mut c = Client::connect(s.addr).await.unwrap();
    for (path, len) in [("/hello.txt", 13usize), ("/big.bin", 3 << 20)] {
        let got = c.send(&get(path)).await.unwrap();
        let head = head_of(&mut c, path, &[]).await;
        assert_eq!(head.status, 200, "{path}");
        assert_eq!(
            head.header("content-length"),
            Some(len.to_string().as_str()),
            "{path}"
        );
        for name in [
            "content-type",
            "etag",
            "last-modified",
            "accept-ranges",
            "x-content-type-options",
        ] {
            assert_eq!(head.header(name), got.header(name), "{path} {name}");
        }
        // Nothing follows the head: the next request on the connection is answered next.
        let again = c.send(&get("/hello.txt")).await.unwrap();
        assert_eq!(again.body, b"hello, folder", "{path}");
    }
    let r = head_of(&mut c, "/docs", &[]).await;
    assert_eq!((r.status, r.header("location")), (308, Some("/docs/")));
    assert_eq!(s.up.count(), 0);
}

#[tokio::test]
async fn a_conditional_request_gets_304_with_the_validators_and_no_body() {
    let s = site("").await;
    let mut c = Client::connect(s.addr).await.unwrap();
    let full = c.send(&get("/hello.txt")).await.unwrap();
    let etag = full.header("etag").unwrap().to_owned();
    let date = full.header("last-modified").unwrap().to_owned();
    for (header, value) in [
        ("If-None-Match", etag.clone()),
        ("If-None-Match", format!("W/{etag}")),
        ("If-None-Match", format!("\"x\", {etag}, \"y\"")),
        ("If-None-Match", "*".to_owned()),
        ("If-Modified-Since", date.clone()),
        (
            "If-Modified-Since",
            "Fri, 01 Jan 2100 00:00:00 GMT".to_owned(),
        ),
    ] {
        let r = c
            .send(&get_with("/hello.txt", &format!("{header}: {value}")))
            .await
            .unwrap();
        assert_eq!(r.status, 304, "{header}: {value}");
        assert!(r.body.is_empty());
        assert_eq!(r.header("etag"), Some(etag.as_str()), "{header}: {value}");
        assert_eq!(
            r.header("last-modified"),
            Some(date.as_str()),
            "{header}: {value}"
        );
        assert_eq!(r.header("content-length"), None);
    }
    for (header, value) in [
        ("If-None-Match", "\"other\"".to_owned()),
        (
            "If-Modified-Since",
            "Thu, 01 Jan 1970 00:00:00 GMT".to_owned(),
        ),
        ("If-Modified-Since", "not a date".to_owned()),
        // A tag that does not match wins over a date that would.
    ] {
        let r = c
            .send(&get_with("/hello.txt", &format!("{header}: {value}")))
            .await
            .unwrap();
        assert_eq!(
            (r.status, r.body.as_slice()),
            (200, &b"hello, folder"[..]),
            "{header}: {value}"
        );
    }
    let both = c
        .send(&with(
            "/hello.txt",
            &[
                "If-None-Match: \"other\"",
                &format!("If-Modified-Since: {date}"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(both.status, 200, "the tag decides when there is one");
    // HEAD is conditional too.
    let r = head_of(&mut c, "/hello.txt", &[&format!("If-None-Match: {etag}")]).await;
    assert_eq!(r.status, 304);
    // A file that changes has another tag, so the old one no longer matches.
    s.dir.file("public/hello.txt", b"hello again, folder!");
    let r = c
        .send(&get_with("/hello.txt", &format!("If-None-Match: {etag}")))
        .await
        .unwrap();
    assert_eq!(
        (r.status, r.body.as_slice()),
        (200, &b"hello again, folder!"[..])
    );
    assert_ne!(r.header("etag"), Some(etag.as_str()));
}

fn get_with(path: &str, header: &str) -> Vec<u8> {
    with(path, &[header])
}

#[tokio::test]
async fn a_range_gets_206_with_its_span_and_a_bad_one_gets_what_the_rules_say() {
    let s = site("").await;
    let text = b"0123456789abcdefghij"; // 20 bytes
    s.dir.file("public/t.txt", text);
    let mut c = Client::connect(s.addr).await.unwrap();
    let full = c.send(&get("/t.txt")).await.unwrap();
    assert_eq!(full.body, text);
    for (range, from, to) in [
        ("bytes=0-4", 0, 4),
        ("bytes=5-", 5, 19),
        ("bytes=-3", 17, 19),
        ("bytes=10-1000", 10, 19),
        ("bytes=19-19", 19, 19),
        ("bytes=-1000", 0, 19),
    ] {
        let r = c
            .send(&get_with("/t.txt", &format!("Range: {range}")))
            .await
            .unwrap();
        assert_eq!(r.status, 206, "{range}");
        assert_eq!(r.body, &text[from..=to], "{range}");
        assert_eq!(
            r.header("content-range"),
            Some(format!("bytes {from}-{to}/20").as_str()),
            "{range}"
        );
        assert_eq!(
            r.header("content-length"),
            Some((to - from + 1).to_string().as_str()),
            "{range}"
        );
        assert_eq!(r.header("etag"), full.header("etag"), "{range}");
        assert_eq!(
            r.header("content-type"),
            full.header("content-type"),
            "{range}"
        );
    }
    // Outside the file.
    for range in ["bytes=20-", "bytes=20-30", "bytes=-0", "bytes=999-"] {
        let r = c
            .send(&get_with("/t.txt", &format!("Range: {range}")))
            .await
            .unwrap();
        assert_eq!(r.status, 416, "{range}");
        assert_eq!(r.header("content-range"), Some("bytes */20"), "{range}");
        assert!(r.body.is_empty(), "{range}");
    }
    // Several ranges, other units and forms that do not parse are the whole file.
    for range in [
        "bytes=0-1,5-6",
        "items=0-1",
        "bytes=a-b",
        "bytes=5-2",
        "bytes=",
        "garbage",
    ] {
        let r = c
            .send(&get_with("/t.txt", &format!("Range: {range}")))
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &text[..]), "{range}");
        assert_eq!(r.header("content-range"), None, "{range}");
    }
    // If-Range: the same file keeps the range, another one gets the whole.
    let tag = full.header("etag").unwrap().to_owned();
    let date = full.header("last-modified").unwrap().to_owned();
    for (validator, status) in [
        (tag.clone(), 206),
        (date, 206),
        ("\"other\"".to_owned(), 200),
        (format!("W/{tag}"), 200),
        ("Thu, 01 Jan 1970 00:00:00 GMT".to_owned(), 200),
    ] {
        let r = c
            .send(&with(
                "/t.txt",
                &["Range: bytes=0-4", &format!("If-Range: {validator}")],
            ))
            .await
            .unwrap();
        assert_eq!(r.status, status, "If-Range: {validator}");
        assert_eq!(
            r.body,
            if status == 206 { &text[..5] } else { &text[..] },
            "{validator}"
        );
    }
    // HEAD with a range, and a conditional that holds before a range that does not.
    let head = head_of(&mut c, "/t.txt", &["Range: bytes=2-5"]).await;
    assert_eq!(
        (
            head.status,
            head.header("content-range"),
            head.header("content-length")
        ),
        (206, Some("bytes 2-5/20"), Some("4"))
    );
    let nm = c
        .send(&with(
            "/t.txt",
            &[&format!("If-None-Match: {tag}"), "Range: bytes=99-"],
        ))
        .await
        .unwrap();
    assert_eq!(nm.status, 304);
    // An empty file has no range to give.
    s.dir.file("public/zero.txt", b"");
    let r = c
        .send(&get_with("/zero.txt", "Range: bytes=0-"))
        .await
        .unwrap();
    assert_eq!(
        (r.status, r.header("content-range")),
        (416, Some("bytes */0"))
    );
    assert_eq!(c.send(&get("/zero.txt")).await.unwrap().status, 200);
    assert_eq!(s.up.count(), 0);
}

#[tokio::test]
async fn a_file_that_is_not_there_goes_to_the_application_or_is_not_found_by_the_mode() {
    let app_mode = site("").await;
    let own = site("not_found").await;
    let mut a = Client::connect(app_mode.addr).await.unwrap();
    let mut n = Client::connect(own.addr).await.unwrap();
    for path in [
        "/nothing.txt",
        "/css/none.css",
        "/empty/",
        "/empty",
        "/nodir/x",
    ] {
        let r = a.send(&get(path)).await.unwrap();
        assert_eq!(
            (r.status, r.body.as_slice()),
            (200, FROM_APP),
            "{path}: the application answers"
        );
        let r = n.send(&get(path)).await.unwrap();
        assert_eq!(r.status, 404, "{path}");
        assert_eq!(r.header("x-up"), None);
    }
    assert_eq!(app_mode.up.count(), 5);
    assert_eq!(own.up.count(), 0, "the application gets no request at all");
    // Other methods: the application, or 405.
    for method in ["POST", "PUT", "DELETE", "OPTIONS", "PATCH"] {
        let raw =
            format!("{method} /hello.txt HTTP/1.1\r\nHost: app.test\r\nContent-Length: 0\r\n\r\n");
        let r = a.send(raw.as_bytes()).await.unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, FROM_APP), "{method}");
        let r = n.send(raw.as_bytes()).await.unwrap();
        assert_eq!(r.status, 405, "{method}");
        assert_eq!(r.header("allow"), Some("GET, HEAD"), "{method}");
    }
    assert_eq!(own.up.count(), 0);
    // The answer of a miss keeps the connection open.
    assert_eq!(n.send(&get("/hello.txt")).await.unwrap().status, 200);
}

/// Where a request that leaves the folder goes: the application in the default mode, a 404 in the
/// other. What it must never get is the file outside.
const TRAVERSAL: &[&str] = &[
    "/../secret.txt",
    "/./../secret.txt",
    "/a/../../secret.txt",
    "/css/../../secret.txt",
    "/%2e%2e/secret.txt",
    "/%2E%2E/secret.txt",
    "/.%2e/secret.txt",
    "/%2e./secret.txt",
    "/%252e%252e/secret.txt",
    "/%252e%252e%252fsecret.txt",
    "/..%2fsecret.txt",
    "/..%2Fsecret.txt",
    "/%2e%2e%2fsecret.txt",
    "/a/..%2f..%2fsecret.txt",
    "/..%5csecret.txt",
    "/%2e%2e%5csecret.txt",
    "/..%255csecret.txt",
    "/%c0%ae%c0%ae/secret.txt",
    "/%c0%ae%c0%ae%c0%afsecret.txt",
    "/%e0%80%ae%e0%80%ae/secret.txt",
    "/..;/secret.txt",
    "/hello.txt%00.html",
    "/%00/../secret.txt",
    "//secret.txt",
    "///..///secret.txt",
    "/hello.txt/../../secret.txt",
    "/hello.txt/..%2f..%2fsecret.txt",
    "/etc/passwd",
    "/../../../../../../../../etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/os-release",
];

#[tokio::test]
async fn no_spelling_of_a_traversal_reaches_a_file_outside_the_folder() {
    let app_mode = site("").await;
    let own = site("not_found").await;
    for target in TRAVERSAL {
        let raw = format!("GET {target} HTTP/1.1\r\nHost: app.test\r\n\r\n");
        for (site, mode) in [(&app_mode, "app"), (&own, "not_found")] {
            let mut c = Client::connect(site.addr).await.unwrap();
            let r = c.send(raw.as_bytes()).await.unwrap();
            let text = r.text();
            assert!(!text.contains("SECRET"), "{target} ({mode}): {text}");
            assert!(!text.contains("root:"), "{target} ({mode}): {text}");
            // A path that is a legal one inside the folder (the double slash is one slash) is
            // looked for there: it is not found, which the mode turns into the application or 404.
            let want = if mode == "app" { 200 } else { 404 };
            assert_eq!(r.status, want, "{target} ({mode}): {text}");
        }
    }
    assert_eq!(own.up.count(), 0);
}

/// A raw request line the parser may accept or refuse: a backslash and a raw byte above 0x7f.
#[tokio::test]
async fn a_backslash_and_raw_high_bytes_in_the_target_do_not_leave_the_folder_either() {
    let s = site("not_found").await;
    for target in [
        &b"/..\\secret.txt"[..],
        b"/..\\..\\secret.txt",
        b"/\xc0\xae\xc0\xae/secret.txt",
        b"/a\\b",
    ] {
        let mut raw = b"GET ".to_vec();
        raw.extend_from_slice(target);
        raw.extend_from_slice(b" HTTP/1.1\r\nHost: app.test\r\n\r\n");
        let r = one(s.addr, &raw).await;
        assert!(
            r.status == 404 || r.status == 400,
            "{target:?}: {}",
            r.status
        );
        assert!(!r.text().contains("SECRET"));
    }
}

#[tokio::test]
async fn a_link_is_never_followed_and_such_a_request_is_missing() {
    let dir = Dir::new("links");
    dir.file("public/real.txt", b"real");
    dir.file("secret.txt", b"SECRET OUTSIDE THE FOLDER");
    dir.file("other/inner.txt", b"INNER OF ANOTHER FOLDER");
    dir.link("public/inside.txt", "real.txt");
    dir.link("public/up.txt", "../secret.txt");
    dir.link("public/abs.txt", dir.path("secret.txt"));
    dir.link("public/etc.txt", "/etc/os-release");
    dir.link("public/dir", dir.path("other"));
    dir.link("public/self", ".");
    dir.link("public/parent", "..");
    dir.link("public/dangling.txt", "nowhere");
    dir.link("public/loop", "loop");
    let s = site_of(dir, "not_found").await;
    assert_eq!(one(s.addr, &get("/real.txt")).await.body, b"real");
    for path in [
        "/inside.txt",
        "/up.txt",
        "/abs.txt",
        "/etc.txt",
        "/dir/inner.txt",
        "/dir/",
        "/dir",
        "/self/real.txt",
        "/parent/secret.txt",
        "/parent/public/real.txt",
        "/dangling.txt",
        "/loop",
    ] {
        let r = one(s.addr, &get(path)).await;
        assert_eq!(r.status, 404, "{path}");
        let text = r.text();
        assert!(
            !text.contains("SECRET") && !text.contains("INNER") && !text.contains("real"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn hidden_php_and_kept_names_are_never_served_in_either_mode() {
    let dir = Dir::new("hidden");
    for name in [
        ".env",
        ".git/config",
        ".htaccess",
        "x/.hidden/y.txt",
        "index.php",
        "a/b/upload.PHP",
        "legacy.php5",
        "page.phtml",
        "tool.phar",
        "source.phps",
        "shadow",
        "Shadow/x.txt",
        "private/key.txt",
        "cron/job.txt",
        "d/passwd",
        "ssh_host_rsa_key",
        ".well-known/.secret",
    ] {
        dir.file(&format!("public/{name}"), b"NEVER SERVED");
    }
    dir.file(
        "public/.well-known/acme-challenge/token",
        b"challenge answer",
    );
    dir.file("public/notphp.php9", b"served as a file");
    dir.file("public/private.txt", b"a name that only holds a kept one");
    let paths = [
        "/.env",
        "/.git/config",
        "/.htaccess",
        "/x/.hidden/y.txt",
        "/index.php",
        "/a/b/upload.PHP",
        "/legacy.php5",
        "/page.phtml",
        "/tool.phar",
        "/source.phps",
        "/shadow",
        "/SHADOW",
        "/Shadow/x.txt",
        "/private/key.txt",
        "/cron/job.txt",
        "/d/passwd",
        "/ssh_host_rsa_key",
        "/.well-known/.secret",
    ];
    let (up_app, up_own) = (upstream().await, upstream().await);
    let root = dir.path("public");
    let (_h1, app_addr) = Harness::serve(vec![folder_app(free_port(), &up_app, &root, "", 0)]);
    let (_h2, own_addr) = Harness::serve(vec![folder_app(
        free_port(),
        &up_own,
        &root,
        "not_found",
        0,
    )]);
    for path in paths {
        let r = one(app_addr, &get(path)).await;
        assert_eq!(
            (r.status, r.body.as_slice()),
            (200, FROM_APP),
            "{path}: the application is asked"
        );
        let r = one(own_addr, &get(path)).await;
        assert_eq!(r.status, 404, "{path}");
        assert!(!r.text().contains("NEVER"), "{path}");
    }
    assert_eq!(up_app.count(), paths.len());
    assert_eq!(up_own.count(), 0);
    // The one dot name that is served, and names that only look like the refused ones.
    for (path, body) in [
        (
            "/.well-known/acme-challenge/token",
            &b"challenge answer"[..],
        ),
        ("/notphp.php9", b"served as a file"),
        ("/private.txt", b"a name that only holds a kept one"),
    ] {
        assert_eq!(one(own_addr, &get(path)).await.body, body, "{path}");
    }
}

#[tokio::test]
async fn a_fifo_and_a_socket_are_missing_and_the_server_does_not_wait_for_them() {
    let dir = Dir::new("special");
    dir.file("public/ok.txt", b"ok");
    nix::unistd::mkfifo(&dir.0.join("public/pipe"), nix::sys::stat::Mode::S_IRWXU).unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(dir.0.join("public/sock")).unwrap();
    let s = site_of(dir, "not_found").await;
    for path in ["/pipe", "/pipe/", "/sock", "/sock/x"] {
        let r = tokio::time::timeout(Duration::from_secs(3), one(s.addr, &get(path)))
            .await
            .unwrap_or_else(|_| panic!("{path}: the server waited"));
        assert_eq!(r.status, 404, "{path}");
    }
    assert_eq!(one(s.addr, &get("/ok.txt")).await.body, b"ok");
}

#[tokio::test]
async fn a_directory_has_an_index_or_nothing_and_asks_for_its_slash_first() {
    let s = site("not_found").await;
    let mut c = Client::connect(s.addr).await.unwrap();
    for (path, location) in [
        ("/docs", "/docs/"),
        ("/docs?a=1&b=<2>", "/docs/?a=1&b=%3C2%3E"),
        ("/docs/../docs", "/docs/"),
        ("/%64ocs", "/docs/"),
    ] {
        let r = c.send(&get(path)).await.unwrap();
        assert_eq!(r.status, 308, "{path}");
        assert_eq!(r.header("location"), Some(location), "{path}");
        assert!(r.body.is_empty());
    }
    assert_eq!(c.send(&get("/docs/")).await.unwrap().body, b"docs");
    // No index.html: not a listing and not a redirect.
    for path in ["/empty", "/empty/", "/css/", "/css", "/img/"] {
        assert_eq!(c.send(&get(path)).await.unwrap().status, 404, "{path}");
    }
    // A location never names another host, whatever the target looks like.
    for target in ["//docs", "/%2F%2Fdocs", "/docs%0d%0aSet-Cookie:%20a=b"] {
        let r = c.send(&get(target)).await.unwrap();
        if let Some(location) = r.header("location") {
            assert!(
                location.starts_with('/') && !location.starts_with("//"),
                "{target}: {location}"
            );
            assert!(
                location.bytes().all(|b| b.is_ascii_graphic()),
                "{target}: {location}"
            );
        }
    }
}

#[tokio::test]
async fn a_request_that_asks_for_an_upgrade_is_the_applications() {
    let s = site("not_found").await;
    let h2c = "GET /hello.txt HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n";
    let r = one(s.addr, h2c.as_bytes()).await;
    assert_eq!((r.status, r.body.as_slice()), (200, FROM_APP));
    assert_eq!(s.up.count(), 1);
}

#[tokio::test]
async fn a_path_prefix_is_taken_off_before_the_folder_is_looked_in() {
    let dir = Dir::new("prefix");
    dir.file("public/img/a.png", b"png bytes");
    dir.file("public/index.html", b"shop home");
    dir.file("public/docs/index.html", b"shop docs");
    let up = upstream().await;
    let mut a = folder_app(free_port(), &up, &dir.path("public"), "not_found", 0);
    a.proxy_config = br#"{"strip_path_prefix":"/shop"}"#.to_vec();
    let (h, addr) = Harness::serve(vec![a]);
    let mut c = Client::connect(addr).await.unwrap();
    assert_eq!(
        c.send(&get("/shop/img/a.png")).await.unwrap().body,
        b"png bytes"
    );
    assert_eq!(c.send(&get("/shop/")).await.unwrap().body, b"shop home");
    assert_eq!(c.send(&get("/shop")).await.unwrap().body, b"shop home");
    assert_eq!(
        c.send(&get("/shop/docs/")).await.unwrap().body,
        b"shop docs"
    );
    // The directory's slash is asked for on the public path.
    let r = c.send(&get("/shop/docs")).await.unwrap();
    assert_eq!((r.status, r.header("location")), (308, Some("/shop/docs/")));
    // Outside the prefix is not the app's, and not the folder's either.
    for path in ["/img/a.png", "/", "/shopping/img/a.png"] {
        assert_eq!(c.send(&get(path)).await.unwrap().status, 404, "{path}");
    }
    assert_eq!(s(&h.last_event().uri), "/shopping/img/a.png");
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn the_decision_event_of_a_static_answer_carries_its_status_and_the_verdict() {
    let s = site("not_found").await;
    let mut c = Client::connect(s.addr).await.unwrap();
    let full = c.send(&get("/hello.txt")).await.unwrap();
    let tag = full.header("etag").unwrap().to_owned();
    for (raw, status) in [
        (get("/hello.txt"), 200),
        (get_with("/hello.txt", "Range: bytes=0-3"), 206),
        (get_with("/hello.txt", "Range: bytes=900-"), 416),
        (
            get_with("/hello.txt", &format!("If-None-Match: {tag}")),
            304,
        ),
        (get("/docs"), 308),
        (get("/none.txt"), 404),
        (request("DELETE", "/hello.txt", &["Content-Length: 0"]), 405),
    ] {
        let uri = String::from_utf8_lossy(&raw)
            .split(' ')
            .nth(1)
            .unwrap()
            .to_owned();
        c.send(&raw).await.unwrap();
        let e = s._h.last_event();
        assert_eq!(
            (e.status, s2(&e.action), s2(&e.uri)),
            (status, "allow", uri.as_str()),
            "{status}"
        );
        assert_eq!(s2(&e.mode), "block");
    }
}

fn s2(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap()
}

#[tokio::test]
async fn a_path_that_a_rule_blocks_is_blocked_even_when_the_folder_holds_the_file() {
    let dir = Dir::new("blocked");
    dir.file("public/blocked/file.txt", b"must not be served");
    dir.file("public/open.txt", b"open");
    let up = upstream().await;
    let mut a = folder_app(free_port(), &up, &dir.path("public"), "", 0);
    a.analysis = analysis_setup(r#"{"path_exceptions":[{"path":"/blocked/file.txt","block":{}}]}"#);
    let (h, addr) = Harness::serve(vec![a]);
    let r = one(addr, &get("/blocked/file.txt")).await;
    assert_eq!(r.status, 403);
    assert!(!r.text().contains("must not be served"));
    assert_eq!(h.last_event().action, b"block");
    assert_eq!(one(addr, &get("/open.txt")).await.body, b"open");
}

#[tokio::test]
async fn in_monitor_mode_the_folder_serves_too() {
    let dir = Dir::new("monitor");
    dir.file("public/a.txt", b"a");
    let up = upstream().await;
    let mut a = folder_app(free_port(), &up, &dir.path("public"), "", 0);
    a.mode = "monitor".into();
    let (h, addr) = Harness::serve(vec![a]);
    assert_eq!(one(addr, &get("/a.txt")).await.body, b"a");
    assert_eq!(s(&h.last_event().mode), "monitor");
    assert_eq!(up.count(), 0);
}

/// The link that a deploy tool moves, followed by the next request, and a link that is moved to
/// a folder that may not be served.
#[tokio::test]
async fn a_current_link_that_moves_is_followed_and_one_moved_to_a_forbidden_folder_serves_nothing()
{
    let dir = Dir::new("current");
    dir.file("releases/1/public/index.html", b"release one");
    dir.file("releases/2/public/index.html", b"release two");
    dir.file("keys/public/index.html", b"THE KEY DIRECTORY");
    dir.file("keys/public/a.txt", b"KEY BYTES");
    dir.link("current", "releases/1");
    let forbidden: &'static [&'static str] =
        Box::leak(vec![&*Box::leak(dir.path("keys").into_boxed_str())].into_boxed_slice());
    let up = upstream().await;
    let mut a = app("shop", free_port(), &format!("http://{}", up.addr));
    a.static_files = Some(
        StaticSpec::check_against(&dir.path("current/public"), "not_found", 0, forbidden).unwrap(),
    );
    let (_h, addr) = Harness::serve(vec![a]);
    let mut c = Client::connect(addr).await.unwrap();
    let repoint = |to: &str| {
        let _ = std::fs::remove_file(dir.0.join("current"));
        symlink(to, dir.0.join("current")).unwrap();
    };
    assert_eq!(c.send(&get("/")).await.unwrap().body, b"release one");
    repoint("releases/2");
    assert_eq!(c.send(&get("/")).await.unwrap().body, b"release two");
    // The key directory: nothing of it, however often it is asked.
    repoint("keys");
    for path in ["/", "/index.html", "/a.txt", "/a.txt"] {
        let r = c.send(&get(path)).await.unwrap();
        assert_eq!(r.status, 404, "{path}");
        assert!(!r.text().contains("KEY"), "{path}");
    }
    repoint("releases/1");
    assert_eq!(c.send(&get("/")).await.unwrap().body, b"release one");
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn a_current_link_that_moves_to_etc_serves_no_file_of_etc() {
    let dir = Dir::new("etc");
    dir.file("releases/1/os-release", b"mine");
    dir.link("current", "releases/1");
    let up = upstream().await;
    let a = folder_app(free_port(), &up, &dir.path("current"), "not_found", 0);
    let (_h, addr) = Harness::serve(vec![a]);
    let mut c = Client::connect(addr).await.unwrap();
    assert_eq!(c.send(&get("/os-release")).await.unwrap().body, b"mine");
    std::fs::remove_file(dir.0.join("current")).unwrap();
    symlink("/etc", dir.0.join("current")).unwrap();
    for path in ["/os-release", "/os-release", "/issue", "/fstab", "/"] {
        let r = c.send(&get(path)).await.unwrap();
        assert_eq!(r.status, 404, "{path}");
    }
}

// Compression of a small file.

fn css(times: usize) -> Vec<u8> {
    "a.button { color: #336699; padding: 4px 8px }\n"
        .repeat(times)
        .into_bytes()
}

fn decoded(r: &ReplyParts) -> Vec<u8> {
    let mut out = Vec::new();
    match r.header("content-encoding") {
        Some("gzip") => {
            flate2::read::GzDecoder::new(&r.body[..])
                .read_to_end(&mut out)
                .unwrap();
        }
        Some("br") => {
            brotli::Decompressor::new(&r.body[..], 4096)
                .read_to_end(&mut out)
                .unwrap();
        }
        None => out = r.body.clone(),
        Some(other) => panic!("encoding {other}"),
    }
    out
}

#[tokio::test]
async fn a_small_file_is_compressed_like_an_application_answer_and_a_range_is_not() {
    let dir = Dir::new("compress");
    let body = css(500);
    dir.file("public/site.css", &body);
    dir.file("public/page.html", &body);
    dir.file("public/photo.png", &vec![7u8; 20_000]);
    dir.file("public/tiny.css", b"a{}");
    let up = upstream().await;
    let mut a = folder_app(free_port(), &up, &dir.path("public"), "not_found", 0);
    a.compression = Some(CompressionSpec { min_bytes: 1024 });
    let (_h, addr) = Harness::serve(vec![a]);
    let mut c = Client::connect(addr).await.unwrap();
    let plain = c.send(&get("/site.css")).await.unwrap();
    assert_eq!(plain.header("content-encoding"), None);
    assert_eq!(plain.body, body);
    let strong = plain.header("etag").unwrap().to_owned();
    for (accept, encoding) in [("gzip", "gzip"), ("br", "br"), ("gzip, br", "br")] {
        let r = c
            .send(&get_with(
                "/site.css",
                &format!("Accept-Encoding: {accept}"),
            ))
            .await
            .unwrap();
        assert_eq!(r.status, 200, "{accept}");
        assert_eq!(r.header("content-encoding"), Some(encoding), "{accept}");
        assert_eq!(decoded(&r), body, "{accept}: the round trip");
        assert!(r.body.len() < body.len() / 5, "{accept}");
        assert_eq!(
            r.header("etag"),
            Some(format!("W/{strong}").as_str()),
            "{accept}: the tag turns weak"
        );
        assert_eq!(r.header("accept-ranges"), None, "{accept}");
        assert!(
            r.header("vary")
                .is_some_and(|v| v.contains("Accept-Encoding")),
            "{accept}"
        );
        assert_eq!(
            r.header("content-length"),
            Some(r.body.len().to_string().as_str()),
            "{accept}"
        );
        // The weak tag from this answer is a match for the file.
        let tag = r.header("etag").unwrap().to_owned();
        let nm = c
            .send(&with(
                "/site.css",
                &["Accept-Encoding: gzip", &format!("If-None-Match: {tag}")],
            ))
            .await
            .unwrap();
        assert_eq!(nm.status, 304, "{accept}");
    }
    // A part of the file is the file's bytes, not compressed.
    let part = c
        .send(&with(
            "/site.css",
            &["Accept-Encoding: gzip", "Range: bytes=0-99"],
        ))
        .await
        .unwrap();
    assert_eq!((part.status, part.header("content-encoding")), (206, None));
    assert_eq!(part.body, &body[..100]);
    // HEAD says nothing of an encoding, as for an application answer.
    let head = head_of(&mut c, "/site.css", &["Accept-Encoding: gzip"]).await;
    assert_eq!((head.status, head.header("content-encoding")), (200, None));
    // A type that is not compressible, and one under the smallest size.
    for path in ["/photo.png", "/tiny.css"] {
        let r = c
            .send(&get_with(path, "Accept-Encoding: gzip"))
            .await
            .unwrap();
        assert_eq!(r.header("content-encoding"), None, "{path}");
    }
    // BREACH: a signed-in visitor gets a page as it is and a style compressed.
    let session = "Cookie: PHPSESSID=abc";
    let page = c
        .send(&with("/page.html", &["Accept-Encoding: gzip", session]))
        .await
        .unwrap();
    assert_eq!(page.header("content-encoding"), None);
    let style = c
        .send(&with("/site.css", &["Accept-Encoding: gzip", session]))
        .await
        .unwrap();
    assert_eq!(style.header("content-encoding"), Some("gzip"));
    // A file that a client reads again after a compressed answer has its own tag.
    assert_eq!(
        c.send(&get("/site.css")).await.unwrap().header("etag"),
        Some(strong.as_str())
    );
}

#[tokio::test]
async fn a_big_file_is_not_compressed_and_is_streamed_whole() {
    let dir = Dir::new("bigcss");
    let size = (3u64 << 20) + 17;
    dir.pattern("public/big.css", size);
    let up = upstream().await;
    let mut a = folder_app(free_port(), &up, &dir.path("public"), "not_found", 0);
    a.compression = Some(CompressionSpec { min_bytes: 1 });
    let (_h, addr) = Harness::serve(vec![a]);
    let r = one(addr, &get_with("/big.css", "Accept-Encoding: gzip, br")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-encoding"), None);
    assert_eq!(r.body.len() as u64, size);
    assert!(checks_out(&r.body, 0));
}

// Big files.

#[tokio::test]
async fn a_big_file_is_sent_whole_with_its_length_and_a_part_of_it_by_range() {
    let dir = Dir::new("big");
    let size = (4u64 << 20) + 123;
    dir.pattern("public/big.bin", size);
    let s = site_of(dir, "not_found").await;
    let mut c = Client::connect(s.addr).await.unwrap();
    let r = c.send(&get("/big.bin")).await.unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-length"), Some(size.to_string().as_str()));
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.body.len() as u64, size);
    assert!(checks_out(&r.body, 0));
    // The same connection serves the next request after the body.
    assert_eq!(c.send(&get("/hello.txt")).await.unwrap().status, 404);
    // Parts: from the middle, the end, and a span of several reads.
    for (range, from, len) in [
        ("bytes=1000000-3999999", 1_000_000u64, 3_000_000u64),
        ("bytes=-5000", size - 5000, 5000),
        ("bytes=4194304-", 4_194_304, size - 4_194_304),
        ("bytes=0-1048576", 0, 1_048_577),
        ("bytes=7-1048583", 7, 1_048_577),
    ] {
        let r = c
            .send(&get_with("/big.bin", &format!("Range: {range}")))
            .await
            .unwrap();
        assert_eq!(r.status, 206, "{range}");
        assert_eq!(r.body.len() as u64, len, "{range}");
        assert!(checks_out(&r.body, from), "{range}");
        let end = from + len - 1;
        assert_eq!(
            r.header("content-range"),
            Some(format!("bytes {from}-{end}/{size}").as_str()),
            "{range}"
        );
    }
    let r = c
        .send(&get_with("/big.bin", &format!("Range: bytes={size}-")))
        .await
        .unwrap();
    assert_eq!(r.status, 416);
    assert_eq!(
        c.send(&get("/big.bin")).await.unwrap().body.len() as u64,
        size
    );
}

#[tokio::test]
async fn a_big_file_answer_ends_the_connection_when_the_request_says_close() {
    let dir = Dir::new("bigclose");
    dir.pattern("public/big.bin", 2 << 20);
    let s = site_of(dir, "not_found").await;
    let mut c = Client::connect(s.addr).await.unwrap();
    let r = c
        .send(&with("/big.bin", &["Connection: close"]))
        .await
        .unwrap();
    assert_eq!((r.status, r.body.len()), (200, 2 << 20));
    assert_eq!(r.header("connection"), Some("close"));
    assert!(at_eof(&mut c.0).await);
}

/// The length in the head was the file's size when it was opened: a file that grows is cut at
/// that size, and one that shrinks ends the connection short of it.
#[tokio::test]
async fn a_file_that_grows_is_sent_up_to_its_length_and_one_cut_short_ends_the_connection() {
    let dir = Dir::new("changing");
    let size = 48u64 << 20;
    dir.sparse("public/log.bin", size);
    let s = site_of(dir, "not_found").await;

    // Cut short: the client takes the head and a little, the file is emptied, the rest is read.
    let mut stream = TcpStream::connect(s.addr).await.unwrap();
    stream.write_all(&get("/log.bin")).await.unwrap();
    let mut reader = BufReader::new(stream);
    let (first, headers) = read_head(&mut reader).await.unwrap().unwrap();
    assert!(first.contains(" 200 "), "{first}");
    assert_eq!(
        header(&headers, "content-length"),
        Some(size.to_string().as_str())
    );
    let mut got = 0u64;
    let mut buf = vec![0u8; 1 << 16];
    while got < (1 << 20) {
        got += reader.read(&mut buf).await.unwrap() as u64;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::OpenOptions::new()
        .write(true)
        .open(s.dir.0.join("public/log.bin"))
        .unwrap()
        .set_len(0)
        .unwrap();
    loop {
        match tokio::time::timeout(Duration::from_secs(10), reader.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => got += n as u64,
            Err(_) => panic!("the connection was not ended"),
        }
    }
    assert!(got < size, "the body was cut short: {got} of {size}");
    // The server is fine: the next connection is answered.
    assert_eq!(one(s.addr, &get("/hello.txt")).await.status, 404);

    // Grown: the answer is the length it announced.
    s.dir.sparse("public/grow.bin", 3 << 20);
    let mut stream = TcpStream::connect(s.addr).await.unwrap();
    stream.write_all(&get("/grow.bin")).await.unwrap();
    let mut reader = BufReader::new(stream);
    let (_, headers) = read_head(&mut reader).await.unwrap().unwrap();
    assert_eq!(
        header(&headers, "content-length"),
        Some((3u64 << 20).to_string().as_str())
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(s.dir.0.join("public/grow.bin"))
        .unwrap()
        .set_len(6 << 20)
        .unwrap();
    let mut body = Vec::new();
    (&mut reader)
        .take(3 << 20)
        .read_to_end(&mut body)
        .await
        .unwrap();
    assert_eq!(body.len() as u64, 3 << 20);
    // Nothing follows: the connection waits for the next request.
    let mut more = [0u8; 16];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), reader.read(&mut more))
            .await
            .is_err()
    );
}

/// The memory of the agent does not follow the size of the files it sends: 100 clients that each
/// hold a download of a 1 GiB file after the first mebibyte cost the buffers of the reads and
/// nothing like the files. Run it by hand: `cargo test --release -p wafio-proxy --test
/// static_files -- --ignored --nocapture rss`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run by hand"]
async fn rss_stays_flat_over_100_parallel_downloads_of_a_1_gib_file() {
    fn rss_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap()
    }
    let dir = Dir::new("rss");
    let size = 1u64 << 30;
    dir.sparse("public/huge.bin", size);
    let s = site_of(dir, "not_found").await;
    // One download first: the pools, the allocator and the blocking threads are warm.
    let mut warm = Client::connect(s.addr).await.unwrap();
    warm.0.get_mut().write_all(&get("/huge.bin")).await.unwrap();
    let mut buf = vec![0u8; 1 << 16];
    let mut seen = 0usize;
    while seen < (4 << 20) {
        seen += warm.0.read(&mut buf).await.unwrap();
    }
    drop(warm);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = rss_kib();
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let addr = s.addr;
        tasks.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&get("/huge.bin")).await.unwrap();
            let mut buf = vec![0u8; 1 << 16];
            let mut got = 0usize;
            while got < (1 << 20) {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                got += n;
            }
            // Hold the download open without reading more.
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(stream);
        }));
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let during = rss_kib();
    for t in tasks {
        t.await.unwrap();
    }
    let grew = during.saturating_sub(before) / 1024;
    eprintln!(
        "rss before {} MiB, during 100 downloads {} MiB, grew {grew} MiB",
        before / 1024,
        during / 1024
    );
    assert!(
        grew < 80,
        "100 downloads of a 1 GiB file grew the process by {grew} MiB"
    );
}

#[tokio::test]
async fn the_folder_answers_are_counted_by_status() {
    use std::sync::atomic::Ordering::Relaxed;
    use wafio_proxy::metrics::{STATIC_BYTES, STATIC_RESPONSES, STATIC_STATUSES};
    let count = |status: u16| {
        let i = STATIC_STATUSES.iter().position(|&s| s == status).unwrap();
        STATIC_RESPONSES[i].load(Relaxed)
    };
    let (before_200, before_404, bytes) = (count(200), count(404), STATIC_BYTES.load(Relaxed));
    let s = site("not_found").await;
    let mut c = Client::connect(s.addr).await.unwrap();
    c.send(&get("/hello.txt")).await.unwrap();
    c.send(&get("/hello.txt")).await.unwrap();
    c.send(&get("/nothing")).await.unwrap();
    // The counters are the process's, and other tests add to them: at least what this one did.
    assert!(count(200) >= before_200 + 2);
    assert!(count(404) > before_404);
    assert!(STATIC_BYTES.load(Relaxed) >= bytes + 26);
}
