//! The folder's settings check, the per-request root check and the plan for a file, on real
//! directories.

use std::fs::File;
use std::path::Path;

use super::walk::{self, tests::Scratch};
use super::*;

fn spec(root: &str) -> StaticSpec {
    StaticSpec::check(root, "", 0).unwrap_or_else(|e| panic!("{root}: {e:?}"))
}

fn folder(root: &str) -> StaticFolder {
    StaticFolder::new("app", &spec(root))
}

/// A forbidden list for a test: the paths, made `'static` (a test leaks a few strings).
fn forbidding(paths: &[&Path]) -> &'static [&'static str] {
    let list: Vec<&'static str> = paths
        .iter()
        .map(|p| &*Box::leak(p.to_str().unwrap().to_owned().into_boxed_str()))
        .collect();
    Box::leak(list.into_boxed_slice())
}

fn refusal(root: &str) -> (RefusalCode, String) {
    let r = StaticSpec::check(root, "", 0).expect_err(root);
    (r.code, r.detail)
}

fn bytes(outcome: Outcome) -> Option<Vec<u8>> {
    match outcome {
        Outcome::Hit(Hit {
            body: Body::Bytes(b),
            ..
        }) => Some(b),
        _ => None,
    }
}

fn served(folder: &StaticFolder, path: &str) -> Option<Vec<u8>> {
    bytes(folder.lookup(path.as_bytes(), &Conditions::default(), false, None))
}

/// The folder text is checked before the disk is, so none of these needs to exist.
#[test]
fn a_folder_that_is_forbidden_or_hidden_is_refused_by_its_text() {
    use RefusalCode::{RootForbidden as F, RootUnreadable as U};
    for (root, want) in [
        ("/", F),
        ("/etc", F),
        ("/etc/wafio", F),
        ("/etc/wafio/certs/x", F),
        ("/proc", F),
        ("/proc/1/root", F),
        ("/sys", F),
        ("/sys/kernel", F),
        ("/dev", F),
        ("/dev/shm", F),
        ("/run", F),
        ("/run/php", F),
        ("/boot", F),
        ("/boot/efi", F),
        ("/usr", F),
        ("/usr/share/nginx/html", F),
        ("/usr/local/www", F),
        ("/var/lib/wafio-waf-agent", F),
        ("/var/lib/wafio-waf-agent/tls", F),
        ("/var/cache/wafio-waf", F),
        ("/var/cache/wafio-waf/objects", F),
        // Above a forbidden folder.
        ("/var", F),
        ("/var/lib", F),
        ("/var/cache", F),
        // A segment on the names the host agent never sheds, in any case, wherever it stands: the
        // root is opened by its path on every request.
        ("/srv/private/site", F),
        ("/srv/site/private", F),
        ("/srv/PRIVATE/site", F),
        ("/var/www/profile", F),
        ("/var/www/Profile/public", F),
        ("/srv/security", F),
        ("/srv/network/site", F),
        ("/srv/group", F),
        ("/srv/hosts/site", F),
        ("/srv/.docker/site", F),
        ("/srv/cron.d/site", F),
        ("/srv/systemd/site", F),
        ("/srv/wafio-waf-agent/site", F),
        // The folders the unit hides read as missing there, and are refused for that.
        ("/home", U),
        ("/home/deploy", U),
        ("/home/deploy/site/public", U),
        ("/root", U),
        ("/root/site", U),
        ("/run/user", U),
        ("/run/user/1000/site", U),
    ] {
        assert_eq!(refusal(root).0, want, "{root}");
        assert_eq!(refusal(root).1, root, "the detail is the folder");
    }
}

/// A name that only starts like a forbidden one is not under it.
#[test]
fn a_folder_that_only_looks_like_a_forbidden_one_is_judged_by_the_disk() {
    for root in [
        "/etcetera",
        "/usrlocal/www",
        "/var/lib/wafio-waf-agent-x",
        "/var/lib/wafio-waf",
        "/var/cache/wafio-waf2",
        "/var/www/shop/public",
        "/srv/site",
        "/homebrew/site",
        "/rootfs",
        "/run2",
        // A name that only holds a kept one.
        "/srv/private-site",
        "/srv/privately",
        "/srv/profiles",
        "/srv/my.profile",
        "/srv/group2/site",
        "/srv/the-hosts/site",
    ] {
        let (code, _) = refusal(root);
        assert_eq!(code, RefusalCode::RootMissing, "{root}");
    }
}

#[test]
fn a_setting_that_is_not_valid_is_refused_as_invalid_with_the_value() {
    let s = Scratch::new("invalid");
    let ok = s.dir("site");
    let ok = ok.to_str().unwrap();
    for (root, missing, max_age, detail) in [
        (ok, "both", 0, "both"),
        (ok, "App", 0, "App"),
        (ok, "", -1, "-1"),
        (ok, "", MAX_BROWSER_CACHE_S + 1, "31536001"),
        ("", "", 0, ""),
        ("var/www", "", 0, "var/www"),
        ("/var/./www", "", 0, "/var/./www"),
        ("/var/www/../etc", "", 0, "/var/www/../etc"),
        ("/var//www", "", 0, "/var//www"),
        ("/var/www/", "", 0, "/var/www/"),
        ("//", "", 0, "//"),
        ("/var/www\n/x", "", 0, "/var/www?/x"),
        ("/var/www\0", "", 0, "/var/www?"),
        ("/var/www/\u{fffd}", "", 0, "/var/www/\u{fffd}"),
        ("/var/www\u{7f}", "", 0, "/var/www?"),
    ] {
        let r = StaticSpec::check(root, missing, max_age).expect_err(root);
        assert_eq!(
            r.code,
            RefusalCode::Invalid,
            "{root:?} {missing:?} {max_age}"
        );
        assert_eq!(r.detail, detail, "{root:?} {missing:?} {max_age}");
    }
    // The edges are fine.
    for (missing, max_age) in [
        ("", 0),
        ("app", 0),
        ("not_found", 0),
        ("", MAX_BROWSER_CACHE_S),
        ("not_found", 1),
    ] {
        assert!(
            StaticSpec::check(ok, missing, max_age).is_ok(),
            "{missing:?} {max_age}"
        );
    }
    // A root of 1,024 bytes is the longest; the detail never passes 256 bytes. The names are
    // short enough for the disk to look at.
    let at_limit = format!("{}/{}", "/aaaaaaaaa".repeat(102), "a".repeat(3));
    assert_eq!(at_limit.len(), ROOT_MAX_BYTES);
    assert_eq!(
        StaticSpec::check(&at_limit, "", 0).unwrap_err().code,
        RefusalCode::RootMissing,
        "1,024 bytes pass the text and fail the disk"
    );
    let r = StaticSpec::check(&format!("{at_limit}a"), "", 0).unwrap_err();
    assert_eq!(r.code, RefusalCode::Invalid);
    assert_eq!(r.detail.len(), 256);
    // The detail is cut on a character, never inside one.
    let wide = format!("/{}", "é".repeat(200));
    let r = StaticSpec::check(&format!("{wide}//"), "", 0).unwrap_err();
    assert!(r.detail.len() <= 256 && r.detail.is_char_boundary(r.detail.len()));
}

#[test]
fn a_folder_on_the_disk_is_a_directory_that_opens_and_is_not_a_system_folder() {
    let s = Scratch::new("disk");
    s.file("file.txt", b"x");
    s.dir("site/public");
    s.link("link-to-site", "site");
    s.link("dangling", "nowhere");
    s.file("sub/file.txt", b"x");

    let root = s.path("site/public");
    let ok = StaticSpec::check(&root, "not_found", 120).unwrap();
    assert_eq!(ok.root(), root);
    assert_eq!((ok.missing, ok.max_age_s), (Missing::NotFound, 120));
    assert!(StaticSpec::check(&s.path("link-to-site/public"), "", 0).is_ok());
    assert!(StaticSpec::check(&s.path("link-to-site"), "", 0).is_ok());

    assert_eq!(refusal(&s.path("nowhere")).0, RefusalCode::RootMissing);
    assert_eq!(refusal(&s.path("dangling")).0, RefusalCode::RootMissing);
    assert_eq!(
        refusal(&s.path("file.txt/inside")).0,
        RefusalCode::RootMissing
    );
    assert_eq!(
        refusal(&s.path("file.txt")).0,
        RefusalCode::RootNotDirectory
    );
    assert_eq!(
        refusal(&s.path("file.txt")).1,
        s.path("file.txt"),
        "the detail names the folder"
    );
}

#[test]
fn a_folder_that_cannot_be_opened_is_unreadable() {
    if nix::unistd::geteuid().is_root() {
        return; // root opens everything
    }
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("unreadable");
    let closed = s.dir("closed");
    s.dir("closed/inner");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let (code, _) = refusal(&s.path("closed/inner"));
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(code, RefusalCode::RootUnreadable);
}

/// The list is run again on what the path opens: a link in the path can lead anywhere.
#[test]
fn a_folder_whose_path_leads_to_a_forbidden_folder_is_refused_for_where_it_leads() {
    let s = Scratch::new("leads");
    let keys = s.dir("keys/tls");
    s.dir("site");
    s.link("site-link", &keys);
    s.link("via-parent", s.0.join("keys"));
    let forbidden = forbidding(&[&s.0.join("keys")]);
    let check = |root: &str| StaticSpec::check_against(root, "", 0, forbidden);
    assert!(check(&s.path("site")).is_ok());
    let r = check(&s.path("site-link")).unwrap_err();
    assert_eq!(
        (r.code, r.detail.as_str()),
        (RefusalCode::RootForbidden, keys.to_str().unwrap())
    );
    // Above it, too: a folder that holds the forbidden one is refused.
    assert_eq!(
        check(&s.path("keys")).unwrap_err().code,
        RefusalCode::RootForbidden
    );
    assert_eq!(
        check(&s.path("via-parent/tls")).unwrap_err().code,
        RefusalCode::RootForbidden
    );
    // The real list refuses the real system folders, which exist here.
    assert_eq!(refusal("/etc").0, RefusalCode::RootForbidden);
    s.link("to-etc", "/etc");
    assert_eq!(refusal(&s.path("to-etc")).0, RefusalCode::RootForbidden);
    s.link("to-proc-self", "/proc/self");
    assert_eq!(
        refusal(&s.path("to-proc-self")).0,
        RefusalCode::RootForbidden
    );
}

/// A link can lead to a folder whose own path holds a kept name: the host agent would see the
/// open of it on every request, so it is refused for where it leads.
#[test]
fn a_folder_whose_path_leads_through_a_kept_name_is_refused_for_where_it_leads() {
    let s = Scratch::new("leads-kept");
    let private = s.dir("private/site");
    s.dir("plain/site");
    s.link("site-link", &private);
    s.link("plain-link", s.0.join("plain/site"));
    assert!(StaticSpec::check(&s.path("plain-link"), "", 0).is_ok());
    let r = StaticSpec::check(&s.path("site-link"), "", 0).unwrap_err();
    assert_eq!(
        (r.code, r.detail.as_str()),
        (RefusalCode::RootForbidden, private.to_str().unwrap()),
        "the detail names the folder the path opens"
    );
}

/// The same after the apply: a `current` link that moves to a folder under a kept name serves
/// nothing, the first time and when the pair is already known, and serves again when it moves back.
#[test]
fn a_current_link_repointed_below_a_kept_name_serves_nothing_and_a_return_serves_again() {
    let s = Scratch::new("repoint-kept");
    s.file("releases/1/index.html", b"one");
    s.file("private/site/index.html", b"under a kept name");
    s.file("Profile/index.html", b"in any case");
    s.link("current", "releases/1");
    let f = folder(&s.path("current"));
    assert_eq!(served(&f, "/").unwrap(), b"one");
    for target in [s.0.join("private/site"), s.0.join("Profile")] {
        std::fs::remove_file(s.0.join("current")).unwrap();
        s.link("current", &target);
        for _ in 0..3 {
            assert!(served(&f, "/").is_none(), "{}", target.display());
            assert!(served(&f, "/index.html").is_none(), "{}", target.display());
        }
        assert!(f.refused.load(Ordering::Relaxed));
        std::fs::remove_file(s.0.join("current")).unwrap();
        s.link("current", "releases/1");
        assert_eq!(served(&f, "/").unwrap(), b"one");
        assert!(!f.refused.load(Ordering::Relaxed));
    }
}

/// The note of a disk that did not answer is kept when the folder is long, and the folder is
/// cleaned like any other detail.
#[test]
fn the_refusal_for_a_disk_that_does_not_answer_names_the_folder_and_keeps_its_note() {
    let r = StaticRefusal::no_answer("/mnt/nfs/site");
    assert_eq!(
        (r.code, r.detail.as_str()),
        (
            RefusalCode::RootUnreadable,
            "/mnt/nfs/site (no answer from the disk)"
        )
    );
    let long = format!("/{}", "é".repeat(600));
    let r = StaticRefusal::no_answer(&long);
    assert!(r.detail.len() <= 256, "{}", r.detail.len());
    assert!(r.detail.ends_with(" (no answer from the disk)"));
    let r = StaticRefusal::no_answer("/mnt/a\u{1}b");
    assert_eq!(r.detail, "/mnt/a?b (no answer from the disk)");
}

#[test]
fn a_file_is_found_through_the_folder_and_a_name_outside_it_is_not() {
    let s = Scratch::new("lookup");
    s.file("public/index.html", b"home");
    s.file("public/css/site.css", b"body{}");
    s.file("secret.txt", b"secret");
    let f = folder(&s.path("public"));
    assert_eq!(served(&f, "/").unwrap(), b"home");
    assert_eq!(served(&f, "/index.html").unwrap(), b"home");
    assert_eq!(served(&f, "/css/site.css").unwrap(), b"body{}");
    assert!(matches!(
        f.lookup(b"/css", &Conditions::default(), false, None),
        Outcome::Missing
    ));
    for path in [
        "/missing.txt",
        "/../secret.txt",
        "/css/../../secret.txt",
        "/%2e%2e/secret.txt",
    ] {
        assert!(served(&f, path).is_none(), "{path}");
    }
}

/// A deploy tool that moves a `current` link is followed from the next request on.
#[test]
fn a_current_link_that_moves_is_followed() {
    let s = Scratch::new("current");
    s.file("releases/1/public/index.html", b"one");
    s.file("releases/2/public/index.html", b"two");
    s.link("current", "releases/1");
    let f = folder(&s.path("current/public"));
    assert_eq!(served(&f, "/").unwrap(), b"one");
    for (release, want) in [
        ("releases/2", "two"),
        ("releases/1", "one"),
        ("releases/2", "two"),
    ] {
        std::fs::remove_file(s.0.join("current")).unwrap();
        s.link("current", release);
        assert_eq!(served(&f, "/").unwrap(), want.as_bytes(), "{release}");
        assert_eq!(
            served(&f, "/").unwrap(),
            want.as_bytes(),
            "{release} again, with the pair kept"
        );
    }
    // A folder that is made again (a new inode at the same path) is followed too.
    std::fs::remove_dir_all(s.0.join("releases/2/public")).unwrap();
    s.file("releases/2/public/index.html", b"three");
    assert_eq!(served(&f, "/").unwrap(), b"three");
}

/// The link moves after the apply to a folder that may not be served: nothing is served, and the
/// answer is the same whether or not an earlier request saw the new directory.
#[test]
fn a_current_link_repointed_to_a_forbidden_folder_serves_nothing_and_a_return_serves_again() {
    let s = Scratch::new("repoint");
    s.file("releases/1/index.html", b"one");
    let keys = s.dir("keys");
    s.file("keys/index.html", b"the key directory");
    s.file("keys/a.txt", b"key bytes");
    s.link("current", "releases/1");
    let forbidden = forbidding(&[&keys]);
    let spec = StaticSpec::check_against(&s.path("current"), "", 0, forbidden).unwrap();
    let f = StaticFolder::new("app", &spec);
    assert_eq!(served(&f, "/").unwrap(), b"one");

    std::fs::remove_file(s.0.join("current")).unwrap();
    s.link("current", &keys);
    for _ in 0..3 {
        for path in ["/", "/index.html", "/a.txt"] {
            assert!(served(&f, path).is_none(), "{path}");
        }
    }
    assert!(f.refused.load(Ordering::Relaxed));

    std::fs::remove_file(s.0.join("current")).unwrap();
    s.link("current", "releases/1");
    assert_eq!(served(&f, "/").unwrap(), b"one");
    assert!(!f.refused.load(Ordering::Relaxed));

    // The key directory's own subfolders count as well, and a link to a folder above it.
    for target in [keys.clone(), s.0.clone()] {
        std::fs::remove_file(s.0.join("current")).unwrap();
        s.link("current", &target);
        assert!(served(&f, "/index.html").is_none(), "{}", target.display());
    }
}

/// The same with the real list: `current` leads to a system folder that exists.
#[test]
fn a_current_link_repointed_to_a_system_folder_never_serves_a_file_of_it() {
    let s = Scratch::new("etc");
    s.file("releases/1/os-release", b"mine");
    s.file("releases/2/os-release", b"also mine");
    s.link("current", "releases/1");
    let f = folder(&s.path("current"));
    assert_eq!(served(&f, "/os-release").unwrap(), b"mine");
    for system in [
        "/etc",
        "/usr",
        "/proc/self",
        "/dev",
        "/sys",
        "/run",
        "/boot",
        "/var/lib",
    ] {
        if !Path::new(system).is_dir() {
            continue;
        }
        std::fs::remove_file(s.0.join("current")).unwrap();
        s.link("current", system);
        for path in [
            "/os-release",
            "/passwd.bak",
            "/status",
            "/null",
            "/index.html",
            "/",
        ] {
            assert!(served(&f, path).is_none(), "{system}{path}");
        }
    }
    std::fs::remove_file(s.0.join("current")).unwrap();
    s.link("current", "releases/2");
    assert_eq!(served(&f, "/os-release").unwrap(), b"also mine");
}

#[test]
fn a_folder_that_disappears_serves_nothing_and_comes_back_when_it_is_made_again() {
    let s = Scratch::new("gone");
    s.file("site/index.html", b"here");
    let f = folder(&s.path("site"));
    assert_eq!(served(&f, "/").unwrap(), b"here");
    std::fs::remove_dir_all(s.0.join("site")).unwrap();
    assert!(served(&f, "/").is_none());
    s.file("site/index.html", b"again");
    assert_eq!(served(&f, "/").unwrap(), b"again");
}

/// The names of the kept list make no system call, whether or not they exist in the folder.
#[test]
fn a_request_for_a_kept_name_makes_no_open_at_all() {
    let s = Scratch::new("kept");
    for name in names::KEPT_NAMES {
        s.file(&format!("public/{name}/inner.txt"), b"on disk");
    }
    s.file("public/ok.txt", b"fine");
    let f = folder(&s.path("public"));
    let opens = || walk::OPENS.with(std::cell::Cell::get);
    for name in names::KEPT_NAMES {
        for path in [
            format!("/{name}"),
            format!("/{}", name.to_ascii_uppercase()),
            format!("/{name}/"),
            format!("/{name}/inner.txt"),
            format!("/ok.txt/{name}"),
            format!("/a/b/{name}/c"),
        ] {
            let before = opens();
            assert!(
                matches!(
                    f.lookup(path.as_bytes(), &Conditions::default(), false, None),
                    Outcome::Missing
                ),
                "{path}"
            );
            assert_eq!(opens(), before, "{path} touched the disk");
        }
    }
    // The same for the other refusals that are decided by text.
    for path in [
        "/.git/config",
        "/.env",
        "/x.php",
        "/a/b.phtml",
        "/../x",
        "/a\\b",
    ] {
        let before = opens();
        assert!(served(&f, path).is_none(), "{path}");
        assert_eq!(opens(), before, "{path}");
    }
    // A file that is allowed does open things.
    let before = opens();
    assert_eq!(served(&f, "/ok.txt").unwrap(), b"fine");
    assert!(opens() > before);
}

/// A name that is on disk but never served: hidden, PHP, kept. The folder holds all of them.
#[test]
fn hidden_php_and_kept_names_that_exist_are_not_served() {
    let s = Scratch::new("hidden");
    for name in [
        ".env",
        ".git/config",
        ".htpasswd",
        "index.php",
        "a/upload.PHP",
        "a/x.phtml",
        "shadow",
        "private/key.txt",
        "cron/job",
        ".well-known/.secret",
    ] {
        s.file(&format!("public/{name}"), b"never");
    }
    s.file("public/.well-known/acme-challenge/token", b"served");
    s.file("public/index.html", b"home");
    let f = folder(&s.path("public"));
    for path in [
        "/.env",
        "/.git/config",
        "/.htpasswd",
        "/index.php",
        "/a/upload.PHP",
        "/a/x.phtml",
        "/shadow",
        "/private/key.txt",
        "/cron/job",
        "/.well-known/.secret",
    ] {
        assert!(served(&f, path).is_none(), "{path}");
    }
    assert_eq!(
        served(&f, "/.well-known/acme-challenge/token").unwrap(),
        b"served"
    );
    assert_eq!(served(&f, "/").unwrap(), b"home");
}

fn sized(s: &Scratch, name: &str, size: u64) {
    let path = s.file(name, b"");
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(size)
        .unwrap();
}

#[test]
fn a_file_is_read_whole_up_to_a_mebibyte_and_sent_from_its_descriptor_above() {
    let s = Scratch::new("sizes");
    sized(&s, "public/exact.bin", READ_WHOLE_MAX);
    sized(&s, "public/over.bin", READ_WHOLE_MAX + 1);
    sized(&s, "public/empty.bin", 0);
    sized(&s, "public/lookup.bin", LOOKUP_READ_MAX);
    sized(&s, "public/after.bin", LOOKUP_READ_MAX + 1);
    let f = folder(&s.path("public"));
    let c = Conditions::default();
    let hit =
        |path: &str, c: &Conditions, head: bool| match f.lookup(path.as_bytes(), c, head, None) {
            Outcome::Hit(h) => h,
            _ => panic!("{path}"),
        };
    let whole = |body: &Body| match body {
        Body::Whole(_, len) => Some(*len as u64),
        _ => None,
    };
    assert_eq!(
        whole(&hit("/exact.bin", &c, false).body),
        Some(READ_WHOLE_MAX)
    );
    // Up to 64 KiB the lookup reads it; above, the runtime thread reads it into its own buffer.
    assert!(
        matches!(&hit("/lookup.bin", &c, false).body, Body::Bytes(b) if b.len() as u64 == LOOKUP_READ_MAX)
    );
    assert_eq!(
        whole(&hit("/after.bin", &c, false).body),
        Some(LOOKUP_READ_MAX + 1)
    );
    assert!(matches!(hit("/over.bin", &c, false).body, Body::File(_)));
    assert!(matches!(&hit("/empty.bin", &c, false).body, Body::Bytes(b) if b.is_empty()));
    // HEAD reads nothing.
    assert!(matches!(hit("/exact.bin", &c, true).body, Body::None));
    assert!(matches!(hit("/over.bin", &c, true).body, Body::None));
    // A part of a big file is read whole when it is small and sent from the file when it is not.
    let part = |range: &str| Conditions {
        range: range.into(),
        ..Conditions::default()
    };
    let small = hit("/over.bin", &part("bytes=10-19"), false);
    assert_eq!(small.plan, Plan::Part { start: 10, len: 10 });
    assert!(matches!(&small.body, Body::Bytes(b) if b.len() == 10));
    let big = hit("/over.bin", &part("bytes=0-"), false);
    assert_eq!(
        big.plan,
        Plan::Part {
            start: 0,
            len: READ_WHOLE_MAX + 1
        }
    );
    assert!(matches!(big.body, Body::File(_)));
    let edge = hit(
        "/over.bin",
        &part(&format!("bytes=0-{}", READ_WHOLE_MAX - 1)),
        false,
    );
    assert_eq!(whole(&edge.body), Some(READ_WHOLE_MAX));
    // Nothing is read for a 304 or a 416.
    let tag = Conditions {
        if_none_match: hit("/exact.bin", &c, true).meta.etag().into(),
        ..Conditions::default()
    };
    let not_modified = hit("/exact.bin", &tag, false);
    assert_eq!(not_modified.plan, Plan::NotModified);
    assert!(matches!(not_modified.body, Body::None));
    let outside = hit("/over.bin", &part("bytes=99999999-"), false);
    assert_eq!(outside.plan, Plan::Unsatisfiable);
    assert!(matches!(outside.body, Body::None));
}

#[test]
fn a_whole_read_fills_the_buffer_it_is_given_and_fails_for_a_file_that_is_shorter_now() {
    let s = Scratch::new("read-whole");
    let path = s.file("f.bin", b"0123456789");
    let file = File::open(path).unwrap();
    let buf = Vec::with_capacity(4);
    let at = buf.as_ptr();
    let read = read_whole(&file, 3, buf, 4).unwrap();
    assert_eq!(read, b"3456");
    assert_eq!(read.as_ptr(), at, "the bytes are in the caller's buffer");
    assert_eq!(read_whole(&file, 8, Vec::new(), 4), None);
    assert_eq!(read_whole(&file, 10, Vec::new(), 0), Some(Vec::new()));
}

fn head(plan: Plan, body: Body, size: u64) -> Hit {
    Hit {
        meta: Meta {
            size,
            mtime: 1_136_214_245,
        },
        content_type: "text/css; charset=utf-8",
        plan,
        body,
        memory: None,
    }
}

fn lines(r: &OutboundResponse, head: bool) -> String {
    String::from_utf8(r.wire(false, head, false, 0)).unwrap()
}

#[test]
fn the_answer_for_a_whole_file_names_its_type_validators_and_ranges() {
    let h = head(Plan::Whole, Body::Bytes(b"abcdef".to_vec()), 6);
    let mut r = head_of(&h, false, 0);
    r.body = b"abcdef".to_vec().into();
    assert_eq!(r.status, 200);
    let text = lines(&r, false);
    for want in [
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/css; charset=utf-8\r\n",
        "Content-Length: 6\r\n",
        "Etag: \"43b940e5-6\"\r\n",
        "Last-Modified: Mon, 02 Jan 2006 15:04:05 GMT\r\n",
        "X-Content-Type-Options: nosniff\r\n",
        "Accept-Ranges: bytes\r\n",
    ] {
        assert!(text.contains(want), "{want} in {text}");
    }
    assert!(!text.contains("Cache-Control"), "no time is set: {text}");
    assert!(text.ends_with("abcdef"));
    let timed = lines(&head_of(&h, false, 3600), true);
    assert!(timed.contains("Cache-Control: max-age=3600\r\n"), "{timed}");
}

#[test]
fn a_part_a_head_a_big_file_and_the_statuses_without_a_body_announce_what_they_need() {
    // 206: the span in `Content-Range`, the length of the span.
    let part = head(
        Plan::Part { start: 2, len: 3 },
        Body::Bytes(b"cde".to_vec()),
        6,
    );
    let mut r = head_of(&part, false, 0);
    r.body = b"cde".to_vec().into();
    let text = lines(&r, false);
    assert!(
        text.starts_with("HTTP/1.1 206 Partial Content\r\n"),
        "{text}"
    );
    assert!(
        text.contains("Content-Range: bytes 2-4/6\r\n") && text.contains("Content-Length: 3\r\n"),
        "{text}"
    );
    // HEAD of the whole file and of a part: the length of what GET would send, no body.
    for (plan, len) in [(Plan::Whole, 6), (Plan::Part { start: 1, len: 2 }, 2)] {
        let r = head_of(&head(plan, Body::None, 6), true, 0);
        let text = lines(&r, true);
        assert!(
            text.contains(&format!("Content-Length: {len}\r\n")),
            "{text}"
        );
        assert!(text.ends_with("\r\n\r\n"), "{text}");
    }
    // A file sent after the head announces its size and holds no body.
    let file = Arc::new(File::open("/").unwrap());
    let big = head_of(&head(Plan::Whole, Body::File(file), 5_000_000), false, 0);
    assert!(big.body.is_empty());
    assert!(lines(&big, true).contains("Content-Length: 5000000\r\n"));
    // 304: the validators and the cache time, no type, no length.
    let nm = head_of(&head(Plan::NotModified, Body::None, 6), false, 60);
    let text = lines(&nm, true);
    assert!(text.starts_with("HTTP/1.1 304 Not Modified\r\n"), "{text}");
    assert!(
        text.contains("Etag: ")
            && text.contains("Last-Modified: ")
            && text.contains("Cache-Control: max-age=60\r\n"),
        "{text}"
    );
    assert!(
        !text.contains("Content-Length")
            && !text.contains("Content-Type")
            && !text.contains("nosniff"),
        "{text}"
    );
    // 416: where the file ends, and nothing else of it.
    let un = head_of(&head(Plan::Unsatisfiable, Body::None, 6), false, 60);
    let text = lines(&un, false);
    assert!(
        text.starts_with("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"),
        "{text}"
    );
    assert!(
        text.contains("Content-Range: bytes */6\r\n") && text.contains("Content-Length: 0\r\n"),
        "{text}"
    );
    assert!(
        !text.contains("Etag") && !text.contains("Cache-Control"),
        "{text}"
    );
}

#[test]
fn a_directory_asked_for_without_its_slash_is_sent_to_the_path_with_one() {
    let go = |head: &str| {
        let req = InboundRequest::from_head(head.as_bytes());
        let Done::Respond(r) = add_slash(&req) else {
            panic!("a plain answer")
        };
        assert_eq!(r.status, 308);
        String::from_utf8(r.peek(b"Location").unwrap().to_vec()).unwrap()
    };
    assert_eq!(go("GET /docs HTTP/1.1\r\nHost: a.test\r\n\r\n"), "/docs/");
    assert_eq!(
        go("GET /a/b?x=1&y=<2> HTTP/1.1\r\nHost: a.test\r\n\r\n"),
        "/a/b/?x=1&y=%3C2%3E"
    );
    assert_eq!(go("GET /a%20b HTTP/1.1\r\nHost: a.test\r\n\r\n"), "/a%20b/");
    // Whatever the path holds, the location is a path on this host: one slash first, and no byte
    // that ends the line.
    for target in [
        "//evil.test/x",
        "/%2F%2Fevil.test",
        "/%5Cevil.test",
        "/x%0d%0aSet-Cookie:%20a=b",
        "/@evil.test",
    ] {
        let got = go(&format!("GET {target} HTTP/1.1\r\nHost: a.test\r\n\r\n"));
        assert!(
            got.starts_with('/') && !got.starts_with("//"),
            "{target}: {got}"
        );
        assert!(got.bytes().all(|b| b.is_ascii_graphic()), "{target}: {got}");
        assert!(got.ends_with('/'), "{target}: {got}");
    }
}
