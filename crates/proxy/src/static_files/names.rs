//! Which request paths the folder never serves, and the segments of those it may. Everything
//! here is text work: a path that fails it is refused before any system call is made for it.

/// The longest path and the most segments a request for a file may have.
pub(super) const MAX_PATH: usize = 4096;
pub(super) const MAX_SEGMENTS: usize = 64;

/// A copy of the names the host agent never sheds from its trace ring (`TraceKeepBuiltin` of the
/// control plane's shared module): an open of one is always reported, and an open by this agent
/// of a name like `shadow` or `private` raises a credential alert. A request that names one as
/// a segment is never served, so the walk never opens it. Lower case, sorted, at most
/// [`LONGEST_KEPT`] bytes. `tests/data/trace-keep-names.json` is the control plane's list, and a
/// test fails when the two differ.
pub(super) const KEPT_NAMES: [&str; 66] = [
    ".aws",
    ".azure",
    ".bash_login",
    ".bash_profile",
    ".bashrc",
    ".docker",
    ".profile",
    ".zprofile",
    ".zshenv",
    ".zshrc",
    "authorized_keys",
    "autostart",
    "bash.bashrc",
    "credentials",
    "cron",
    "cron.d",
    "cron.daily",
    "cron.hourly",
    "cron.monthly",
    "cron.weekly",
    "crontab",
    "crontabs",
    "environ",
    "environment",
    "group",
    "gshadow",
    "hostname",
    "hosts",
    "id_dsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_rsa",
    "init.d",
    "iptables",
    "ld.so.conf",
    "ld.so.conf.d",
    "login.defs",
    "master.passwd",
    "mem",
    "netplan",
    "network",
    "networkmanager",
    "nftables.conf",
    "nsswitch.conf",
    "pam.d",
    "passwd",
    "private",
    "privkey.pem",
    "profile",
    "profile.d",
    "rc.d",
    "rc.local",
    "resolv.conf",
    "secring.gpg",
    "security",
    "shadow",
    "ssh_host_dsa_key",
    "ssh_host_ecdsa_key",
    "ssh_host_ed25519_key",
    "ssh_host_rsa_key",
    "sudoers",
    "sudoers.d",
    "systemd",
    "wafio-waf-agent",
];

/// The length of the longest name of [`KEPT_NAMES`], rounded up.
const LONGEST_KEPT: usize = 24;

/// Whether `segment`, in any case, is one of [`KEPT_NAMES`].
pub(super) fn kept_name(segment: &[u8]) -> bool {
    if segment.len() > LONGEST_KEPT {
        return false;
    }
    let mut lower = [0u8; LONGEST_KEPT];
    let lower = &mut lower[..segment.len()];
    lower.copy_from_slice(segment);
    lower.make_ascii_lowercase();
    KEPT_NAMES
        .binary_search_by(|kept| kept.as_bytes().cmp(&*lower))
        .is_ok()
}

/// Endings of a name that a PHP server runs: the folder never serves these as files.
const PHP_ENDINGS: [&str; 10] = [
    ".php", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phtml", ".phar", ".phps",
];

fn php_name(name: &[u8]) -> bool {
    PHP_ENDINGS.iter().any(|ending| {
        name.len() >= ending.len()
            && name[name.len() - ending.len()..].eq_ignore_ascii_case(ending.as_bytes())
    })
}

/// A path the folder may answer for, cut into its segments.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Target<'a> {
    pub segments: Vec<&'a [u8]>,
    /// The path ends with `/` (the root is one): the answer is the directory's `index.html`.
    pub directory: bool,
}

/// A segment the folder may open. A name that starts with a dot is hidden (a first `.well-known`
/// is the one kind that is not), a backslash or control byte is no name of a public file, and a
/// name on the copy of the kept names is refused as a whole.
fn servable(segment: &[u8], first: bool) -> bool {
    if segment.iter().any(|&c| c < 0x20 || c == 0x7f || c == b'\\') {
        return false;
    }
    if segment[0] == b'.' && !(first && segment == b".well-known") {
        return false;
    }
    !kept_name(segment)
}

/// The segments of `path` (the decoded path of the request, dot segments resolved), or `None`
/// when the folder never serves it: not an absolute path, over [`MAX_PATH`] or [`MAX_SEGMENTS`],
/// a `.` or `..` segment that the request path should have lost already, a hidden or kept name,
/// a control byte or backslash, or a last name a PHP server runs. An empty segment (a doubled or
/// a final slash) is not a name.
pub(super) fn plan(path: &[u8]) -> Option<Target<'_>> {
    if path.len() > MAX_PATH {
        return None;
    }
    let rest = path.strip_prefix(b"/")?;
    let directory = rest.is_empty() || rest.ends_with(b"/");
    let mut segments = Vec::new();
    for segment in rest.split(|&c| c == b'/').filter(|s| !s.is_empty()) {
        if segments.len() == MAX_SEGMENTS || !servable(segment, segments.is_empty()) {
            return None;
        }
        segments.push(segment);
    }
    if !directory && segments.last().is_some_and(|name| php_name(name)) {
        return None;
    }
    Some(Target {
        segments,
        directory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(path: &str) -> Option<Vec<String>> {
        plan(path.as_bytes()).map(|t| {
            t.segments
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
    }

    /// The control plane's list of names, read without a JSON library (one `"name": tier` line
    /// each).
    fn fixture_names() -> Vec<String> {
        include_str!("../../tests/data/trace-keep-names.json")
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix('"')?;
                Some(rest[..rest.find('"')?].to_owned())
            })
            .collect()
    }

    #[test]
    fn the_copy_of_the_kept_names_equals_the_control_plane_list() {
        let fixture = fixture_names();
        assert!(
            fixture.len() > 60,
            "the fixture was read: {}",
            fixture.len()
        );
        assert_eq!(KEPT_NAMES.to_vec(), fixture);
    }

    #[test]
    fn the_copy_is_lower_case_sorted_and_fits_the_buffer() {
        assert!(KEPT_NAMES.windows(2).all(|w| w[0] < w[1]));
        assert!(
            KEPT_NAMES
                .iter()
                .all(|n| n.bytes().all(|c| !c.is_ascii_uppercase()))
        );
        let longest = KEPT_NAMES.iter().map(|n| n.len()).max().unwrap();
        assert!(longest <= LONGEST_KEPT, "{longest}");
    }

    /// Every name of the copy, in the case it is written and in capitals, as the first, a middle
    /// and the last segment, is refused, and a name that only holds one is not.
    #[test]
    fn every_kept_name_is_refused_wherever_it_stands_and_in_any_case() {
        for kept in KEPT_NAMES {
            for name in [kept.to_owned(), kept.to_ascii_uppercase()] {
                for path in [
                    format!("/{name}"),
                    format!("/{name}/"),
                    format!("/a/{name}/b.css"),
                    format!("/a/b/{name}"),
                ] {
                    assert_eq!(names(&path), None, "{path}");
                }
            }
            let near = [
                format!("/{kept}x"),
                format!("/x{kept}"),
                format!("/{kept}.css"),
            ];
            for path in near {
                assert!(
                    names(&path).is_some() || path.contains("/."),
                    "a name that only starts or ends like one is a file: {path}"
                );
            }
        }
        assert_eq!(names("/Shadow"), None);
        assert_eq!(names("/ShAdOw/x.png"), None);
        assert_eq!(
            names("/shadowy/x.png"),
            Some(vec!["shadowy".into(), "x.png".into()])
        );
    }

    #[test]
    fn a_path_that_leaves_the_folder_or_hides_a_file_is_refused() {
        for path in [
            "/..",
            "/../etc/passwd",
            "/a/../b",
            "/a/./b",
            "/.",
            "/.git/config",
            "/a/.env",
            "/.htaccess",
            "/a/.well-known/x",
            "/.well-known2/x",
            "/.WELL-KNOWN/x",
            "/a\\b",
            "/..\\..\\x",
            "/a\0b",
            "/a\nb",
            "/a\x7fb",
            "no-slash",
            "",
        ] {
            assert_eq!(names(path), None, "{path:?}");
        }
        // Raw bytes that are no name of a public file, and those that only look like a dot.
        assert_eq!(
            plan(b"/\xc0\xae\xc0\xae/x").map(|t| t.segments.len()),
            Some(2)
        );
        assert_eq!(plan(b"/a\0b"), None);
    }

    #[test]
    fn the_first_segment_may_be_well_known_and_nothing_else_may_start_with_a_dot() {
        assert_eq!(
            names("/.well-known/acme-challenge/token"),
            Some(vec![
                ".well-known".into(),
                "acme-challenge".into(),
                "token".into()
            ])
        );
        assert_eq!(names("/.well-known/.hidden"), None);
        assert_eq!(names("/.well-known/"), Some(vec![".well-known".into()]));
    }

    #[test]
    fn a_last_name_that_a_php_server_runs_is_refused_in_any_case_and_a_directory_is_not_a_name() {
        for name in [
            "x.php", "x.PHP", "x.pHp", "x.php3", "x.php4", "x.php5", "x.php6", "x.php7", "x.php8",
            "x.phtml", "x.PHTML", "x.phar", "x.phps", "a.b.php",
        ] {
            assert_eq!(names(&format!("/{name}")), None, "{name}");
            assert_eq!(names(&format!("/a/{name}")), None, "{name}");
        }
        for name in [
            "x.php9",
            "x.php.txt",
            "x.phpx",
            "x.ph",
            "phpx",
            "php",
            "x.html",
            "x.pharm",
            "x.php~",
        ] {
            assert!(names(&format!("/{name}")).is_some(), "{name}");
        }
        // A path that ends in a slash names a directory, whatever the last name looks like.
        assert!(names("/x.php/").is_some());
        assert!(names("/a/x.phtml/").is_some());
    }

    #[test]
    fn the_root_and_a_directory_are_a_directory_and_a_file_is_not() {
        assert_eq!(
            plan(b"/"),
            Some(Target {
                segments: vec![],
                directory: true
            })
        );
        let dir = plan(b"/img/").unwrap();
        assert!(dir.directory && dir.segments == [b"img"]);
        let file = plan(b"/img/a.png").unwrap();
        assert!(!file.directory && file.segments == [&b"img"[..], b"a.png"]);
        // Doubled slashes are not names.
        assert_eq!(plan(b"//a///b").unwrap().segments, [&b"a"[..], b"b"]);
    }

    #[test]
    fn the_length_and_the_depth_have_a_limit() {
        let deep = |n: usize| format!("/{}", vec!["d"; n].join("/"));
        assert!(plan(deep(MAX_SEGMENTS).as_bytes()).is_some());
        assert_eq!(plan(deep(MAX_SEGMENTS + 1).as_bytes()), None);
        let long = |n: usize| format!("/{}", "a".repeat(n - 1));
        assert!(plan(long(MAX_PATH).as_bytes()).is_some());
        assert_eq!(plan(long(MAX_PATH + 1).as_bytes()), None);
    }
}
