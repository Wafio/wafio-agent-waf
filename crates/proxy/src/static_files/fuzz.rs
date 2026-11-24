//! Random input for the walk and the range parser, for as long as the budget says: a second in
//! the gate, and `WAFIO_FUZZ_SECONDS` when someone wants to run it longer (the office host
//! caps such sessions at about 15 minutes). The seed is printed, and `WAFIO_FUZZ_SEED` repeats
//! a run.

use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use super::answer::{Asked, asked, parse_http_date};
use super::names::{self, Target};
use super::walk::{self, Found, tests::Scratch};

/// xorshift64*, enough to vary the input.
struct Rng(u64);

impl Rng {
    fn from_env() -> Rng {
        let seed = std::env::var("WAFIO_FUZZ_SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(1, |d| d.as_nanos() as u64)
            });
        eprintln!("fuzz seed {seed} (WAFIO_FUZZ_SEED={seed} repeats it)");
        Rng(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn budget() -> Duration {
    let seconds = std::env::var("WAFIO_FUZZ_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    Duration::from_secs(seconds)
}

/// What a segment of a generated path may be: names that exist, links, spellings of a dot
/// segment before and after decoding, hidden, PHP and kept names, and bytes that are no name.
const PIECES: &[&str] = &[
    "",
    "",
    ".",
    "..",
    "...",
    "a.txt",
    "A.TXT",
    "dir",
    "sub",
    "b.txt",
    "c.txt",
    "index.html",
    "link-out",
    "link-dir",
    "link-in",
    "up",
    "abs",
    "passwd",
    "shadow",
    "Private",
    "p.txt",
    ".hidden",
    "h.txt",
    ".well-known",
    "x.php",
    "x.PHTML",
    "loop",
    "fifo",
    "%2e%2e",
    "%2E",
    "%2e",
    ".%2e",
    "%252e%252e",
    "..%2f",
    "%2f",
    "%5c",
    "..%5c",
    "%00",
    "%c0%ae",
    "%c0%ae%c0%ae",
    "%e0%80%ae",
    "a%00.txt",
    "..;",
    "é",
    "%zz",
    "%",
    "+",
    " ",
    "\\",
    "?",
    "#",
];

/// A request target made of those pieces.
fn target(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    if rng.below(8) != 0 {
        out.push(b'/');
    }
    for i in 0..1 + rng.below(8) {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(rng.pick(PIECES).as_bytes());
    }
    match rng.below(4) {
        0 => out.push(b'/'),
        1 => out.extend_from_slice(b"?x=1"),
        _ => {}
    }
    out
}

/// A folder with everything a walk can meet, and a secret beside it.
fn tree() -> Scratch {
    let s = Scratch::new("fuzz");
    s.file("secret.txt", b"SECRET");
    s.file("public/index.html", b"home");
    s.file("public/a.txt", b"a");
    s.file("public/dir/b.txt", b"b");
    s.file("public/dir/sub/c.txt", b"c");
    s.file("public/dir/index.html", b"dir index");
    s.file("public/.hidden/h.txt", b"hidden");
    s.file("public/.well-known/h.txt", b"well known");
    s.file("public/x.php", b"php");
    s.file("public/private/p.txt", b"kept");
    s.file("public/shadow", b"kept");
    s.link("public/link-out", "../secret.txt");
    s.link("public/link-dir", "..");
    s.link("public/link-in", "a.txt");
    s.link("public/dir/up", "../../secret.txt");
    s.link("public/abs", "/etc");
    s.link("public/loop", "loop");
    nix::unistd::mkfifo(&s.0.join("public/fifo"), nix::sys::stat::Mode::S_IRWXU).unwrap();
    s
}

/// The invariants of a plan: no segment that leaves the folder, hides a file, or is a name the
/// host agent keeps.
fn check_plan(raw: &[u8], decoded: &[u8], plan: &Target<'_>) {
    assert!(plan.segments.len() <= names::MAX_SEGMENTS && decoded.len() <= names::MAX_PATH);
    for (i, seg) in plan.segments.iter().enumerate() {
        let shown = String::from_utf8_lossy(raw);
        assert!(!seg.is_empty() && *seg != b"." && *seg != b"..", "{shown}");
        assert!(
            !seg.contains(&0) && !seg.contains(&b'/') && !seg.contains(&b'\\'),
            "{shown}"
        );
        assert!(seg.iter().all(|&c| c >= 0x20 && c != 0x7f), "{shown}");
        assert!(
            seg[0] != b'.' || (i == 0 && *seg == b".well-known"),
            "{shown}"
        );
        let lower = seg.to_ascii_lowercase();
        assert!(
            names::KEPT_NAMES
                .iter()
                .all(|k| k.as_bytes() != lower.as_slice()),
            "{shown}"
        );
    }
    if !plan.directory {
        let last = plan
            .segments
            .last()
            .expect("a file has a name")
            .to_ascii_lowercase();
        assert!(
            !last.ends_with(b".php") && !last.ends_with(b".phtml"),
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[test]
fn random_targets_never_leave_the_folder_and_never_reach_what_is_hidden() {
    let tree = tree();
    let root_path = tree.0.join("public");
    let root = walk::open_root(root_path.to_str().unwrap()).unwrap();
    let secret = std::fs::metadata(tree.0.join("secret.txt")).unwrap();
    let mut rng = Rng::from_env();
    let (start, limit) = (Instant::now(), budget());
    let (mut runs, mut served) = (0u64, 0u64);
    while start.elapsed() < limit {
        for _ in 0..200 {
            let raw = target(&mut rng);
            let (decoded, _) = wafio_engine_rules::decode_forwarded_path(&raw);
            runs += 1;
            let Some(plan) = names::plan(&decoded) else {
                continue;
            };
            check_plan(&raw, &decoded, &plan);
            let Found::File(file, _, _) = walk::find(&root, &plan) else {
                continue;
            };
            served += 1;
            let shown = String::from_utf8_lossy(&raw);
            let meta = file.metadata().unwrap();
            assert!(meta.is_file(), "{shown}");
            assert_ne!(
                (meta.dev(), meta.ino()),
                (secret.dev(), secret.ino()),
                "{shown} reached the secret"
            );
            let at = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
            assert!(
                at.starts_with(&root_path),
                "{shown} served {}",
                at.display()
            );
            let rel = at.strip_prefix(&root_path).unwrap();
            assert!(
                rel.components()
                    .all(|c| !c.as_os_str().as_encoded_bytes().starts_with(b".")
                        || c.as_os_str() == ".well-known"),
                "{shown} served {}",
                at.display()
            );
        }
    }
    eprintln!("walk fuzz: {runs} targets, {served} served");
    assert!(served > 0, "the generator reaches files");
}

/// Random bytes as a path never panic in the plan.
#[test]
fn random_bytes_as_a_path_are_a_plan_or_nothing() {
    let mut rng = Rng::from_env();
    let (start, limit) = (Instant::now(), budget() / 4);
    while start.elapsed() < limit {
        for _ in 0..500 {
            let len = rng.below(200);
            let mut path: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if rng.below(2) == 0 {
                path.insert(0, b'/');
            }
            if let Some(plan) = names::plan(&path) {
                check_plan(&path, &path, &plan);
            }
        }
    }
}

const RANGE_TOKENS: &[&str] = &[
    "bytes",
    "BYTES",
    "items",
    "=",
    "-",
    "-",
    ",",
    " ",
    "0",
    "1",
    "7",
    "99",
    "1000",
    "1048576",
    "18446744073709551615",
    "18446744073709551616",
    "a",
    "+",
    "\t",
    "",
];

#[test]
fn a_random_range_is_a_span_inside_the_file_or_a_refusal_or_ignored() {
    let sizes = [
        0u64,
        1,
        2,
        7,
        1000,
        1 << 20,
        (1 << 20) + 1,
        u64::MAX / 2,
        u64::MAX,
    ];
    let mut rng = Rng::from_env();
    let (start, limit) = (Instant::now(), budget());
    let mut parts = 0u64;
    while start.elapsed() < limit {
        for _ in 0..500 {
            let mut header = String::new();
            if rng.below(2) == 0 {
                // The shape of a real header, with numbers around the size.
                let size = *rng.pick(&sizes);
                let number = |rng: &mut Rng| match rng.below(4) {
                    0 => String::new(),
                    1 => rng.below(8).to_string(),
                    2 => size
                        .saturating_add(rng.below(3) as u64)
                        .saturating_sub(1)
                        .to_string(),
                    _ => rng.next().to_string(),
                };
                header = format!("bytes={}-{}", number(&mut rng), number(&mut rng));
            } else {
                for _ in 0..1 + rng.below(7) {
                    let token = *rng.pick(RANGE_TOKENS);
                    header.push_str(token);
                }
            }
            let size = *rng.pick(&sizes);
            match asked(header.as_bytes(), size) {
                Asked::Part { start, len } => {
                    parts += 1;
                    assert!(
                        len >= 1 && start < size,
                        "{header:?} of {size}: {start}+{len}"
                    );
                    assert!(
                        start.checked_add(len).is_some_and(|end| end <= size),
                        "{header:?} of {size}"
                    );
                }
                Asked::Unsatisfiable | Asked::Ignored => {}
            }
            // The date parser takes any bytes too.
            let _ = parse_http_date(header.as_bytes());
        }
    }
    eprintln!("range fuzz: {parts} spans");
    assert!(parts > 0, "the generator reaches a span");
}

#[test]
fn a_random_time_is_read_back_from_its_date() {
    let mut rng = Rng::from_env();
    for _ in 0..20_000 {
        let unix = rng.next() % 4_102_444_800;
        let text = crate::response::http_date(unix);
        assert_eq!(parse_http_date(text.as_bytes()), Some(unix), "{text}");
    }
}
