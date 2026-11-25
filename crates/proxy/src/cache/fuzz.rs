//! Random input for the reader of `Cache-Control` and for the reader of the files of copies, for
//! as long as the budget says: a second in the gate, and `WAFIO_FUZZ_SECONDS` when someone wants to
//! run it longer (the office host caps such sessions at about 15 minutes). The seed is printed, and
//! `WAFIO_FUZZ_SEED` repeats a run.
//!
//! `Cache-Control` is checked against a model: the test makes the directives, so it knows what the
//! reader has to find, whatever spacing, case, quoting and junk surround them. The files are checked
//! the other way round: a file that was written and then damaged in any way is never read as an
//! answer, and nothing a damaged file declares makes the reader take memory or panic.

use std::time::{Duration, Instant};

use super::control::{CacheControl, vary_names};
use super::format::{self, StoredHead, Times};
use super::key::file_id;
use super::{Windows, format::Loaded};

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

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
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

const FLAGS: [&str; 7] = [
    "no-store",
    "private",
    "no-cache",
    "public",
    "must-revalidate",
    "proxy-revalidate",
    "no-transform",
];
const NUMBERS: [&str; 4] = [
    "max-age",
    "s-maxage",
    "stale-while-revalidate",
    "stale-if-error",
];
/// A directive the reader does not know, with a value that may hold what looks like another
/// directive: it must stay a value.
const EXTENSIONS: [&str; 6] = [
    "community=\"UCI\"",
    "ext=\"a, no-store\"",
    "x-y=\"max-age=1\\\", private\"",
    "pre-check=0",
    "immutable",
    "foo=",
];
/// Values for a number directive that are not delta-seconds.
const BAD_VALUES: [&str; 9] = ["", "abc", "-1", "1.5", "1e3", "+5", "\"", "\"5", "5s"];
const CAP: u128 = 1 << 31;

fn cased(rng: &mut Rng, text: &str) -> String {
    text.chars()
        .map(|c| {
            if rng.chance(2) {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

fn spaces(rng: &mut Rng) -> &'static str {
    ["", " ", "  ", "\t"][rng.below(4)]
}

/// What the model says a number directive reads as: `Err` for one that cannot be read.
fn model_number(value: &str) -> Result<u64, ()> {
    let t = value.trim();
    let t = if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        &t[1..t.len() - 1]
    } else {
        t
    };
    if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    Ok(t.parse::<u128>().map_or(CAP, |n| n.min(CAP)) as u64)
}

#[derive(Default, Debug)]
struct Model {
    flags: [bool; 7],
    numbers: [Option<u64>; 4],
    invalid: bool,
    tokens: usize,
}

/// A line of directives and what the reader has to find in it.
fn line(rng: &mut Rng, model: &mut Model) -> String {
    let mut parts = Vec::new();
    for _ in 0..rng.below(9) {
        let part = match rng.below(10) {
            0..=3 => {
                let i = rng.below(FLAGS.len());
                model.flags[i] = true;
                cased(rng, FLAGS[i])
            }
            4..=7 => {
                let i = rng.below(NUMBERS.len());
                let value = if rng.chance(8) {
                    (*rng.pick(&BAD_VALUES)).to_owned()
                } else {
                    let digits = 1 + rng.below(13);
                    let n: String = (0..digits)
                        .map(|_| char::from(b'0' + rng.below(10) as u8))
                        .collect();
                    // A repeat of the same value is allowed, another is not.
                    if rng.chance(3) { format!("\"{n}\"") } else { n }
                };
                match model_number(&value) {
                    Ok(n) => match model.numbers[i] {
                        Some(old) if old != n => model.invalid = true,
                        _ => model.numbers[i] = Some(n),
                    },
                    Err(()) => model.invalid = true,
                }
                format!(
                    "{}{}={}{}",
                    cased(rng, NUMBERS[i]),
                    spaces(rng),
                    spaces(rng),
                    value
                )
            }
            8 => (*rng.pick(&EXTENSIONS)).to_owned(),
            _ => String::new(),
        };
        if !part.trim().is_empty() {
            model.tokens += 1;
        }
        parts.push(format!("{}{part}{}", spaces(rng), spaces(rng)));
    }
    parts.join(",")
}

#[test]
fn a_random_cache_control_is_read_as_the_directives_it_was_made_of() {
    let mut rng = Rng::from_env();
    let (started, budget) = (Instant::now(), budget());
    let mut runs = 0u64;
    while started.elapsed() < budget {
        for _ in 0..2000 {
            runs += 1;
            let mut model = Model::default();
            let lines: Vec<String> = (0..1 + rng.below(3))
                .map(|_| line(&mut rng, &mut model))
                .collect();
            let cc = CacheControl::parse(lines.iter().map(|l| l.as_bytes()));
            let shown = format!("{lines:?} {model:?}");
            if model.tokens > 64 {
                assert!(cc.invalid, "more than 64 directives: {shown}");
                continue;
            }
            assert_eq!(cc.invalid, model.invalid, "{shown}");
            if model.invalid {
                continue;
            }
            let flag = |name: &str| model.flags[FLAGS.iter().position(|f| *f == name).unwrap()];
            assert_eq!(cc.no_store, flag("no-store"), "{shown}");
            assert_eq!(cc.private, flag("private"), "{shown}");
            assert_eq!(cc.no_cache, flag("no-cache"), "{shown}");
            assert_eq!(cc.public, flag("public"), "{shown}");
            assert_eq!(cc.must_revalidate, flag("must-revalidate"), "{shown}");
            assert_eq!(cc.proxy_revalidate, flag("proxy-revalidate"), "{shown}");
            assert_eq!(
                cc.forbids_storing(),
                cc.no_store || cc.private || cc.no_cache
            );
            assert_eq!(
                [
                    cc.max_age,
                    cc.s_maxage,
                    cc.stale_while_revalidate,
                    cc.stale_if_error
                ],
                model.numbers,
                "{shown}"
            );
            // The lifetime is never more than the cap, whatever the header says, and a copy that
            // says it must be revalidated never has a window unless it names one.
            if let Some(n) = cc.lifetime(None, None, 1_700_000_000) {
                assert!(u128::from(n) <= CAP, "{shown}");
            }
            let w = Windows::of(&looked(&lines), 600);
            let never = cc.must_revalidate || cc.proxy_revalidate || cc.s_maxage.is_some();
            let own = cc.stale_while_revalidate.is_some() || cc.stale_if_error.is_some();
            if never && !own {
                assert_eq!((w.revalidate, w.error), (0, 0), "{shown}");
            }
            assert!(u128::from(w.revalidate.max(w.error)) <= CAP, "{shown}");
        }
    }
    eprintln!("{runs} Cache-Control headers");
}

/// A stored copy that carries these lines as its `Cache-Control`.
fn looked(lines: &[String]) -> Loaded {
    Loaded {
        times: Times {
            stored_at: 0,
            fresh_until: 0,
            initial_age: 0,
            stale_window: 0,
        },
        head: StoredHead {
            status: 200,
            http10: false,
            reason: Vec::new(),
            lines: lines
                .iter()
                .map(|l| (b"Cache-Control".to_vec(), l.as_bytes().to_vec()))
                .collect(),
        },
        body: Vec::new(),
        size: 0,
    }
}

#[test]
fn random_bytes_as_cache_control_or_vary_never_break_the_reader() {
    let mut rng = Rng::from_env();
    let (started, budget) = (Instant::now(), budget());
    let mut runs = 0u64;
    while started.elapsed() < budget {
        for _ in 0..2000 {
            runs += 1;
            let len = if rng.chance(50) {
                4090 + rng.below(20)
            } else {
                rng.below(120)
            };
            let bytes: Vec<u8> = (0..len)
                .map(|_| match rng.below(6) {
                    0 => b',',
                    1 => b'"',
                    2 => b'\\',
                    3 => b'=',
                    4 => b'0' + rng.below(10) as u8,
                    _ => rng.next() as u8,
                })
                .collect();
            let cc = CacheControl::parse([&bytes[..], &bytes[..bytes.len() / 2]]);
            if bytes.len() > 4096 {
                assert!(cc.invalid, "a line past 4096 bytes is not trusted");
            }
            for n in [
                cc.max_age,
                cc.s_maxage,
                cc.stale_while_revalidate,
                cc.stale_if_error,
            ]
            .into_iter()
            .flatten()
            {
                assert!(u128::from(n) <= CAP);
            }
            if let Ok(names) = vary_names([&bytes[..]]) {
                assert!(names.len() <= 4);
                assert!(names.iter().all(|n| {
                    n.len() <= 256
                        && !matches!(&n[..], b"*" | b"cookie" | b"authorization")
                        && n.iter().all(|c| !c.is_ascii_uppercase())
                }));
                let mut sorted = names.clone();
                sorted.sort();
                sorted.dedup();
                assert_eq!(sorted, names, "sorted, once each");
            }
        }
    }
    eprintln!("{runs} random headers");
}

const TIMES: Times = Times {
    stored_at: 1_700_000_000,
    fresh_until: 1_700_000_600,
    initial_age: 7,
    stale_window: 90,
};

/// How a good file is damaged.
fn damage(rng: &mut Rng, good: &[u8]) -> Vec<u8> {
    let mut bytes = good.to_vec();
    match rng.below(9) {
        0 => {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << rng.below(8);
        }
        1 => {
            let at = rng.below(bytes.len());
            bytes[at] = rng.next() as u8;
        }
        2 => bytes.truncate(rng.below(bytes.len())),
        3 => bytes.extend((0..1 + rng.below(40)).map(|_| rng.next() as u8)),
        // The header, which names every length: one of its numbers is anything.
        4 => {
            let at = *rng.pick(&[8usize, 12, 16, 20, 24, 32, 40, 48, 52]);
            let other = rng.next() as u8;
            for b in &mut bytes[at..at + 4] {
                *b = *rng.pick(&[0, 0xff, other]);
            }
        }
        5 => {
            let (a, b) = (rng.below(bytes.len()), rng.below(bytes.len()));
            bytes.swap(a, b);
        }
        6 => {
            let from = rng.below(bytes.len());
            let to = from + rng.below(bytes.len() - from);
            bytes.drain(from..to);
        }
        7 => bytes = (0..rng.below(300)).map(|_| rng.next() as u8).collect(),
        _ => {
            let at = rng.below(bytes.len().min(64));
            bytes[at..].fill(rng.next() as u8);
        }
    }
    bytes
}

#[test]
fn a_file_that_is_damaged_in_any_way_is_never_read_as_an_answer() {
    let mut rng = Rng::from_env();
    let (started, budget) = (Instant::now(), budget());
    let dir = format::tests::Scratch::new();
    let head = StoredHead {
        status: 200,
        http10: false,
        reason: b"OK".to_vec(),
        lines: vec![
            (b"Content-Type".to_vec(), b"text/css".to_vec()),
            (b"Vary".to_vec(), b"Accept-Encoding".to_vec()),
        ],
    };
    let key = b"P1\0\x05a.test\x04\0\0\0/a.c\0\0".to_vec();
    let body = b"body { color: red }".to_vec();
    let id = file_id(&key, b"");
    let size = format::write(
        &dir.0,
        &id,
        key.len(),
        &key,
        &head.encode().unwrap(),
        &body,
        TIMES,
    )
    .unwrap();
    let good_path = format::path_of(&dir.0, &id);
    let good = std::fs::read(&good_path).unwrap();
    assert_eq!(good.len() as u64, size);
    let scratch = dir.0.join("damaged");
    let mut runs = 0u64;
    while started.elapsed() < budget {
        for _ in 0..500 {
            runs += 1;
            let bytes = damage(&mut rng, &good);
            std::fs::write(&scratch, &bytes).unwrap();
            let len = bytes.len() as u64;
            // Both with the size the index holds and with the size the file has.
            for expect in [size, len] {
                match format::read(&scratch, expect, &key) {
                    Ok(read) => {
                        assert_eq!(bytes, good, "a damaged file was taken for an answer");
                        assert_eq!((read.body.as_slice(), read.times), (&body[..], TIMES));
                        assert_eq!(read.head, head);
                    }
                    Err(_) => assert!(bytes != good || expect != size, "a good file was refused"),
                }
            }
            // The scan reads less (no body, no check sum) and must hold up as well; when it
            // accepts a file the key it gives back is the one the file holds.
            if let Ok(summary) = format::read_summary(&scratch) {
                assert!(summary.primary_len <= summary.key.len());
                assert_eq!(summary.size, len);
            }
            // The head by itself, on bytes that are anything.
            let tail = &bytes[bytes.len().min(64)..];
            if let Some(decoded) = StoredHead::decode(tail)
                && let Some(again) = decoded.encode()
            {
                assert_eq!(StoredHead::decode(&again).as_ref(), Some(&decoded));
            }
        }
    }
    eprintln!("{runs} damaged files");
}
