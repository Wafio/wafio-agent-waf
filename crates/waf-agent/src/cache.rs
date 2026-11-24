//! The response cache as the agent runs it: the directory the unit made for it, the settings of
//! each app turned into [`CacheSpec`]s, and what an apply makes of them given what the host has.
//!
//! A bundle whose cache settings do not pass, or ask for more disk or memory than the host has,
//! is not refused: the app keeps the settings it ran with (or none) and `EdgeStatus` says why.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use wafio_proxy::{
    CacheHost, CacheRefusal, CacheRefusalCode, CacheRule, CacheSpec, HostFacts, valid_app_id,
};

use crate::bundle::{BundleApp, CacheEntry};

/// The cache directory of a running agent: `CacheDirectory=wafio-waf` of the unit.
pub const CACHE_DIR: &str = "/var/cache/wafio-waf";

/// How long an apply waits for the index of what is on disk before it checks the disk sum without
/// knowing what the cache already holds (then the disk check is left out, never failed).
const INDEX_WAIT: Duration = Duration::from_secs(3);

/// What the agent has for a cache directory.
pub enum CacheSetup {
    /// The directory passed its checks and is open.
    Ready(Arc<CacheHost>),
    /// It did not: the cache stays off for every app and `EdgeStatus` says so for each of them.
    Unusable(CacheRefusal),
}

fn default_path() -> PathBuf {
    #[cfg(feature = "test-response-cache")]
    if let Some(dir) = std::env::var_os("WAFIO_TEST_CACHE_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(CACHE_DIR)
}

/// Opens the cache directory, as the user the agent runs as. A directory that cannot be used is
/// logged with the reason and leaves the cache off.
pub fn open() -> CacheSetup {
    let path = default_path();
    match CacheHost::open(&path, nix::unistd::geteuid().as_raw()) {
        Ok(host) => CacheSetup::Ready(host),
        Err(refusal) => {
            tracing::warn!("[cache] the response cache stays off: {}", refusal.detail);
            CacheSetup::Unusable(refusal)
        }
    }
}

fn invalid(field: &str) -> CacheRefusal {
    CacheRefusal {
        code: CacheRefusalCode::Invalid,
        detail: field.to_owned(),
    }
}

/// The settings of an app's `cache` object: a number that is not sent takes the default, and the
/// result passes the checks of the control plane, which this agent is never stricter than.
pub(crate) fn cache_spec(entry: &CacheEntry) -> Result<CacheSpec, CacheRefusal> {
    let defaults = CacheSpec::default();
    // A number that is negative or too big for its type is kept as one that fails the check.
    let small =
        |n: Option<i64>, default: u32| n.map_or(default, |n| u32::try_from(n).unwrap_or(u32::MAX));
    let big =
        |n: Option<i64>, default: u64| n.map_or(default, |n| u64::try_from(n).unwrap_or(u64::MAX));
    let mut rules = Vec::with_capacity(entry.rules.len());
    for r in &entry.rules {
        let bypass = match r.action.as_str() {
            "cache" => false,
            "bypass" => true,
            _ => return Err(invalid("rules.action")),
        };
        rules.push(CacheRule {
            prefix: r.prefix.clone(),
            bypass,
            ttl_s: if bypass {
                0
            } else {
                u32::try_from(r.ttl_s).unwrap_or(u32::MAX)
            },
            signed_in: !bypass && r.signed_in,
        });
    }
    let spec = CacheSpec {
        default_ttl_s: small(entry.default_ttl_s, defaults.default_ttl_s),
        stale_if_error_s: small(entry.stale_if_error_s, defaults.stale_if_error_s),
        disk_bytes: big(entry.disk_bytes, defaults.disk_bytes),
        memory_bytes: big(entry.memory_bytes, defaults.memory_bytes),
        max_object_bytes: big(entry.max_object_bytes, defaults.max_object_bytes),
        session_cookies: entry.session_cookies.clone(),
        rules,
    };
    spec.check()?;
    Ok(spec)
}

/// What an apply does with the cache of one app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CachePlan {
    /// The settings run.
    Apply(CacheSpec),
    /// They do not. The settings the app ran with, when it ran any, run on.
    Refuse {
        refusal: CacheRefusal,
        previous: Option<CacheSpec>,
    },
}

/// What the host says, read before the apply takes its lock.
pub(crate) struct HostView {
    pub facts: Option<HostFacts>,
    /// What the cache holds on disk; `None` when its index was not built in time.
    pub in_use: Option<u64>,
}

/// Reads what the host has, when a bundle asks for a cache and there is a directory to ask about.
pub(crate) fn host_view(setup: Option<&CacheSetup>, apps: &[BundleApp]) -> Option<HostView> {
    let Some(CacheSetup::Ready(host)) = setup else {
        return None;
    };
    if !apps
        .iter()
        .any(|a| a.cache.as_ref().is_some_and(|c| c.enabled))
    {
        return None;
    }
    let facts = host
        .host_facts()
        .inspect_err(|e| tracing::warn!("[cache] the host could not be read: {e}"))
        .ok();
    Some(HostView {
        facts,
        in_use: host.disk_in_use(INDEX_WAIT),
    })
}

/// Whether `spec` asks for more disk or memory than the settings that run now: an app that runs
/// none asks for more than it has.
fn grew(running: &HashMap<String, CacheSpec>, id: &str, spec: &CacheSpec) -> bool {
    running
        .get(id)
        .is_none_or(|old| spec.disk_bytes > old.disk_bytes || spec.memory_bytes > old.memory_bytes)
}

/// What an apply does with the cache of each app of `apps`. `running` holds the settings that run
/// now. An app with its cache on gets its settings checked, and an app id that cannot name a
/// directory is refused. When an app asks for more disk or memory than it runs with, the sums over
/// all the apps are held to what the host allows: if they do not fit, every app that asks for more
/// is refused (never reduced) and keeps what it ran with. An app that asks for the same or less,
/// or only edits a rule, a lifetime or a cookie name, is always applied: refusing it would leave
/// the host no better off. When the directory cannot be used every app is refused, with the cache
/// on or off.
pub(crate) fn plan(
    setup: &CacheSetup,
    apps: &[BundleApp],
    running: &HashMap<String, CacheSpec>,
    view: Option<&HostView>,
) -> HashMap<String, CachePlan> {
    let mut out = HashMap::new();
    let refuse = |refusal: CacheRefusal, id: &str| CachePlan::Refuse {
        refusal,
        previous: running.get(id).cloned(),
    };
    if let CacheSetup::Unusable(refusal) = setup {
        for app in apps {
            out.insert(
                app.app_id.clone(),
                CachePlan::Refuse {
                    refusal: refusal.clone(),
                    previous: None,
                },
            );
        }
        return out;
    }
    let mut valid: Vec<(&str, CacheSpec)> = Vec::new();
    for app in apps {
        let Some(entry) = app.cache.as_ref().filter(|c| c.enabled) else {
            continue;
        };
        let spec = if valid_app_id(&app.app_id) {
            cache_spec(entry)
        } else {
            Err(invalid("app_id"))
        };
        match spec {
            Ok(spec) => valid.push((&app.app_id, spec)),
            Err(refusal) => {
                tracing::warn!(
                    "[waf-bundle] app {:?}: cache refused, {} {:?}",
                    app.app_id.chars().take(64).collect::<String>(),
                    refusal.code.as_str(),
                    refusal.detail
                );
                out.insert(app.app_id.clone(), refuse(refusal, &app.app_id));
            }
        }
    }
    let asks_more = valid.iter().any(|(id, spec)| grew(running, id, spec));
    let verdict = match view.and_then(|v| Some((v.facts?, v.in_use))) {
        Some((facts, in_use)) if asks_more => {
            let disk = valid.iter().map(|(_, s)| s.disk_bytes).sum::<u64>();
            let memory = valid.iter().map(|(_, s)| s.memory_bytes).sum::<u64>();
            // What the cache holds is not known: the disk is not checked, and never failed for it.
            facts.check(
                in_use.unwrap_or(0),
                if in_use.is_some() { disk } else { 0 },
                memory,
            )
        }
        _ => Ok(()),
    };
    for (id, spec) in valid {
        let plan = match &verdict {
            Err(refusal) if grew(running, id, &spec) => {
                tracing::warn!(
                    "[waf-bundle] app {:?}: cache refused, {} {:?}",
                    id.chars().take(64).collect::<String>(),
                    refusal.code.as_str(),
                    refusal.detail
                );
                refuse(refusal.clone(), id)
            }
            _ => CachePlan::Apply(spec),
        };
        out.insert(id.to_owned(), plan);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::CacheRuleEntry;

    fn entry() -> CacheEntry {
        CacheEntry {
            enabled: true,
            ..CacheEntry::default()
        }
    }

    #[test]
    fn a_cache_object_that_sends_nothing_gets_the_defaults() {
        assert_eq!(cache_spec(&entry()), Ok(CacheSpec::default()));
    }

    #[test]
    fn numbers_rules_and_names_are_carried_over_and_a_bypass_rule_keeps_no_time() {
        let e = CacheEntry {
            default_ttl_s: Some(0),
            stale_if_error_s: Some(30),
            disk_bytes: Some(32 << 20),
            memory_bytes: Some(0),
            max_object_bytes: Some(2048),
            session_cookies: vec!["Sid".into()],
            rules: vec![
                CacheRuleEntry {
                    prefix: "/blog/".into(),
                    action: "cache".into(),
                    ttl_s: 90,
                    signed_in: true,
                },
                CacheRuleEntry {
                    prefix: "/admin/".into(),
                    action: "bypass".into(),
                    ttl_s: 77,
                    signed_in: true,
                },
            ],
            ..entry()
        };
        let spec = cache_spec(&e).unwrap();
        assert_eq!(
            (
                spec.default_ttl_s,
                spec.stale_if_error_s,
                spec.disk_bytes,
                spec.memory_bytes,
                spec.max_object_bytes
            ),
            (0, 30, 32 << 20, 0, 2048)
        );
        assert_eq!(spec.session_cookies, ["Sid"]);
        assert_eq!(
            spec.rules,
            vec![
                CacheRule {
                    prefix: "/blog/".into(),
                    bypass: false,
                    ttl_s: 90,
                    signed_in: true
                },
                CacheRule {
                    prefix: "/admin/".into(),
                    bypass: true,
                    ttl_s: 0,
                    signed_in: false
                },
            ]
        );
    }

    #[test]
    fn a_setting_out_of_range_or_not_valid_is_refused_with_its_name() {
        let refused = |edit: &dyn Fn(&mut CacheEntry)| {
            let mut e = entry();
            edit(&mut e);
            let r = cache_spec(&e).unwrap_err();
            assert_eq!(r.code, CacheRefusalCode::Invalid);
            r.detail
        };
        assert_eq!(refused(&|e| e.default_ttl_s = Some(-1)), "default_ttl_s");
        assert_eq!(
            refused(&|e| e.default_ttl_s = Some(i64::MAX)),
            "default_ttl_s"
        );
        assert_eq!(refused(&|e| e.disk_bytes = Some(-5)), "disk_bytes");
        assert_eq!(
            refused(&|e| e.max_object_bytes = Some(i64::MIN)),
            "max_object_bytes"
        );
        assert_eq!(
            refused(&|e| e.rules = vec![CacheRuleEntry {
                prefix: "/a".into(),
                action: "keep".into(),
                ttl_s: 5,
                signed_in: false
            }]),
            "rules.action"
        );
        assert_eq!(
            refused(&|e| e.rules = vec![CacheRuleEntry {
                prefix: "/a".into(),
                action: "cache".into(),
                ttl_s: -3,
                signed_in: false
            }]),
            "rules.ttl_s"
        );
    }

    /// The case table of the control plane, `delivery-checks.json`: a case it accepts passes here
    /// and comes out as its `result`, and a case it refuses is refused. A section is read only
    /// while the cache is on, as the agent never sees a cache that is off.
    #[test]
    fn the_cache_cases_of_the_control_plane_get_the_same_answer() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../proxy/tests/data/delivery-checks.json"
        );
        let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let cases = doc["cache"].as_array().unwrap();
        assert!(cases.len() >= 43, "{} cases", cases.len());
        let mut on = 0;
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let bundle = serde_json::json!({"apps": [{"app_id": "a", "cache": case["in"]}]});
            let decoded = crate::bundle::decode_bundle(bundle.to_string().as_bytes()).unwrap();
            let entry = decoded.apps[0].cache.clone().unwrap();
            if !entry.enabled {
                continue;
            }
            on += 1;
            let got = cache_spec(&entry);
            match (case.get("message"), got) {
                (Some(_), got) => assert!(got.is_err(), "{name}: the control plane refuses it"),
                (None, Err(e)) => panic!("{name}: refused here, {e:?}"),
                (None, Ok(spec)) => {
                    let want = &case["result"];
                    assert_eq!(
                        u64::from(spec.default_ttl_s),
                        want["default_ttl_s"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        u64::from(spec.stale_if_error_s),
                        want["stale_if_error_s"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        spec.disk_bytes,
                        want["disk_bytes"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        spec.memory_bytes,
                        want["memory_bytes"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(
                        spec.max_object_bytes,
                        want["max_object_bytes"].as_u64().unwrap(),
                        "{name}"
                    );
                    let names: Vec<&str> = want["session_cookies"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|n| n.as_str().unwrap())
                        .collect();
                    assert_eq!(spec.session_cookies, names, "{name}");
                    assert_eq!(
                        spec.rules.len(),
                        want["rules"].as_array().unwrap().len(),
                        "{name}"
                    );
                    for (rule, want) in spec.rules.iter().zip(want["rules"].as_array().unwrap()) {
                        assert_eq!(rule.prefix, want["prefix"].as_str().unwrap(), "{name}");
                        assert_eq!(rule.bypass, want["action"] == "bypass", "{name}");
                        assert_eq!(
                            u64::from(rule.ttl_s),
                            want["ttl_s"].as_u64().unwrap(),
                            "{name}"
                        );
                        assert_eq!(
                            rule.signed_in,
                            want["signed_in"].as_bool().unwrap(),
                            "{name}"
                        );
                    }
                }
            }
        }
        assert!(on >= 40, "{on} cases ran with the cache on");
    }

    // The plan of an apply.

    use std::sync::atomic::{AtomicU64, Ordering};

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "wafio-agent-cache-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Dir(dir.canonicalize().unwrap())
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ready() -> (CacheSetup, Dir) {
        let dir = Dir::new();
        let host = CacheHost::open(&dir.0, nix::unistd::geteuid().as_raw()).unwrap();
        (CacheSetup::Ready(host), dir)
    }

    fn app(id: &str, cache: Option<CacheEntry>) -> BundleApp {
        BundleApp {
            app_id: id.into(),
            cache,
            ..BundleApp::default()
        }
    }

    fn sized(disk: i64, memory: i64) -> CacheEntry {
        CacheEntry {
            disk_bytes: Some(disk),
            memory_bytes: Some(memory),
            ..entry()
        }
    }

    const GIB: i64 = 1 << 30;

    fn view(free: u64, fs: u64, memory: u64, in_use: Option<u64>) -> HostView {
        HostView {
            facts: Some(HostFacts {
                free_bytes: free,
                fs_bytes: fs,
                memory_bytes: memory,
            }),
            in_use,
        }
    }

    #[test]
    fn an_app_with_the_cache_on_runs_its_settings_and_one_with_it_off_is_not_named() {
        let (setup, _dir) = ready();
        let apps = [
            app("a", Some(entry())),
            app("b", None),
            app("c", Some(CacheEntry::default())),
        ];
        let planned = plan(&setup, &apps, &HashMap::new(), None);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned["a"], CachePlan::Apply(CacheSpec::default()));
    }

    #[test]
    fn settings_that_do_not_pass_are_refused_and_the_previous_ones_run_on() {
        let (setup, _dir) = ready();
        let running = HashMap::from([("a".to_owned(), CacheSpec::default())]);
        let bad = CacheEntry {
            default_ttl_s: Some(-1),
            ..entry()
        };
        let planned = plan(
            &setup,
            &[
                app("a", Some(bad.clone())),
                app("b", Some(bad)),
                app("a b", Some(entry())),
            ],
            &running,
            None,
        );
        let CachePlan::Refuse { refusal, previous } = &planned["a"] else {
            panic!("{:?}", planned["a"]);
        };
        assert_eq!(
            (refusal.code, refusal.detail.as_str()),
            (CacheRefusalCode::Invalid, "default_ttl_s")
        );
        assert_eq!(previous, &Some(CacheSpec::default()));
        let CachePlan::Refuse { previous, .. } = &planned["b"] else {
            panic!()
        };
        assert_eq!(previous, &None, "nothing ran before: the cache stays off");
        let CachePlan::Refuse { refusal, .. } = &planned["a b"] else {
            panic!()
        };
        assert_eq!(
            refusal.detail, "app_id",
            "an id that cannot name a directory"
        );
    }

    #[test]
    fn when_the_disk_is_too_small_every_app_that_asks_for_more_is_refused_and_none_is_reduced() {
        let (setup, _dir) = ready();
        let small = view(10 * GIB as u64, 100 * GIB as u64, 64 * GIB as u64, Some(0));
        // 5 GiB may be asked for in all: two apps of 4 GiB do not fit, whichever is new.
        let running = HashMap::from([("a".to_owned(), cache_spec(&sized(4 * GIB, 0)).unwrap())]);
        let apps = [
            app("a", Some(sized(4 * GIB, 0))),
            app("b", Some(sized(4 * GIB, 0))),
        ];
        let planned = plan(&setup, &apps, &running, Some(&small));
        assert!(
            matches!(planned["a"], CachePlan::Apply(_)),
            "a did not change and runs on"
        );
        let CachePlan::Refuse { refusal, previous } = &planned["b"] else {
            panic!("{:?}", planned["b"]);
        };
        assert_eq!(refusal.code, CacheRefusalCode::DiskTooSmall);
        assert_eq!(refusal.detail, format!("{} {}", 5 * GIB, 8 * GIB));
        assert_eq!(previous, &None);
        // The same bundle again, with nothing changed, passes whatever the disk says.
        let both = HashMap::from([
            ("a".to_owned(), cache_spec(&sized(4 * GIB, 0)).unwrap()),
            ("b".to_owned(), cache_spec(&sized(4 * GIB, 0)).unwrap()),
        ]);
        let again = plan(&setup, &apps, &both, Some(&small));
        assert!(again.values().all(|p| matches!(p, CachePlan::Apply(_))));
        // What the cache holds already is free to reuse: 3 GiB in use makes room for 8 GiB.
        let roomy = view(
            10 * GIB as u64,
            100 * GIB as u64,
            64 * GIB as u64,
            Some(3 * GIB as u64),
        );
        let fits = plan(&setup, &apps, &running, Some(&roomy));
        assert!(fits.values().all(|p| matches!(p, CachePlan::Apply(_))));
        // A changed app keeps what it ran with when its new settings do not fit.
        let grown = [app("a", Some(sized(8 * GIB, 0)))];
        let CachePlan::Refuse { previous, .. } = &plan(&setup, &grown, &running, Some(&small))["a"]
        else {
            panic!()
        };
        assert_eq!(previous.as_ref().map(|s| s.disk_bytes), Some(4 << 30));
    }

    #[test]
    fn a_full_disk_never_refuses_an_app_that_asks_for_less_or_edits_a_rule() {
        let (setup, _dir) = ready();
        let gib = GIB as u64;
        // 6 GiB are in use and 5 GiB of the 100 are kept free, so 1 GiB may be asked for in all:
        // what runs already does not fit.
        let full = view(0, 100 * gib, 64 * gib, Some(6 * gib));
        let running: HashMap<String, CacheSpec> = [("a", 4), ("b", 1), ("c", 1)]
            .into_iter()
            .map(|(id, n)| (id.to_owned(), cache_spec(&sized(n * GIB, 0)).unwrap()))
            .collect();
        let apps = [
            // Asks for less: applied, though the sum is over what the host allows.
            app("a", Some(sized(2 * GIB, 0))),
            // Only a lifetime changes: applied.
            app(
                "b",
                Some(CacheEntry {
                    default_ttl_s: Some(60),
                    ..sized(GIB, 0)
                }),
            ),
            // Asks for more, and a new app asks for the first time: refused, and the old settings
            // run on.
            app("c", Some(sized(2 * GIB, 0))),
            app("d", Some(sized(GIB, 0))),
        ];
        let planned = plan(&setup, &apps, &running, Some(&full));
        let CachePlan::Apply(a) = &planned["a"] else {
            panic!("{:?}", planned["a"]);
        };
        assert_eq!(a.disk_bytes, 2 << 30, "lowered, not refused");
        let CachePlan::Apply(b) = &planned["b"] else {
            panic!("{:?}", planned["b"]);
        };
        assert_eq!(b.default_ttl_s, 60, "the rule edit runs");
        let CachePlan::Refuse { refusal, previous } = &planned["c"] else {
            panic!("{:?}", planned["c"]);
        };
        assert_eq!(refusal.code, CacheRefusalCode::DiskTooSmall);
        assert_eq!(refusal.detail, format!("{} {}", gib, 6 * gib));
        assert_eq!(previous.as_ref().map(|s| s.disk_bytes), Some(gib));
        let CachePlan::Refuse { previous, .. } = &planned["d"] else {
            panic!("{:?}", planned["d"]);
        };
        assert_eq!(previous, &None);
        // With nobody asking for more there is nothing to refuse, whatever the disk says.
        let calm = plan(&setup, &apps[..2], &running, Some(&full));
        assert!(calm.values().all(|p| matches!(p, CachePlan::Apply(_))));
    }

    #[test]
    fn a_change_that_asks_for_more_memory_only_is_refused_for_memory() {
        let (setup, _dir) = ready();
        let gib = GIB as u64;
        let host = view(100 * gib, 100 * gib, 8 * gib, Some(0));
        let running = HashMap::from([
            ("a".to_owned(), cache_spec(&sized(GIB, GIB)).unwrap()),
            ("b".to_owned(), cache_spec(&sized(2 * GIB, GIB)).unwrap()),
        ]);
        // b lowers its disk and a raises its memory: 3 GiB of memory do not fit (2 GiB may).
        let apps = [
            app("a", Some(sized(GIB, 2 * GIB))),
            app("b", Some(sized(GIB, GIB))),
        ];
        let planned = plan(&setup, &apps, &running, Some(&host));
        let CachePlan::Refuse { refusal, previous } = &planned["a"] else {
            panic!("{:?}", planned["a"]);
        };
        assert_eq!(refusal.code, CacheRefusalCode::MemoryTooSmall);
        assert_eq!(previous.as_ref().map(|s| s.memory_bytes), Some(gib));
        assert!(matches!(planned["b"], CachePlan::Apply(_)));
    }

    #[test]
    fn when_memory_is_too_small_the_detail_is_the_hosts_memory() {
        let (setup, _dir) = ready();
        let host = view(100 * GIB as u64, 100 * GIB as u64, 8 * GIB as u64, Some(0));
        let planned = plan(
            &setup,
            &[app("a", Some(sized(GIB, 3 * GIB)))],
            &HashMap::new(),
            Some(&host),
        );
        let CachePlan::Refuse { refusal, .. } = &planned["a"] else {
            panic!()
        };
        assert_eq!(refusal.code, CacheRefusalCode::MemoryTooSmall);
        assert_eq!(refusal.detail, (8 * GIB).to_string());
        let fits = plan(
            &setup,
            &[app("a", Some(sized(GIB, 2 * GIB)))],
            &HashMap::new(),
            Some(&host),
        );
        assert!(matches!(fits["a"], CachePlan::Apply(_)));
    }

    #[test]
    fn a_cache_whose_index_is_not_built_yet_is_not_failed_for_the_disk_it_holds() {
        let (setup, _dir) = ready();
        // The disk is nearly full, which the cache itself may be the reason of.
        let unknown = view(0, 100 * GIB as u64, 64 * GIB as u64, None);
        let planned = plan(
            &setup,
            &[app("a", Some(sized(4 * GIB, 0)))],
            &HashMap::new(),
            Some(&unknown),
        );
        assert!(matches!(planned["a"], CachePlan::Apply(_)));
        // A host that could not be read is not a reason to refuse either.
        let blind = HostView {
            facts: None,
            in_use: Some(0),
        };
        assert!(matches!(
            plan(
                &setup,
                &[app("a", Some(sized(4 * GIB, 0)))],
                &HashMap::new(),
                Some(&blind)
            )["a"],
            CachePlan::Apply(_)
        ));
    }

    #[test]
    fn a_directory_that_cannot_be_used_refuses_every_app_with_the_cache_on_or_off() {
        let refusal = CacheRefusal {
            code: CacheRefusalCode::DirUnusable,
            detail: "/var/cache/wafio-waf: cannot stat (NotFound)".into(),
        };
        let setup = CacheSetup::Unusable(refusal.clone());
        let running = HashMap::from([("a".to_owned(), CacheSpec::default())]);
        let planned = plan(
            &setup,
            &[app("a", Some(entry())), app("b", None)],
            &running,
            None,
        );
        assert_eq!(planned.len(), 2);
        for id in ["a", "b"] {
            assert_eq!(
                planned[id],
                CachePlan::Refuse {
                    refusal: refusal.clone(),
                    previous: None
                },
                "nothing runs: the cache stays off"
            );
        }
    }

    #[test]
    fn the_host_is_read_only_when_a_bundle_asks_for_a_cache() {
        let (setup, _dir) = ready();
        assert!(host_view(Some(&setup), &[app("a", None)]).is_none());
        assert!(host_view(None, &[app("a", Some(entry()))]).is_none());
        let seen = host_view(Some(&setup), &[app("a", Some(entry()))]).unwrap();
        assert!(seen.facts.is_some_and(|f| f.fs_bytes > 0));
        assert_eq!(seen.in_use, Some(0));
        let dead = CacheSetup::Unusable(CacheRefusal {
            code: CacheRefusalCode::DirUnusable,
            detail: String::new(),
        });
        assert!(host_view(Some(&dead), &[app("a", Some(entry()))]).is_none());
    }
}
