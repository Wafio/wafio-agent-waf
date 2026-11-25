use std::collections::HashMap;

use clap::Parser;

use super::*;

struct FakeEnv {
    vars: HashMap<&'static str, &'static str>,
    files: Vec<&'static str>,
}

impl Env for FakeEnv {
    fn get(&self, key: &str) -> String {
        self.vars
            .get(key)
            .map(|v| v.to_string())
            .unwrap_or_default()
    }
    fn non_empty_file(&self, path: &str) -> bool {
        self.files.contains(&path)
    }
}

fn env(vars: &[(&'static str, &'static str)], files: &[&'static str]) -> FakeEnv {
    FakeEnv {
        vars: vars.iter().copied().collect(),
        files: files.to_vec(),
    }
}

fn parse(args: &[&str]) -> AgentArgs {
    let mut argv = vec!["wafio-waf-agent"];
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).expect("parse");
    assert!(cli.command.is_none());
    cli.agent
}

#[test]
fn defaults_match_documented_values() {
    let f = parse(&[]);
    assert_eq!(f.jail_threshold, 0);
    assert_eq!(f.jail_window_sec, 60);
    assert_eq!(f.jail_duration_sec, 3600);
    assert_eq!(f.jail_url, "http://127.0.0.1:18089/api/ebpf/blocklist");
    assert_eq!(f.bundle_cache_max_age, DEFAULT_BUNDLE_CACHE_MAX_AGE_NS);
    assert_eq!(f.grpc_server, "");
    assert_eq!(f.pid_file, "");
}

#[test]
fn flag_syntax_accepts_equals_space_and_radix_prefixes() {
    let f = parse(&[
        "--grpc-server=cp.example:9090",
        "--agent-name",
        "edge",
        "--jail-threshold",
        "0x10",
        "--jail-window-sec=-1",
        "--bundle-cache-max-age",
        "1h30m",
        "--security-data-dir",
        "/etc/wafio/security-data",
    ]);
    assert_eq!(f.grpc_server, "cp.example:9090");
    assert_eq!(f.agent_name, "edge");
    assert_eq!(f.jail_threshold, 16, "pflag IntVar parses base 0");
    assert_eq!(f.jail_window_sec, -1);
    assert_eq!(f.bundle_cache_max_age, 5_400_000_000_000);
    assert_eq!(f.security_data_dir, "/etc/wafio/security-data");
    // The next argument is taken as the value even when it starts with '-'.
    let f = parse(&["--jail-threshold", "-3", "--grpc-server", "--agent-name"]);
    assert_eq!(
        (
            f.jail_threshold,
            f.grpc_server.as_str(),
            f.agent_name.as_str()
        ),
        (-3, "--agent-name", "")
    );
    for bad in [
        &["--jail-threshold", "x"][..],
        &["--bundle-cache-max-age", "7d"],
        &["--no-such-flag"],
        &["extra"],
    ] {
        let mut argv = vec!["wafio-waf-agent"];
        argv.extend_from_slice(bad);
        assert!(Cli::try_parse_from(argv).is_err(), "{bad:?}");
    }
}

#[test]
fn fetch_data_subcommand_parses() {
    let cli = Cli::try_parse_from([
        "wafio-waf-agent",
        "fetch-data",
        "--dir",
        "/tmp/x",
        "--only",
        "ua,ja4",
        "--force",
    ])
    .unwrap();
    match cli.command {
        Some(Command::FetchData(f)) => {
            assert_eq!(f.dir, "/tmp/x");
            assert_eq!(f.only, "ua,ja4");
            assert!(f.force);
            assert_eq!(f.profile, "agent");
        }
        None => panic!("no subcommand"),
    }
    // The retired --crs-version flag is no longer accepted.
    assert!(
        Cli::try_parse_from(["wafio-waf-agent", "fetch-data", "--crs-version", "v4.7.0"]).is_err()
    );
}

#[test]
fn env_fills_only_empty_flags() {
    let mut f = parse(&["--agent-name", "cli-name"]);
    let e = env(
        &[
            ("WAFIO_AGENT_NAME", "env-name"),
            ("WAFIO_GRPC_SERVER", "cp:9090"),
            ("WAFIO_GRPC_SERVER_NAME", "cp.example"),
            ("WAFIO_GRPC_CLIENT_CERT", "/c.crt"),
            ("WAFIO_GRPC_CLIENT_KEY", "/c.key"),
            ("WAFIO_GRPC_CA_CERT", "/ca.crt"),
            ("WAFIO_HOST_KEY", "wafh_x"),
            ("WAFIO_GEO_COUNTRY_DB_PATH", "/g/c"),
            ("WAFIO_GEO_CITY_DB_PATH", "/g/ci"),
            ("WAFIO_GEO_ASN_DB_PATH", "/g/a"),
            ("WAFIO_UA_BAD_BOT_FILE", "/ua"),
            ("WAFIO_JA3_BLACKLIST_FILE", "/ja3"),
            ("WAFIO_IPREP_LEVEL1_FILE", "/l1"),
            ("WAFIO_IPREP_LEVEL2_FILE", "/l2"),
            ("WAFIO_SECURITY_DATA_DIR", "/srv/data"),
        ],
        &[
            "/etc/wafio/security-data/ja4/ja4.txt",
            "/usr/local/share/wafio/ja4/ja4.txt",
        ],
    );
    assert!(f.fill_from_env(&e).is_empty());
    assert_eq!(f.agent_name, "cli-name", "CLI wins over env");
    assert_eq!(f.grpc_server, "cp:9090");
    assert_eq!(f.grpc_server_name, "cp.example");
    assert_eq!(
        (
            f.client_cert.as_str(),
            f.client_key.as_str(),
            f.ca_cert.as_str()
        ),
        ("/c.crt", "/c.key", "/ca.crt")
    );
    assert_eq!(f.host_key, "wafh_x");
    assert_eq!(
        (
            f.geo_country_db.as_str(),
            f.geo_city_db.as_str(),
            f.geo_asn_db.as_str()
        ),
        ("/g/c", "/g/ci", "/g/a")
    );
    assert_eq!(f.bot_ua_file, "/ua");
    assert_eq!(
        f.bot_ja4_file, "/etc/wafio/security-data/ja4/ja4.txt",
        "first existing JA4 candidate"
    );
    assert_eq!(f.bot_ja3_file, "/ja3");
    assert_eq!(
        (f.iprep_level1_file.as_str(), f.iprep_level2_file.as_str()),
        ("/l1", "/l2")
    );
    assert_eq!(f.security_data_dir, "/srv/data");
    assert_eq!(f.resolved_security_data_dir(), "/srv/data");
    assert!(f.legacy_data_dir_warning().is_none());
    assert!(f.check_required().is_ok());
}

#[test]
fn the_tls_sites_file_is_gone_and_its_variable_gets_one_warning() {
    assert!(Cli::try_parse_from(["wafio-waf-agent", "--tls-sites-file", "x"]).is_err());
    let warning = |vars: &[(&'static str, &'static str)]| {
        parse(&[])
            .fill_from_env(&env(vars, &[]))
            .into_iter()
            .filter(|l| l.contains("WAFIO_TLS_SITES_FILE"))
            .collect::<Vec<_>>()
    };
    assert!(warning(&[]).is_empty());
    let lines = warning(&[("WAFIO_TLS_SITES_FILE", "/etc/wafio/tls-sites.json")]);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("no longer read") && lines[0].contains("dashboard"));
}

#[test]
fn the_old_data_directory_setting_still_gives_the_directory_with_one_warning() {
    let f = parse(&[
        "--crs-default-dir",
        "/etc/wafio/security-data/crs/coreruleset/rules",
    ]);
    assert_eq!(f.resolved_security_data_dir(), "/etc/wafio/security-data");
    let w = f.legacy_data_dir_warning().unwrap();
    assert!(w.contains("--security-data-dir") && w.contains("/etc/wafio/security-data"));
    let mut f = parse(&[]);
    f.fill_from_env(&env(
        &[("WAFIO_CRS_DEFAULT_DIR", "/srv/waf/data/crs/coreruleset")],
        &[],
    ));
    assert_eq!(f.resolved_security_data_dir(), "/srv/waf/data");
    assert!(f.legacy_data_dir_warning().is_some());
    // The new setting wins, from the flag or from the environment, and then there is no warning.
    let f = parse(&[
        "--security-data-dir",
        "/new",
        "--crs-default-dir",
        "/old/crs",
    ]);
    assert_eq!(f.resolved_security_data_dir(), "/new");
    assert!(f.legacy_data_dir_warning().is_none());
    let mut f = parse(&["--crs-default-dir", "/old/crs"]);
    f.fill_from_env(&env(&[("WAFIO_SECURITY_DATA_DIR", "/new")], &[]));
    assert_eq!(f.resolved_security_data_dir(), "/new");
    assert!(f.legacy_data_dir_warning().is_none());
    // Neither: the agent default applies.
    assert_eq!(parse(&[]).resolved_security_data_dir(), "");
    // The retired companions are gone.
    assert!(
        Cli::try_parse_from(["wafio-waf-agent", "--crs-setup-file", "x"]).is_err()
            && Cli::try_parse_from(["wafio-waf-agent", "--crs-rules-glob", "x"]).is_err()
    );
}

#[test]
fn ja4_env_beats_candidates_and_relative_candidate_first() {
    let mut f = parse(&[]);
    f.fill_from_env(&env(
        &[("WAFIO_JA4_BLACKLIST_FILE", "/env/ja4")],
        &["security-data/ja4/ja4.txt"],
    ));
    assert_eq!(f.bot_ja4_file, "/env/ja4");
    let mut f = parse(&[]);
    f.fill_from_env(&env(
        &[],
        &[
            "security-data/ja4/ja4.txt",
            "/etc/wafio/security-data/ja4/ja4.txt",
        ],
    ));
    assert_eq!(f.bot_ja4_file, "security-data/ja4/ja4.txt");
    let mut f = parse(&[]);
    f.fill_from_env(&env(&[], &[]));
    assert_eq!(f.bot_ja4_file, "");
}

#[test]
fn bundle_cache_max_age_env_only_over_the_default() {
    let mut f = parse(&[]);
    assert!(
        f.fill_from_env(&env(&[("WAFIO_BUNDLE_CACHE_MAX_AGE", "2h")], &[]))
            .is_empty()
    );
    assert_eq!(f.bundle_cache_max_age, 7_200_000_000_000);

    let mut f = parse(&["--bundle-cache-max-age", "1h"]);
    f.fill_from_env(&env(&[("WAFIO_BUNDLE_CACHE_MAX_AGE", "2h")], &[]));
    assert_eq!(
        f.bundle_cache_max_age, 3_600_000_000_000,
        "an explicit flag wins"
    );

    // The comparison is with the default value, so an explicit default still takes the env.
    let mut f = parse(&["--bundle-cache-max-age", "168h"]);
    f.fill_from_env(&env(&[("WAFIO_BUNDLE_CACHE_MAX_AGE", "2h")], &[]));
    assert_eq!(f.bundle_cache_max_age, 7_200_000_000_000);

    for bad in ["soon", "-1h", "0"] {
        let mut f = parse(&[]);
        let logs = f.fill_from_env(&env(&[("WAFIO_BUNDLE_CACHE_MAX_AGE", bad)], &[]));
        assert_eq!(
            logs,
            vec![format!(
                "[wafio-waf-agent] ignoring invalid WAFIO_BUNDLE_CACHE_MAX_AGE=\"{bad}\""
            )]
        );
        assert_eq!(f.bundle_cache_max_age, DEFAULT_BUNDLE_CACHE_MAX_AGE_NS);
    }
    let f = parse(&["--bundle-cache-max-age", "-5m"]);
    assert_eq!(
        f.bundle_cache_max_age(),
        std::time::Duration::from_secs(7 * 24 * 3600),
        "SetBundleCache: <= 0 → default"
    );
}

#[test]
fn check_required_lists_every_missing_flag() {
    let f = parse(&[]);
    assert_eq!(
        f.check_required().unwrap_err(),
        "missing required flag(s): --grpc-server, --client-cert, --client-key, --ca-cert, --agent-name, \
--geo-country-db, --geo-city-db, --geo-asn-db, --bot-ua-file, --bot-ja4-file"
    );
    let mut f = parse(&[
        "--grpc-server",
        "cp:9090",
        "--client-cert",
        "a",
        "--client-key",
        "b",
        "--ca-cert",
        "c",
        "--agent-name",
        "  ",
        "--geo-country-db",
        "d",
        "--geo-city-db",
        "e",
        "--geo-asn-db",
        "f",
        "--bot-ua-file",
        "g",
        "--bot-ja3-file",
        "h",
    ]);
    assert_eq!(
        f.check_required().unwrap_err(),
        "missing required flag(s): --agent-name",
        "blank counts as missing"
    );
    f.agent_name = "x".into();
    assert!(
        f.check_required().is_ok(),
        "JA3 alone satisfies the JA4/JA3 requirement"
    );
}

#[test]
fn check_paths_reports_os_error_text() {
    let dir = std::env::temp_dir().join(format!("wafio-flags-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let full = dir.join("full");
    std::fs::write(&full, "x").unwrap();
    let empty = dir.join("empty");
    std::fs::write(&empty, "").unwrap();
    let full = full.to_str().unwrap().to_string();
    let mut f = AgentArgs {
        client_cert: full.clone(),
        client_key: full.clone(),
        ca_cert: full.clone(),
        geo_country_db: full.clone(),
        geo_city_db: full.clone(),
        geo_asn_db: full.clone(),
        bot_ua_file: full.clone(),
        ..Default::default()
    };
    assert!(f.check_paths().is_ok());
    f.bot_ja3_file = empty.to_str().unwrap().into();
    assert_eq!(
        f.check_paths().unwrap_err(),
        format!("--bot-ja3-file: \"{}\" is empty", empty.display())
    );
    f.bot_ja3_file.clear();
    f.geo_city_db = "/nonexistent/wafio".into();
    assert_eq!(
        f.check_paths().unwrap_err(),
        "--geo-city-db: cannot stat \"/nonexistent/wafio\": stat /nonexistent/wafio: no such file or directory"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn choose_state_dir_table() {
    // TestResolveStateDir.
    for (flag, env, systemd, want) in [
        ("", "", "", ""),
        (
            "",
            "",
            "/var/lib/wafio-waf-agent",
            "/var/lib/wafio-waf-agent",
        ),
        ("", "", "/var/lib/a:/var/lib/b", "/var/lib/a"),
        ("", "/srv/state", "/var/lib/wafio-waf-agent", "/srv/state"),
        ("/tmp/x", "/srv/state", "/var/lib/wafio-waf-agent", "/tmp/x"),
        ("  ", " ", " ", ""),
    ] {
        assert_eq!(
            choose_state_dir(flag, env, systemd),
            want,
            "{flag:?} {env:?} {systemd:?}"
        );
    }
}

#[test]
fn server_name_and_token_file_fallbacks() {
    let mut f = parse(&["--grpc-server", "cp.example.com:9090"]);
    assert_eq!(f.server_name(), "cp.example.com");
    f.grpc_server = "[::1]:9090".into();
    assert_eq!(f.server_name(), "[::1]", "the brackets stay");
    f.grpc_server = "nohostport".into();
    assert_eq!(f.server_name(), "nohostport");
    f.grpc_server_name = "override".into();
    assert_eq!(f.server_name(), "override");

    let e = env(&[(LOCAL_API_TOKEN_FILE_ENV, "/run/x.token")], &[]);
    assert_eq!(f.jail_token_file(&e), "/run/x.token");
    f.jail_token_file = "/flag.token".into();
    assert_eq!(f.jail_token_file(&e), "/flag.token");
}

#[test]
fn engine_env_and_component_paths() {
    let f = AgentArgs {
        agent_name: "a".into(),
        grpc_server: "cp:1".into(),
        bot_ua_file: "/ua".into(),
        bot_ja4_file: "/ja4".into(),
        security_data_dir: "/etc/wafio/security-data".into(),
        ..Default::default()
    };
    let env = f.engine_env();
    assert!(
        !env.iter().any(|(k, _)| *k == "WAFIO_HOST_KEY"),
        "empty host key not exported"
    );
    assert!(!env.iter().any(|(k, _)| *k == "WAFIO_JA3_BLACKLIST_FILE"));
    assert!(env.contains(&("WAFIO_JA4_BLACKLIST_FILE", "/ja4".into())));
    assert!(env.contains(&("WAFIO_SECURITY_DATA_DIR", "/etc/wafio/security-data".into())));
    let paths = f.component_paths();
    assert!(!paths.contains_key("crs"));
    assert_eq!(paths["ua"], "/ua");
    assert_eq!(paths["ja3"], "");
    assert_eq!(paths.len(), 8);
}

#[test]
fn the_acme_directory_is_the_one_of_lets_encrypt_unless_named_and_must_be_https() {
    assert_eq!(
        parse(&[]).resolved_acme_directory().unwrap(),
        "https://acme-v02.api.letsencrypt.org/directory"
    );
    // The flag, and the environment when the flag is not given; the flag wins.
    let f = parse(&["--acme-directory", "https://acme.test:14000/dir"]);
    assert_eq!(
        f.resolved_acme_directory().unwrap(),
        "https://acme.test:14000/dir"
    );
    let mut f = parse(&[]);
    f.fill_from_env(&env(
        &[("WAFIO_ACME_DIRECTORY", "https://env.test/dir")],
        &[],
    ));
    assert_eq!(f.resolved_acme_directory().unwrap(), "https://env.test/dir");
    let mut f = parse(&["--acme-directory=https://flag.test/dir"]);
    f.fill_from_env(&env(
        &[("WAFIO_ACME_DIRECTORY", "https://env.test/dir")],
        &[],
    ));
    assert_eq!(
        f.resolved_acme_directory().unwrap(),
        "https://flag.test/dir"
    );
    // The account key and every request go there: nothing but https is taken, from either.
    for bad in [
        "http://acme.test/dir",
        "HTTP://acme.test/dir",
        "ftp://acme.test/dir",
        "acme.test/dir",
        "https://",
        "//acme.test",
    ] {
        let e = parse(&["--acme-directory", bad])
            .resolved_acme_directory()
            .unwrap_err();
        assert!(
            e.contains("--acme-directory") && e.contains("https"),
            "{bad}: {e}"
        );
        let mut f = parse(&[]);
        f.fill_from_env(&env(&[("WAFIO_ACME_DIRECTORY", bad)], &[]));
        assert!(f.resolved_acme_directory().is_err(), "{bad}");
    }
    assert!(
        parse(&["--acme-directory", "HTTPS://acme.test/dir"])
            .resolved_acme_directory()
            .is_ok(),
        "the scheme is not case sensitive"
    );
}
