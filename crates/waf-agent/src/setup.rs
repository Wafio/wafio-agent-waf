//! The setup downloads the WAF agent runs: component selection, the download order and the
//! atomic file write.
//! Downloads go through [`crate::httpclient`]; the MalwareBazaar feed is `setup_malware`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const COMPONENT_NAMES: [&str; 8] = [
    "geoip-country",
    "geoip-city",
    "geoip-asn",
    "firehol",
    "ja4",
    "ja3",
    "ua",
    "malware",
];

/// The fetch options (the fields the agent sets).
#[derive(Clone, Debug, Default)]
pub struct FetchOptions {
    pub dir: String,
    pub max_mind_license_key: String,
    pub force: bool,
    /// Server-only override of `WAFIO_MALWARE_AUTH_KEY`; empty = the env.
    pub malware_auth_key: String,
    /// Empty = every component.
    pub only: Vec<String>,
    /// Progress lines; None = discard.
    pub log: Option<fn(&str)>,
}

/// The outcome of fetching one component (component and error text).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchOutcome {
    pub component: String,
    pub error: Option<String>,
}

impl FetchOptions {
    pub(crate) fn log(&self, s: &str) {
        if let Some(f) = self.log {
            f(s);
        }
    }

    /// Whether `component` is wanted: "geoip" enables the three GeoIP components.
    pub fn wants_component(&self, component: &str) -> bool {
        if self.only.is_empty() {
            return true;
        }
        self.only.iter().any(|o| {
            let o = o.trim().to_lowercase();
            wafio_bytetext::strings::eq_ignore_case(o.as_bytes(), component.as_bytes())
                || (o == "geoip" && component.starts_with("geoip"))
        })
    }
}

/// The components of a profile; None = every component.
pub fn components_for_profile(p: &str) -> Option<Vec<String>> {
    let list: &[&str] = match p {
        "control-plane" => &["geoip-country", "geoip-city", "geoip-asn", "ja4", "ua"],
        "agent" => &[
            "geoip-country",
            "geoip-city",
            "geoip-asn",
            "firehol",
            "ja4",
            "ua",
            "malware",
        ],
        "host-agent" => &["geoip-country"],
        _ => return None,
    };
    Some(list.iter().map(|s| s.to_string()).collect())
}

fn is_malware_feed(c: &str) -> bool {
    let c = c.trim().to_lowercase();
    c == "malware" || c == "malware-hashes"
}

/// A profile run without `WAFIO_MALWARE_AUTH_KEY` drops the
/// MalwareBazaar download (agents get the database from the control plane).
pub fn malware_skipped_for_agent(
    only: Vec<String>,
    explicit: bool,
    auth_key: &str,
) -> (Vec<String>, bool) {
    let includes = only.is_empty() || only.iter().any(|c| is_malware_feed(c));
    if explicit || !includes || !auth_key.trim().is_empty() {
        return (only, false);
    }
    let base: Vec<String> = if only.is_empty() {
        COMPONENT_NAMES.iter().map(|s| s.to_string()).collect()
    } else {
        only
    };
    (
        base.into_iter().filter(|c| !is_malware_feed(c)).collect(),
        true,
    )
}

const UA: &str = "WAFio/1.0 (security-data-fetcher)";
/// Timeout of one download (10 minutes).
const GET_TIMEOUT: Duration = Duration::from_secs(600);
/// Bodies are held in memory; the largest (DB-IP city) is ~130 MB.
const BODY_CAP: usize = 512 << 20;
/// A downloaded gzip file may expand to at most this many bytes.
const GUNZIP_CAP: usize = 1 << 30;

const DBIP_URL_TEMPLATE: (&str, &str) = ("https://download.db-ip.com/free/dbip-", "-lite-");
const FIREHOL_LEVEL1_LIST_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset";
const FIREHOL_LEVEL2_LIST_URL: &str =
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset";
const SALESFORCE_JA3_FEED: &str =
    "https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv";
const ABUSECH_JA3_FEED: &str = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv";
const BAD_BOT_AGENTS_FEED: &str = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list";

fn outcome(component: &str, err: Option<String>) -> FetchOutcome {
    FetchOutcome {
        component: component.into(),
        error: err,
    }
}

/// An existing, non-empty file is kept unless `--force`.
fn existing(cfg: &FetchOptions, dst: &Path, name: &str) -> bool {
    if !cfg.force && std::fs::metadata(dst).is_ok_and(|m| m.len() > 0) {
        cfg.log(&format!(
            "  ✓ {name} — already exists (use --force to re-download)"
        ));
        return true;
    }
    false
}

fn fetch_url(url: &str) -> Result<crate::httpclient::Response, String> {
    crate::httpclient::get_blocking(url, UA, BODY_CAP, GET_TIMEOUT)
}

/// Writes through a temp file, then renames.
fn write_from(dst: &Path, mut r: impl Read) -> Result<i64, String> {
    let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
    let res = (|| -> std::io::Result<u64> {
        let mut f = std::fs::File::create(&tmp)?;
        let n = std::io::copy(&mut r, &mut f)?;
        f.sync_all()?;
        Ok(n)
    })();
    match res.and_then(|n| std::fs::rename(&tmp, dst).map(|_| n)) {
        Ok(n) => Ok(n as i64),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e.to_string())
        }
    }
}

fn fetch_gunzipped(url: &str, dst: &Path) -> Result<i64, String> {
    let r = fetch_url(url)?;
    if r.status != 200 {
        return Err(format!("HTTP {}", r.status));
    }
    let body =
        wafio_bodyinspect::gunzip_to_vec(&r.body, GUNZIP_CAP).map_err(|e| format!("gzip: {e}"))?;
    write_from(dst, body.as_slice())
}

fn fetch_text(url: &str, dst: &Path) -> Result<i64, String> {
    let r = fetch_url(url)?;
    if r.status != 200 {
        return Err(format!("HTTP {}", r.status));
    }
    write_from(dst, r.body.as_slice())
}

/// HEAD answered 200 within 10 s.
fn url_answers_head(url: &str) -> bool {
    crate::httpclient::head_blocking(url, UA, Duration::from_secs(10))
        .is_ok_and(|r| r.status == 200)
}

/// "YYYY-MM" of the current month and the one before (UTC).
fn months() -> [String; 2] {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let ts = crate::stderr_log::timestamp(secs);
    let (y, m): (i64, i64) = (
        ts[0..4].parse().unwrap_or(1970),
        ts[5..7].parse().unwrap_or(1),
    );
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}")]
}

fn download_dbip_databases(cfg: &FetchOptions, want: &[(&str, &str)]) -> Vec<FetchOutcome> {
    let dir = Path::new(&cfg.dir).join("geoip");
    let _ = std::fs::create_dir_all(&dir);
    let mut out = Vec::new();
    for (slug, name) in want {
        let dst = dir.join(name);
        let component = format!("geoip/{name}");
        if existing(cfg, &dst, name) {
            out.push(outcome(&component, None));
            continue;
        }
        cfg.log(&format!("  ↓ {name} ..."));
        let url = months()
            .iter()
            .map(|m| {
                format!(
                    "{}{slug}{}{m}.mmdb.gz",
                    DBIP_URL_TEMPLATE.0, DBIP_URL_TEMPLATE.1
                )
            })
            .find(|u| url_answers_head(u));
        let Some(url) = url else {
            let e = format!("DB-IP {slug}: no accessible URL found for current/previous month");
            cfg.log(&format!("  ✗ {name}: {e}"));
            out.push(outcome(&component, Some(e)));
            continue;
        };
        match fetch_gunzipped(&url, &dst) {
            Ok(n) => {
                cfg.log(&format!(
                    "  ✓ {name} → {} ({})",
                    dst.display(),
                    format_byte_size(n)
                ));
                out.push(outcome(&component, None));
            }
            Err(e) => {
                cfg.log(&format!("  ✗ {name}: {e}"));
                out.push(outcome(&component, Some(format!("DB-IP {slug}: {e}"))));
            }
        }
    }
    out
}

/// The first regular file of a tar stream whose name ends with `suffix`.
// shortcut: ustar names (prefix + name) only, no PAX/GNU long names; MaxMind archives use
// short names. Upgrade if MaxMind ever ships long paths.
fn tar_extract(mut r: impl Read, suffix: &str, dst: &Path) -> Result<i64, String> {
    let mut hdr = [0u8; 512];
    loop {
        if r.read_exact(&mut hdr).is_err() || hdr.iter().all(|&b| b == 0) {
            return Err(format!("{suffix} not found in MaxMind archive"));
        }
        let field = |a: usize, b: usize| {
            let f = &hdr[a..b];
            String::from_utf8_lossy(&f[..f.iter().position(|&c| c == 0).unwrap_or(f.len())])
                .into_owned()
        };
        let size = i64::from_str_radix(field(124, 136).trim(), 8)
            .map_err(|_| "tar: invalid header".to_string())?;
        let prefix = field(345, 500);
        let name = if prefix.is_empty() {
            field(0, 100)
        } else {
            format!("{prefix}/{}", field(0, 100))
        };
        let typ = hdr[156];
        if (typ == b'0' || typ == 0) && name.ends_with(suffix) {
            return write_from(dst, (&mut r).take(size as u64));
        }
        let padded = (size + 511) / 512 * 512;
        std::io::copy(&mut (&mut r).take(padded as u64), &mut std::io::sink())
            .map_err(|e| format!("tar: {e}"))?;
    }
}

fn download_maxmind_databases(cfg: &FetchOptions, want: &[(&str, &str)]) -> Vec<FetchOutcome> {
    let dir = Path::new(&cfg.dir).join("geoip");
    let _ = std::fs::create_dir_all(&dir);
    let mut out = Vec::new();
    for (slug, name) in want {
        let edition = match *slug {
            "country" => "GeoLite2-Country",
            "city" => "GeoLite2-City",
            _ => "GeoLite2-ASN",
        };
        let dst = dir.join(name);
        let component = format!("geoip/{name}");
        if existing(cfg, &dst, name) {
            out.push(outcome(&component, None));
            continue;
        }
        cfg.log(&format!("  ↓ {name} ..."));
        let url = format!(
            "https://download.maxmind.com/app/geoip_download?edition_id={edition}&license_key={}&suffix=tar.gz",
            cfg.max_mind_license_key
        );
        let r = fetch_url(&url).and_then(|r| match r.status {
            401 | 403 => Err(format!("HTTP {} — invalid MaxMind license key", r.status)),
            200 => wafio_bodyinspect::gunzip_to_vec(&r.body, GUNZIP_CAP)
                .map_err(|e| format!("gzip: {e}"))
                .and_then(|tar| tar_extract(tar.as_slice(), &format!("{edition}.mmdb"), &dst)),
            s => Err(format!("HTTP {s}")),
        });
        match r {
            Ok(n) => {
                cfg.log(&format!(
                    "  ✓ {name} → {} ({})",
                    dst.display(),
                    format_byte_size(n)
                ));
                out.push(outcome(&component, None));
            }
            Err(e) => {
                cfg.log(&format!("  ✗ {name}: {e}"));
                out.push(outcome(&component, Some(format!("MaxMind {edition}: {e}"))));
            }
        }
    }
    out
}

fn download_firehol_lists(cfg: &FetchOptions) -> Vec<FetchOutcome> {
    let dir = Path::new(&cfg.dir).join("firehol");
    let _ = std::fs::create_dir_all(&dir);
    let mut out = Vec::new();
    for (name, url) in [
        ("firehol_level1.netset", FIREHOL_LEVEL1_LIST_URL),
        ("firehol_level2.netset", FIREHOL_LEVEL2_LIST_URL),
    ] {
        let dst = dir.join(name);
        let component = format!("firehol/{name}");
        if existing(cfg, &dst, name) {
            out.push(outcome(&component, None));
            continue;
        }
        cfg.log(&format!("  ↓ {name} ..."));
        match fetch_text(url, &dst) {
            Ok(_) => {
                cfg.log(&format!(
                    "  ✓ {name} → {} ({} entries)",
                    dst.display(),
                    format_thousands(count_feed_lines(&dst))
                ));
                out.push(outcome(&component, None));
            }
            Err(e) => {
                cfg.log(&format!("  ✗ {name}: {e}"));
                out.push(outcome(&component, Some(e)));
            }
        }
    }
    out
}

/// A feed named by `env` (body of a 200), else `default`.
fn feed_or_default(env: &str, default: &str) -> Vec<u8> {
    match std::env::var(env) {
        Ok(url) if !url.is_empty() => match fetch_url(&url) {
            Ok(r) if r.status == 200 && !r.body.is_empty() => r.body,
            _ => default.as_bytes().to_vec(),
        },
        _ => default.as_bytes().to_vec(),
    }
}

fn write_tmp_rename(dst: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = PathBuf::from(format!("{}.tmp", dst.display()));
    std::fs::write(&tmp, data)
        .and_then(|_| std::fs::rename(&tmp, dst))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })
}

fn download_ja4_lists(cfg: &FetchOptions) -> FetchOutcome {
    let dir = Path::new(&cfg.dir).join("ja4");
    let _ = std::fs::create_dir_all(&dir);
    let (block, allow) = (dir.join("ja4.txt"), dir.join("ja4_allowlist.txt"));
    let non_empty = |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.len() > 0);
    if !cfg.force && non_empty(&block) && non_empty(&allow) {
        cfg.log("  ✓ ja4.txt — already exists (use --force to re-download)");
        cfg.log("  ✓ ja4_allowlist.txt — already exists (use --force to re-download)");
        return outcome("ja4", None);
    }
    cfg.log("  ↓ ja4.txt ...");
    if let Err(e) = write_tmp_rename(
        &block,
        &feed_or_default(
            "WAFIO_JA4_BLOCKLIST_URL",
            crate::setup_ja4::DEFAULT_JA4_BLOCKLIST_TEXT,
        ),
    ) {
        cfg.log(&format!("  ✗ ja4.txt: {e}"));
        return outcome("ja4", Some(e));
    }
    cfg.log(&format!(
        "  ✓ ja4.txt → {} ({} entries)",
        block.display(),
        format_thousands(count_feed_lines(&block))
    ));
    cfg.log("  ↓ ja4_allowlist.txt ...");
    if write_tmp_rename(
        &allow,
        &feed_or_default(
            "WAFIO_JA4_ALLOWLIST_URL",
            crate::setup_ja4::DEFAULT_JA4_ALLOWLIST_TEXT,
        ),
    )
    .is_ok()
    {
        cfg.log(&format!(
            "  ✓ ja4_allowlist.txt → {} ({} entries)",
            allow.display(),
            format_thousands(count_feed_lines(&allow))
        ));
    }
    outcome("ja4", None)
}

fn download_ja3_lists(cfg: &FetchOptions) -> FetchOutcome {
    let dir = Path::new(&cfg.dir).join("ja3");
    let _ = std::fs::create_dir_all(&dir);
    let dst = dir.join("ja3.txt");
    if existing(cfg, &dst, "ja3.txt") {
        return outcome("ja3", None);
    }
    let mut seen = std::collections::HashSet::new();
    let mut entries: Vec<(String, String)> = Vec::new();
    cfg.log("  ↓ ja3.txt from Salesforce JA3 CSV...");
    if let Ok(r) = fetch_url(SALESFORCE_JA3_FEED)
        && r.status == 200
    {
        for line in String::from_utf8_lossy(&r.body).lines().map(str::trim) {
            if line.is_empty()
                || ["\"Copyright", "All rights", "Licensed", "For full"]
                    .iter()
                    .any(|p| line.starts_with(p))
            {
                continue;
            }
            let Some((h, note)) = line.split_once(',') else {
                continue;
            };
            let h = h.trim().to_lowercase();
            if h.len() == 32 && seen.insert(h.clone()) {
                entries.push((h, note.trim().trim_matches('"').to_string()));
            }
        }
    }
    cfg.log("  ↓ ja3.txt from abuse.ch SSLBL...");
    if let Ok(r) = fetch_url(ABUSECH_JA3_FEED)
        && r.status == 200
    {
        for line in String::from_utf8_lossy(&r.body).lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ',').collect();
            if parts.len() < 4 {
                continue;
            }
            let h = parts[0].trim().to_lowercase();
            if h.len() == 32 && seen.insert(h.clone()) {
                entries.push((h, parts[3].trim().to_string()));
            }
        }
    }
    if entries.is_empty() {
        let e = "no JA3 entries fetched from any source".to_string();
        cfg.log(&format!("  ✗ ja3: {e}"));
        return outcome("ja3", Some(e));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut text = format!(
        "# JA3 malicious TLS fingerprints\n# Sources: github.com/salesforce/ja3 + sslbl.abuse.ch\n# Downloaded: {}\n",
        rfc3339(now)
    );
    for (h, note) in &entries {
        if note.is_empty() {
            text.push_str(&format!("{h}\n"));
        } else {
            text.push_str(&format!("{h} {note}\n"));
        }
    }
    if let Err(e) = write_tmp_rename(&dst, text.as_bytes()) {
        cfg.log(&format!("  ✗ ja3: {e}"));
        return outcome("ja3", Some(e));
    }
    cfg.log(&format!(
        "  ✓ ja3.txt → {} ({} fingerprints)",
        dst.display(),
        format_thousands(entries.len())
    ));
    outcome("ja3", None)
}

pub fn escape_regex_meta(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if r"\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn download_bad_bot_agents(cfg: &FetchOptions) -> FetchOutcome {
    let dir = Path::new(&cfg.dir).join("user-agents");
    let _ = std::fs::create_dir_all(&dir);
    let dst = dir.join("bot.txt");
    if existing(cfg, &dst, "bot.txt") {
        return outcome("ua", None);
    }
    cfg.log("  ↓ bot.txt from nginx-ultimate-bad-bot-blocker...");
    let r = match fetch_url(BAD_BOT_AGENTS_FEED) {
        Ok(r) if r.status == 200 => r,
        Ok(r) => {
            let e = format!("HTTP {}", r.status);
            cfg.log(&format!("  ✗ bot UA: {e}"));
            return outcome("ua", Some(e));
        }
        Err(e) => {
            cfg.log(&format!("  ✗ bot UA: {e}"));
            return outcome("ua", Some(e));
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut text = format!(
        "# Bad bot user-agent patterns — source: github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker\n# Downloaded: {}\n",
        rfc3339(now)
    );
    let mut count = 0;
    for line in String::from_utf8_lossy(&r.body).lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.replace("\\ ", " ");
        let line = line.trim_matches('"');
        if line.is_empty() {
            continue;
        }
        text.push_str(&format!("^{}.*\n", escape_regex_meta(line)));
        count += 1;
    }
    if let Err(e) = write_tmp_rename(&dst, text.as_bytes()) {
        cfg.log(&format!("  ✗ bot UA: {e}"));
        return outcome("ua", Some(e));
    }
    cfg.log(&format!(
        "  ✓ bot.txt → {} ({} entries)",
        dst.display(),
        format_thousands(count)
    ));
    outcome("ua", None)
}

/// A Unix time as RFC 3339 (UTC).
fn rfc3339(unix: i64) -> String {
    let t = crate::stderr_log::timestamp(unix);
    format!("{}-{}-{}T{}Z", &t[0..4], &t[5..7], &t[8..10], &t[11..])
}

pub fn format_byte_size(n: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = 1024 * KB;
    if n >= MB {
        format!("{:.1} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

/// Thousands separated by commas.
pub fn format_thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Non-empty, non-comment lines.
fn count_feed_lines(p: &Path) -> usize {
    std::fs::read_to_string(p).map_or(0, |s| {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .count()
    })
}

/// Downloads the components in the fixed component order.
pub fn download_components(cfg: &FetchOptions) -> Vec<FetchOutcome> {
    let mut out = Vec::new();
    let geo: Vec<(&str, &str)> = [
        ("country", "country.mmdb", "geoip-country"),
        ("city", "city.mmdb", "geoip-city"),
        ("asn", "asn.mmdb", "geoip-asn"),
    ]
    .into_iter()
    .filter(|(_, _, c)| cfg.wants_component(c))
    .map(|(s, n, _)| (s, n))
    .collect();
    if !geo.is_empty() {
        if cfg.max_mind_license_key.is_empty() {
            cfg.log("\n[GeoIP] Provider: DB-IP (free, no registration required)");
            out.extend(download_dbip_databases(cfg, &geo));
        } else {
            cfg.log("\n[GeoIP] Provider: MaxMind GeoLite2 (license key configured)");
            out.extend(download_maxmind_databases(cfg, &geo));
        }
    }
    if cfg.wants_component("firehol") {
        cfg.log("\n[Firehol] IP Reputation Blocklists");
        out.extend(download_firehol_lists(cfg));
    }
    if cfg.wants_component("ja4") {
        cfg.log("\n[JA4] Malicious TLS Fingerprints");
        out.push(download_ja4_lists(cfg));
    }
    if cfg.wants_component("ja3") {
        cfg.log("\n[JA3] Malicious TLS Fingerprints (Legacy)");
        out.push(download_ja3_lists(cfg));
    }
    if cfg.wants_component("ua") {
        cfg.log("\n[Bot UA] Bad Bot User Agents");
        out.push(download_bad_bot_agents(cfg));
    }
    if cfg.wants_component("malware") || cfg.wants_component("malware-hashes") {
        cfg.log("\n[Malware] Threat Intelligence Feeds (MalwareBazaar + WebShell Signatures)");
        out.extend(crate::setup_malware::download_malware_feed(cfg));
    }
    out
}

/// Writes through a temp file in the same directory, 0644, fsync, rename, dir fsync.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".malware-{}-{}", std::process::id(), nanos()));
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    let _ = std::fs::remove_file(&tmp);
    res.map_err(|e| e.to_string())
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch_options(only: &[&str]) -> FetchOptions {
        FetchOptions {
            only: only.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn wants_component_aliases() {
        assert!(fetch_options(&[]).wants_component("ua"));
        assert!(fetch_options(&[" GeoIP "]).wants_component("geoip-asn"));
        assert!(fetch_options(&["UA"]).wants_component("ua"));
        assert!(!fetch_options(&["ua"]).wants_component("ja4"));
    }

    #[test]
    fn malware_skipped_for_agent_rules() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            malware_skipped_for_agent(v(&["ua", "malware"]), false, ""),
            (v(&["ua"]), true)
        );
        assert_eq!(
            malware_skipped_for_agent(v(&["ua", "malware"]), true, ""),
            (v(&["ua", "malware"]), false)
        );
        assert_eq!(
            malware_skipped_for_agent(v(&["ua"]), false, ""),
            (v(&["ua"]), false)
        );
        assert_eq!(
            malware_skipped_for_agent(v(&["malware"]), false, "key"),
            (v(&["malware"]), false)
        );
        let (all, skipped) = malware_skipped_for_agent(Vec::new(), false, "");
        assert!(skipped);
        assert_eq!(all.len(), 7);
        assert_eq!(components_for_profile("agent").unwrap().len(), 7);
        assert!(components_for_profile("all").is_none());
    }

    #[test]
    fn download_components_ignores_the_retired_crs_name_and_keeps_existing_files() {
        let dir = std::env::temp_dir().join(format!("wafio-fetch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("user-agents")).unwrap();
        std::fs::write(dir.join("user-agents/bot.txt"), "^x.*\n").unwrap();
        let mut c = fetch_options(&["crs", "ua", "ja4"]);
        c.dir = dir.to_string_lossy().into_owned();
        let r = download_components(&c);
        assert_eq!(
            r.iter().map(|r| r.component.as_str()).collect::<Vec<_>>(),
            vec!["ja4", "ua"]
        );
        assert!(r.iter().all(|r| r.error.is_none()), "{r:?}");
        let ja4 = std::fs::read_to_string(dir.join("ja4/ja4.txt")).unwrap();
        assert!(ja4.starts_with("# WAFio Default JA4 TLS Blocklist"));
        assert!(
            !dir.join("crs").exists(),
            "a retired component name downloads nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn text_helpers() {
        assert_eq!(escape_regex_meta(r"a.b*c\ (x)"), r"a\.b\*c\\ \(x\)");
        assert_eq!(format_thousands(999), "999");
        assert_eq!(format_thousands(1234567), "1,234,567");
        assert_eq!(format_byte_size(1536), "1.5 KB");
        assert_eq!(format_byte_size(10), "10 B");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn tar_extract_finds_the_mmdb() {
        let mut tar = Vec::new();
        for (name, data) in [
            ("GeoLite2-City_1/README.txt", &b"readme"[..]),
            ("GeoLite2-City_1/GeoLite2-City.mmdb", &b"MMDB-DATA"[..]),
        ] {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            let size = format!("{:011o}\0", data.len());
            h[124..136].copy_from_slice(size.as_bytes());
            h[156] = b'0';
            tar.extend_from_slice(&h);
            tar.extend_from_slice(data);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.extend_from_slice(&[0u8; 1024]);
        let dst = std::env::temp_dir().join(format!("wafio-tar-{}.mmdb", std::process::id()));
        assert_eq!(
            tar_extract(tar.as_slice(), "GeoLite2-City.mmdb", &dst).unwrap(),
            9
        );
        assert_eq!(std::fs::read(&dst).unwrap(), b"MMDB-DATA");
        assert!(tar_extract(tar.as_slice(), "GeoLite2-ASN.mmdb", &dst).is_err());
        let _ = std::fs::remove_file(&dst);
    }
}
