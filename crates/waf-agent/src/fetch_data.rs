//! The `fetch-data` subcommand.

use std::time::Instant;

use clap::Args;

use crate::setup;

/// `fetch-data` flags (Go names and defaults).
#[derive(Args, Debug, Clone)]
#[command(
    long_about = "Download all security data required by the WAF agent onto this machine.

Run this command once after deploying the agent binary, and periodically
to refresh the data. No control-plane connection is needed.

Components downloaded:
  geoip    Country/City/ASN databases for geoblocking and geo-enrichment
  firehol  FireHOL IP reputation blocklists (level1 + level2)
  ja4      JA4 TLS bot fingerprints and browser allowlist
  ja3      Salesforce / abuse.ch JA3 TLS fingerprint list (legacy)
  ua       Bad bot user-agent blocklist
  malware  MalwareBazaar SHA-256 feed & webshell Bloom filter / hash database"
)]
pub struct FetchDataFlags {
    /// Directory to store downloaded security data
    #[arg(
        long,
        allow_hyphen_values = true,
        default_value = "/etc/wafio/security-data"
    )]
    pub dir: String,
    /// MaxMind GeoLite2 license key (free at maxmind.com; overrides WAFIO_MAXMIND_LICENSE_KEY env)
    #[arg(
        long = "maxmind-key",
        allow_hyphen_values = true,
        default_value = "",
        hide_default_value = true
    )]
    pub maxmind_key: String,
    /// Re-download even if files already exist
    #[arg(long)]
    pub force: bool,
    /// Comma-separated subset: geoip,geoip-country,geoip-city,geoip-asn,firehol,ja4,ja3,ua,malware,malware-hashes
    #[arg(
        long,
        allow_hyphen_values = true,
        default_value = "",
        hide_default_value = true
    )]
    pub only: String,
    /// Preset component set: "all", "control-plane", "agent" (default: agent)
    #[arg(long, allow_hyphen_values = true, default_value = "agent")]
    pub profile: String,
}

fn say(s: &str) {
    println!("{s}");
}

pub fn run(f: &FetchDataFlags) -> Result<(), String> {
    println!("WAFio Agent — Security Data Fetcher");
    println!("{}", "─".repeat(52));
    let mm_key = if f.maxmind_key.is_empty() {
        std::env::var("WAFIO_MAXMIND_LICENSE_KEY").unwrap_or_default()
    } else {
        f.maxmind_key.clone()
    };
    if mm_key.is_empty() {
        println!("  GeoIP provider : DB-IP (free, no key)");
    } else {
        println!("  GeoIP provider : MaxMind GeoLite2");
    }
    println!("  Output dir     : {}", f.dir);
    println!();
    let mut only: Vec<String> = Vec::new();
    if !f.only.is_empty() {
        only = f
            .only
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
    } else if let Some(list) = setup::components_for_profile(&f.profile) {
        only = list;
        if !f.profile.is_empty() && f.profile != "all" {
            println!("  Profile        : {} → {}\n", f.profile, only.join(", "));
        }
    }
    let auth_key = std::env::var("WAFIO_MALWARE_AUTH_KEY").unwrap_or_default();
    let (only, skipped) = setup::malware_skipped_for_agent(only, !f.only.is_empty(), &auth_key);
    if skipped {
        println!(
            "  Malware        : skipped — the agent receives the malware database from the control plane"
        );
        println!();
    }
    let cfg = setup::FetchOptions {
        dir: f.dir.clone(),
        max_mind_license_key: mm_key,
        force: f.force,
        only,
        log: Some(say),
        ..Default::default()
    };
    let start = Instant::now();
    let results = setup::download_components(&cfg);
    println!("\n{}", "─".repeat(52));
    let failed = results.iter().filter(|r| r.error.is_some()).count();
    let elapsed = format!("{}ms", start.elapsed().as_millis());
    if failed == 0 {
        println!("✅  All security data ready ({elapsed})\n");
        print_start_hint(&f.dir);
        return Ok(());
    }
    println!("⚠️   Completed with {failed} error(s) ({elapsed})");
    for r in &results {
        if let Some(e) = &r.error {
            eprintln!("  ERROR [{}]: {e}", r.component);
        }
    }
    Err(format!("{failed} component(s) failed"))
}

fn print_start_hint(dir: &str) {
    println!("Agent startup flags for this machine:");
    println!("  --geo-country-db     {dir}/geoip/country.mmdb");
    println!("  --geo-city-db        {dir}/geoip/city.mmdb");
    println!("  --geo-asn-db         {dir}/geoip/asn.mmdb");
    println!("  --bot-ua-file        {dir}/user-agents/bot.txt");
    println!("  --bot-ja4-file       {dir}/ja4/ja4.txt");
    println!("  --bot-ja3-file       {dir}/ja3/ja3.txt");
    println!("  --iprep-level1-file  {dir}/firehol/firehol_level1.netset");
    println!("  --iprep-level2-file  {dir}/firehol/firehol_level2.netset");
}
