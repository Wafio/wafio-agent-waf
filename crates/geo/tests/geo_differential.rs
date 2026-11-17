//! Differential for crate wafio-geo against a reference dump. Without `GODUMP_GEO` the test
//! does nothing; the database directory is `GEO_DB_DIR` (country.mmdb, city.mmdb, asn.mmdb).

use std::net::IpAddr;

use serde_json::Value;
use wafio_geo::{
    GeoLookup, IpEnricher, MmdbCountryLookup, MmdbEnricher, ReloadableCountryLookup, country_codes,
    english_country_name, is_valid_country_code, open_country_lookup,
};

fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

#[test]
fn reference_differential() {
    let Ok(dump) = std::env::var("GODUMP_GEO") else {
        return;
    };
    let dir = std::env::var("GEO_DB_DIR").expect("GEO_DB_DIR");
    let (country, city, asn) = (
        format!("{dir}/country.mmdb"),
        format!("{dir}/city.mmdb"),
        format!("{dir}/asn.mmdb"),
    );
    let look = MmdbCountryLookup::open(&country).unwrap();
    let enr = MmdbEnricher::open(&city, &asn).unwrap();
    let (mut n, mut bad, mut hits, mut city_hits, mut isp_hits, mut ambiguous) = (0, 0, 0, 0, 0, 0);
    let mut complain = |msg: String| {
        bad += 1;
        if bad <= 15 {
            eprintln!("MISMATCH {msg}");
        }
    };
    for line in std::fs::read_to_string(dump).unwrap().lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        match row["kind"].as_str().unwrap() {
            "ip" => {
                let ip = s(&row, "ip");
                n += 1;
                let (got, err) = match look.country(ip.as_bytes()) {
                    Ok(c) => (String::from_utf8(c).unwrap(), false),
                    Err(_) => (String::new(), true),
                };
                if got != s(&row, "country") || err == s(&row, "country_err").is_empty() {
                    complain(format!(
                        "country({ip:?}): got {got:?} err={err}, want {:?} err={:?}",
                        s(&row, "country"),
                        s(&row, "country_err")
                    ));
                }
                hits += usize::from(!got.is_empty());
                let e = enr.enrich(ip.as_bytes());
                let alts: Vec<String> = row.get("alts").and_then(Value::as_array).map_or_else(
                    || vec![String::new()],
                    |a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect(),
                );
                ambiguous += usize::from(alts.len() > 1);
                city_hits += usize::from(!e.city.is_empty());
                isp_hits += usize::from(!e.isp.is_empty());
                let bits = |k: &str| s(&row, k).parse::<u64>().unwrap_or(0);
                let ok = alts.contains(&e.city)
                    && e.country_iso == s(&row, "iso")
                    && e.lat.to_bits() == bits("lat")
                    && e.lon.to_bits() == bits("lon")
                    && e.isp == s(&row, "isp");
                if !ok {
                    complain(format!(
                        "enrich({ip:?}): got {e:?}, want city in {alts:?} iso={:?} lat={} lon={} isp={:?}",
                        s(&row, "iso"),
                        f64::from_bits(bits("lat")),
                        f64::from_bits(bits("lon")),
                        s(&row, "isp")
                    ));
                }
            }
            "lookup_db" => {
                // A non-country database behind a country lookup: the type gate answers.
                let l = open_country_lookup(&format!("{dir}/{}", s(&row, "ip"))).unwrap();
                let got = l.country(b"8.8.8.8");
                let want_err = s(&row, "country_err");
                match got {
                    Ok(c) => assert!(
                        want_err.is_empty() && c == s(&row, "country").as_bytes(),
                        "{row}"
                    ),
                    Err(e) => assert_eq!(e, want_err),
                }
            }
            "enrich_asn_as_city" => {
                let e = MmdbEnricher::open(&format!("{dir}/asn.mmdb"), "")
                    .unwrap()
                    .enrich(b"8.8.8.8");
                assert_eq!(
                    (
                        e.city.as_str(),
                        e.country_iso.as_str(),
                        e.lat,
                        e.lon,
                        e.isp.as_str()
                    ),
                    ("", "", 0.0, 0.0, "")
                );
                assert_eq!(s(&row, "city") + &s(&row, "iso") + &s(&row, "isp"), "");
            }
            "cidr" => {
                let codes: Vec<String> = row["codes"].as_array().map_or_else(Vec::new, |a| {
                    a.iter().map(|v| v.as_str().unwrap().to_string()).collect()
                });
                let refs: Vec<&str> = codes.iter().map(String::as_str).collect();
                let mut got = Vec::new();
                look.for_each_country_network(&refs, |ip: IpAddr, p| got.push(format!("{ip}/{p}")))
                    .unwrap();
                let want: Vec<String> = row["nets"].as_array().map_or_else(Vec::new, |a| {
                    a.iter().map(|v| v.as_str().unwrap().to_string()).collect()
                });
                n += 1;
                if got != want {
                    let (mut g, mut w) = (got.clone(), want.clone());
                    g.sort();
                    w.sort();
                    complain(format!(
                        "cidr {codes:?}: {} networks vs {} (same set: {})",
                        got.len(),
                        want.len(),
                        g == w
                    ));
                } else {
                    eprintln!("cidr {codes:?}: {} networks identical, in order", got.len());
                }
            }
            "names" => {
                let want: Vec<String> = row["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                let got: Vec<String> = country_codes()
                    .iter()
                    .map(|c| format!("{c}={}", english_country_name(c.as_bytes())))
                    .collect();
                assert_eq!(got, want);
            }
            "names_misc" => {
                for e in row["names"].as_array().unwrap() {
                    let parts: Vec<&str> = e.as_str().unwrap().split('\0').collect();
                    let (name, valid) = (
                        english_country_name(parts[0].as_bytes()),
                        is_valid_country_code(parts[0].as_bytes()),
                    );
                    assert_eq!(
                        (name, valid.to_string().as_str()),
                        (parts[1], parts[2]),
                        "code {:?}",
                        parts[0]
                    );
                }
            }
            k => panic!("unknown row kind {k}"),
        }
    }
    assert_eq!(
        bad, 0,
        "{bad} of {n} geo cases differ from the recorded reference"
    );
    eprintln!(
        "geo reference: {n} cases identical ({hits} country hits, {city_hits} cities, {isp_hits} isps, {ambiguous} with several city names)"
    );
}

/// An empty path (`open_country_lookup("  ")`) and a missing file.
#[test]
fn open_rules() {
    assert_eq!(
        open_country_lookup("  ").unwrap().country(b"8.8.8.8"),
        Ok(Vec::new())
    );
    assert!(open_country_lookup("/nonexistent/country.mmdb").is_err());
    assert!(MmdbEnricher::open("/nonexistent/city.mmdb", "").is_err());
    let e = MmdbEnricher::open("", "").unwrap();
    assert_eq!(e.enrich(b"8.8.8.8"), Default::default());
}

/// Reload and Close with the real database, when `GEO_DB_DIR` is set.
#[test]
fn reload_and_close() {
    let Ok(dir) = std::env::var("GEO_DB_DIR") else {
        return;
    };
    let look = MmdbCountryLookup::open(&format!("{dir}/country.mmdb")).unwrap();
    let before = look.country(b"8.8.8.8").unwrap();
    assert_eq!(before.len(), 2);
    assert!(look.reload("/nonexistent").is_err());
    assert_eq!(
        look.country(b"8.8.8.8").unwrap(),
        before,
        "failed reload keeps the database"
    );
    look.reload(&format!(" {dir}/country.mmdb ")).unwrap();
    assert_eq!(look.country(b"8.8.8.8").unwrap(), before);
    look.reload("").unwrap();
    assert_eq!(look.country(b"8.8.8.8").unwrap(), b"");
    look.reload(&format!("{dir}/country.mmdb")).unwrap();
    look.close();
    assert_eq!(look.country(b"8.8.8.8").unwrap(), b"");
}
