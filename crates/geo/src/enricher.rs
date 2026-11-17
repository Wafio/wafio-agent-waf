//! City, country, coordinates and ISP of an IP from a city database and an optional ASN
//! database.

use std::net::IpAddr;
use std::sync::RwLock;

use wafio_application::geo::parse_ip;
use wafio_bytetext::strings::trim_whitespace;

use crate::reader::{CityRecord, Named, Reader};

/// What `IpEnricher::enrich` returns: city, country, coordinates and ISP.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Enrichment {
    pub city: String,
    pub country_iso: String,
    pub lat: f64,
    pub lon: f64,
    pub isp: String,
}

/// All methods are safe for concurrent use.
pub trait IpEnricher: Send + Sync {
    fn enrich(&self, ip: &[u8]) -> Enrichment;
}

pub trait ReloadableIpEnricher: IpEnricher {
    fn reload(&self, city_path: &str, asn_path: &str) -> Result<(), String>;
}

/// Empty enrichment.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledEnricher;

impl IpEnricher for DisabledEnricher {
    fn enrich(&self, _ip: &[u8]) -> Enrichment {
        Enrichment::default()
    }
}

#[derive(Default)]
struct Dbs {
    city: Option<Reader>,
    asn: Option<Reader>,
}

/// GeoLite2-City (or GeoIP2-City, DB-IP City Lite) for city/lat/lon and
/// an optional ASN database for the ISP.
pub struct MmdbEnricher {
    dbs: RwLock<Dbs>,
}

fn trimmed(path: &str) -> String {
    String::from_utf8_lossy(trim_whitespace(path.as_bytes())).into_owned()
}

fn open_pair(city_path: &str, asn_path: &str) -> Result<Dbs, String> {
    let (city_path, asn_path) = (trimmed(city_path), trimmed(asn_path));
    let city = if city_path.is_empty() {
        None
    } else {
        Some(Reader::open(&city_path)?)
    };
    let asn = if asn_path.is_empty() {
        None
    } else {
        Some(Reader::open(&asn_path)?)
    };
    Ok(Dbs { city, asn })
}

/// The name of a `Names` map: "en" when non-empty, else a non-empty value of the map. The
/// fallback takes the first by key.
fn pick_name(n: &Named) -> String {
    match n.names.get("en") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => n
            .names
            .values()
            .find(|v| !v.is_empty())
            .cloned()
            .unwrap_or_default(),
    }
}

fn enrich_city(rec: &CityRecord, out: &mut Enrichment) {
    out.country_iso = rec.country.iso_code.clone();
    out.city = pick_name(&rec.city);
    // Many IPs have only a region/province, not a city: use the first subdivision as fallback.
    if out.city.is_empty()
        && let Some(sub) = rec.subdivisions.first()
    {
        out.city = pick_name(sub);
    }
    out.lat = rec.location.latitude;
    out.lon = rec.location.longitude;
}

impl IpEnricher for MmdbEnricher {
    fn enrich(&self, ip: &[u8]) -> Enrichment {
        let Some(parsed) = parse_ip(ip) else {
            return Enrichment::default();
        };
        self.enrich_ip(&parsed)
    }
}

impl MmdbEnricher {
    /// Opens the city and ASN databases; an empty path skips that database.
    pub fn open(city_path: &str, asn_path: &str) -> Result<Self, String> {
        Ok(Self {
            dbs: RwLock::new(open_pair(city_path, asn_path)?),
        })
    }

    fn enrich_ip(&self, ip: &IpAddr) -> Enrichment {
        let dbs = self.dbs.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Enrichment::default();
        if let Some(Ok(rec)) = dbs.city.as_ref().map(|db| db.city(ip)) {
            enrich_city(&rec, &mut out);
        }
        if let Some(Ok(rec)) = dbs.asn.as_ref().map(|db| db.asn(ip))
            && !rec.autonomous_system_organization.is_empty()
        {
            out.isp = rec.autonomous_system_organization;
        }
        out
    }

    /// Releases both databases; `enrich` answers empty afterwards.
    pub fn close(&self) {
        *self.dbs.write().unwrap_or_else(|e| e.into_inner()) = Dbs::default();
    }
}

impl ReloadableIpEnricher for MmdbEnricher {
    /// Opens both files first, then swaps them in together.
    fn reload(&self, city_path: &str, asn_path: &str) -> Result<(), String> {
        let next = open_pair(city_path, asn_path)?;
        *self.dbs.write().unwrap_or_else(|e| e.into_inner()) = next;
        Ok(())
    }
}
