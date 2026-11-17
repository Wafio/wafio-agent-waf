//! The MaxMind database reader layer: database type check at open, the per-method
//! type gate and the lookup rules (an IPv4-mapped IPv6 address is looked up as IPv4, IPv6 in
//! an IPv4-only database is an error).

use std::net::IpAddr;

use serde::Deserialize;
use wafio_application::geo::to_ipv4;

type Source = Vec<u8>;

const IS_ANONYMOUS_IP: u32 = 1;
const IS_ASN: u32 = 1 << 1;
const IS_CITY: u32 = 1 << 2;
const IS_CONNECTION_TYPE: u32 = 1 << 3;
const IS_COUNTRY: u32 = 1 << 4;
const IS_DOMAIN: u32 = 1 << 5;
const IS_ENTERPRISE: u32 = 1 << 6;
const IS_ISP: u32 = 1 << 7;

/// The lookups a database type supports; unknown types do not open.
fn db_type(database_type: &str) -> Result<u32, String> {
    Ok(match database_type {
        "GeoIP2-Anonymous-IP" => IS_ANONYMOUS_IP,
        "DBIP-ASN-Lite (compat=GeoLite2-ASN)" | "GeoLite2-ASN" => IS_ASN,
        // City lookups on Country databases are allowed for back compat.
        "DBIP-City-Lite"
        | "DBIP-Country-Lite"
        | "DBIP-Country"
        | "DBIP-Location (compat=City)"
        | "GeoLite2-City"
        | "GeoIP-City-Redacted-US"
        | "GeoIP2-City"
        | "GeoIP2-City-Africa"
        | "GeoIP2-City-Asia-Pacific"
        | "GeoIP2-City-Europe"
        | "GeoIP2-City-North-America"
        | "GeoIP2-City-South-America"
        | "GeoIP2-Precision-City"
        | "GeoLite2-Country"
        | "GeoIP2-Country" => IS_CITY | IS_COUNTRY,
        "GeoIP2-Connection-Type" => IS_CONNECTION_TYPE,
        "GeoIP2-Domain" => IS_DOMAIN,
        "DBIP-ISP (compat=Enterprise)"
        | "DBIP-Location-ISP (compat=Enterprise)"
        | "GeoIP-Enterprise-Redacted-US"
        | "GeoIP2-Enterprise" => IS_ENTERPRISE | IS_CITY | IS_COUNTRY,
        "GeoIP2-ISP" | "GeoIP2-Precision-ISP" => IS_ISP | IS_ASN,
        other => {
            return Err(format!(
                "geoip2: reader does not support the {other:?} database type"
            ));
        }
    })
}

/// An open database and the lookups its type supports.
pub(crate) struct Reader {
    db: maxminddb::Reader<Source>,
    kind: u32,
}

/// The `Country` fields this crate reads (`country.iso_code`).
#[derive(Deserialize, Default)]
pub(crate) struct CountryRecord {
    #[serde(default)]
    pub country: IsoCountry,
}

#[derive(Deserialize, Default)]
pub(crate) struct IsoCountry {
    #[serde(default)]
    pub iso_code: String,
}

#[derive(Deserialize, Default)]
pub(crate) struct Named {
    #[serde(default)]
    pub names: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
pub(crate) struct Location {
    #[serde(default)]
    pub latitude: f64,
    #[serde(default)]
    pub longitude: f64,
}

/// The `City` fields this crate reads.
#[derive(Deserialize, Default)]
pub(crate) struct CityRecord {
    #[serde(default)]
    pub country: IsoCountry,
    #[serde(default)]
    pub city: Named,
    #[serde(default)]
    pub subdivisions: Vec<Named>,
    #[serde(default)]
    pub location: Location,
}

/// The `ASN` fields this crate reads.
#[derive(Deserialize, Default)]
pub(crate) struct AsnRecord {
    #[serde(default)]
    pub autonomous_system_organization: String,
}

impl Reader {
    pub(crate) fn open(path: &str) -> Result<Reader, String> {
        let db = maxminddb::Reader::open_readfile(path).map_err(|e| e.to_string())?;
        let kind = db_type(&db.metadata().database_type)?;
        Ok(Reader { db, kind })
    }

    pub(crate) fn database_type(&self) -> &str {
        &self.db.metadata().database_type
    }

    pub(crate) fn raw(&self) -> &maxminddb::Reader<Source> {
        &self.db
    }

    /// Looks up `ip` behind the method gate: a missing record
    /// leaves `T::default()`.
    fn lookup<T: for<'a> Deserialize<'a> + Default>(
        &self,
        method: &str,
        gate: u32,
        ip: &IpAddr,
    ) -> Result<T, String> {
        if self.kind & gate == 0 {
            return Err(format!(
                "geoip2: the {method} method does not support the {} database",
                self.database_type()
            ));
        }
        let ip = match to_ipv4(ip) {
            Some(v4) => IpAddr::V4(v4),
            None => *ip,
        };
        if ip.is_ipv6() && self.db.metadata().ip_version == 4 {
            return Err(format!(
                "error looking up '{ip}': you attempted to look up an IPv6 address in an IPv4-only database"
            ));
        }
        let result = self.db.lookup(ip).map_err(|e| e.to_string())?;
        Ok(result
            .decode::<T>()
            .map_err(|e| e.to_string())?
            .unwrap_or_default())
    }

    /// `Reader.Country`.
    pub(crate) fn country(&self, ip: &IpAddr) -> Result<CountryRecord, String> {
        self.lookup("Country", IS_COUNTRY, ip)
    }

    /// `Reader.City`.
    pub(crate) fn city(&self, ip: &IpAddr) -> Result<CityRecord, String> {
        self.lookup("City", IS_CITY, ip)
    }

    /// `Reader.ASN`.
    pub(crate) fn asn(&self, ip: &IpAddr) -> Result<AsnRecord, String> {
        self.lookup("ASN", IS_ASN, ip)
    }
}
