//! The MaxMind `GeoLookup` (country by IP) with hot reload.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use maxminddb::WithinOptions;
use wafio_application::geo::{DisabledGeoLookup, GeoLookup, parse_ip};
use wafio_bytetext::strings::{to_uppercase, trim_whitespace};

use crate::reader::{CountryRecord, Reader};

/// A lookup that swaps its database without a restart.
pub trait ReloadableCountryLookup: GeoLookup {
    fn reload(&self, path: &str) -> Result<(), String>;
}

struct State {
    db: Option<Reader>,
    path: String,
}

/// A GeoLite2/GeoIP2/DB-IP country (or city) `.mmdb`.
pub struct MmdbCountryLookup {
    state: RwLock<State>,
}

fn trim_path(path: &str) -> String {
    String::from_utf8_lossy(trim_whitespace(path.as_bytes())).into_owned()
}

/// `DisabledGeoLookup` for an empty path, else the opened database.
pub fn open_country_lookup(path: &str) -> Result<Arc<dyn GeoLookup>, String> {
    let path = trim_path(path);
    if path.is_empty() {
        return Ok(Arc::new(DisabledGeoLookup));
    }
    Ok(Arc::new(MmdbCountryLookup::open(&path)?))
}

impl MmdbCountryLookup {
    /// Opens `path` (not trimmed, not empty).
    pub fn open(path: &str) -> Result<MmdbCountryLookup, String> {
        let db = Reader::open(path)?;
        Ok(MmdbCountryLookup {
            state: RwLock::new(State {
                db: Some(db),
                path: path.to_string(),
            }),
        })
    }

    /// Drops the database; every lookup answers "" afterwards.
    pub fn close(&self) {
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        st.db = None;
        st.path.clear();
    }

    /// Calls `f(network address, prefix length)` for every network of
    /// the database that belongs to one of `codes` (case-insensitive), IPv4 networks as IPv4.
    /// Used to pre-fill the eBPF LPM trie. Iterates the open reader instead of
    /// opening the file a second time.
    pub fn for_each_country_network(
        &self,
        codes: &[&str],
        mut f: impl FnMut(IpAddr, u8),
    ) -> Result<(), String> {
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());
        if st.path.is_empty() {
            return Ok(());
        }
        let Some(db) = &st.db else { return Ok(()) };
        let wanted: Vec<Vec<u8>> = codes.iter().map(|c| to_uppercase(c.as_bytes())).collect();
        for item in db
            .raw()
            .networks(WithinOptions::default())
            .map_err(|e| e.to_string())?
        {
            let lookup = item.map_err(|e| e.to_string())?;
            let Ok(Some(rec)) = lookup.decode::<CountryRecord>() else {
                continue;
            };
            if !wanted.contains(&to_uppercase(rec.country.iso_code.as_bytes())) {
                continue;
            }
            let Ok(net) = lookup.network() else { continue };
            f(net.ip(), net.prefix());
        }
        Ok(())
    }
}

impl GeoLookup for MmdbCountryLookup {
    /// The upper-case ISO 3166-1 alpha-2 code of `ip`, "" if unknown, private or
    /// not an IP address.
    fn country(&self, ip: &[u8]) -> Result<Vec<u8>, String> {
        let Some(parsed) = parse_ip(ip) else {
            return Ok(Vec::new());
        };
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());
        let Some(db) = &st.db else {
            return Ok(Vec::new());
        };
        let record = db.country(&parsed)?;
        Ok(to_uppercase(record.country.iso_code.as_bytes()))
    }
}

impl ReloadableCountryLookup for MmdbCountryLookup {
    /// Atomically swaps the database; an empty path leaves the lookup answering "".
    fn reload(&self, path: &str) -> Result<(), String> {
        let path = trim_path(path);
        let next = if path.is_empty() {
            None
        } else {
            Some(Reader::open(&path)?)
        };
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        st.db = next;
        st.path = path;
        Ok(())
    }
}
