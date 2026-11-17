//! MaxMind country lookup (`GeoLookup`), city/ASN enrichment and
//! the country name table the WAF agent and the analyze pipeline use.
//! The IP matching helpers (`parse_client_ip`, `ip_in_list`, `DisabledGeoLookup`)
//! live in `wafio_application::geo`, where the pipeline already calls them.

// This crate has no `unsafe`; a new site needs `#[allow(unsafe_code)]` and its reason.
#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod countrynames;
mod enricher;
mod maxmind;
mod reader;

pub use countrynames::{
    country_code_names, country_codes, english_country_name, is_valid_country_code,
};
pub use enricher::{DisabledEnricher, Enrichment, IpEnricher, MmdbEnricher, ReloadableIpEnricher};
pub use maxmind::{MmdbCountryLookup, ReloadableCountryLookup, open_country_lookup};
pub use wafio_application::geo::{DisabledGeoLookup, GeoLookup, ip_in_list, parse_client_ip};
