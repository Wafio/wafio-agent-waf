//! The observer chain a bundle goes through.
//!
//! The bundle JSON is opaque here: the agent's [`BundleSink`] decodes and applies it. The link
//! reads only the top-level fields the delivery path needs, matching keys the way the bundle
//! decoder does ([`BundleProbe`]).

use crate::json_members;

/// Why a bundle was not applied. A bundle that does not decode is never retried; one the
/// observer refused is retried unless it is a management command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    /// The bundle did not decode.
    #[error("{0}")]
    Decode(String),
    /// The observer (the inline proxy) returned an error.
    #[error("{0}")]
    Apply(String),
    /// An address the bundle names could not be bound, most likely because another program still
    /// holds it. Retried every minute, without an attempt limit, until it binds or a newer bundle
    /// arrives.
    #[error("{0}")]
    Bind(String),
}

/// The inline proxy side: decodes and applies a bundle.
/// Called on a blocking thread, one call at a time per stream.
pub trait BundleSink: Send + Sync + 'static {
    /// Decode `bundle_json` and apply it. `generation` is the one in force: the message's
    /// `BundleUpdate.generation` when non-zero, else the embedded one (the bundle's generation is
    /// set before the observer runs). Management-only bundles (unblock commands) come through
    /// here too.
    fn apply(&self, bundle_json: &[u8], generation: i64) -> Result<(), BundleError>;

    /// Full decode check of a cached bundle before it counts as usable. Default: accept.
    fn check(&self, _bundle_json: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

/// The name of the type a bundle decodes into, as its decode errors print it.
const BUNDLE_TYPE: &str = "agent.Bundle";

/// The bundle fields the delivery path reads.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BundleProbe {
    pub generation: i64,
    pub management_only: bool,
    pub unblock_entries: usize,
    pub apps: usize,
}

impl BundleProbe {
    /// Decode the probed fields; a syntax error or a type error in one of them is a decode error
    /// with the decoder's text. Type errors in the fields it does not read (and inside the app
    /// elements) are the sink's.
    pub fn parse(json: &[u8]) -> Result<Self, String> {
        let mut p = BundleProbe::default();
        for (k, v) in json_members::members(json, BUNDLE_TYPE)? {
            if json_members::key_matches(&k, "generation") {
                if let Some(g) = json_members::int64(v, "Bundle", "generation", "int64")? {
                    p.generation = g;
                }
            } else if json_members::key_matches(&k, "management_only") {
                if let Some(b) = json_members::boolean(v, "Bundle", "management_only")? {
                    p.management_only = b;
                }
            } else if json_members::key_matches(&k, "unblock_entries") {
                p.unblock_entries = json_members::struct_slice_len(
                    v,
                    "Bundle",
                    "unblock_entries",
                    "[]agent.UnblockEntry",
                    "agent.UnblockEntry",
                )?;
            } else if json_members::key_matches(&k, "apps") {
                p.apps = json_members::struct_slice_len(
                    v,
                    "Bundle",
                    "apps",
                    "[]agent.BundleApp",
                    "agent.BundleApp",
                )?;
            }
        }
        Ok(p)
    }

    /// The bundle JSON with its top-level generation set to `generation` (members kept in
    /// order and verbatim). The cache stores the bundle with its generation overridden, and
    /// reading the cache requires the embedded generation to equal the envelope's.
    pub(crate) fn with_generation(json: &[u8], generation: i64) -> Result<Vec<u8>, String> {
        if Self::parse(json)?.generation == generation {
            return Ok(json.to_vec());
        }
        let mut out = Vec::with_capacity(json.len() + 24);
        out.push(b'{');
        for (k, v) in json_members::members(json, BUNDLE_TYPE)? {
            if json_members::key_matches(&k, "generation") {
                continue;
            }
            out.extend_from_slice(
                serde_json::to_string(&k)
                    .map_err(|e| e.to_string())?
                    .as_bytes(),
            );
            out.push(b':');
            out.extend_from_slice(v.get().as_bytes());
            out.push(b',');
        }
        out.extend_from_slice(format!("\"generation\":{generation}}}").as_bytes());
        Ok(out)
    }
}

/// Decodes only `management_only`, so any decode error is "no".
pub(crate) fn is_management_only(json: &[u8]) -> bool {
    let Ok(members) = json_members::members(json, BUNDLE_TYPE) else {
        return false;
    };
    let mut m = false;
    for (k, v) in members {
        if json_members::key_matches(&k, "management_only") {
            match json_members::boolean(v, "", "management_only") {
                Ok(Some(b)) => m = b,
                Ok(None) => {}
                Err(_) => return false,
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reads_wire_fields() {
        let p = BundleProbe::parse(
            br#"{"agent_id":"a","Generation":3,"apps":[{"app_id":"x"},null],"management_only":false,"unblock_entries":null}"#,
        )
        .unwrap();
        assert_eq!(
            p,
            BundleProbe {
                generation: 3,
                management_only: false,
                unblock_entries: 0,
                apps: 2
            }
        );
        assert!(BundleProbe::parse(br#"{"generation":"3"}"#).is_err());
        assert!(BundleProbe::parse(br#"{"apps":[1]}"#).is_err());
        assert!(BundleProbe::parse(b"[1,2,3]").is_err());
        assert_eq!(BundleProbe::parse(b"null").unwrap(), BundleProbe::default());
        // Unknown fields of any type are ignored.
        assert!(BundleProbe::parse(br#"{"rules_json":[1],"x":"y"}"#).is_ok());
    }

    #[test]
    fn management_probe_ignores_other_fields() {
        assert!(is_management_only(
            br#"{"management_only":true,"generation":"x"}"#
        ));
        assert!(!is_management_only(br#"{"management_only":"yes"}"#));
        assert!(!is_management_only(b"not json"));
        assert!(!is_management_only(br#"{"apps":[]}"#));
    }

    #[test]
    fn with_generation_patches_only_when_needed() {
        let raw = br#"{ "generation": 4, "apps": [] }"#;
        assert_eq!(BundleProbe::with_generation(raw, 4).unwrap(), raw.to_vec());
        let out = BundleProbe::with_generation(
            br#"{"generation":4,"apps":[],"GENERATION":5,"x":"\u00e9"}"#,
            9,
        )
        .unwrap();
        assert_eq!(out, br#"{"apps":[],"x":"\u00e9","generation":9}"#.to_vec());
        assert_eq!(BundleProbe::parse(&out).unwrap().generation, 9);
        assert_eq!(
            BundleProbe::with_generation(b"{}", 2).unwrap(),
            br#"{"generation":2}"#.to_vec()
        );
    }
}
