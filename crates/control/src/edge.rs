//! The edge side of the link: the status of the edge parts of each app (redirects, compression)
//! and the answer to a cache purge. The agent supplies the sink.

use wafio_proto::v1::{CachePurge, EdgeStatus};

/// Why a purge was not done. `as_str` is the whole `CommandAck.error` of a refusal, a fixed code
/// and never free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeCode {
    /// The app is not in the agent's bundle.
    NotInBundle,
    /// The app has no cache.
    CacheOff,
    /// The scope or the address is not one the agent accepts.
    Invalid,
    /// Try again later.
    Busy,
}

impl PurgeCode {
    pub fn as_str(self) -> &'static str {
        match self {
            PurgeCode::NotInBundle => "not_in_bundle",
            PurgeCode::CacheOff => "cache_off",
            PurgeCode::Invalid => "invalid",
            PurgeCode::Busy => "busy",
        }
    }
}

/// What the agent says of its apps' edge parts, and how it purges.
///
/// Both methods run on a blocking thread. The link calls `statuses` after each live bundle, when
/// a stream comes up and every minute while one is up; it sends what comes back as it is.
pub trait EdgeSink: Send + Sync + 'static {
    /// One status for each app of the bundle in force that has an edge part on, with the counters
    /// as of now.
    fn statuses(&self) -> Vec<EdgeStatus>;

    /// Removes the stored answers `purge` names.
    fn purge(&self, purge: &CachePurge) -> Result<(), PurgeCode>;
}

/// A sink for an agent with no edge part: no status, and every purge is for an app with no cache.
pub struct NoEdge;

impl EdgeSink for NoEdge {
    fn statuses(&self) -> Vec<EdgeStatus> {
        Vec::new()
    }

    fn purge(&self, _: &CachePurge) -> Result<(), PurgeCode> {
        Err(PurgeCode::CacheOff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The string of the contract for each code. The match is exhaustive, so a new code does not
    /// compile here until it has one; add it to `ALL` too.
    fn contract(code: PurgeCode) -> &'static str {
        match code {
            PurgeCode::NotInBundle => "not_in_bundle",
            PurgeCode::CacheOff => "cache_off",
            PurgeCode::Invalid => "invalid",
            PurgeCode::Busy => "busy",
        }
    }

    const ALL: [PurgeCode; 4] = [
        PurgeCode::NotInBundle,
        PurgeCode::CacheOff,
        PurgeCode::Invalid,
        PurgeCode::Busy,
    ];

    #[test]
    fn every_code_is_the_string_of_the_contract() {
        for code in ALL {
            assert_eq!(code.as_str(), contract(code));
        }
    }

    #[test]
    fn no_edge_says_nothing_and_refuses_every_purge() {
        assert!(NoEdge.statuses().is_empty());
        assert_eq!(
            NoEdge.purge(&CachePurge::default()),
            Err(PurgeCode::CacheOff)
        );
    }
}
