//! How strongly an engine reports a finding, and the number a decision event carries for it.

use crate::reason::*;

/// What an engine says about one value or one request: nothing, a weak detection (the request goes on and the
/// decision is a LOG line) or a strong one (the decision is a BLOCK).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    #[default]
    Clean,
    Weak,
    Strong,
}

/// The score of every weak detection on the wire.
pub const WEAK_DECISION_SCORE: i64 = 115;

/// The `score` a decision event carries for a finding. Old dashboards and stored rows read it; no verdict does.
/// It is fixed per reason and tier. An engine also uses it to order two findings of one scan of the same tier, so
/// that the same finding is reported on every run.
pub fn decision_score(reason: &str, tier: Tier) -> i64 {
    match tier {
        Tier::Clean => 0,
        Tier::Weak => WEAK_DECISION_SCORE,
        Tier::Strong => match reason {
            REASON_SEMANTIC_CMD | REASON_SEMANTIC_JWT => 200,
            REASON_SEMANTIC_PHP
            | REASON_SEMANTIC_PYTHON
            | REASON_SEMANTIC_JAVA
            | REASON_SEMANTIC_SSTI
            | REASON_SEMANTIC_DESER => 190,
            REASON_SEMANTIC_PROTO_POLLUTION => 185,
            REASON_SEMANTIC_SQL
            | REASON_SEMANTIC_LFI
            | REASON_SEMANTIC_SSRF
            | REASON_SEMANTIC_XXE
            | REASON_SEMANTIC_NOSQL
            | REASON_SEMANTIC_LDAP => 180,
            _ => 150,
        },
    }
}

/// Whether the finding `(tier, reason)` is reported instead of `other`: a stronger tier, or the same tier with a
/// higher decision score for its reason. A tie keeps `other`.
pub fn outranks(this: (Tier, &str), other: (Tier, &str)) -> bool {
    (this.0, decision_score(this.1, this.0)) > (other.0, decision_score(other.1, other.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tier_orders_before_the_reason() {
        assert!(Tier::Strong > Tier::Weak && Tier::Weak > Tier::Clean);
        assert_eq!(decision_score(REASON_SEMANTIC_SQL, Tier::Clean), 0);
        assert_eq!(decision_score(REASON_SEMANTIC_SQL, Tier::Weak), 115);
        assert_eq!(decision_score(REASON_SEMANTIC_SQL, Tier::Strong), 180);
        assert_eq!(decision_score(REASON_SEMANTIC_XSS, Tier::Strong), 150);
        assert_eq!(decision_score(REASON_SEMANTIC_CMD, Tier::Strong), 200);
        assert_eq!(
            decision_score(REASON_SEMANTIC_PROTO_POLLUTION, Tier::Strong),
            185
        );
        assert_eq!(decision_score("", Tier::Strong), 150);
    }
}
