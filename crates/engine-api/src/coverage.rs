//! What the semantic stage could not fully analyze.

use crate::config::SemanticScanResult;

/// The gaps of one request's scan. The engine sets the fields; the agent turns them into the coverage text of
/// the decision and into the uninspected floor.
#[derive(Clone, Debug, Default)]
pub struct ScanCoverage {
    pub truncated: bool,
    pub engine_panic: bool,
    pub budget: bool,
    pub field_cap: bool,
    pub query_cap: bool,
    pub body_skipped: String,
    pub binary_text: bool,
    pub transport: String,
    pub header_count: bool,
    pub header_len: bool,
    pub header_skip: bool,
    pub regex_budget: bool,
    pub body_scan_gap: bool,
    pub other_scan_gap: bool,
    /// No engine is installed, so nothing was inspected. Informational: not a gap, never part of
    /// [`complete`](Self::complete).
    pub engine_absent: bool,
}

impl ScanCoverage {
    pub fn record_part_scan(&mut self, r: &SemanticScanResult, body: bool) {
        self.merge_scan(r);
        if r.truncated || r.engine_panicked || r.budget_exhausted {
            if body {
                self.body_scan_gap = true;
            } else {
                self.other_scan_gap = true;
            }
        }
    }

    pub fn body_uninspected(&self) -> bool {
        self.body_scan_gap
            || self.field_cap
            || !self.body_skipped.is_empty()
            || self.binary_text
            || !self.transport.is_empty()
    }

    pub fn other_uninspected(&self) -> bool {
        self.other_scan_gap
            || self.query_cap
            || self.header_count
            || self.header_len
            || self.header_skip
            || self.regex_budget
    }

    pub fn complete(&self) -> bool {
        !self.truncated
            && !self.engine_panic
            && !self.budget
            && !self.field_cap
            && !self.query_cap
            && self.body_skipped.is_empty()
            && !self.binary_text
            && self.transport.is_empty()
            && !self.header_count
            && !self.header_len
            && !self.header_skip
            && !self.regex_budget
    }

    pub fn merge_scan(&mut self, r: &SemanticScanResult) {
        self.truncated |= r.truncated;
        self.engine_panic |= r.engine_panicked;
        self.budget |= r.budget_exhausted;
    }
}
