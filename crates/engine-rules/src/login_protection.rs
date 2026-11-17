//! Login scopes and per-path limit resolution.

use crate::config::{
    PathExceptionConfig, PathReading, exception_matches_path_folded, first_exception_on_reading,
    request_path_readings,
};
use crate::forwarded_path::RequestPathReadings;

pub fn login_scope_key(project_id: &str, pattern: &str) -> String {
    format!("login:{project_id}:{pattern}")
}

/// PathLimits: indices into the exceptions slice.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathLimits {
    pub body_size: Option<usize>,
    pub rate_limit: Vec<usize>,
    pub login: Vec<usize>,
}

/// Returns (governing exception, per-path limits), as indices.
pub fn find_path_rules_for_request(
    rp: &RequestPathReadings,
    exceptions: &[PathExceptionConfig],
) -> (Option<usize>, PathLimits) {
    if exceptions.is_empty() {
        return (None, PathLimits::default());
    }
    let readings = request_path_readings(rp);
    let matched = first_exception_on_reading(rp, &readings, exceptions, false);
    let mut limits = PathLimits::default();
    for r in &readings {
        let (mut rl, mut bs): (Option<usize>, Option<usize>) = (None, None);
        for (i, exc) in exceptions.iter().enumerate() {
            let want_rl = rl.is_none() && exc.rate_limit.is_some();
            let want_bs = bs.is_none() && exc.body_size_limit > 0;
            if exc.disabled
                || (!want_rl && !want_bs)
                || !exception_matches_path_folded(
                    &r.path,
                    &r.folded,
                    exc,
                    exc.limit_matches_case_insensitively(),
                )
            {
                continue;
            }
            if want_rl {
                rl = Some(i);
            }
            if want_bs {
                bs = Some(i);
            }
        }
        if let Some(rl) = rl
            && !limits.rate_limit.contains(&rl)
        {
            limits.rate_limit.push(rl);
        }
        if let Some(bs) = bs
            && limits
                .body_size
                .is_none_or(|cur| exceptions[bs].body_size_limit < exceptions[cur].body_size_limit)
        {
            limits.body_size = Some(bs);
        }
    }
    for (i, exc) in exceptions.iter().enumerate() {
        if !exc.disabled
            && exc.login_protection.as_ref().is_some_and(|l| l.enabled)
            && limit_matches_reading(exc, &readings)
        {
            limits.login.push(i);
        }
    }
    (matched, limits)
}

fn limit_matches_reading(e: &PathExceptionConfig, readings: &[PathReading]) -> bool {
    let fold = e.limit_matches_case_insensitively();
    readings
        .iter()
        .any(|r| exception_matches_path_folded(&r.path, &r.folded, e, fold))
}
