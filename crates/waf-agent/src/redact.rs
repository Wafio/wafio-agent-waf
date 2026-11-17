//! The control link's `redact` hook, run on every decision before it is queued.

use wafio_control::DecisionEvent;
use wafio_domain::{
    BODY_PREVIEW_LIMIT, DecisionHeaders, REQUEST_BODY_CAPTURE_LIMIT, decision_evidence,
    is_body_copy_complete, redact_stored_body_copy, redact_stored_headers, redact_stored_query,
    redact_stored_uri,
};

/// Credentials become "[redacted]" in the headers, the query string, the URI, the body
/// preview and the request body, except the input an exact match source names.
pub fn mask_decision_event(ev: &mut DecisionEvent) {
    let cats: Vec<String> = ev
        .categories
        .iter()
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    let mut m = decision_evidence(&ev.match_source, ev.match_source_exact, &cats);
    if ev.match_source_exact {
        // A secret-named input of the exact source keeps its value only when it holds the
        // flagged value (a same-named field elsewhere is redacted).
        m.flagged = ev.match_value.clone();
    }
    ev.match_value = None;
    let headers: DecisionHeaders = std::mem::take(&mut ev.request_headers)
        .into_iter()
        .collect();
    ev.request_headers = redact_stored_headers(headers, &m)
        .map(|h| h.into_iter().collect())
        .unwrap_or_default();
    ev.query_params = redact_stored_query(&ev.query_params, &m);
    ev.uri = redact_stored_uri(&ev.uri, &m);
    let preview_complete =
        is_body_copy_complete(&ev.body_preview, ev.body_size, BODY_PREVIEW_LIMIT as i64);
    ev.body_preview =
        redact_stored_body_copy(&ev.body_preview, &ev.content_type, &m, preview_complete);
    let body_complete = is_body_copy_complete(
        &ev.request_body,
        ev.body_size,
        REQUEST_BODY_CAPTURE_LIMIT as i64,
    );
    ev.request_body =
        redact_stored_body_copy(&ev.request_body, &ev.content_type, &m, body_complete);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_leave_redacted() {
        let mut ev = DecisionEvent {
            uri: b"/login?password=hunter2&q=1".to_vec(),
            query_params: b"password=hunter2&q=1".to_vec(),
            match_source: b"query:q".to_vec(),
            match_value: Some(b"1".to_vec()),
            ..Default::default()
        };
        ev.request_headers
            .insert(b"Authorization".to_vec(), b"Bearer abc.def.ghi".to_vec());
        ev.request_headers
            .insert(b"Accept".to_vec(), b"*/*".to_vec());
        mask_decision_event(&mut ev);
        assert!(ev.match_value.is_none());
        assert!(!ev.request_headers.contains_key(b"Authorization".as_slice()));
        assert_eq!(
            ev.request_headers
                .get(b"Accept".as_slice())
                .map(Vec::as_slice),
            Some(&b"*/*"[..])
        );
        assert!(!String::from_utf8_lossy(&ev.uri).contains("hunter2"));
        assert!(!String::from_utf8_lossy(&ev.query_params).contains("hunter2"));
    }
}
