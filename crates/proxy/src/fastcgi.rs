//! FastCGI routes: the agent-io pool behind the pipeline, and the conversion of its response
//! into an outbound response.

use std::sync::Arc;

use wafio_agent_io::fastcgi_client::FastCgiConnectionPool;
use wafio_domain::Headers;

use crate::response::OutboundResponse;

/// Sends the request through the FastCGI pool and converts the response. `headers` are the
/// client headers, already set.
pub(crate) async fn forward_fcgi(
    pool: &Arc<FastCgiConnectionPool>,
    method: &[u8],
    request_uri: &[u8],
    host: &[u8],
    remote: &str,
    headers: &Headers,
    body: &[u8],
) -> Result<OutboundResponse, String> {
    let lines: Vec<(Vec<u8>, Vec<u8>)> = headers
        .iter()
        .flat_map(|(k, vs)| vs.iter().map(move |v| (k.clone(), v.clone())))
        .collect();
    let resp = pool
        .send_request(method, request_uri, host, remote.as_bytes(), &lines, body)
        .await?;
    // shortcut: a FastCGI status outside 100..=999 (http::StatusCode's range) becomes 502.
    let mut out = OutboundResponse::new(
        u16::try_from(resp.status)
            .ok()
            .filter(|s| (100..=999).contains(s))
            .unwrap_or(502),
    );
    for (k, vs) in resp.headers {
        for v in vs {
            out.add(&k, &v);
        }
    }
    out.body = resp.body;
    Ok(out)
}
