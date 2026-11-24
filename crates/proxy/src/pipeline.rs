//! One request of one app, after the route read its head and the whole body (route.rs; an app in
//! maintenance mode answered at the head and never gets here). Order:
//! challenge verify endpoint, path-encoding reject, IP reputation gate,
//! challenge gate (skipped only for a WebSocket handshake this route takes over), decrypt field
//! rules, body inspection, Analyze, verdict merge, block page / rule challenge / monitor, then
//! WebSocket takeover, main host redirect, the app's folder of static files, FastCGI or HTTP
//! upstream. Detection runs via `run_detection` (16 MiB stack).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use wafio_agent_io::client_ip::{
    effective_client_ip, is_direct_local_client, outgoing_forwarded_for, tcp_peer_address,
};
use wafio_agent_io::fastcgi_client::cgi_header_param;
use wafio_agent_pages::block_response::{render_block_response, status_for_block};
use wafio_agent_pages::challenge::VERIFY_ENDPOINT_PATH;
use wafio_agent_pages::challenge_handler::{
    CaptchaVerifier, ChallengeReason, ChallengeRequest, PageResponse, challenge_if_required,
    process_verify_request, respond_ip_reputation_block,
};
use wafio_agent_pages::challenge_verify_limit::{verify_limited_response, verify_post_allowed};
use wafio_agent_pages::field_paths::{self as fp, RequestFieldRule, ResponseFieldTransformRule};
use wafio_agent_pages::iprep::ReputationLevel;
use wafio_bodyinspect::{
    BODY_KIND_MULTIPART, BODY_KIND_TEXT, Options, decoded_size_cap, inspect, join_note,
    should_attach_notes,
};
use wafio_bytetext::strings::trim_whitespace;
use wafio_domain::ip_address::IpAddress;
use wafio_domain::{AnalysisResult, IncomingRequest};

use crate::cache::{self, Label, Plan};
use crate::compress;
use crate::config::{AppAnalysisSetup, Route, Target};
use crate::decision::{
    AnalysisRequest, DecisionEvent, REQUEST_BODY_CAPTURE_LIMIT, Verdict, canonical_content_type,
    emit_decision_event, emit_upstream_error_event, first_header_value, now_unix,
};
use crate::proxy::Shared;
use crate::redirect::{outside_prefix, upstream_target};
use crate::request::InboundRequest;
use crate::response::OutboundResponse;
use crate::upstream::Forwarded;
use crate::websocket::{Hook, WsPlan, route_accepts_websocket};

/// How a request ended.
pub(crate) enum Done {
    /// The response for the client; the route writes it (keep-alive or close).
    Respond(OutboundResponse),
    /// The head of a response whose body the route relays from the upstream as it arrives.
    Stream(Box<crate::upstream::Streamed>),
    /// A file of the app's static folder that is sent from its open descriptor after the head.
    File(Box<crate::static_files::FileAnswer>),
    /// WebSocket takeover: the session becomes the relay's client stream.
    Upgrade(Box<WsPlan>),
}

/// Reason and category of the verdict for an invalid path encoding.
const BAD_PATH_ENCODING_REASON: &str = "invalid_path_encoding";
const BAD_PATH_ENCODING_CATEGORY: &str = "ProtocolAttack";
/// The verdict `analyze_method` for policy pages.
const POLICY: &str = wafio_domain::ANALYZE_METHOD_POLICY;
const UPSTREAM_UNAVAILABLE: &str = r#"{"error":"upstream unavailable"}"#;

fn request_field_rule_from_engine(r: &wafio_engine_rules::PathFieldRule) -> RequestFieldRule {
    RequestFieldRule {
        field: r.field.clone(),
        source: r.source.clone(),
        action: r.action.clone(),
        cipher_key_hex: r.aes_key.clone(),
        methods: r.methods.clone(),
    }
}

pub(crate) fn response_field_rule_from_engine(
    r: &wafio_engine_rules::ResponseFieldRule,
) -> ResponseFieldTransformRule {
    ResponseFieldTransformRule {
        field: r.field.clone(),
        action: r.action.clone(),
        cipher_key_hex: r.aes_key.clone(),
    }
}

/// The field rules of the first path exception with field rules that matches the forwarded
/// path, for this method.
fn rules_for_request_path(
    exec: &AppAnalysisSetup,
    fwd_path: &[u8],
    method: &[u8],
) -> Vec<RequestFieldRule> {
    let excs = &exec.analyze.path_exceptions;
    if excs.is_empty() {
        return Vec::new();
    }
    let Some(exc) =
        wafio_engine_rules::find_exception_for_forwarded_path_with_field_rules(fwd_path, excs)
    else {
        return Vec::new();
    };
    exc.field_rules
        .iter()
        .filter(|r| fp::allows_method(&r.methods, method))
        .map(request_field_rule_from_engine)
        .collect()
}

/// JA4 and JA3 of the client. The JA4 of a handshake the agent terminated wins; otherwise they
/// come from the headers of a proxy in front. When the agent is the edge of the app, a client
/// could write them itself, so they count only from a peer the route trusts as a proxy.
fn read_client_fingerprints(
    req: &InboundRequest,
    route: &Route,
    peer: &IpAddress,
) -> (Vec<u8>, Vec<u8>) {
    if let Some(ja4) = req.tls.as_ref().and_then(|t| t.ja4.as_ref()) {
        return (ja4.clone().into_bytes(), Vec::new());
    }
    if route.edge && !route.proxy_config.may_supply_forwarded_headers(peer) {
        return (Vec::new(), Vec::new());
    }
    let first = |names: &[&str]| {
        names
            .iter()
            .map(|n| first_header_value(&req.headers, n.as_bytes()))
            .find(|v| !v.is_empty())
            .map_or(Vec::new(), |v| trim_whitespace(v).to_vec())
    };
    (
        first(&["CF-JA4-Hash", "CF-JA4", "X-JA4", "X-JA4-Fingerprint", "JA4"]),
        first(&["CF-JA3-Hash", "X-JA3", "X-JA3-Fingerprint", "JA3"]),
    )
}

/// `scope` is the route's app ID, passed to both the challenge gate and the verify endpoint:
/// every challenge token and cookie is bound to it.
fn challenge_request<'a>(
    req: &'a InboundRequest,
    scope: &'a str,
    local: bool,
    post_body: &'a [u8],
) -> ChallengeRequest<'a> {
    ChallengeRequest {
        scope: scope.as_bytes(),
        path: &req.forward_path,
        request_target: &req.request_target,
        user_agent: &req.user_agent,
        accept: req.peek("Accept"),
        x_requested_with: req.peek("X-Requested-With"),
        sec_ch_ua: req.peek("Sec-CH-UA"),
        accept_language: req.peek("Accept-Language"),
        sec_fetch_mode: req.peek("Sec-Fetch-Mode"),
        sec_fetch_site: req.peek("Sec-Fetch-Site"),
        x_forwarded_proto: req.peek("X-Forwarded-Proto"),
        challenge_cookie: req.cookie(wafio_agent_pages::challenge::CHALLENGE_COOKIE.as_bytes()),
        over_tls: req.tls.is_some(),
        local_socket_client: local,
        submitted_body: post_body,
    }
}

struct NoCaptcha;

impl CaptchaVerifier for NoCaptcha {
    fn submit_form(&self, _url: &str, _body: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// `POST /_wafio/challenge/verify`, on a blocking thread (the CAPTCHA siteverify call
/// blocks).
async fn challenge_verify(
    shared: &Shared,
    exec: Arc<AppAnalysisSetup>,
    app_id: &str,
    req: &InboundRequest,
    body: Vec<u8>,
    peer: &IpAddress,
    remote: &str,
) -> PageResponse {
    let local = is_direct_local_client(peer, remote);
    let (captcha, req, remote, app_id) = (
        shared.captcha.clone(),
        req.clone(),
        remote.to_string(),
        app_id.to_string(),
    );
    tokio::task::spawn_blocking(move || {
        let cap: &dyn CaptchaVerifier = match captcha.as_deref() {
            Some(c) => c,
            None => &NoCaptcha,
        };
        process_verify_request(
            &challenge_request(&req, &app_id, local, &body),
            exec.challenge.as_ref(),
            remote.as_bytes(),
            cap,
            now_unix(),
        )
    })
    .await
    .unwrap_or_else(|_| {
        crate::metrics::count_agent_panic();
        PageResponse {
            status: 500,
            ..Default::default()
        }
    })
}

/// What detection produced: the body variables and the verdict.
struct Detection {
    body: Vec<u8>,
    raw_ct: Vec<u8>,
    ct_cat: String,
    notes: Vec<String>,
    preview: Option<Vec<u8>>,
    verdict: AnalysisResult,
}

/// Body preparation (decrypt rules, body inspection, audit preview) and the analysis (Analyze,
/// latency/coverage metrics, IP jail hook).
fn detect(
    route: &Route,
    req: &InboundRequest,
    mut body: Vec<u8>,
    field_rules: &[RequestFieldRule],
    remote: &str,
    peer: &IpAddress,
) -> Detection {
    let exec = &route.analysis;
    let (mut raw_ct, mut ct_cat) = (Vec::new(), String::new());
    let (mut scan, mut skipped, mut notes, mut preview) =
        (Vec::new(), String::new(), Vec::new(), None);
    if !body.is_empty() {
        raw_ct = req.content_type.clone();
        ct_cat = String::from_utf8_lossy(&canonical_content_type(&raw_ct)).into_owned();
        // decrypt_aes rules before inspection: the WAF sees plaintext.
        if !field_rules.is_empty() {
            let (dec, dec_ct) = fp::transform_request_body(
                &body,
                &raw_ct,
                &ct_cat,
                &fp::filter_decrypt_rules(field_rules),
            );
            if dec_ct != raw_ct {
                raw_ct = dec_ct;
                ct_cat = String::from_utf8_lossy(&canonical_content_type(&raw_ct)).into_owned();
            }
            body = dec;
        }
        let decrypt = fp::filter_decrypt_rules(field_rules);
        let transform =
            |decoded: Vec<u8>| fp::transform_request_body(&decoded, &raw_ct, &ct_cat, &decrypt).0;
        let opt = Options {
            output_limit: decoded_size_cap(route.proxy_config.max_body_bytes),
            transform: (!field_rules.is_empty())
                .then_some(&transform as &dyn Fn(Vec<u8>) -> Vec<u8>),
        };
        let bi = inspect(&body, &raw_ct, &req.headers, &opt);
        let preview_category = if bi.kind == BODY_KIND_TEXT && !bi.sniffed.is_empty() {
            bi.sniffed.to_string()
        } else {
            ct_cat.clone()
        };
        let bi_scan = bi.scan.as_deref().unwrap_or_default();
        if bi.kind == BODY_KIND_MULTIPART {
            let mut p = fp::compose_multipart_preview(&raw_ct, bi_scan, field_rules);
            p.truncate(REQUEST_BODY_CAPTURE_LIMIT);
            preview = Some(p);
        } else if bi.kind == BODY_KIND_TEXT {
            let p = &bi_scan[..bi_scan.len().min(REQUEST_BODY_CAPTURE_LIMIT)];
            preview = Some(if field_rules.is_empty() {
                p.to_vec()
            } else {
                fp::redact_body_preview(p, &preview_category, field_rules)
            });
        }
        scan = bi_scan.to_vec();
        skipped = bi.skipped;
        notes = bi.notes;
    }
    let (ja4, ja3) = read_client_fingerprints(req, route, peer);
    let mut dreq = IncomingRequest {
        method: req.method.clone(),
        uri: req.request_target.clone(),
        forwarded_path: req.forward_path.clone(),
        headers: req.headers.clone(),
        remote_address: remote.as_bytes().to_vec(),
        client_forwarded: remote != peer.to_string(),
        host: req.host.clone(),
        body: scan,
        body_size: body.len() as i64,
        content_type: raw_ct.clone(),
        body_scan_skipped: skipped,
        user_agent: if req.user_agent.is_empty() {
            first_header_value(&req.headers, b"User-Agent").to_vec()
        } else {
            req.user_agent.clone()
        },
        ja4,
        ja3,
        ..Default::default()
    };
    dreq.content_scan_body = Some(body);
    let t = Instant::now();
    let verdict = wafio_application::analyze(&dreq, &exec.analyze);
    // The final verdict is reported once, after every deferred adjustment.
    if let Some(siem) = &exec.siem {
        crate::siem::send_verdict(siem.as_ref(), &dreq, &verdict);
    }
    crate::metrics::ANALYZE_LATENCY_HISTOGRAM.observe(t.elapsed());
    crate::metrics::count_coverage_flags(&verdict.coverage);
    wafio_agent_io::ip_jail::report_block_to_jail(
        exec.jail.as_deref(),
        &verdict.action,
        verdict.coverage_raised,
        dreq.client_forwarded,
        remote,
    );
    Detection {
        body: dreq.content_scan_body.take().unwrap_or_default(),
        raw_ct,
        ct_cat,
        notes,
        preview,
        verdict,
    }
}

/// Appends note `n` to the match `detail`.
fn note(detail: &[u8], n: &[u8]) -> Vec<u8> {
    join_note(detail, n)
}

/// The response, after recording (the route writes it after the handler returns).
fn answer(r: OutboundResponse) -> pingora::Result<Done> {
    Ok(Done::Respond(r))
}

/// One request.
pub(crate) async fn handle(
    shared: &Shared,
    route: &Arc<Route>,
    req: InboundRequest,
    body: Vec<u8>,
    peer_ip: Option<IpAddr>,
) -> pingora::Result<Done> {
    let started = Instant::now();
    let exec = route.analysis.clone();
    let peer = tcp_peer_address(peer_ip);
    let remote = effective_client_ip(&peer, &req.lines, &route.proxy_config);
    let challenge = exec.challenge.as_ref();
    let sink = &shared.decisions;
    let mode = route.mode.as_str();

    // The challenge verify POST is answered before any inspection.
    if req.forward_path == VERIFY_ENDPOINT_PATH.as_bytes() && req.method == b"POST" {
        // Counted per client before any verify work; a route without the challenge answers 404.
        if challenge.is_some_and(|c| c.enabled)
            && !verify_post_allowed(remote.as_bytes(), now_unix())
        {
            return answer(OutboundResponse::from_page(verify_limited_response()));
        }
        let page = challenge_verify(
            shared,
            exec.clone(),
            &route.app_id,
            &req,
            body,
            &peer,
            &remote,
        )
        .await;
        return answer(OutboundResponse::from_page(page));
    }

    let ws = route_accepts_websocket(route, &req);
    let (blocked_method, blocked_source): (Vec<u8>, &[u8]) = if ws {
        (b"WEBSOCKET".to_vec(), b"ws:handshake")
    } else {
        (req.method.clone(), b"")
    };
    let gate_event = |action: &str,
                      categories: &[&str],
                      detail: &[u8],
                      method: &[u8],
                      source: &[u8],
                      status: u16| {
        DecisionEvent {
            app_id: route.app_id.as_bytes().to_vec(),
            host: req.host.clone(),
            method: method.to_vec(),
            uri: req.request_target.clone(),
            remote_addr: remote.as_bytes().to_vec(),
            user_agent: req.user_agent.clone(),
            action: action.as_bytes().to_vec(),
            categories: categories.iter().map(|c| c.as_bytes().to_vec()).collect(),
            match_detail: detail.to_vec(),
            analyze_method: b"challenge_gate".to_vec(),
            match_source: source.to_vec(),
            event_time_unix: now_unix(),
            mode: mode.as_bytes().to_vec(),
            status: i64::from(status),
            ..Default::default()
        }
    };

    // A '%' without two hex digits in the raw path is rejected (block mode).
    let bad_path = route.proxy_config.reject_invalid_path_encoding
        && wafio_engine_rules::contains_invalid_percent_escape(&req.original_path);
    if bad_path && mode == "block" {
        let areq = AnalysisRequest {
            method: blocked_method.clone(),
            uri: req.request_target.clone(),
            host: req.host.clone(),
            remote_address: remote.as_bytes().to_vec(),
            user_agent: req.user_agent.clone(),
            headers: req.headers.clone(),
            body_size: body.len() as i64,
            ..Default::default()
        };
        let br = render_block_response(
            0,
            &[BAD_PATH_ENCODING_CATEGORY.as_bytes()],
            POLICY.as_bytes(),
            BAD_PATH_ENCODING_REASON.as_bytes(),
            b"",
            b"Invalid percent-encoding in request path",
            challenge,
        );
        let source = if blocked_source.is_empty() {
            &b"path"[..]
        } else {
            blocked_source
        };
        let v = Verdict {
            action: "block".into(),
            categories: vec![BAD_PATH_ENCODING_CATEGORY.into()],
            match_detail: BAD_PATH_ENCODING_REASON.into(),
            analyze_method: POLICY.into(),
            match_source: source.to_vec(),
            ..Default::default()
        };
        emit_decision_event(sink, &route.app_id, mode, &areq, &v, started.elapsed(), 400);
        return answer(OutboundResponse::with(400, br.content_type, br.body));
    }

    // IP reputation gate. Hits the gate does not answer are recorded on the request's own
    // decision after analysis.
    let mut force_challenge = false;
    let (mut iprep_would_block, mut iprep_unchallenged) = (Vec::new(), Vec::new());
    if let (Some(iprep), Some(ch)) = (&shared.ip_rep, challenge)
        && ch.ip_rep_enabled
    {
        let (detail, blocks): (&[u8], bool) = match iprep.check(remote.as_bytes()) {
            ReputationLevel::Block => (b"iprep_level1", ch.ip_rep_block_level1),
            ReputationLevel::Challenge => (b"iprep_level2", ch.ip_rep_block_level2),
            ReputationLevel::Clean => (b"", false),
        };
        if detail.is_empty() {
        } else if blocks && mode == "block" {
            let page = respond_ip_reputation_block(Some(ch), peer.to_string().as_bytes());
            sink(gate_event(
                "block",
                &["IPReputation"],
                detail,
                &blocked_method,
                blocked_source,
                page.status,
            ));
            return answer(OutboundResponse::from_page(page));
        } else if blocks {
            iprep_would_block = detail.to_vec();
        } else if mode == "block" && ch.enabled {
            force_challenge = true;
        } else if mode == "block" {
            iprep_unchallenged = note(detail, b"challenge_off");
        } else {
            iprep_unchallenged = note(detail, b"monitor_mode");
        }
    }

    // Bot challenge gate (skipped only for a handshake this route takes over).
    let local = is_direct_local_client(&peer, &remote);
    if !ws
        && let Some(page) = challenge_if_required(
            &challenge_request(&req, &route.app_id, local, b""),
            challenge,
            remote.as_bytes(),
            if force_challenge {
                ChallengeReason::IpReputation
            } else {
                ChallengeReason::BotGate
            },
            shared.good_bots.as_deref(),
            now_unix(),
        )
    {
        let (detail, cats): (&[u8], &[&str]) = if force_challenge {
            (b"iprep_challenge", &["BotChallenge", "IPReputation"])
        } else {
            (b"bot_challenge", &["BotChallenge"])
        };
        sink(gate_event(
            "challenge",
            cats,
            detail,
            &req.method,
            b"",
            page.status,
        ));
        return answer(OutboundResponse::from_page(page));
    }

    let field_rules = rules_for_request_path(&exec, &req.forward_path, &req.method);
    let weight = body.len();
    let body_read = weight > 0;
    let det = crate::run_detection_async(weight, || {
        detect(route, &req, body, &field_rules, &remote, &peer)
    })
    .await;
    let verdict = &det.verdict;
    let mut areq = AnalysisRequest {
        method: req.method.clone(),
        uri: req.request_target.clone(),
        host: req.host.clone(),
        remote_address: remote.as_bytes().to_vec(),
        user_agent: req.user_agent.clone(),
        headers: req.headers.clone(),
        body_size: det.body.len() as i64,
        body_preview_source: det.preview.clone(),
        coverage: crate::decision::event_coverage(verdict),
    };
    let latency = started.elapsed();
    let mut v = Verdict {
        action: verdict.action.clone(),
        score: verdict.score,
        categories: verdict.categories.clone(),
        cwe: verdict.cwe.clone(),
        match_detail: verdict.match_detail.clone(),
        analyze_method: verdict.analyze_method.clone(),
        match_source: verdict.match_source.clone(),
        match_exact: verdict.match_source_exact,
        match_value: verdict.match_value.clone(),
    };
    let mut block_status = verdict.status_code;
    if v.match_detail.is_empty()
        && (verdict.message.starts_with(b"custom_gui_rule:")
            || verdict.message.starts_with(b"custom_script_rule:"))
    {
        v.match_detail = verdict.message.clone();
    }
    if !det.notes.is_empty() && should_attach_notes(&v.action, &v.analyze_method) {
        v.match_detail = note(&v.match_detail, det.notes.join("; ").as_bytes());
    }
    // Monitor mode with an invalid path escape: the would-be rejection, unless the WAF blocks.
    if bad_path && v.action != "block" {
        v = Verdict {
            action: "block".into(),
            categories: vec![BAD_PATH_ENCODING_CATEGORY.into()],
            match_detail: BAD_PATH_ENCODING_REASON.into(),
            analyze_method: POLICY.into(),
            match_source: b"path".to_vec(),
            ..Default::default()
        };
        block_status = 400;
    }
    if !iprep_would_block.is_empty() {
        if v.action == "block" {
            if !v.categories.iter().any(|c| c == "IPReputation") {
                v.categories.push("IPReputation".into());
            }
            v.match_detail = note(&v.match_detail, &iprep_would_block);
        } else {
            v = Verdict {
                action: "block".into(),
                categories: vec!["IPReputation".into()],
                match_detail: iprep_would_block.clone(),
                analyze_method: "challenge_gate".into(),
                match_source: blocked_source.to_vec(),
                ..Default::default()
            };
            block_status = 403;
        }
    }
    if !iprep_unchallenged.is_empty() {
        if v.action == "allow" {
            v = Verdict {
                action: "log".into(),
                categories: vec!["IPReputation".into()],
                match_detail: iprep_unchallenged.clone(),
                analyze_method: "challenge_gate".into(),
                match_source: blocked_source.to_vec(),
                ..Default::default()
            };
        } else {
            if !v.categories.iter().any(|c| c == "IPReputation") {
                v.categories.push("IPReputation".into());
            }
            v.match_detail = note(&v.match_detail, &iprep_unchallenged);
        }
    }
    if v.action == "block" && mode == "block" {
        let cats: Vec<&[u8]> = verdict.categories.iter().map(|c| c.as_bytes()).collect();
        let br = render_block_response(
            verdict.score,
            &cats,
            verdict.analyze_method.as_bytes(),
            &verdict.match_detail,
            verdict.cwe.as_bytes(),
            &verdict.message,
            challenge,
        );
        if !blocked_source.is_empty() {
            // A WebSocket upgrade denied before the relay: identify it as the handshake.
            areq.method = blocked_method;
            v.match_source = blocked_source.to_vec();
            v.match_exact = false;
            v.match_value = None;
        }
        let status = status_for_block(block_status);
        emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, status);
        return answer(OutboundResponse::with(status, br.content_type, br.body));
    }
    // A custom rule's "challenge": served in block mode through the interactive gate, which
    // skips the on_bot_detect trigger for it; otherwise the pipeline's own fallback verdict applies.
    if v.action == "challenge" {
        if mode == "block"
            && let Some(page) = challenge_if_required(
                &challenge_request(&req, &route.app_id, local, b""),
                challenge,
                remote.as_bytes(),
                ChallengeReason::CustomRule,
                shared.good_bots.as_deref(),
                now_unix(),
            )
        {
            emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, page.status);
            return answer(OutboundResponse::from_page(page));
        }
        v.action = if verdict.challenge_fallback == "log" {
            "log".into()
        } else {
            "allow".into()
        };
        if !iprep_unchallenged.is_empty() && v.action == "allow" {
            v.action = "log".into();
        }
    }
    if v.action == "block" && mode == "monitor" {
        v.action = "monitor".into();
    }

    // A path outside the app's path prefix is not the application's: `404`, for a WebSocket
    // handshake too. Forwarded as it came it would reach the application under a path that no rule
    // written for the public one covers (`/admin` for the page that is public at `/shop/admin`).
    if outside_prefix(route, &req) {
        emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, 404);
        return answer(OutboundResponse::error(404, "Not Found"));
    }

    if ws {
        let mut wsv = verdict.clone();
        (wsv.score, wsv.categories, wsv.cwe, wsv.match_detail) = (
            v.score,
            v.categories.clone(),
            v.cwe.clone(),
            v.match_detail.clone(),
        );
        return match crate::websocket::hook(shared, route, &req, &peer, &remote, &v.action, &wsv) {
            Hook::Respond(r) => answer(r),
            Hook::Takeover(plan) => Ok(Done::Upgrade(plan)),
        };
    }

    // Another host name of the app is sent to its main host, after the verdict and the WebSocket
    // takeover: a block is never redirected, and an upgrade request goes upstream untouched.
    if v.action != "block"
        && !req.has_upgrade()
        && let Some(r) = route.main_host.as_ref().and_then(|m| m.answer(&req))
    {
        emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, r.status);
        return answer(r);
    }

    // The response cache, after the verdict: only an `allow` reads or fills it. A fresh copy is
    // the answer, with the response header rules of the app applied as they are to every answer.
    let cache_plan = cache::plan(route, &req, &v.action, body_read, &peer);
    if let Plan::Lookup(ask) = &cache_plan
        && let Some(mut hit) = cache::lookup(shared, route, ask, &req).await
    {
        if matches!(route.target, Target::Http(_)) {
            crate::upstream::apply_response_header_rules(route, &mut hit);
        }
        cache::tag(&mut hit, Label::Hit);
        emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, hit.status);
        return answer(hit);
    }

    // The app's folder of files answers `GET` and `HEAD` for a file it holds, after the verdict
    // like everything that reaches the application. A request that asks for an upgrade is the
    // application's. What the folder sends is not from the cache.
    if let Some(folder) = &route.static_files
        && !req.has_upgrade()
        && let Some(mut done) = crate::static_files::serve(shared, route, folder, &req).await
    {
        let status = match &mut done {
            Done::Respond(r) => {
                if cache_plan.label().is_some() {
                    cache::tag(r, Label::Bypass);
                }
                r.status
            }
            Done::File(f) => {
                if cache_plan.label().is_some() {
                    cache::tag(&mut f.head, Label::Bypass);
                }
                f.head.status
            }
            Done::Stream(s) => s.head.status,
            Done::Upgrade(_) => 101,
        };
        emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, status);
        return Ok(done);
    }

    // Allow (or monitor-mode block) → upstream, encrypt rules applied to what it receives.
    let target = upstream_target(route, &req);
    let (mut fbody, mut fct) = (det.body, det.raw_ct.clone());
    if !field_rules.is_empty() && !fbody.is_empty() {
        let (enc, enc_ct) = fp::transform_request_body(
            &fbody,
            &det.raw_ct,
            &det.ct_cat,
            &fp::filter_encrypt_rules(&field_rules),
        );
        (fbody, fct) = (enc, enc_ct);
    }
    let ct_override = (fct != det.raw_ct && !fct.is_empty()).then_some(fct.as_slice());
    let result = match &route.target {
        Target::Fcgi(pool) => {
            let mut hm = req.headers.clone();
            if let Some(ct) = ct_override {
                hm.insert(b"Content-Type".to_vec(), vec![ct.to_vec()]);
            }
            // PHP sees the same client headers as an HTTP upstream.
            // Every spelling that becomes the same CGI param (`X_Forwarded_For`, `X-Real_IP`) goes
            // too: PHP-FPM keeps the last of a repeated param and the sorted map put such a
            // spelling after ours, so a client could name its own address.
            // Over TLS the scheme is ours to state too: PHP derives `HTTPS` and the port from it.
            let over_tls = req.tls.is_some();
            // With the cache on, what an untrusted peer says in the headers that are not part of
            // the key is not sent on, and the scheme is the connection's: PHP would answer by it.
            let drop_unkeyed = cache::drops_unkeyed_inputs(route, &peer);
            hm.retain(|k, _| {
                if drop_unkeyed
                    && (crate::cache::unkeyed_input(k) || crate::cache::forwarded_host_or_proto(k))
                {
                    return false;
                }
                match cgi_header_param(k).as_slice() {
                    b"HTTP_X_REAL_IP" | b"HTTP_X_FORWARDED_FOR" => false,
                    b"HTTP_X_FORWARDED_PROTO" => !over_tls,
                    _ => true,
                }
            });
            if over_tls {
                hm.insert(b"X-Forwarded-Proto".to_vec(), vec![b"https".to_vec()]);
            }
            hm.insert(b"X-Real-IP".to_vec(), vec![remote.as_bytes().to_vec()]);
            hm.insert(
                b"X-Forwarded-For".to_vec(),
                vec![outgoing_forwarded_for(
                    &peer,
                    &req.lines,
                    &route.proxy_config,
                )],
            );
            crate::fastcgi::forward_fcgi(
                pool,
                &req.method,
                &target,
                &req.host,
                &remote,
                &hm,
                &fbody,
            )
            .await
            .map(Forwarded::Whole)
            .map_err(|e| ("fastcgi ", e))
        }
        Target::Http(t) => match crate::upstream::upstream_request(
            route,
            t,
            &req,
            &target,
            &peer,
            &remote,
            &fbody,
            ct_override,
        ) {
            Err(e) => Err(("", e.to_string())),
            Ok(head) => {
                let rewrites = crate::upstream::rewrites_response_body(route, &req.forward_path);
                crate::upstream::forward_http(shared, route, t, head, &fbody, !rewrites)
                    .await
                    .map(|f| match f {
                        // An answer that may be kept gets the header rules after its copy is
                        // made, so the copy holds what the application said and a change to the
                        // rules reaches it at once. A path that rewrites the body is never kept.
                        Forwarded::Whole(r) if cache_plan.fills() => Forwarded::Whole(r),
                        Forwarded::Whole(mut r) => {
                            crate::upstream::apply_response_rules(
                                route,
                                &req.forward_path,
                                &req.request_target,
                                &mut r,
                            );
                            Forwarded::Whole(r)
                        }
                        Forwarded::Stream(mut s) => {
                            crate::upstream::apply_response_header_rules(route, &mut s.head);
                            Forwarded::Stream(s)
                        }
                    })
                    .map_err(|e| ("", e))
            }
        },
    };
    match result {
        Ok(Forwarded::Whole(mut resp)) => {
            if let Some(spec) = &route.compression {
                let stats = shared.edge.app(&route.app_id);
                compress::apply(&stats, spec, &req, &route.session, &mut resp).await;
            }
            if cache_plan.fills() {
                if let Plan::Lookup(ask) = &cache_plan {
                    cache::fill(shared, route, ask, &req, &resp).await;
                }
                if matches!(route.target, Target::Http(_)) {
                    crate::upstream::apply_response_header_rules(route, &mut resp);
                }
            }
            cache::drop_copies(shared, route, &req, &peer, resp.status).await;
            if let Some(label) = cache_plan.label() {
                cache::tag(&mut resp, label);
            }
            emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, resp.status);
            answer(resp)
        }
        Ok(Forwarded::Stream(mut s)) => {
            if route.compression.is_some() {
                compress::note_streamed(
                    &shared.edge.app(&route.app_id),
                    &req,
                    &route.session,
                    &s.head,
                );
            }
            cache::drop_copies(shared, route, &req, &peer, s.head.status).await;
            if let Some(label) = cache_plan.label() {
                cache::tag(&mut s.head, label);
            }
            emit_decision_event(sink, &route.app_id, mode, &areq, &v, latency, s.head.status);
            Ok(Done::Stream(s))
        }
        Err((kind, e)) => {
            tracing::warn!(
                "[inline-proxy] app={} {kind}{} error: {e}",
                route.app_id,
                route.upstream
            );
            emit_upstream_error_event(sink, &route.app_id, mode, &areq, latency);
            let mut resp = OutboundResponse::with(502, "application/json", UPSTREAM_UNAVAILABLE);
            if let Some(label) = cache_plan.label() {
                cache::tag(&mut resp, label);
            }
            answer(resp)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_store::BookChange;
    use crate::config::{AppSpec, TlsSite, build_route};
    use crate::request::TlsClient;
    use wafio_domain::ip_address::parse_ip_address;

    const LISTED: &[u8] = b"t13d0000h2_000000000000_000000000000";

    fn route(edge: bool, proxy_config: &str) -> Route {
        build_route(&AppSpec {
            app_id: "a".into(),
            listen_host: String::new(),
            listen_port: 0,
            upstream: "http://127.0.0.1:1".into(),
            mode: "block".into(),
            proxy_config: proxy_config.as_bytes().to_vec(),
            rules_json: Vec::new(),
            fcgi_doc_root: String::new(),
            fcgi_index: String::new(),
            fcgi_keep_conn: false,
            maintenance: Vec::new(),
            analysis: Arc::new(crate::testing::analysis_setup(b"{}")),
            tls: edge.then(|| TlsSite {
                listen: "0.0.0.0:443".into(),
                hosts: vec!["shop.test".into()],
                certificate: BookChange::Keep,
                redirect_listen: None,
                canonical_host: None,
            }),
            compression: None,
            static_files: None,
            cache: None,
            session_cookies: Vec::new(),
        })
        .unwrap()
    }

    /// A request that carries `X-JA4` and `X-JA3` headers and the outcome of a TLS handshake whose
    /// hello gave `ja4`.
    fn request(ja4: Option<&str>) -> InboundRequest {
        let mut req = InboundRequest {
            tls: Some(Arc::new(TlsClient {
                server_name: "shop.test".into(),
                ja4: ja4.map(str::to_owned),
            })),
            ..InboundRequest::default()
        };
        req.headers.insert(b"X-JA4".to_vec(), vec![LISTED.to_vec()]);
        req.headers
            .insert(b"X-JA3".to_vec(), vec![b"ja3-from-header".to_vec()]);
        req
    }

    fn peer(ip: &str) -> IpAddress {
        parse_ip_address(ip.as_bytes()).unwrap()
    }

    /// A client of an app the agent serves over HTTPS writes the fingerprint headers itself, so
    /// they count only from a peer that `proxy_config` trusts as a proxy. This is reached when the
    /// handshake gave no JA4 (a hello that spans two TLS records).
    #[test]
    fn an_app_served_by_the_agent_reads_fingerprint_headers_only_from_a_trusted_proxy() {
        let req = request(None);
        let from_header = (LISTED.to_vec(), b"ja3-from-header".to_vec());
        let nothing = (Vec::new(), Vec::new());
        let (client, proxy) = (peer("203.0.113.9"), peer("10.1.2.3"));

        // The agent is the edge and trusts no proxy: nobody may name a fingerprint.
        let alone = route(true, "");
        assert_eq!(read_client_fingerprints(&req, &alone, &client), nothing);
        assert_eq!(read_client_fingerprints(&req, &alone, &proxy), nothing);

        // It trusts proxies on private addresses: a public client still may not, a proxy may.
        let trusting = route(true, r#"{"trust_forwarded":true}"#);
        assert_eq!(read_client_fingerprints(&req, &trusting, &client), nothing);
        assert_eq!(
            read_client_fingerprints(&req, &trusting, &proxy),
            from_header
        );

        // An app the agent is not the edge of reads the headers from any peer, as before.
        let behind = route(false, "");
        assert_eq!(
            read_client_fingerprints(&req, &behind, &client),
            from_header
        );
    }

    #[test]
    fn the_ja4_of_the_handshake_wins_over_a_header_even_from_a_trusted_proxy() {
        let trusting = route(true, r#"{"trust_forwarded":true}"#);
        let req = request(Some("t13d1516h2_8daaf6152771_02713d6af862"));
        assert_eq!(
            read_client_fingerprints(&req, &trusting, &peer("10.1.2.3")),
            (b"t13d1516h2_8daaf6152771_02713d6af862".to_vec(), Vec::new())
        );
    }
}
