//! Block pages: policy, geo and WAF block bodies in HTML, JSON or XML with the
//! `{{WAFIO_*}}` placeholders escaped per format.

use crate::challenge::ChallengeSettings;
use crate::challenge::fill_format_template;
use crate::templates as t;
use wafio_bytetext::html::escape as html_escape;
use wafio_bytetext::strings::replace_all;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedBlockPage {
    pub body: Vec<u8>,
    pub content_type: &'static str,
}

/// 400..=599 honoured, else 403.
pub fn status_for_block(override_: i64) -> u16 {
    if (400..=599).contains(&override_) {
        override_ as u16
    } else {
        403
    }
}

/// JSON string escaping without the quotes.
pub fn escape_for_json(s: &[u8]) -> Vec<u8> {
    let b = wafio_domain::json_text::encode_string(s);
    b[1..b.len() - 1].to_vec()
}

pub fn escape_for_xml(s: &[u8]) -> Vec<u8> {
    let s = replace_all(s, b"&", b"&amp;");
    let s = replace_all(&s, b"<", b"&lt;");
    let s = replace_all(&s, b">", b"&gt;");
    let s = replace_all(&s, b"\"", b"&quot;");
    replace_all(&s, b"'", b"&apos;")
}

pub(crate) const JSON: &str = "application/json; charset=utf-8";
pub(crate) const XML: &str = "application/xml; charset=utf-8";
pub(crate) const HTML: &str = "text/html; charset=utf-8";

/// Picks a template field of the config.
type Field = fn(&ChallengeSettings) -> &String;

fn custom<'a>(c: Option<&'a ChallengeSettings>, f: Field, default: &'a str) -> &'a [u8] {
    c.map(f)
        .filter(|s| !s.is_empty())
        .map_or(default.as_bytes(), |s| s.as_bytes())
}

// Policy and geo pages carry only {{WAFIO_MESSAGE}}.
fn message_page(
    challenge: Option<&ChallengeSettings>,
    format: &str,
    tmpls: [(Field, &'static str); 3],
    message: &[u8],
) -> RenderedBlockPage {
    let (tmpl, esc, ct) = match format {
        "json" => (
            custom(challenge, tmpls[0].0, tmpls[0].1),
            escape_for_json(message),
            JSON,
        ),
        "xml" => (
            custom(challenge, tmpls[1].0, tmpls[1].1),
            escape_for_xml(message),
            XML,
        ),
        _ => (
            custom(challenge, tmpls[2].0, tmpls[2].1),
            html_escape(message),
            HTML,
        ),
    };
    RenderedBlockPage {
        body: replace_all(tmpl, b"{{WAFIO_MESSAGE}}", &esc),
        content_type: ct,
    }
}

/// analyze_method "policy" → policy page, "geo" → geo page, else
/// the WAF block page.
pub fn render_block_response(
    score: i64,
    categories: &[&[u8]],
    analyze_method: &[u8],
    match_detail: &[u8],
    cwe: &[u8],
    message: &[u8],
    challenge: Option<&ChallengeSettings>,
) -> RenderedBlockPage {
    const DASH: &[u8] = "—".as_bytes();
    let cats = wafio_bytetext::strings::join(categories, b", ");
    let cats: &[u8] = if cats.is_empty() { DASH } else { &cats };
    let analyze_method = if analyze_method.is_empty() {
        DASH
    } else {
        analyze_method
    };
    let match_detail = if match_detail.is_empty() {
        DASH
    } else {
        match_detail
    };
    let cwe = if cwe.is_empty() { DASH } else { cwe };
    let message: &[u8] = if message.is_empty() {
        b"Request blocked by WAF."
    } else {
        message
    };

    if analyze_method == b"policy" {
        let format = challenge.map_or("", |c| c.policy_block_format.as_str());
        return message_page(
            challenge,
            format,
            [
                (|c| &c.custom_policy_block_json, t::STOCK_POLICY_BLOCK_JSON),
                (|c| &c.custom_policy_block_xml, t::STOCK_POLICY_BLOCK_XML),
                (|c| &c.custom_policy_block_html, t::STOCK_POLICY_BLOCK_HTML),
            ],
            message,
        );
    }
    if analyze_method == b"geo" {
        let format = challenge.map_or("", |c| c.geo_block_format.as_str());
        return message_page(
            challenge,
            format,
            [
                (|c| &c.custom_geo_block_json, t::STOCK_GEO_BLOCK_JSON),
                (|c| &c.custom_geo_block_xml, t::STOCK_GEO_BLOCK_XML),
                (|c| &c.custom_geo_block_html, t::STOCK_GEO_BLOCK_HTML),
            ],
            message,
        );
    }

    let score_s = score.to_string().into_bytes();
    let fill = |tmpl: &[u8], score: &[u8], esc: fn(&[u8]) -> Vec<u8>| {
        let r = replace_all(tmpl, b"{{WAFIO_SCORE}}", score);
        let r = replace_all(&r, b"{{WAFIO_CATEGORIES}}", &esc(cats));
        let r = replace_all(&r, b"{{WAFIO_METHOD}}", &esc(analyze_method));
        let r = replace_all(&r, b"{{WAFIO_DETAIL}}", &esc(match_detail));
        let r = replace_all(&r, b"{{WAFIO_CWE}}", &esc(cwe));
        replace_all(&r, b"{{WAFIO_MESSAGE}}", &esc(message))
    };
    match challenge.map_or("", |c| c.waf_block_format.as_str()) {
        "json" => RenderedBlockPage {
            body: fill(
                custom(
                    challenge,
                    |c| &c.custom_waf_block_json,
                    t::STOCK_WAF_BLOCK_JSON,
                ),
                &score_s,
                escape_for_json,
            ),
            content_type: JSON,
        },
        "xml" => RenderedBlockPage {
            body: fill(
                custom(
                    challenge,
                    |c| &c.custom_waf_block_xml,
                    t::STOCK_WAF_BLOCK_XML,
                ),
                &score_s,
                escape_for_xml,
            ),
            content_type: XML,
        },
        _ => {
            if let Some(c) = challenge.filter(|c| !c.custom_block_html.is_empty()) {
                return RenderedBlockPage {
                    body: fill(
                        c.custom_block_html.as_bytes(),
                        &html_escape(&score_s),
                        html_escape,
                    ),
                    content_type: HTML,
                };
            }
            RenderedBlockPage {
                content_type: HTML,
                body: fill_format_template(
                    t::WAF_BLOCK_DEFAULT_HTML_FMT,
                    &[
                        &score_s,
                        &html_escape(cats),
                        &html_escape(analyze_method),
                        &html_escape(match_detail),
                        &html_escape(cwe),
                        &html_escape(message),
                    ],
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_escaping() {
        let mut c = ChallengeSettings {
            waf_block_format: "json".into(),
            ..Default::default()
        };
        let r = render_block_response(
            7,
            &[b"SQLi", b"XSS"],
            b"semantic",
            b"<x>\"",
            b"",
            b"",
            Some(&c),
        );
        assert_eq!(r.content_type, JSON);
        let body = String::from_utf8(r.body).unwrap();
        assert!(
            body.contains(r#""threat_score": 7"#)
                && body.contains(r#""detail": "\u003cx\u003e\"""#)
                && body.contains(r#""cwe": "—""#)
        );
        c.waf_block_format = "xml".into();
        let r = render_block_response(7, &[], b"", b"a'b", b"", b"m", Some(&c));
        assert!(
            String::from_utf8(r.body)
                .unwrap()
                .contains("<detail>a&apos;b</detail>")
        );
        let r = render_block_response(0, &[], b"policy", b"", b"", b"<m>", None);
        assert!(String::from_utf8(r.body).unwrap().contains("&lt;m&gt;"));
        let r = render_block_response(9, &[b"A"], b"x", b"d", b"c", b"m", None);
        assert!(
            String::from_utf8(r.body)
                .unwrap()
                .contains(r#"<span class="val">9</span>"#)
        );
        assert_eq!(status_for_block(429), 429);
        assert_eq!(status_for_block(200), 403);
    }
}
