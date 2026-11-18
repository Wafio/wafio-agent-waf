//! The maintenance page: what an app in maintenance mode answers with, in the format the client asks
//! for. Only the HTML page can be customised; the JSON and XML bodies are the stock ones.

use crate::block_response::{HTML, JSON, RenderedBlockPage, XML, escape_for_json, escape_for_xml};
use crate::templates as t;
use wafio_bytetext::html::escape as html_escape;
use wafio_bytetext::strings::replace_all;
use wafio_domain::MaintenanceSettings;

/// The message when the operator wrote none.
pub const DEFAULT_MESSAGE: &str =
    "We are carrying out planned maintenance. Please check back soon.";

/// Whether the `Accept` header names `needle` in any letter case.
fn names(accept: &[u8], needle: &[u8]) -> bool {
    accept
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// The page for a request with this `Accept`, and the `Retry-After` seconds while the expected end
/// lies ahead. `text/html` gets HTML, else `json` gets JSON, else `xml` gets XML, else HTML. A past
/// end counts as none.
pub fn render_maintenance(
    m: &MaintenanceSettings,
    accept: &[u8],
    now_unix: i64,
) -> (RenderedBlockPage, Option<u64>) {
    let end = m.end_unix.filter(|&end| end > now_unix);
    let end_text = end.map_or("", |_| m.end_text.as_str()).as_bytes();
    let message = match m.message.trim() {
        "" => DEFAULT_MESSAGE,
        text => text,
    }
    .as_bytes();
    let (tmpl, escaped, content_type) = if names(accept, b"text/html") {
        (html_template(m), html_escape(message), HTML)
    } else if names(accept, b"json") {
        (
            t::STOCK_MAINTENANCE_JSON.as_bytes(),
            escape_for_json(message),
            JSON,
        )
    } else if names(accept, b"xml") {
        (
            t::STOCK_MAINTENANCE_XML.as_bytes(),
            escape_for_xml(message),
            XML,
        )
    } else {
        (html_template(m), html_escape(message), HTML)
    };
    // The end time goes in first so that a message holding the placeholder text is not filled again.
    let body = replace_all(tmpl, b"{{WAFIO_END_TIME}}", end_text);
    let body = replace_all(&body, b"{{WAFIO_MESSAGE}}", &escaped);
    let retry_after = end.map(|end| (end - now_unix) as u64);
    (RenderedBlockPage { body, content_type }, retry_after)
}

fn html_template(m: &MaintenanceSettings) -> &[u8] {
    if m.custom_html.is_empty() {
        t::STOCK_MAINTENANCE_HTML.as_bytes()
    } else {
        m.custom_html.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_795_000_000;

    fn settings() -> MaintenanceSettings {
        MaintenanceSettings::default()
    }

    fn page(m: &MaintenanceSettings, accept: &str) -> (String, &'static str, Option<u64>) {
        let (p, retry) = render_maintenance(m, accept.as_bytes(), NOW);
        (String::from_utf8(p.body).unwrap(), p.content_type, retry)
    }

    #[test]
    fn the_accept_header_picks_the_format() {
        let m = settings();
        for (accept, want) in [
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                HTML,
            ),
            ("TEXT/HTML", HTML),
            ("application/json", JSON),
            ("application/json, text/plain, */*", JSON),
            ("application/vnd.api+JSON", JSON),
            ("text/xml", XML),
            ("application/xml", XML),
            ("application/json, application/xml", JSON),
            ("*/*", HTML),
            ("", HTML),
            ("text/plain", HTML),
            ("image/png", HTML),
            ("text/html, application/json", HTML),
        ] {
            assert_eq!(page(&m, accept).1, want, "Accept: {accept:?}");
        }
    }

    #[test]
    fn the_default_message_and_an_empty_end_time() {
        let m = settings();
        let (html, _, retry) = page(&m, "text/html");
        assert!(html.contains(DEFAULT_MESSAGE), "{html}");
        assert!(html.contains(r#"datetime="""#));
        assert!(!html.contains("{{WAFIO_"));
        assert_eq!(retry, None);
        assert_eq!(
            page(&m, "application/json").0,
            format!(
                "{{\n  \"status\": 503,\n  \"maintenance\": true,\n  \"message\": \"{DEFAULT_MESSAGE}\",\n  \"expected_end\": \"\"\n}}"
            )
        );
        assert_eq!(
            page(&m, "text/xml").0,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<maintenance>\n  <status>503</status>\n  <message>{DEFAULT_MESSAGE}</message>\n  <expected_end></expected_end>\n</maintenance>"
            )
        );
        let blank = MaintenanceSettings {
            message: " \n\t ".into(),
            ..settings()
        };
        assert!(page(&blank, "").0.contains(DEFAULT_MESSAGE));
    }

    #[test]
    fn a_future_end_is_shown_and_sets_retry_after() {
        let m = MaintenanceSettings {
            message: "Back soon.".into(),
            end_unix: Some(NOW + 90),
            end_text: "2026-11-18T22:00:00Z".into(),
            ..settings()
        };
        for accept in ["text/html", "application/json", "text/xml"] {
            let (body, _, retry) = page(&m, accept);
            assert!(body.contains("2026-11-18T22:00:00Z"), "{accept}: {body}");
            assert_eq!(retry, Some(90), "{accept}");
        }
        let one = MaintenanceSettings {
            end_unix: Some(NOW + 1),
            ..m.clone()
        };
        assert_eq!(page(&one, "").2, Some(1));
    }

    #[test]
    fn a_past_or_current_end_counts_as_none() {
        for end in [NOW - 3600, NOW] {
            let m = MaintenanceSettings {
                end_unix: Some(end),
                end_text: "2026-11-18T22:00:00Z".into(),
                ..settings()
            };
            for accept in ["text/html", "application/json", "text/xml"] {
                let (body, _, retry) = page(&m, accept);
                assert_eq!(retry, None, "{accept}");
                assert!(!body.contains("2026-11-18"), "{accept}: {body}");
            }
            assert!(
                page(&m, "application/json")
                    .0
                    .contains(r#""expected_end": """#)
            );
        }
    }

    #[test]
    fn the_message_is_escaped_for_each_format() {
        let m = MaintenanceSettings {
            message: r#"<script>alert("x")</script> & 'q'"#.into(),
            ..settings()
        };
        let (html, _, _) = page(&m, "text/html");
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(
            html.contains("&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; &#39;q&#39;"),
            "{html}"
        );
        let (json, _, _) = page(&m, "application/json");
        assert!(
            json.contains(
                r#""message": "\u003cscript\u003ealert(\"x\")\u003c/script\u003e \u0026 'q'","#
            ),
            "{json}"
        );
        let (xml, _, _) = page(&m, "application/xml");
        assert!(
            xml.contains("<message>&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &apos;q&apos;</message>"),
            "{xml}"
        );
    }

    #[test]
    fn a_message_holding_a_placeholder_is_not_filled_again() {
        let m = MaintenanceSettings {
            message: "{{WAFIO_END_TIME}}".into(),
            end_unix: Some(NOW + 60),
            end_text: "2026-11-18T22:00:00Z".into(),
            ..settings()
        };
        assert!(
            page(&m, "application/json")
                .0
                .contains(r#""message": "{{WAFIO_END_TIME}}""#)
        );
    }

    #[test]
    fn custom_html_replaces_the_html_page_only() {
        let m = MaintenanceSettings {
            message: "Back at nine.".into(),
            custom_html: "<h1>Closed</h1><p>{{WAFIO_MESSAGE}}</p><i>{{WAFIO_END_TIME}}</i>".into(),
            end_unix: Some(NOW + 60),
            end_text: "2026-11-18T22:00:00Z".into(),
            ..settings()
        };
        assert_eq!(
            page(&m, "text/html").0,
            "<h1>Closed</h1><p>Back at nine.</p><i>2026-11-18T22:00:00Z</i>"
        );
        assert_eq!(
            page(&m, "").0,
            "<h1>Closed</h1><p>Back at nine.</p><i>2026-11-18T22:00:00Z</i>"
        );
        let (json, ct, _) = page(&m, "application/json");
        assert_eq!(ct, JSON);
        assert!(json.contains(r#""maintenance": true"#) && !json.contains("Closed"));
        let (xml, ct, _) = page(&m, "text/xml");
        assert_eq!(ct, XML);
        assert!(xml.contains("<maintenance>") && !xml.contains("Closed"));
    }

    #[test]
    fn the_stock_page_has_both_placeholders() {
        assert!(t::STOCK_MAINTENANCE_HTML.contains("{{WAFIO_MESSAGE}}"));
        assert!(t::STOCK_MAINTENANCE_HTML.contains("{{WAFIO_END_TIME}}"));
        let (html, ct, _) = page(&settings(), "text/html");
        assert_eq!(ct, HTML);
        assert!(html.contains("<title>Down for maintenance</title>"));
    }
}
