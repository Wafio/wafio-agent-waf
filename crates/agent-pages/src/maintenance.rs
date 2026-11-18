//! The maintenance page: what an app in maintenance mode answers with, in the format the client asks
//! for. Only the HTML page can be customised; the JSON and XML bodies are the stock ones. The bodies
//! are built once, when the settings are loaded, so a request only picks one.

use crate::block_response::{HTML, JSON, XML, escape_for_json, escape_for_xml};
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

/// One format: the body without the end time, and with it when the settings carry one.
struct Format {
    content_type: &'static str,
    hidden: Vec<u8>,
    shown: Option<Vec<u8>>,
}

/// The pages of one app in maintenance mode, ready to be sent.
pub struct MaintenancePages {
    end_unix: Option<i64>,
    html: Format,
    json: Format,
    xml: Format,
}

impl MaintenancePages {
    /// Builds HTML (the custom page or the stock one), JSON and XML, each without the end time
    /// and, when `end_unix` is set, with it. The end time goes in first so that a message holding
    /// the placeholder text is not filled again.
    pub fn new(m: &MaintenanceSettings) -> MaintenancePages {
        let message = match m.message.trim() {
            "" => DEFAULT_MESSAGE,
            text => text,
        }
        .as_bytes();
        let build = |content_type, tmpl: &[u8], escaped: Vec<u8>| {
            let fill = |end_text: &[u8]| {
                let body = replace_all(tmpl, b"{{WAFIO_END_TIME}}", end_text);
                replace_all(&body, b"{{WAFIO_MESSAGE}}", &escaped)
            };
            Format {
                content_type,
                hidden: fill(b""),
                shown: m.end_unix.map(|_| fill(m.end_text.as_bytes())),
            }
        };
        let html_tmpl = if m.custom_html.is_empty() {
            t::STOCK_MAINTENANCE_HTML.as_bytes()
        } else {
            m.custom_html.as_bytes()
        };
        MaintenancePages {
            end_unix: m.end_unix,
            html: build(HTML, html_tmpl, html_escape(message)),
            json: build(
                JSON,
                t::STOCK_MAINTENANCE_JSON.as_bytes(),
                escape_for_json(message),
            ),
            xml: build(
                XML,
                t::STOCK_MAINTENANCE_XML.as_bytes(),
                escape_for_xml(message),
            ),
        }
    }

    /// The content type and body for a request with this `Accept`, and the `Retry-After` seconds
    /// while the expected end lies ahead. `text/html` gets HTML, else `json` gets JSON, else `xml`
    /// gets XML, else HTML. An end that is not after `now_unix` counts as none.
    pub fn page(&self, accept: &[u8], now_unix: i64) -> (&'static str, &[u8], Option<u64>) {
        let format = if names(accept, b"text/html") {
            &self.html
        } else if names(accept, b"json") {
            &self.json
        } else if names(accept, b"xml") {
            &self.xml
        } else {
            &self.html
        };
        match (self.end_unix.filter(|&end| end > now_unix), &format.shown) {
            (Some(end), Some(shown)) => (format.content_type, shown, Some((end - now_unix) as u64)),
            _ => (format.content_type, &format.hidden, None),
        }
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
        let pages = MaintenancePages::new(m);
        let (content_type, body, retry) = pages.page(accept.as_bytes(), NOW);
        (
            String::from_utf8(body.to_vec()).unwrap(),
            content_type,
            retry,
        )
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

    #[test]
    fn the_stock_page_is_the_control_plane_copy() {
        // The dashboard previews the control plane's StockMaintenanceHTML: change both, then this hash.
        let hash =
            crate::crypto::hex_encode(&crate::crypto::sha256(t::STOCK_MAINTENANCE_HTML.as_bytes()));
        assert_eq!(
            String::from_utf8(hash).unwrap(),
            "19e7dcca79422988cd08f783ffc80b70dc0f4058ba78530afd7bbb06928da633"
        );
    }

    #[test]
    fn retry_after_is_exact_for_each_request_and_a_passed_end_uses_the_hidden_page() {
        let m = MaintenanceSettings {
            end_unix: Some(NOW + 3600),
            end_text: "2026-11-18T22:00:00Z".into(),
            ..settings()
        };
        let pages = MaintenancePages::new(&m);
        for (now, want) in [
            (NOW + 3600 - 1, Some(1)),
            (NOW + 3600 - 90, Some(90)),
            (NOW, Some(3600)),
            (NOW + 3600, None),
            (NOW + 3600 + 5, None),
        ] {
            let (_, body, retry) = pages.page(b"application/json", now);
            let body = String::from_utf8_lossy(body);
            assert_eq!(retry, want, "now {now}");
            assert_eq!(
                body.contains("2026-11-18T22:00:00Z"),
                want.is_some(),
                "now {now}: {body}"
            );
        }
    }

    #[test]
    fn a_request_gets_a_slice_of_the_prepared_body() {
        let m = MaintenanceSettings {
            custom_html: "<p>{{WAFIO_MESSAGE}}</p>".into(),
            end_unix: Some(NOW + 60),
            end_text: "2026-11-18T22:00:00Z".into(),
            ..settings()
        };
        let pages = MaintenancePages::new(&m);
        for accept in [&b"text/html"[..], b"application/json", b"text/xml"] {
            for now in [NOW, NOW + 60] {
                let (_, a, _) = pages.page(accept, now);
                let (_, b, _) = pages.page(accept, now);
                assert!(std::ptr::eq(a, b), "{}", String::from_utf8_lossy(accept));
            }
        }
        // Without an end time there is one variant, whatever the clock says.
        let pages = MaintenancePages::new(&settings());
        let (_, a, _) = pages.page(b"text/html", NOW);
        let (_, b, _) = pages.page(b"text/html", NOW + 1_000_000);
        assert!(std::ptr::eq(a, b));
    }
}
