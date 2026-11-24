//! Whether a request comes from a signed-in visitor. What is sent to such a visitor holds secrets
//! of their own, so it is not compressed in a way a guess can read off its size.

use crate::request::InboundRequest;

/// `Authorization`, the userinfo of an absolute-form target, or a cookie whose name is a session
/// name. The test is by name only: a cookie that holds a session under another name needs the
/// app's own list of names (not read yet).
pub(crate) fn is_signed_in(req: &InboundRequest) -> bool {
    req.userinfo.is_some()
        || req
            .lines
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(b"authorization"))
        || req.cookies.iter().any(|(name, _)| session_cookie(name))
}

/// A name that holds `sess` (PHPSESSID, JSESSIONID, laravel_session, ASP.NET_SessionId), the
/// WordPress login cookies, the ASP.NET Core cookies, any remember-me cookie (Laravel
/// `remember_web_*`, `remember-me`) and the Express `connect.sid`.
fn session_cookie(name: &[u8]) -> bool {
    let name = name.to_ascii_lowercase();
    memchr::memmem::find(&name, b"sess").is_some()
        || name.starts_with(b"wordpress_logged_in")
        || name.starts_with(b"wordpress_sec")
        || name.starts_with(b".aspnetcore.")
        || name.starts_with(b"remember")
        || name == b"connect.sid"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(head: &str) -> InboundRequest {
        InboundRequest::from_head(
            format!("GET / HTTP/1.1\r\nHost: a.test\r\n{head}\r\n").as_bytes(),
        )
    }

    #[test]
    fn a_request_with_no_credential_is_not_signed_in() {
        assert!(!is_signed_in(&request("")));
        assert!(!is_signed_in(&request(
            "Cookie: theme=dark; _ga=GA1.2; lang=id\r\nX-Session: no\r\n"
        )));
    }

    #[test]
    fn authorization_and_userinfo_sign_a_request_in() {
        assert!(is_signed_in(&request("Authorization: Basic eDp5\r\n")));
        assert!(is_signed_in(&request("authorization: Bearer t\r\n")));
        let absolute =
            InboundRequest::from_head(b"GET http://u:p@a.test/x HTTP/1.1\r\nHost: a.test\r\n\r\n");
        assert!(absolute.userinfo.is_some());
        assert!(is_signed_in(&absolute));
    }

    #[test]
    fn session_cookies_are_found_by_name_in_any_case() {
        for name in [
            "PHPSESSID",
            "JSESSIONID",
            "laravel_session",
            "ASP.NET_SessionId",
            "sessionid",
            "my_sess_v2",
            "wordpress_logged_in_0a1b2c",
            "wordpress_sec_0a1b2c",
            ".AspNetCore.Identity.Application",
            ".AspNetCore.Cookies",
            "remember_web_59ba36addc2b2f94",
            "remember-me",
            "connect.sid",
        ] {
            assert!(
                is_signed_in(&request(&format!("Cookie: a=1; {name}=x\r\n"))),
                "{name}"
            );
        }
    }

    #[test]
    fn a_cookie_with_a_session_word_in_its_value_does_not_count() {
        assert!(!is_signed_in(&request(
            "Cookie: theme=session; wordpress_test_cookie=WP\r\n"
        )));
    }
}
