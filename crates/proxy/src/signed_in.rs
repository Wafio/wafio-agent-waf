//! Whether a request comes from a signed-in visitor. What is sent to such a visitor holds secrets
//! of their own, so it is not compressed in a way a guess can read off its size, and the response
//! cache keeps it only for a path the app has a rule for. Compression and the cache use this one
//! test.

use crate::request::InboundRequest;

/// How a name of the built-in table is matched against the cookie name, in lower case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Match {
    Contains,
    Prefix,
    Exact,
}

/// The names of the session cookies the agent knows. `sess` covers
/// `PHPSESSID`, `laravel_session`, `ASP.NET_SessionId`; the prefixes carry a hash after them
/// (`wordpress_logged_in_<hash>`).
pub(crate) const SESSION_NAMES: [(Match, &str); 8] = [
    (Match::Contains, "sess"),
    (Match::Prefix, "wordpress_logged_in_"),
    (Match::Prefix, "wp-postpass_"),
    (Match::Prefix, "remember_web_"),
    (Match::Prefix, "remember-me"),
    (Match::Prefix, ".aspnetcore."),
    (Match::Exact, "jsessionid"),
    (Match::Exact, "connect.sid"),
];

/// The names of the session cookies an app names itself, lower case, compared whole.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionNames(Vec<Vec<u8>>);

impl SessionNames {
    pub fn new<I, S>(names: I) -> SessionNames
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut all: Vec<Vec<u8>> = names
            .into_iter()
            .map(|n| n.as_ref().to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        all.sort();
        all.dedup();
        SessionNames(all)
    }

    fn contains(&self, lower: &[u8]) -> bool {
        self.0.iter().any(|n| n == lower)
    }
}

/// `Authorization`, the userinfo of an absolute-form target, or a cookie whose name is a session
/// name: one of the table above, or one of `names`. The test is by name only, so a session kept
/// under a name that is in neither is not seen.
pub(crate) fn is_signed_in(req: &InboundRequest, names: &SessionNames) -> bool {
    req.userinfo.is_some()
        || req
            .lines
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(b"authorization"))
        || req
            .cookies
            .iter()
            .any(|(name, _)| session_cookie(name, names))
}

fn session_cookie(name: &[u8], names: &SessionNames) -> bool {
    let lower = name.to_ascii_lowercase();
    names.contains(&lower)
        || SESSION_NAMES.iter().any(|(how, text)| {
            let text = text.as_bytes();
            match how {
                Match::Contains => memchr::memmem::find(&lower, text).is_some(),
                Match::Prefix => lower.starts_with(text),
                Match::Exact => lower == text,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(head: &str) -> InboundRequest {
        InboundRequest::from_head(
            format!("GET / HTTP/1.1\r\nHost: a.test\r\n{head}\r\n").as_bytes(),
        )
    }

    fn signed_in(head: &str) -> bool {
        is_signed_in(&request(head), &SessionNames::default())
    }

    #[test]
    fn a_request_with_no_credential_is_not_signed_in() {
        assert!(!signed_in(""));
        assert!(!signed_in(
            "Cookie: theme=dark; _ga=GA1.2; lang=id\r\nX-Session: no\r\n"
        ));
    }

    #[test]
    fn authorization_and_userinfo_sign_a_request_in() {
        assert!(signed_in("Authorization: Basic eDp5\r\n"));
        assert!(signed_in("authorization: Bearer t\r\n"));
        let absolute =
            InboundRequest::from_head(b"GET http://u:p@a.test/x HTTP/1.1\r\nHost: a.test\r\n\r\n");
        assert!(absolute.userinfo.is_some());
        assert!(is_signed_in(&absolute, &SessionNames::default()));
    }

    /// The list written out once more here: a change to the table changes what compression and
    /// the cache take for a session, and must change this test and the README with it.
    #[test]
    fn the_table_is_the_list_the_readme_gives() {
        let listed: [(Match, &str); 8] = [
            (Match::Contains, "sess"),
            (Match::Prefix, "wordpress_logged_in_"),
            (Match::Prefix, "wp-postpass_"),
            (Match::Prefix, "remember_web_"),
            (Match::Prefix, "remember-me"),
            (Match::Prefix, ".aspnetcore."),
            (Match::Exact, "jsessionid"),
            (Match::Exact, "connect.sid"),
        ];
        assert_eq!(SESSION_NAMES, listed);
    }

    /// Each row of the table finds the cookies it stands for, in any case, and not what only looks
    /// like it.
    #[test]
    fn every_name_of_the_table_is_found_in_any_case_and_a_near_miss_is_not() {
        for (how, text) in SESSION_NAMES {
            let found: Vec<String> = match how {
                Match::Contains => vec![format!("my_{text}_v2"), text.to_uppercase()],
                Match::Prefix => vec![format!("{text}0a1b2c"), format!("{}X", text.to_uppercase())],
                Match::Exact => vec![text.to_owned(), text.to_uppercase()],
            };
            for name in found {
                assert!(signed_in(&format!("Cookie: a=1; {name}=x\r\n")), "{name}");
            }
            let missed: Vec<String> = match how {
                Match::Contains => vec![format!("{}x", &text[..text.len() - 1])],
                Match::Prefix => vec![format!("x{text}"), text[..text.len() - 1].to_owned()],
                Match::Exact => vec![format!("{text}2"), format!("x{text}")],
            };
            for name in missed {
                // `sess` inside another name still counts, so a near miss must not hold it.
                let holds_sess = name.to_ascii_lowercase().contains("sess");
                assert_eq!(
                    signed_in(&format!("Cookie: {name}=x\r\n")),
                    holds_sess,
                    "{name}"
                );
            }
        }
        for name in [
            "PHPSESSID",
            "JSESSIONID",
            "laravel_session",
            "ASP.NET_SessionId",
            "sessionid",
            "wordpress_logged_in_0a1b2c",
            ".AspNetCore.Identity.Application",
            ".AspNetCore.Cookies",
            "remember_web_59ba36addc2b2f94",
            "remember-me",
            "wp-postpass_0a1b2c",
            "connect.sid",
        ] {
            assert!(signed_in(&format!("Cookie: a=1; {name}=x\r\n")), "{name}");
        }
    }

    /// A cookie that is not on the list does not count. That narrows two older rules: a name that
    /// only starts with `remember`, and the secure WordPress cookie (the login cookie always comes
    /// with it).
    #[test]
    fn names_that_are_not_on_the_list_do_not_count() {
        for name in [
            "remember_token",
            "rememberme",
            "wordpress_sec_0a1b2c",
            "wordpress_logged_in",
            "wordpress_test_cookie",
            "connect_sid",
            "jwt",
            "token",
        ] {
            assert!(!signed_in(&format!("Cookie: {name}=x\r\n")), "{name}");
        }
    }

    #[test]
    fn the_names_an_app_gives_count_in_any_case_and_only_whole() {
        let names = SessionNames::new(["MyAuth", "sb-access-token", "", "MYAUTH"]);
        let seen = |head: &str| is_signed_in(&request(head), &names);
        assert!(seen("Cookie: myauth=1\r\n"));
        assert!(seen("Cookie: MyAuth=1\r\n"));
        assert!(seen("Cookie: sb-access-token=1\r\n"));
        assert!(!seen("Cookie: myauth2=1\r\n"));
        assert!(!seen("Cookie: xmyauth=1\r\n"));
        assert!(!seen("Cookie: theme=myauth\r\n"));
        // An empty name matches no cookie, a nameless value included.
        assert!(!seen("Cookie: =1\r\n"));
        assert_eq!(names, SessionNames::new(["myauth", "sb-access-token"]));
    }

    #[test]
    fn a_cookie_with_a_session_word_in_its_value_does_not_count() {
        assert!(!signed_in(
            "Cookie: theme=session; wordpress_test_cookie=WP\r\n"
        ));
    }
}
