//! The local TLS sites file (`--tls-sites-file`): the apps this agent serves over HTTPS itself.
//! The control plane does not send it. It is read once at start, so a change takes effect on a
//! reload; the certificate files are watched separately by the proxy.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;
use wafio_proxy::TlsSite;
use wafio_proxy::cert_store::CertFiles;

use crate::agent::format_host_port;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SitesFile {
    apps: HashMap<String, Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    /// `false` leaves the app out, so the file can keep an app's settings while it is off.
    tls: bool,
    #[serde(default)]
    listen: String,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    certificate: PathBuf,
    #[serde(default)]
    key: PathBuf,
    redirect_listen: Option<String>,
}

/// The sites of the file by app id. The error names the file and what is wrong in it.
pub fn load(path: &str) -> Result<HashMap<String, TlsSite>, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "--tls-sites-file: {}",
            crate::flags::path_error_text("open", path, &e)
        )
    })?;
    parse(&bytes).map_err(|e| format!("--tls-sites-file {path}: {e}"))
}

fn parse(bytes: &[u8]) -> Result<HashMap<String, TlsSite>, String> {
    let file: SitesFile = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let mut sites = HashMap::new();
    for (app, entry) in file.apps {
        if entry.tls {
            let site = entry.into_site().map_err(|e| format!("app {app}: {e}"))?;
            sites.insert(app, site);
        }
    }
    Ok(sites)
}

impl Entry {
    fn into_site(self) -> Result<TlsSite, String> {
        let listen = address(&self.listen).map_err(|e| format!("listen: {e}"))?;
        let redirect_listen = self
            .redirect_listen
            .as_deref()
            .map(address)
            .transpose()
            .map_err(|e| format!("redirect_listen: {e}"))?;
        let mut hosts = self
            .hosts
            .iter()
            .map(|h| host_name(h))
            .collect::<Result<Vec<_>, _>>()?;
        if hosts.is_empty() {
            return Err("hosts is empty".into());
        }
        hosts.sort();
        hosts.dedup();
        if self.certificate.as_os_str().is_empty() || self.key.as_os_str().is_empty() {
            return Err("certificate and key are required".into());
        }
        Ok(TlsSite {
            listen,
            hosts,
            cert: CertFiles {
                certificate: self.certificate,
                key: self.key,
            },
            redirect_listen,
        })
    }
}

/// `host:port` written the way a bundle listener's address is, so that it matches a socket a
/// predecessor handed over. An empty host is every IPv4 address.
fn address(text: &str) -> Result<String, String> {
    let (host, port) = text.rsplit_once(':').ok_or("expected host:port")?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|&p| p != 0)
        .ok_or("the port must be a number from 1 to 65535")?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok(format_host_port(
        if host.is_empty() { "0.0.0.0" } else { host },
        i64::from(port),
    ))
}

/// A host name as the proxy matches it: lower case, no trailing dot, letters, digits, `-`, `_`
/// and `.` only (no port, no wildcard; an internationalised name is given in its ASCII form).
fn host_name(host: &str) -> Result<String, String> {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    let plain = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.');
    if name.is_empty() || !name.bytes().all(plain) {
        return Err(format!(
            "host name {host:?} must be a plain DNS name, without port or wildcard"
        ));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOP: &str = r#"{"apps":{"shop":{"tls":true,"listen":"0.0.0.0:443",
        "hosts":["Shop.Example.com.","www.shop.example.com","shop.example.com"],
        "certificate":"/etc/wafio/tls/shop/fullchain.pem","key":"/etc/wafio/tls/shop/privkey.pem",
        "redirect_listen":"0.0.0.0:80"}}}"#;

    fn error(json: &str) -> String {
        parse(json.as_bytes()).unwrap_err()
    }

    #[test]
    fn an_entry_becomes_a_site() {
        let sites = parse(SHOP.as_bytes()).unwrap();
        let site = &sites["shop"];
        assert_eq!(site.listen, "0.0.0.0:443");
        assert_eq!(site.redirect_listen.as_deref(), Some("0.0.0.0:80"));
        assert_eq!(site.hosts, ["shop.example.com", "www.shop.example.com"]);
        assert_eq!(
            site.cert.certificate,
            PathBuf::from("/etc/wafio/tls/shop/fullchain.pem")
        );
        assert_eq!(
            site.cert.key,
            PathBuf::from("/etc/wafio/tls/shop/privkey.pem")
        );
    }

    #[test]
    fn an_entry_that_is_off_is_left_out_whatever_else_it_holds() {
        let sites = parse(br#"{"apps":{"shop":{"tls":false},"blog":{"tls":false,"hosts":[]}}}"#);
        assert!(sites.unwrap().is_empty());
    }

    #[test]
    fn addresses_match_the_bundle_listener_form() {
        assert_eq!(address(":443").unwrap(), "0.0.0.0:443");
        assert_eq!(address("10.0.0.5:8443").unwrap(), "10.0.0.5:8443");
        assert_eq!(address("[::]:443").unwrap(), "[::]:443");
        assert!(address("443").is_err());
        assert!(address("0.0.0.0:0").is_err());
        assert!(address("0.0.0.0:https").is_err());
        assert!(address("0.0.0.0:70000").is_err());
    }

    #[test]
    fn a_wrong_file_is_refused_with_the_reason() {
        let with = |field: &str, value: &str| SHOP.replace(field, value);
        assert!(error("{").contains("line 1"));
        assert!(error(r#"{"apps":{"a":{"tls":true,"port":1}}}"#).contains("unknown field"));
        assert!(
            error(r#"{"apps":{"a":{"tls":true}}}"#).contains("app a: listen: expected host:port")
        );
        assert!(error(&with(r#""shop.example.com""#, r#""*.example.com""#)).contains("wildcard"));
        assert!(error(&with("Shop.Example.com.", "shop.example.com:443")).contains("without port"));
        assert!(
            error(&with(
                r#""hosts":["Shop.Example.com.","www.shop.example.com","shop.example.com"]"#,
                r#""hosts":[]"#
            ))
            .contains("hosts is empty")
        );
        assert!(
            error(&with("/etc/wafio/tls/shop/privkey.pem", "")).contains("certificate and key")
        );
        assert!(error(&with("0.0.0.0:80", "80")).contains("redirect_listen"));
    }

    #[test]
    fn load_names_the_file_it_cannot_read() {
        let e = load("/nonexistent/tls-sites.json").unwrap_err();
        assert!(e.contains("--tls-sites-file") && e.contains("/nonexistent/tls-sites.json"));
    }
}
