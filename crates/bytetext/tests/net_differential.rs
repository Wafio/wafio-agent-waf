//! Differential for `url::parse`, `net::parse_ip` and `path::normalize_path`: replays a
//! reference file; skips without `WAFIO_GONET_ORACLE=<file>`.

use wafio_bytetext::{net, path, url};

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn net_differential() {
    let Ok(path) = std::env::var("WAFIO_GONET_ORACLE") else {
        eprintln!("skipped: set WAFIO_GONET_ORACLE=<file>");
        return;
    };
    let data = std::fs::read_to_string(path).unwrap();
    let (mut total, mut bad) = ([0usize; 3], [0usize; 3]);
    let mut shown = 0;
    let mut report = |kind: usize, input: &[u8], what: String| {
        bad[kind] += 1;
        if shown < 40 {
            shown += 1;
            eprintln!(
                "MISMATCH {}: {:?}: {what}",
                ["url", "ip", "clean"][kind],
                String::from_utf8_lossy(input)
            );
        }
    };
    for line in data.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let input = hex_to_bytes(f[1]);
        match f[0] {
            "url" => {
                total[0] += 1;
                let reference_ok = f[2] == "1";
                match (url::parse(&input), reference_ok) {
                    (Err(_), false) => {}
                    (Ok(_), false) => report(0, &input, "go rejects, rust accepts".into()),
                    (Err(_), true) => report(0, &input, "go accepts, rust rejects".into()),
                    (Ok(u), true) => {
                        let want: Vec<Vec<u8>> = f[3..10].iter().map(|x| hex_to_bytes(x)).collect();
                        let got = [
                            &u.scheme,
                            &u.opaque,
                            &u.host,
                            &u.path,
                            &u.raw_query,
                            &u.fragment,
                        ];
                        for (i, g) in got.iter().enumerate() {
                            if **g != want[i] {
                                report(
                                    0,
                                    &input,
                                    format!(
                                        "field {i}: go={:?} rust={:?}",
                                        String::from_utf8_lossy(&want[i]),
                                        String::from_utf8_lossy(g)
                                    ),
                                );
                            }
                        }
                        if u.hostname() != want[6].as_slice() {
                            report(0, &input, "hostname".into());
                        }
                    }
                }
            }
            "ip" => {
                total[1] += 1;
                let reference_ok = f[2] == "1";
                match (net::parse_ip(&input), reference_ok) {
                    (None, false) => {}
                    (Some(_), false) => report(1, &input, "go rejects, rust accepts".into()),
                    (None, true) => report(1, &input, "go accepts, rust rejects".into()),
                    (Some(ip), true) => {
                        let flags = format!(
                            "{}{}{}{}{}",
                            ip.is_loopback() as u8,
                            ip.is_private() as u8,
                            ip.is_unspecified() as u8,
                            ip.is_link_local_unicast() as u8,
                            ip.is_link_local_multicast() as u8
                        );
                        if ip.0 != hex_to_bytes(f[3]) || flags != f[4] {
                            report(
                                1,
                                &input,
                                format!("bytes/flags go={}/{} rust={:?}/{flags}", f[3], f[4], ip.0),
                            );
                        }
                    }
                }
            }
            "clean" => {
                total[2] += 1;
                let got = path::normalize_path(&input);
                if got != hex_to_bytes(f[2]) {
                    report(
                        2,
                        &input,
                        format!(
                            "go={:?} rust={:?}",
                            String::from_utf8_lossy(&hex_to_bytes(f[2])),
                            String::from_utf8_lossy(&got)
                        ),
                    );
                }
            }
            _ => {}
        }
    }
    eprintln!(
        "gonet differential: url {}/{} ip {}/{} clean {}/{} mismatches",
        bad[0], total[0], bad[1], total[1], bad[2], total[2]
    );
    assert_eq!(bad, [0, 0, 0]);
}
