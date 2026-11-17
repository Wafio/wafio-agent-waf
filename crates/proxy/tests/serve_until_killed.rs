//! Serves one block-mode app in front of a given upstream until the process is killed, so an
//! external HTTP test tool can be pointed at the proxy. Ignored in normal test runs.

mod common;

use common::*;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs until killed; needs WAFIO_SERVE_PORT and WAFIO_SERVE_UPSTREAM"]
async fn serve_until_killed() {
    let port: u16 = std::env::var("WAFIO_SERVE_PORT")
        .expect("WAFIO_SERVE_PORT")
        .parse()
        .expect("a port number");
    let upstream = std::env::var("WAFIO_SERVE_UPSTREAM").expect("WAFIO_SERVE_UPSTREAM");
    let mut served = app("serve", port, &upstream);
    // WAFIO_SERVE_RULES: a rules JSON file to serve with, in place of the test default.
    if let Ok(path) = std::env::var("WAFIO_SERVE_RULES") {
        served.analysis = analysis_setup(&std::fs::read_to_string(path).expect("rules file"));
    }
    let (harness, addr) = Harness::serve(vec![served]);
    eprintln!("serving on {addr}, upstream {upstream}");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        // The harness keeps every decision event; print the ones that did not pass and drop
        // them all, so a long run stays flat in memory.
        for e in harness.events.lock().unwrap().drain(..) {
            if s(&e.action) == "block" || s(&e.action) == "challenge" {
                let cats: Vec<_> = e
                    .categories
                    .iter()
                    .map(|c| String::from_utf8_lossy(c))
                    .collect();
                let uri = String::from_utf8_lossy(&e.uri);
                eprintln!(
                    "EVENT\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}",
                    String::from_utf8_lossy(&e.action),
                    String::from_utf8_lossy(&e.method),
                    e.score,
                    String::from_utf8_lossy(&e.analyze_method),
                    String::from_utf8_lossy(&e.match_detail),
                    cats.join(","),
                    uri.chars().take(160).collect::<String>(),
                    String::from_utf8_lossy(&e.match_source),
                    e.match_value
                        .as_deref()
                        .map(|v| String::from_utf8_lossy(&v[..v.len().min(200)]).into_owned())
                );
            }
        }
    }
}
