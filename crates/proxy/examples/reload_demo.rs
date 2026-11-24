//! Reload harness: one app proxied to an HTTP upstream, SIGUSR2 = hand over to a successor,
//! SIGTERM = stop. Every response carries `x-served-by: <pid>`.
//!
//!   reload_demo --listen 127.0.0.1:8080 --upstream 127.0.0.1:9000 [--run-dir DIR] [--apply-delay-ms N]
//!               [--maintenance-file FILE]
//!
//! `--maintenance-file`: the file's text (read when the configuration is applied, so a successor
//! reads the file as it is then) is the app's `maintenance` object; a missing file means none.

use std::sync::Arc;
use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};
use wafio_proxy::{AppSpec, Proxy, ProxyOptions, upgrade};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> std::io::Result<()> {
    wafio_proxy::runtime_builder().build()?.block_on(run())
}

async fn run() -> std::io::Result<()> {
    let listen = arg("--listen").expect("--listen");
    let upstream = arg("--upstream").expect("--upstream");
    let run_dir = std::path::PathBuf::from(arg("--run-dir").unwrap_or_else(|| "/tmp".into()));
    let delay = Duration::from_millis(arg("--apply-delay-ms").map_or(0, |v| v.parse().unwrap()));

    let mut opts = ProxyOptions::new(Arc::new(|_| {}));
    opts.inherited = tokio::task::spawn_blocking(upgrade::inherited_listeners).await??;
    let proxy = Proxy::new(opts);
    // Stands for waiting for the first bundle (live or cached); the predecessor keeps serving.
    tokio::time::sleep(delay).await;
    let (host, port) = listen.rsplit_once(':').expect("host:port");
    let app = AppSpec {
        app_id: "demo".into(),
        listen_host: host.into(),
        listen_port: port.parse().expect("port"),
        upstream: format!("http://{upstream}"),
        mode: "block".into(),
        proxy_config: format!(
            r#"{{"resp_headers":{{"add":{{"x-served-by":"{}"}}}}}}"#,
            std::process::id()
        )
        .into_bytes(),
        rules_json: Vec::new(),
        fcgi_doc_root: String::new(),
        fcgi_index: String::new(),
        fcgi_keep_conn: false,
        maintenance: arg("--maintenance-file")
            .and_then(|f| std::fs::read(f).ok())
            .unwrap_or_default(),
        analysis: Arc::new(wafio_proxy::testing::analysis_setup(br#"{}"#)),
        tls: None,
        compression: None,
        static_files: None,
    };
    proxy.apply(vec![app]).map_err(std::io::Error::other)?;
    upgrade::notify_ready();

    let mut usr2 = signal(SignalKind::user_defined2())?;
    let mut term = signal(SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = usr2.recv() => match upgrade::spawn_successor(proxy.handover_fds(), &run_dir, upgrade::HANDOVER_TIMEOUT).await {
                Ok(pid) => {
                    eprintln!("[reload_demo {}] handed over to {pid}; draining", std::process::id());
                    proxy.shutdown(true).await;
                    return Ok(());
                }
                Err(e) => eprintln!("[reload_demo] upgrade failed, still serving: {e}"),
            },
            _ = term.recv() => {
                proxy.shutdown(false).await;
                return Ok(());
            }
        }
    }
}
