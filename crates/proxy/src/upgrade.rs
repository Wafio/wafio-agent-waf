//! Zero-downtime reload.
//!
//! On SIGUSR2 (`systemctl reload` = `kill -USR2 $MAINPID`) the running process starts the binary
//! at its path with the same arguments, hands it every live listening socket over a unix socket
//! (Pingora's `Fds` SCM_RIGHTS transfer), and keeps serving until the successor applied its
//! first configuration and reported ready; then it stops accepting and drains. The successor
//! sends systemd `READY=1` + `MAINPID=<own pid>` (the unit needs `NotifyAccess=all` for a
//! message from a process that is not yet the main PID).
//!
//! Pingora's own graceful upgrade (`Server` + `--upgrade` + SIGQUIT) is not used: it transfers
//! only the listeners its services had at start and needs the new process started from
//! outside before the old one is signalled.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::TcpListener as StdListener;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pingora::server::Fds;
use sd_notify::NotifyState;
use tokio::io::AsyncReadExt;

pub const ENV_SOCK: &str = "WAFIO_UPGRADE_SOCK";
pub const ENV_READY: &str = "WAFIO_UPGRADE_READY";
/// Pingora's receiving side takes at most 32 descriptors per transfer (`get_fds_from`) and
/// panics on more; the address list must fit its 2048-byte buffer.
pub const MAX_HANDOVER_FDS: usize = 32;
/// How long the predecessor waits for the successor to report ready.
pub const HANDOVER_TIMEOUT: Duration = Duration::from_secs(60);

/// Successor side, before the first configuration: the sockets the predecessor handed over,
/// keyed by listen address. Empty for a normal start. Blocking (waits up to ~6 s).
pub fn inherited_listeners() -> io::Result<HashMap<String, StdListener>> {
    let Ok(path) = std::env::var(ENV_SOCK) else {
        return Ok(HashMap::new());
    };
    let mut fds = Fds::new();
    fds.get_from_sock(path.as_str())
        .map_err(|e| io::Error::other(format!("upgrade: receive listeners: {e}")))?;
    let (binds, raw) = fds.serialize();
    Ok(binds
        .into_iter()
        .zip(raw)
        .map(|(b, fd)| {
            // SAFETY: the descriptors were just received with SCM_RIGHTS and are owned by nothing else.
            #[allow(unsafe_code)]
            let listener = unsafe { StdListener::from_raw_fd(fd) };
            (b, listener)
        })
        .collect())
}

/// Successor side, after the first configuration (live or cached bundle) was applied: lets
/// the predecessor stop and makes this process the service's main PID. Also used on a normal
/// start (`READY=1` only after the first bundle).
pub fn notify_ready() {
    if let Ok(path) = std::env::var(ENV_READY)
        && let Ok(mut s) = UnixStream::connect(&path)
    {
        let _ = s.write_all(b"ready\n");
    }
    let _ = sd_notify::notify(&[NotifyState::Ready, NotifyState::MainPid(std::process::id())]);
}

/// The binary to start. After a package upgrade replaced the file, `/proc/self/exe` reads
/// "<path> (deleted)"; Rust's `current_exe` keeps that suffix, so it is stripped here.
pub fn successor_exe() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(
        match exe.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
            Some(p) => PathBuf::from(p),
            None => exe,
        },
    )
}

/// Predecessor side (SIGUSR2): starts the successor, hands it `fds` and waits until it reports
/// ready. Returns its pid; on error the successor is killed and this process keeps serving.
pub async fn spawn_successor(
    fds: Vec<(String, RawFd)>,
    run_dir: &Path,
    timeout: Duration,
) -> io::Result<u32> {
    let key_bytes: usize = fds.iter().map(|(a, _)| a.len() + 1).sum();
    if fds.len() > MAX_HANDOVER_FDS || key_bytes > 2048 {
        return Err(io::Error::other(format!(
            "upgrade: {} listeners exceed the handover limit",
            fds.len()
        )));
    }
    let pid = std::process::id();
    let sock = run_dir.join(format!("wafio-upgrade-{pid}.sock"));
    let ready = run_dir.join(format!("wafio-ready-{pid}.sock"));
    let _ = std::fs::remove_file(&ready);
    let ready_listener = tokio::net::UnixListener::bind(&ready)?;
    let mut child = std::process::Command::new(successor_exe()?)
        .args(std::env::args_os().skip(1))
        .env(ENV_SOCK, &sock)
        .env(ENV_READY, &ready)
        .spawn()?;
    let child_pid = child.id();
    let sock_path = sock.to_string_lossy().into_owned();
    let sent = tokio::task::spawn_blocking(move || {
        let mut out = Fds::new();
        for (addr, fd) in fds {
            out.add(addr, fd);
        }
        out.send_to_sock(sock_path.as_str())
            .map(|_| ())
            .map_err(|e| io::Error::other(format!("upgrade: send listeners: {e}")))
    })
    .await
    .map_err(io::Error::other)
    .and_then(|r| r);
    let result = match sent {
        Ok(()) => tokio::time::timeout(timeout, async {
            let (mut c, _) = ready_listener.accept().await?;
            let mut b = [0u8; 6];
            c.read_exact(&mut b).await
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "upgrade: successor not ready in time",
            )
        })
        .and_then(|r| r.map(|_| ())),
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_file(&ready);
    if let Err(e) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(child_pid)
}
