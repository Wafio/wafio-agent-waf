//! The SIGUSR2 upgrade, on the proxy
//! crate's handover protocol (`wafio_proxy::upgrade`: Pingora `Fds` over a unix socket,
//! ready socket). Private copy of `upgrade::spawn_successor` that also sets the successor's
//! environment: the current host key (`WAFIO_HOST_KEY`, replaced by a
//! `KeyRotation`) is exported so the upgraded child authenticates with it; the process must not
//! `setenv` while threaded, so it goes on the child's command line environment instead.

use std::io;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use pingora::server::Fds;
use tokio::io::AsyncReadExt;
use wafio_proxy::upgrade::{ENV_READY, ENV_SOCK, MAX_HANDOVER_FDS};

pub use wafio_proxy::upgrade::{HANDOVER_TIMEOUT, inherited_listeners, successor_exe};

/// The upgrade state: refused before ready, one at a time, once only.
#[derive(Default)]
pub struct UpgradeState {
    inner: Mutex<Phase>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    #[default]
    Idle,
    Running,
    Done,
}

impl UpgradeState {
    /// Upgrade admission: `ready` says whether the ready signal was sent.
    pub fn begin(&self, ready: bool) -> Result<(), String> {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match *p {
            Phase::Done => Err("already upgraded".into()),
            Phase::Running => Err("upgrade in progress".into()),
            Phase::Idle if !ready => Err("process is not ready yet".into()),
            Phase::Idle => {
                *p = Phase::Running;
                Ok(())
            }
        }
    }

    pub fn finish(&self, ok: bool) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) =
            if ok { Phase::Done } else { Phase::Idle };
    }
}

/// The predecessor's ready socket, when this process is an upgrade successor.
pub fn predecessor_ready_socket() -> Option<PathBuf> {
    std::env::var_os(ENV_READY).map(PathBuf::from)
}

/// Directory for the handover sockets: systemd's `RUNTIME_DIRECTORY`, else the temp dir.
pub fn run_dir() -> PathBuf {
    match std::env::var("RUNTIME_DIRECTORY") {
        Ok(v) if !v.is_empty() => PathBuf::from(v.split(':').next().unwrap_or(&v)),
        _ => std::env::temp_dir(),
    }
}

/// Starts the successor with this process's arguments plus `env`, hands it `fds` (listen
/// address → socket) and waits until it reports ready. Returns its pid; on error the
/// successor is killed and this process keeps serving.
pub async fn spawn_successor(
    fds: Vec<(String, RawFd)>,
    run_dir: &Path,
    timeout: Duration,
    env: Vec<(String, String)>,
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
        .envs(env)
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
                format!("child {child_pid} timed out"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_admission_phases() {
        let s = UpgradeState::default();
        assert_eq!(s.begin(false).unwrap_err(), "process is not ready yet");
        s.begin(true).unwrap();
        assert_eq!(s.begin(true).unwrap_err(), "upgrade in progress");
        s.finish(false);
        s.begin(true).unwrap();
        s.finish(true);
        assert_eq!(s.begin(true).unwrap_err(), "already upgraded");
    }
}
