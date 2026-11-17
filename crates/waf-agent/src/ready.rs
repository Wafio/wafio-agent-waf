//! The ready signal: the PID file, the predecessor notified and the service manager told.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

/// What a ready signal does, in order: PID file, predecessor, then systemd.
#[derive(Clone, Debug, Default)]
pub struct ReadyActions {
    /// `--pid-file`; empty = none.
    pub pid_file: String,
    /// The predecessor's ready socket (`WAFIO_UPGRADE_READY`); None on a normal start.
    pub predecessor: Option<PathBuf>,
    /// `NOTIFY_SOCKET`; empty = not under systemd.
    pub notify_socket: String,
}

/// `SignalReady`: only the first call acts.
pub struct Ready {
    once: Once,
    signaled: AtomicBool,
    actions: ReadyActions,
}

impl Ready {
    pub fn new(actions: ReadyActions) -> Ready {
        Ready {
            once: Once::new(),
            signaled: AtomicBool::new(false),
            actions,
        }
    }

    /// `SignalReady`: after the first bundle (live or cached) or the start fallback.
    pub fn signal(&self) {
        self.once.call_once(|| {
            self.signaled.store(true, Ordering::SeqCst);
            let a = &self.actions;
            if !a.pid_file.is_empty()
                && let Err(e) = write_pid_file(Path::new(&a.pid_file), std::process::id())
            {
                tracing::info!(
                    "[tableflip] ready signal failed: tableflip: can't write PID file: {e}"
                );
            }
            if let Some(p) = &a.predecessor
                && let Err(e) = std::os::unix::net::UnixStream::connect(p)
                    .and_then(|mut s| s.write_all(b"ready\n"))
            {
                tracing::info!("[tableflip] ready signal failed: {e}");
            }
            let _ = send_service_manager_notification(
                &a.notify_socket,
                &format!("READY=1\nMAINPID={}\n", std::process::id()),
            );
        });
    }

    /// `ReadySignaled`.
    pub fn signaled(&self) -> bool {
        self.signaled.load(Ordering::SeqCst)
    }
}

/// Writes the pid (no newline) to a temp file next to `path`, renamed
/// over it.
pub fn write_pid_file(path: &Path, pid: u32) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(
        "{name}{}",
        std::process::id() as u64 * 1_000_003 + nanos()
    ));
    let res = (|| {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(pid.to_string().as_bytes())?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    let _ = std::fs::remove_file(&tmp);
    res
}

fn nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or_default()
}

/// Sends one sd_notify datagram (`READY=1`, `MAINPID=`, ...) to `NOTIFY_SOCKET` ("@name" =
/// abstract socket); nothing without a socket or a message.
pub fn send_service_manager_notification(socket: &str, msg: &str) -> std::io::Result<()> {
    if socket.is_empty() || msg.is_empty() {
        return Ok(());
    }
    let sock = std::os::unix::net::UnixDatagram::unbound()?;
    if let Some(name) = socket.strip_prefix('@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
            sock.send_to_addr(msg.as_bytes(), &addr)?;
            return Ok(());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return Err(std::io::Error::other("abstract sockets need Linux"));
        }
    }
    sock.send_to(msg.as_bytes(), socket)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_runs_once_in_handover_order() {
        let dir = std::env::temp_dir().join(format!("wafio-ready-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let notify = dir.join("notify.sock");
        let systemd = std::os::unix::net::UnixDatagram::bind(&notify).unwrap();
        let pred = dir.join("pred.sock");
        let pred_l = std::os::unix::net::UnixListener::bind(&pred).unwrap();
        let pid_file = dir.join("agent.pid");
        let r = Ready::new(ReadyActions {
            pid_file: pid_file.to_string_lossy().into_owned(),
            predecessor: Some(pred.clone()),
            notify_socket: notify.to_string_lossy().into_owned(),
        });
        assert!(!r.signaled());
        r.signal();
        r.signal();
        assert!(r.signaled());
        assert_eq!(
            std::fs::read_to_string(&pid_file).unwrap(),
            std::process::id().to_string()
        );
        let (mut c, _) = pred_l.accept().unwrap();
        let mut got = String::new();
        std::io::Read::read_to_string(&mut c, &mut got).unwrap();
        assert_eq!(got, "ready\n");
        systemd.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 128];
        let n = systemd.recv(&mut buf).unwrap();
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            format!("READY=1\nMAINPID={}\n", std::process::id())
        );
        assert!(
            systemd.recv(&mut buf).is_err(),
            "second signal sends nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn notify_without_socket_is_a_no_op() {
        assert!(send_service_manager_notification("", "READY=1\n").is_ok());
        assert!(send_service_manager_notification("/nonexistent/sock", "").is_ok());
        assert!(send_service_manager_notification("/nonexistent/sock", "READY=1\n").is_err());
    }
}
