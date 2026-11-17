//! The host block of the WAF heartbeat (field 4) plus `siem_delivery`, written as JSON with a fixed
//! field order and `omitempty`. Linux procfs/sysfs readers; the root disk and the
//! primary address are read with `statfs(2)` / `getifaddrs(3)` (`libc`), on every call.

use std::sync::OnceLock;

/// Set at build time through `WAFIO_AGENT_VERSION`.
pub const AGENT_VERSION: &str = match option_env!("WAFIO_AGENT_VERSION") {
    Some(v) => v,
    None => "dev",
};

#[derive(Clone, Debug, Default)]
struct Static {
    hostname: String,
    kernel_name: String,
    kernel_rel: String,
    os_version: String,
    cpu_count: i64,
    cpu_model: String,
    cpu_mhz: f64,
    memory_total: u64,
    boot_time: i64,
    distro: String,
    distro_like: String,
    virt_type: String,
    timezone: String,
    selinux: String,
    apparmor: String,
    bpf_lsm: String,
    container_runtime: String,
    binary_path: String,
    install_dir: String,
    service_name: String,
    service_user: String,
}

fn read(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn exists(p: &str) -> bool {
    std::fs::metadata(p).is_ok()
}

/// Parses the leading digits.
fn parse_uint(s: &str) -> u64 {
    s.bytes().take_while(u8::is_ascii_digit).fold(0u64, |v, c| {
        v.wrapping_mul(10).wrapping_add(u64::from(c - b'0'))
    })
}

/// Parses the leading decimal number of `s`; trailing text is ignored.
fn parse_float(s: &str) -> f64 {
    let (mut f, mut frac, mut seen_dot, mut neg) = (0f64, 1f64, false, false);
    for (i, c) in s.chars().enumerate() {
        if i == 0 && c == '-' {
            neg = true;
            continue;
        }
        if c == '.' {
            seen_dot = true;
            continue;
        }
        let Some(d) = c.to_digit(10) else { break };
        if seen_dot {
            frac *= 10.0;
            f += f64::from(d) / frac;
        } else {
            f = f * 10.0 + f64::from(d);
        }
    }
    if neg { -f } else { f }
}

fn os_release(key: &str) -> String {
    let Some(s) = read("/etc/os-release") else {
        return String::new();
    };
    let mut out = String::new();
    for line in s.lines() {
        if let Some(v) = line.strip_prefix(key) {
            out = v.trim_matches('"').to_string();
            if key == "PRETTY_NAME=" {
                return out;
            }
        }
    }
    out
}

fn line_value(path: &str, prefix: &str) -> Option<String> {
    read(path)?
        .lines()
        .find(|l| l.starts_with(prefix))
        .map(String::from)
}

fn cpu_field(prefix: &str) -> Option<String> {
    let l = line_value("/proc/cpuinfo", prefix)?;
    l.find(':').map(|i| l[i + 1..].trim().to_string())
}

fn meminfo(prefix: &str) -> u64 {
    line_value("/proc/meminfo", prefix)
        .and_then(|l| l.split_whitespace().nth(1).map(parse_uint))
        .map_or(0, |v| v * 1024)
}

fn boot_time() -> i64 {
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    };
    line_value("/proc/stat", "btime")
        .and_then(|l| {
            l.split_whitespace()
                .nth(1)
                .map(|v| parse_uint(v).min(i64::MAX as u64) as i64)
        })
        .unwrap_or_else(now)
}

fn detect_virtualization() -> String {
    if exists("/.dockerenv") {
        return "docker".into();
    }
    if let Some(s) = read("/proc/1/cgroup") {
        for (needle, v) in [
            ("docker", "docker"),
            ("kubepods", "kubernetes"),
            ("lxc", "lxc"),
        ] {
            if s.contains(needle) {
                return v.into();
            }
        }
    }
    if let Some(s) = read("/sys/class/dmi/id/sys_vendor") {
        let s = s.trim().to_lowercase();
        for (needles, v) in [
            (&["qemu", "kvm"][..], "kvm"),
            (&["vmware"], "vmware"),
            (&["xen"], "xen"),
            (&["microsoft"], "hyperv"),
            (&["amazon ec2"], "ec2"),
            (&["google"], "gcp"),
        ] {
            if needles.iter().any(|n| s.contains(n)) {
                return v.into();
            }
        }
    }
    // The service manager's notify socket must not reach the child: systemd-detect-virt reports its
    // exit status there, and the manager would read it as the agent's own state change.
    if let Ok(out) = std::process::Command::new("systemd-detect-virt")
        .env_remove("NOTIFY_SOCKET")
        .output()
        && out.status.success()
    {
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if v == "none" {
            return "bare-metal".into();
        }
        if !v.is_empty() {
            return v;
        }
    }
    if exists("/sys/class/dmi/id/sys_vendor") {
        return "bare-metal".into();
    }
    String::new()
}

fn timezone() -> String {
    if let Some(s) = read("/etc/timezone")
        && !s.trim().is_empty()
    {
        return s.trim().to_string();
    }
    if let Ok(link) = std::fs::read_link("/etc/localtime") {
        let l = link.to_string_lossy();
        if let Some(i) = l.find("zoneinfo/") {
            return l[i + "zoneinfo/".len()..].to_string();
        }
    }
    // No named zone found: UTC.
    "UTC".into()
}

fn selinux() -> String {
    match read("/sys/fs/selinux/enforce").as_deref().map(str::trim) {
        Some("1") => return "enforcing".into(),
        Some("0") => return "permissive".into(),
        _ => {}
    }
    if exists("/sys/fs/selinux") {
        "disabled".into()
    } else {
        "not-installed".into()
    }
}

fn apparmor() -> String {
    if !exists("/sys/kernel/security/apparmor") {
        return "not-installed".into();
    }
    match read("/sys/module/apparmor/parameters/enabled")
        .as_deref()
        .map(str::trim)
    {
        Some("N" | "n") => "disabled".into(),
        _ => "enabled".into(),
    }
}

fn bpf_lsm() -> String {
    match read("/sys/kernel/security/lsm") {
        Some(s) if s.contains("bpf") => "enabled".into(),
        Some(_) => "disabled".into(),
        None => "unknown".into(),
    }
}

fn container_runtime() -> String {
    for (p, n) in [
        ("/var/run/docker.sock", "docker"),
        ("/run/containerd/containerd.sock", "containerd"),
        ("/run/crio/crio.sock", "cri-o"),
        ("/run/podman/podman.sock", "podman"),
    ] {
        if exists(p) {
            return n.into();
        }
    }
    "none".into()
}

fn service_name() -> String {
    if let Some(s) = read("/proc/self/cgroup") {
        for line in s.lines().map(str::trim) {
            if line.contains(".service")
                && let Some(i) = line.rfind('/')
                && line[i + 1..].ends_with(".service")
            {
                return line[i + 1..].to_string();
            }
        }
    }
    std::env::var("SYSTEMD_UNIT").unwrap_or_default()
}

/// The current user name: the uid's /etc/passwd entry.
fn service_user() -> String {
    let uid = line_value("/proc/self/status", "Uid:")
        .and_then(|l| l.split_whitespace().nth(1).map(String::from))
        .unwrap_or_default();
    read("/etc/passwd")
        .and_then(|p| {
            p.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 2 && f[2] == uid).then(|| f[0].to_string())
            })
        })
        .unwrap_or_default()
}

fn collect_static() -> Static {
    let hostname = read("/proc/sys/kernel/hostname")
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_default();
    let (binary_path, install_dir) = match crate::reload::successor_exe() {
        Ok(p) => {
            let real = std::fs::canonicalize(&p).unwrap_or(p);
            let dir = real
                .parent()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default();
            (real.to_string_lossy().into_owned(), dir)
        }
        Err(_) => (String::new(), String::new()),
    };
    Static {
        hostname,
        // These procfs files hold the same strings as uname(2) on Linux.
        kernel_name: read("/proc/sys/kernel/ostype")
            .map_or("Linux".into(), |s| s.trim().to_string()),
        kernel_rel: read("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        os_version: os_release("PRETTY_NAME="),
        cpu_count: std::thread::available_parallelism().map_or(1, |n| n.get() as i64),
        cpu_model: cpu_field("model name").unwrap_or_default(),
        cpu_mhz: cpu_field("cpu MHz").map_or(0.0, |v| parse_float(&v)),
        memory_total: meminfo("MemTotal:"),
        boot_time: boot_time(),
        distro: os_release("ID="),
        distro_like: os_release("ID_LIKE="),
        virt_type: detect_virtualization(),
        timezone: timezone(),
        selinux: selinux(),
        apparmor: apparmor(),
        bpf_lsm: bpf_lsm(),
        container_runtime: container_runtime(),
        binary_path,
        install_dir,
        service_name: service_name(),
        service_user: service_user(),
    }
}

fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        a => a,
    }
}

struct Obj(Vec<u8>);

impl Obj {
    fn key(&mut self, k: &str) {
        self.0.push(if self.0.is_empty() { b'{' } else { b',' });
        self.0
            .extend_from_slice(&wafio_domain::json_text::encode_string(k.as_bytes()));
        self.0.push(b':');
    }
    fn s(&mut self, k: &str, v: &str, omit: bool) {
        if !(omit && v.is_empty()) {
            self.key(k);
            self.0
                .extend_from_slice(&wafio_domain::json_text::encode_string(v.as_bytes()));
        }
    }
    fn n(&mut self, k: &str, v: impl std::fmt::Display + PartialEq + Default, omit: bool) {
        if !(omit && v == Default::default()) {
            self.key(k);
            self.0.extend_from_slice(v.to_string().as_bytes());
        }
    }
    fn raw(&mut self, k: &str, v: &str) {
        self.key(k);
        self.0.extend_from_slice(v.as_bytes());
    }
    fn done(mut self) -> Vec<u8> {
        if self.0.is_empty() {
            self.0.push(b'{');
        }
        self.0.push(b'}');
        self.0
    }
}

/// `statfs("/")` as (blocks × block size, available blocks × block size);
/// (0, 0) when the call fails.
#[cfg(target_os = "linux")]
fn root_disk() -> (u64, u64) {
    let Ok(st) = nix::sys::statfs::statfs("/") else {
        return (0, 0);
    };
    // A negative block size counts as 0; the products wrap in u64 arithmetic.
    let bsize = u64::try_from(st.block_size()).unwrap_or(0);
    (
        st.blocks().wrapping_mul(bsize),
        st.blocks_available().wrapping_mul(bsize),
    )
}

#[cfg(not(target_os = "linux"))]
fn root_disk() -> (u64, u64) {
    (0, 0)
}

/// The first up, non-loopback interface (in interface index order)
/// that has a non-loopback IPv4 address, as (address, interface name); both empty when none.
#[cfg(target_os = "linux")]
fn primary_ip() -> (String, String) {
    use nix::net::if_::InterfaceFlags;
    use std::collections::BTreeMap;
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return (String::new(), String::new());
    };
    // Per real interface (index, name): its first usable IPv4 in the kernel's address order. glibc
    // names an IPv4 alias by its label (`eth0:1`); `:` cannot be part of an interface name.
    let mut first: BTreeMap<u32, (String, std::net::Ipv4Addr)> = BTreeMap::new();
    for e in addrs {
        if !e.flags.contains(InterfaceFlags::IFF_UP)
            || e.flags.contains(InterfaceFlags::IFF_LOOPBACK)
        {
            continue;
        }
        let Some(addr) = e.address else {
            continue;
        };
        let ip = if let Some(a) = addr.as_sockaddr_in() {
            a.ip()
        } else if let Some(a) = addr.as_sockaddr_in6() {
            // An IPv4-mapped IPv6 address counts as IPv4.
            let a = a.ip().octets();
            if a[..10].iter().any(|&b| b != 0) || a[10] != 0xff || a[11] != 0xff {
                continue;
            }
            std::net::Ipv4Addr::new(a[12], a[13], a[14], a[15])
        } else {
            continue;
        };
        if ip.is_loopback() {
            continue;
        }
        let label = e.interface_name;
        let name = label.split(':').next().unwrap_or(&label).to_string();
        let index = nix::net::if_::if_nametoindex(name.as_str()).unwrap_or(0);
        if index != 0 {
            first.entry(index).or_insert((name, ip));
        }
    }
    first
        .into_values()
        .next()
        .map_or((String::new(), String::new()), |(name, ip)| {
            (ip.to_string(), name)
        })
}

#[cfg(not(target_os = "linux"))]
fn primary_ip() -> (String, String) {
    (String::new(), String::new())
}

/// The host info JSON of the WAF heartbeat: the host block plus `siem_delivery`.
pub fn heartbeat_host_info() -> Vec<u8> {
    static STATIC: OnceLock<Static> = OnceLock::new();
    let st = STATIC.get_or_init(collect_static);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let (total, avail) = (meminfo("MemTotal:"), meminfo("MemAvailable:"));
    let mem_used = total.saturating_sub(avail);
    let load: Vec<f64> = read("/proc/loadavg")
        .map(|s| s.split_whitespace().take(3).map(parse_float).collect())
        .unwrap_or_default();
    let l = |i: usize| load.get(i).copied().unwrap_or(0.0);
    let mut o = Obj(Vec::new());
    o.s("hostname", &st.hostname, false);
    o.s("os", std::env::consts::OS, false);
    o.s("os_version", &st.os_version, false);
    o.s("kernel_name", &st.kernel_name, false);
    o.s("kernel_release", &st.kernel_rel, false);
    o.s("arch", arch(), false);
    o.n("cpu_count", st.cpu_count, false);
    o.s("cpu_model", &st.cpu_model, true);
    o.n("cpu_mhz", st.cpu_mhz, true);
    o.n("memory_total_bytes", st.memory_total, false);
    o.n("memory_used_bytes", mem_used, true);
    o.n("memory_free_bytes", avail, true);
    o.n("load_avg_1", l(0), true);
    o.n("load_avg_5", l(1), true);
    o.n("load_avg_15", l(2), true);
    o.n("uptime_seconds", now - st.boot_time, false);
    o.n("boot_time", st.boot_time, false);
    o.s("agent_version", AGENT_VERSION, false);
    o.s("agent_kind", "waf", false);
    o.s("distro", &st.distro, true);
    o.s("distro_like", &st.distro_like, true);
    o.s("virt_type", &st.virt_type, true);
    o.s("timezone", &st.timezone, true);
    let (disk_total, disk_free) = root_disk();
    let (primary_ip, primary_interface) = primary_ip();
    o.n("disk_total_bytes", disk_total, true);
    o.n("disk_free_bytes", disk_free, true);
    o.s("primary_ip", &primary_ip, true);
    o.s("primary_interface", &primary_interface, true);
    o.s("selinux_mode", &st.selinux, true);
    o.s("apparmor", &st.apparmor, true);
    o.s("bpf_lsm", &st.bpf_lsm, true);
    o.s("container_runtime", &st.container_runtime, true);
    o.s("binary_path", &st.binary_path, true);
    o.s("install_dir", &st.install_dir, true);
    o.s("service_name", &st.service_name, true);
    o.s("service_user", &st.service_user, true);
    o.raw("siem_delivery", &crate::siem::delivery_counts().to_json());
    o.done()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_parsers() {
        assert_eq!(parse_uint("123kB"), 123);
        assert_eq!(parse_float("2400.000"), 2400.0);
        assert_eq!(parse_float("-0.25x"), -0.25);
        assert_eq!(
            format!("{}", 2400.0f64),
            "2400",
            "whole floats are written without .0"
        );
    }

    /// `statfs("/")` and the primary address are real values on a Linux host (a container has a
    /// root file system and, unless it runs with no network, an address on a non-loopback interface).
    #[cfg(target_os = "linux")]
    #[test]
    fn root_disk_and_primary_address_are_read() {
        let (total, free) = root_disk();
        assert!(total > 0 && free <= total, "{total} {free}");
        let (ip, ifc) = primary_ip();
        assert_eq!(ip.is_empty(), ifc.is_empty());
        if !ip.is_empty() {
            let v4: std::net::Ipv4Addr = ip.parse().unwrap();
            assert!(!v4.is_loopback() && ifc != "lo", "{ip} {ifc}");
        }
        let v: serde_json::Value = serde_json::from_slice(&heartbeat_host_info()).unwrap();
        assert!(v["disk_total_bytes"].as_u64().unwrap() > 0);
        assert_eq!(v.get("primary_ip").is_some(), !ip.is_empty());
        // Field order: timezone, disk, primary address, selinux.
        let raw = String::from_utf8(heartbeat_host_info()).unwrap();
        let at = |k: &str| raw.find(&format!("\"{k}\"")).unwrap_or(usize::MAX);
        assert!(
            at("disk_total_bytes") < at("disk_free_bytes")
                && at("disk_free_bytes")
                    < at("primary_ip")
                        .min(at("selinux_mode"))
                        .min(at("container_runtime"))
        );
    }

    #[test]
    fn heartbeat_info_is_json_with_wire_keys() {
        let raw = heartbeat_host_info();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["agent_kind"], "waf");
        assert_eq!(v["siem_delivery"]["accepted"], 0);
        assert!(
            v.get("hostname").is_some()
                && v.get("cpu_count").is_some()
                && v.get("uptime_seconds").is_some()
        );
    }
}
