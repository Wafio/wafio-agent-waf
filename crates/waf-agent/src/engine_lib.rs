//! The engine library at start: whether to look for one, where, and what the agent does when it cannot use it.
//!
//! An agent whose binary has no engine linked in looks for `libwafio_semantic_engine.so` once, before it starts any
//! thread. A library that is missing, that fails a check or that does not load leaves the agent as it is when built
//! alone: it proxies, enforces everything that is not semantic detection, reports `no_semantic_engine` in its Hello and
//! marks what it forwarded with `engine_absent`. One log line says why. The exception is `WAFIO_ENGINE_LIB_REQUIRED=1`:
//! with it a library that cannot be used is fatal and the agent does not start. The release installers write it into
//! the service environment, so a cold start without the library fails. An agent that ran with a library also sets it
//! for the successor of a zero-downtime reload, so a successor that cannot load the library refuses to start and the
//! predecessor keeps serving.
//!
//! `--features` runs the same step as a start, so it reports the engine the service would run with.

use std::path::Path;
use std::sync::OnceLock;

use wafio_engine_loader::{CAN_LOAD, DEFAULT_LIBRARY_PATH, LibraryInfo, Trust};

/// `1` makes a missing or unusable library fatal at start. The release installers set it for the service, and an agent
/// that ran with a library sets it for its reload successor.
pub const ENV_REQUIRED: &str = "WAFIO_ENGINE_LIB_REQUIRED";
/// The environment name of `--engine-lib`.
pub const ENV_LIBRARY: &str = "WAFIO_ENGINE_LIB";

static LOADED: OnceLock<LibraryInfo> = OnceLock::new();

/// The library this process runs with, if it loaded one.
pub fn loaded() -> Option<&'static LibraryInfo> {
    LOADED.get()
}

/// What to do at start, decided from the facts alone.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Nothing to load. The line, if any, is logged.
    Skip(Option<String>),
    /// Do not start.
    Refuse(String),
    /// Try the library at this path.
    Load {
        path: String,
        explicit: bool,
        required: bool,
    },
}

/// `configured` is `--engine-lib` or its environment variable, empty when neither is set.
pub fn plan(configured: &str, engine_installed: bool, required: bool, can_load: bool) -> Plan {
    let configured = configured.trim();
    let explicit = !configured.is_empty();
    if engine_installed {
        return Plan::Skip(explicit.then(|| {
            "--engine-lib is ignored: this binary has the semantic engine linked in".to_string()
        }));
    }
    if !can_load {
        return if explicit {
            Plan::Refuse(format!(
                "--engine-lib {configured}: a static musl agent cannot load a shared library; run the glibc build, or the official agent with the engine linked in"
            ))
        } else {
            Plan::Skip(None)
        };
    }
    Plan::Load {
        path: if explicit {
            configured.to_string()
        } else {
            DEFAULT_LIBRARY_PATH.to_string()
        },
        explicit,
        required,
    }
}

fn trust() -> Trust {
    #[cfg(feature = "test-owner")]
    return Trust::root_or_current_user();
    #[cfg(not(feature = "test-owner"))]
    Trust::root_only()
}

/// The line for a library that cannot be used while `ENV_REQUIRED` is set. A reload successor has a process it
/// replaces; a cold start has none, and the line must not say otherwise.
fn refusal(path: &str, error: &dyn std::fmt::Display, successor: bool) -> String {
    if successor {
        format!(
            "engine library {path}: {error}; the process this one replaces runs with it, so this one does not start without it"
        )
    } else {
        format!(
            "engine library {path}: {error}; {ENV_REQUIRED}=1 is set, so the agent does not start without it"
        )
    }
}

/// Loads the library, if the facts say so, and installs it as the engine of the process. Call it before any thread starts.
pub fn load_at_start(configured: &str) -> Result<(), String> {
    load(configured, true)
}

/// The same step for `--features`, which prints the engine and so has no need of the line about a default path with no
/// library in it. Every other line and every refusal is the same as at start.
pub fn load_for_report(configured: &str) -> Result<(), String> {
    load(configured, false)
}

fn load(configured: &str, say_missing_default: bool) -> Result<(), String> {
    let required = std::env::var(ENV_REQUIRED).is_ok_and(|v| v == "1");
    let installed = wafio_engine_api::engine().info().installed;
    match plan(configured, installed, required, CAN_LOAD) {
        Plan::Skip(line) => {
            if let Some(l) = line {
                tracing::info!("{l}");
            }
            Ok(())
        }
        Plan::Refuse(why) => Err(why),
        Plan::Load {
            path,
            explicit,
            required,
        } => match wafio_engine_loader::install(Path::new(&path), trust()) {
            Ok(info) => {
                tracing::info!(
                    "engine library loaded: {} {} (interface {}, engine-api {}) from {}",
                    info.name,
                    info.version,
                    info.interface_version,
                    info.api_revision,
                    info.path.display()
                );
                let _ = LOADED.set(info);
                Ok(())
            }
            Err(e) if required => Err(refusal(
                &path,
                &e,
                crate::reload::predecessor_ready_socket().is_some(),
            )),
            Err(e) if e.is_missing() && !explicit => {
                if say_missing_default {
                    tracing::info!(
                        "no engine library at {path}: running without a semantic engine"
                    );
                }
                Ok(())
            }
            Err(e) => {
                tracing::warn!("engine library not loaded: {e}; running without a semantic engine");
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_with_an_engine_linked_in_does_not_look_for_a_library() {
        assert_eq!(plan("", true, false, true), Plan::Skip(None));
        assert!(matches!(
            plan("/x.so", true, false, true),
            Plan::Skip(Some(_))
        ));
    }

    #[test]
    fn an_engine_less_binary_looks_at_the_default_path_unless_told_otherwise() {
        assert_eq!(
            plan("", false, false, true),
            Plan::Load {
                path: DEFAULT_LIBRARY_PATH.into(),
                explicit: false,
                required: false
            }
        );
        // A probe that names nothing plans the default path too, whatever the variable says.
        assert_eq!(
            plan("", false, true, true),
            Plan::Load {
                path: DEFAULT_LIBRARY_PATH.into(),
                explicit: false,
                required: true
            }
        );
        assert_eq!(
            plan(" /opt/e.so ", false, true, true),
            Plan::Load {
                path: "/opt/e.so".into(),
                explicit: true,
                required: true
            }
        );
    }

    #[test]
    fn a_static_musl_agent_refuses_a_library_that_was_asked_for_and_otherwise_stays_quiet() {
        assert_eq!(plan("", false, false, false), Plan::Skip(None));
        let Plan::Refuse(why) = plan("/opt/e.so", false, false, false) else {
            panic!("a musl build must refuse")
        };
        assert!(why.contains("musl") && why.contains("/opt/e.so"), "{why}");
    }

    #[test]
    fn a_required_library_that_is_missing_is_refused_in_words_true_for_both_starts() {
        let why = "the file does not exist";
        let cold = refusal("/usr/lib/wafio/e.so", &why, false);
        assert_eq!(
            cold,
            "engine library /usr/lib/wafio/e.so: the file does not exist; WAFIO_ENGINE_LIB_REQUIRED=1 is set, so the agent does not start without it"
        );
        assert!(!cold.contains("replaces"), "{cold}");
        let successor = refusal("/usr/lib/wafio/e.so", &why, true);
        assert_eq!(
            successor,
            "engine library /usr/lib/wafio/e.so: the file does not exist; the process this one replaces runs with it, so this one does not start without it"
        );
        assert!(!successor.contains(ENV_REQUIRED), "{successor}");
    }
}
