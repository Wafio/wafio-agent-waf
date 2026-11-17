//! The `App` type, as the agent reads it from bundles. `Deployment` is control-plane only.

use serde::{Deserialize, Serialize};

/// A WAF-target application within a project.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct App {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub listen_host: Option<String>,
    pub listen_port: Option<i64>,
    pub upstream_url: Option<String>,
    /// RFC 3339; kept as text, the agent never reads it.
    pub created_at: String,
    pub updated_at: String,
}
