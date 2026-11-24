//! Control-plane link of the WAF agent: the gRPC stream, reconnect backoff, bundle cache,
//! bundle puller, telemetry and the malware database.

#![forbid(unsafe_code)]

mod bundle_cache;
mod bundle_puller;
mod certificates;
mod edge;
mod grpc_reconnect;
mod grpc_stream;
mod json_members;
mod malware_database;
pub mod proxy_env;
mod timestamp;
mod waf_telemetry;

pub use bundle_cache::{
    BUNDLE_CACHE_FILE_NAME, BUNDLE_SOURCE_CACHE, BUNDLE_SOURCE_CACHE_STALE, BUNDLE_SOURCE_LIVE,
    CacheReadError, CacheStart, CacheWrite, CachedBundle, DEFAULT_BUNDLE_CACHE_MAX_AGE, TempGuard,
    create_temp, load_bundle_cache, save_bundle_cache,
};
pub use bundle_puller::{BundleError, BundleProbe, BundleSink};
pub use certificates::{AckCode, CertificateSink};
pub use edge::{EdgeSink, NoEdge, PurgeCode};
pub use grpc_reconnect::{
    GRPC_CLIENT_KEEPALIVE_TIME, GRPC_CLIENT_KEEPALIVE_TIMEOUT, RECONNECT_BACKOFF_MAX,
    RECONNECT_BACKOFF_MIN, RECONNECT_HEALTHY_AFTER, RECONNECT_JITTER, ReconnectBackoff, jitter,
};
pub use grpc_stream::{
    AgentStats, ControlConfig, ControlLink, DEFAULT_SECURITY_DATA_DIR, HANDSHAKE_TIMEOUT,
    HEARTBEAT_INTERVAL, HeartbeatCounters, Hooks, LinkError, WAF_BUNDLE_RETRY_MAX,
    default_server_name,
};
pub use malware_database::{FetchResult, MAX_MALWARE_SNAPSHOT_BYTES, SecurityData};
pub use timestamp::Timestamp;
pub use waf_telemetry::{
    DecisionEvent, Redactor, TELEMETRY_QUEUE_CAP, TelemetryStats, clamp_i32, replace_invalid_utf8,
    to_proto,
};
// The messages of the certificate and edge hooks, so the agent names them through this crate.
pub use wafio_proto::v1::{
    CachePurge, CertificateInstall, CertificateStatus, EdgeCacheCounters, EdgeCompressionCounters,
    EdgeFeatureState, EdgeStatus,
};
