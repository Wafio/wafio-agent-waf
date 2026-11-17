//! The per-engine evidence thresholds `SemanticConfig` carries. Engine crates use these types instead of
//! defining their own. `block_threshold` and `soft_threshold` are how much evidence a detector wants before it
//! reports a strong or a weak detection.

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SqlPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct XssPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CmdPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PhpPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PythonPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LfiPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SsrfPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct JavaPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NosqlPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SstiPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct XxePolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DeserPolicy {
    pub block_threshold: f64,
    pub soft_threshold: f64,
}
