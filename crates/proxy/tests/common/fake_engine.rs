//! The harness of the test files whose tests need something to detect. A file that tests the proxy without an engine
//! does not include this one, and the private repository, which runs these tests with the real engine, does not either.

use std::net::SocketAddr;

use wafio_proxy::AppSpec;

use crate::common::Harness;

impl Harness {
    /// Like [`Harness::serve`], with the fake engine installed first. Installing is idempotent: the first call of the
    /// process counts.
    pub fn serve_with_fake_engine(apps: Vec<AppSpec>) -> (Harness, SocketAddr) {
        wafio_engine_fake::install();
        Harness::serve(apps)
    }
}
