//! The memory tier for the files of an app's static folder: a file up to 1 MiB, as it was sent
//! (compressed or not), is kept so that the next visitor who takes the same encoding gets it with
//! no read of the file and no compression. The folder still looks the file up on every request,
//! so a file that changed is another key: its path, device, inode, size and modification time are
//! part of it. The tier shares the memory limit of the app's cache and its LRU.

use std::sync::Arc;

use super::key::{Bucket, FileId, StaticFile, static_key};
use super::store::AppCache;
use crate::config::Route;
use crate::request::InboundRequest;
use crate::response::OutboundResponse;
use crate::signed_in::is_signed_in;

/// Where the answer for a file is kept.
pub(crate) type StaticKey = FileId;

/// The memory tier as one request sees it: the app's store, and what of the request and the
/// settings changes the answer for a file.
#[derive(Clone)]
pub(crate) struct StaticMemory {
    app: Arc<AppCache>,
    bucket: Bucket,
    signed_in: bool,
    shape: Vec<u8>,
}

impl StaticMemory {
    pub fn key(&self, file: &StaticFile<'_>) -> StaticKey {
        static_key(file, self.bucket, self.signed_in, &self.shape)
    }

    pub fn get(&self, key: &StaticKey) -> Option<OutboundResponse> {
        self.app.index().static_copy(key)
    }

    pub fn put(&self, key: StaticKey, answer: &OutboundResponse) {
        self.app.index().admit_static(key, answer.clone());
    }
}

/// The memory tier for a request to the folder of `route`, `None` when the app has no cache.
/// `max_age_s` is the folder's browser cache time, which is part of the answer.
pub(crate) fn static_memory(
    route: &Route,
    req: &InboundRequest,
    max_age_s: u32,
) -> Option<StaticMemory> {
    let (_, app) = route.cache_active()?;
    let mut shape = max_age_s.to_le_bytes().to_vec();
    let min_bytes = route
        .compression
        .as_ref()
        .map_or(u64::MAX, |c| c.min_bytes as u64);
    shape.extend_from_slice(&min_bytes.to_le_bytes());
    Some(StaticMemory {
        app: app.clone(),
        // With compression off every visitor gets the file as it is.
        bucket: if route.compression.is_some() {
            Bucket::of(req, true)
        } else {
            Bucket::Identity
        },
        signed_in: is_signed_in(req, &route.session),
        shape,
    })
}
