//! Transport-independent Mina and Pickles backend for o1js.
//!
//! This crate is the single production boundary between o1js and the Rust
//! implementation. NAPI and WASM crates must be thin transports over this API;
//! they must not call `pickles`, `snarky`, or `mina-tree` directly.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
};

mod backend;
mod contract;
mod transaction;

pub use backend::{Backend, BackendError};
pub use contract::*;

/// Configuration shared by every transport using a backend instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendConfig {
    /// Maximum number of live opaque resources retained by the backend.
    pub max_resources: usize,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            max_resources: 1_024,
        }
    }
}

/// An opaque identifier suitable for crossing a native or WASM boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ResourceId(u64);

impl ResourceId {
    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn from_raw(id: u64) -> Self {
        Self(id)
    }
}

/// Errors produced by the transport-independent resource layer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResourceError {
    #[error("the backend resource limit ({limit}) has been reached")]
    LimitReached { limit: usize },
    #[error("resource {id} does not exist")]
    NotFound { id: u64 },
    #[error("the backend resource lock is poisoned")]
    Poisoned,
}

/// Thread-safe storage for long-lived prover keys, circuits, and Ledger state.
///
/// Values never cross the transport boundary directly. A transport receives a
/// [`ResourceId`] and resolves it through the backend for each operation.
pub struct ResourceStore<T> {
    limit: usize,
    next_id: AtomicU64,
    values: RwLock<HashMap<ResourceId, T>>,
}

impl<T> ResourceStore<T> {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            next_id: AtomicU64::new(1),
            values: RwLock::new(HashMap::new()),
        }
    }

    pub fn insert(&self, value: T) -> Result<ResourceId, ResourceError> {
        let mut values = self.values.write().map_err(|_| ResourceError::Poisoned)?;
        if values.len() >= self.limit {
            return Err(ResourceError::LimitReached { limit: self.limit });
        }

        let id = ResourceId(self.next_id.fetch_add(1, Ordering::Relaxed));
        values.insert(id, value);
        Ok(id)
    }

    pub fn with<R>(&self, id: ResourceId, f: impl FnOnce(&T) -> R) -> Result<R, ResourceError> {
        let values = self.values.read().map_err(|_| ResourceError::Poisoned)?;
        let value = values
            .get(&id)
            .ok_or(ResourceError::NotFound { id: id.get() })?;
        Ok(f(value))
    }

    pub fn remove(&self, id: ResourceId) -> Result<T, ResourceError> {
        self.values
            .write()
            .map_err(|_| ResourceError::Poisoned)?
            .remove(&id)
            .ok_or(ResourceError::NotFound { id: id.get() })
    }

    pub fn len(&self) -> Result<usize, ResourceError> {
        Ok(self
            .values
            .read()
            .map_err(|_| ResourceError::Poisoned)?
            .len())
    }

    pub fn is_empty(&self) -> Result<bool, ResourceError> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resources_have_opaque_stable_ids_and_explicit_lifetimes() {
        let store = ResourceStore::new(2);
        let first = store.insert(String::from("circuit")).unwrap();
        let second = store.insert(String::from("ledger")).unwrap();

        assert_eq!(first.get(), 1);
        assert_eq!(store.with(second, String::len).unwrap(), 6);
        assert_eq!(
            store.insert(String::from("proof")),
            Err(ResourceError::LimitReached { limit: 2 })
        );
        assert_eq!(store.remove(first).unwrap(), "circuit");
        assert_eq!(store.len().unwrap(), 1);
    }
}
