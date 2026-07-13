//! Thin Node-API transport for [`o1js_backend`].

use std::sync::Arc;

use napi::bindgen_prelude::{AbortSignal, AsyncTask, Env, Result, Task};
use napi_derive::napi;
use o1js_backend::{Backend, BackendConfig};

/// A cancellable execution of one versioned backend request.
pub struct ExecuteTask {
    backend: Arc<Backend>,
    request: String,
}

#[napi]
impl Task for ExecuteTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(self.backend.execute_json(&self.request))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Owns one backend resource domain. Circuit and Ledger handles are valid only
/// for the lifetime of this object.
#[napi(js_name = "MinaRustBackend")]
pub struct NativeBackend {
    inner: Arc<Backend>,
}

#[napi]
impl NativeBackend {
    #[napi(constructor)]
    pub fn new(max_resources: Option<u32>) -> Self {
        let mut config = BackendConfig::default();
        if let Some(max_resources) = max_resources {
            config.max_resources = max_resources as usize;
        }
        Self {
            inner: Arc::new(Backend::new(config)),
        }
    }

    /// Executes a lightweight request on the JavaScript thread.
    #[napi]
    pub fn execute(&self, request: String) -> String {
        self.inner.execute_json(&request)
    }

    /// Executes proving, verification, or Ledger work on the N-API worker
    /// pool. Passing an AbortSignal lets JavaScript cancel queued work.
    #[napi]
    pub fn execute_async(
        &self,
        request: String,
        signal: Option<AbortSignal>,
    ) -> AsyncTask<ExecuteTask> {
        AsyncTask::with_optional_signal(
            ExecuteTask {
                backend: Arc::clone(&self.inner),
                request,
            },
            signal,
        )
    }

    #[napi(getter)]
    pub fn info(&self) -> String {
        serde_json::to_string(&self.inner.info()).expect("BackendInfo is serializable")
    }
}

#[napi]
pub fn backend_info() -> String {
    serde_json::to_string(&Backend::default().info()).expect("BackendInfo is serializable")
}
