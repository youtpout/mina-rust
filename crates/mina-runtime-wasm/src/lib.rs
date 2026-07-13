//! Thin WebAssembly transport for [`mina_runtime`].
//!
//! The methods are synchronous on purpose: proof generation must run inside a
//! Web Worker so it cannot block the browser's UI thread. The JavaScript worker
//! adapter is responsible for request scheduling and cancellation.

use wasm_bindgen::prelude::*;

use mina_runtime::{Backend, BackendConfig};

/// Owns one backend resource domain inside a Web Worker. Circuit and Ledger
/// handles are valid only for the lifetime of this object.
#[wasm_bindgen(js_name = MinaRuntime)]
pub struct WasmBackend {
    inner: Backend,
}

#[wasm_bindgen(js_class = MinaRuntime)]
impl WasmBackend {
    #[wasm_bindgen(constructor)]
    pub fn new(max_resources: Option<u32>) -> Self {
        let mut config = BackendConfig::default();
        if let Some(max_resources) = max_resources {
            config.max_resources = max_resources as usize;
        }
        Self {
            inner: Backend::new(config),
        }
    }

    /// Executes the same versioned JSON request accepted by the NAPI transport.
    pub fn execute(&self, request: &str) -> String {
        self.inner.execute_json(request)
    }

    #[wasm_bindgen(getter)]
    pub fn info(&self) -> String {
        serde_json::to_string(&self.inner.info()).expect("BackendInfo is serializable")
    }
}

#[wasm_bindgen(js_name = backendInfo)]
pub fn backend_info() -> String {
    serde_json::to_string(&Backend::default().info()).expect("BackendInfo is serializable")
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn request(payload: Value) -> String {
        json!({ "version": 1, "payload": payload }).to_string()
    }

    #[test]
    fn uses_the_core_wire_contract_without_translation() {
        let wasm = WasmBackend::new(Some(8));
        let core = Backend::new(BackendConfig { max_resources: 8 });
        let input = request(json!({ "operation": "getInfo" }));

        assert_eq!(wasm.execute(&input), core.execute_json(&input));
        assert_eq!(wasm.info(), serde_json::to_string(&core.info()).unwrap());
    }

    #[test]
    fn structured_errors_are_byte_identical() {
        let wasm = WasmBackend::new(None);
        let core = Backend::default();
        let input = request(json!({ "operation": "notAnOperation" }));

        assert_eq!(wasm.execute(&input), core.execute_json(&input));
    }

    #[test]
    fn deterministic_circuit_artifacts_are_byte_identical() {
        let wasm = WasmBackend::new(Some(8));
        let core = Backend::new(BackendConfig { max_resources: 8 });
        let input = request(json!({
            "operation": "compileCircuit",
            "input": {
                "circuit": {
                    "aux_count": 2,
                    "output": [{ "terms": [["1", 1]] }],
                    "constraints": [{
                        "kind": "square",
                        "v": { "terms": [["1", 0]] },
                        "square": { "terms": [["1", 1]] }
                    }]
                }
            }
        }));

        assert_eq!(wasm.execute(&input), core.execute_json(&input));
    }
}
