# o1js browser backend

This crate exposes the transport-independent `o1js-backend` v1 JSON contract
through `wasm-bindgen`. It contains no duplicate Mina or Pickles protocol
conversion code.

The backend performs CPU-heavy work synchronously. Instantiate and call it from
a Web Worker; the o1js JavaScript adapter owns scheduling, cancellation, and
worker lifecycle.

Mina's WebAssembly dependencies use threads and shared memory. Build the final
artifact with the workspace's nightly atomics configuration and a rebuilt
standard library:

```text
cargo +nightly build -p o1js-backend-wasm \
  --target wasm32-unknown-unknown \
  -Z build-std=std,panic_abort
```

The generated module therefore requires a cross-origin-isolated browser context
with `SharedArrayBuffer` support, like the existing Mina web node.
