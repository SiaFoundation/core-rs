---
sia_storage_napi: minor
sia_storage_ffi: minor
sia_storage_wasm: minor
---

# Add host-query support to the bindings

Added optional `HostQuery` parameters to `Sdk.hosts` and `SharedSdk.hosts` in
the N-API and UniFFI bindings.

Native bindings expose location, protocol, country, limit, and offset filters.
WASM now exposes location filtering and continues to enforce QUIC because
browser transports do not support SiaMux. Its generated TypeScript declaration
now correctly marks every `HostQuery` field as optional.
