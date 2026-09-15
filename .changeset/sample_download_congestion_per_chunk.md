---
sia_storage: patch
sia_storage_ffi: patch
sia_storage_napi: patch
sia_storage_wasm: patch
---

# Sample the download inflight controller per chunk rather than per sector read, and let it climb further before settling.

The latency a chunk reports is the slowest read that finished it, not the chunk's wall time. A chunk that completed nine shards quickly and then sat idle waiting for a racer to replace one bad host was charging that stall to the pipeline, so a single bad peer read as congestion and narrowed the limit for every transfer.

The controller also backs off when reads time out, since a saturated link reads as flat goodput rather than as a decline. Timeouts count once per host and decay as windows complete, so neither one unreachable peer nor strays spread over a long download narrows the pipeline.
