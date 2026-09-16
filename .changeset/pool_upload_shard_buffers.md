---
sia_storage: patch
---

# Pool upload shard buffers

Upload slabs now draw their shard buffers from a per-upload pool and return
them when the last handle drops, instead of allocating and freeing 4 MiB per
shard. This reduces memory pressure during large concurrent uploads.
