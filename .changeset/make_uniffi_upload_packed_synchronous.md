---
sia_storage_ffi: major
---

# Make UniFFI `upload_packed` synchronous

Creating a packed upload does not perform asynchronous work or start a Tokio
task. Call `upload_packed` directly instead of awaiting it. Operations on the
returned upload, including `add` and `finalize`, remain asynchronous.

```python
-upload = await sdk.upload_packed(options)
+upload = sdk.upload_packed(options)
```
