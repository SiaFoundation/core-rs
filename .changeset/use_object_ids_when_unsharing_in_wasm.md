---
sia_storage_wasm: major
---

# Use object IDs when unsharing in WASM

`Sdk.unshareObject` now takes the object's ID string instead of a complete
`PinnedObject`, matching the core SDK and the native bindings.

```js
-await sdk.unshareObject(sharingKey, object);
+await sdk.unshareObject(sharingKey, object.id());
```
