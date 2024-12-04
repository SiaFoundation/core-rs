---
sia_sdk: minor
---

# Refactor V1 transaction signing

Replaced `v1::Transaction::sign` with `v1::Transaction::whole_sig_hash` and `v1::Transaction::partial_sig_hash`. This change is primarily to provide a more consistent experience with `core` and the V2::Transaction API.
