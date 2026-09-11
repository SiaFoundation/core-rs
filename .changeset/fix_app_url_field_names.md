---
sia_storage: patch
---

# Fixed the logo and service URL fields of `App` never decoding.

`App` relied on `rename_all` for every field, so it looked for `logoUrl` and `serviceUrl` while the indexer sends `logoURL` and `serviceURL`. Both are optional, so the mismatch left them `None` on every account rather than failing, and `AppMetadata` was unaffected because it already renames them explicitly. Callers reading `Account::app` now get the values the indexer holds.
