# Sia Core RS

This is a Rust implementation of core Sia types. It is intended to be used as a 
library for projects that need to interact with Sia at a low level. It is not 
intended to be a full Sia node implementation.

This project is currently in the early stages of development and is not yet ready 
for production use. The API will have breaking changes.

## Features
- [x] BIP-39 Seeds
- [x] Addresses
- [x] Sia binary encoding
- [ ] Sector roots
- [ ] Merkle proofs

### v1
- [x] Unlock conditions
- [x] Transaction signing

### v2
- [x] Spend policies
- [ ] Transaction signing
- [ ] RHP4
- [ ] State tree verification