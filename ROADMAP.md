# Roadmap

One item per pull request, in order.

- [ ] CLI (`offline-license keygen | issue | verify`) built on `node:util` `parseArgs`, zero dependencies, with tests that spawn it.
- [ ] Key rotation: accept a list of public keys; `kid` in claims selects one; unknown `kid` → `invalid_signature`.
- [ ] License file envelope: JSON `{ version, token, issuer, notes }` with `readLicenseFile` / `writeLicenseFile`.
- [ ] Configurable grace period after `expiresAt` (`{ graceSeconds }`) returning `expired_in_grace` so the UI can warn instead of block.
- [ ] Browser build on WebCrypto Ed25519 (`offline-license/web`) for Electron renderers and dashboards; same test vectors as Node.
- [ ] `MonotonicClock` store for browsers (`localStorage`) mirroring `FileStore` semantics.
