# Roadmap

One item per pull request, in order.

- [x] CLI (`offline-license keygen | issue | verify`) built on `node:util` `parseArgs`, zero dependencies, with tests that spawn it.
- [x] Key rotation: accept a list of public keys; `kid` in claims selects one; unknown `kid` → `invalid_signature`.
- [x] License file envelope: JSON `{ version, token, issuer, notes }` with `readLicenseFile` / `writeLicenseFile`.
- [x] Configurable grace period after `expiresAt` (`{ graceSeconds }`) returning `expired_in_grace` so the UI can warn instead of block.
- [x] Browser build on WebCrypto Ed25519 (`offline-license/web`) for Electron renderers and dashboards; same test vectors as Node.
- [x] `MonotonicClock` store for browsers (`localStorage`) mirroring `FileStore` semantics.

## Batch 2 — set by the owner, 30 Sep 2026

Same rule: one item per change, in order.

- [x] Valued features: `features` may be a record (`{ sso: true, seats: 25, tier: "pro" }`) alongside the array form; `guard.value("seats")` typed; old tokens keep verifying unchanged.
- [x] Metered limits: a tamper-evident `UsageLedger` (file and localStorage) that counts consumption against `limits` and refuses past the cap; entries HMAC-chained with the license id so editing the file is detectable.
- [x] Offline activation exchange: the product emits a signed machine claim (fingerprint + nonce), the issuer returns a machine-bound license; CLI `request` and `fulfil` subcommands and a documented flow for air-gapped installs.
- [ ] Renewal chain: a license may carry `renews: <previous id>`; `verify` accepts the newer license while the old one is in grace, and refuses a renewal that skips a generation.
- [ ] Check audit: `LicenseGuard({ onCheck })` plus a small rotating log store so a self-hosted install can show "last verified at" and the last failures on its admin page.
- [ ] Shared test vectors: a `vectors/` fixture set (keys, tokens, expected results) run by both the Node and the web build, published so third-party implementations can prove compatibility.
