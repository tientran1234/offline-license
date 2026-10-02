# Changelog

## 2026-10-02

- Metered limits: a tamper-evident `UsageLedger` (file and localStorage) that counts consumption against `limits` and refuses past the cap, with entries HMAC-chained with the license id so editing the file is detectable, so a product metering exports or seats no longer has to keep its own tally in a number anyone can lower.

## 2026-09-30

- Valued features: `features` may be a record (`{ sso: true, seats: 25, tier: "pro" }`) alongside the array form, with `guard.value("seats")` typed and old tokens verifying unchanged, so an entitlement that carries a tier or a count no longer has to hide in `metadata`, which nothing checks.

## 2026-09-28

- `MonotonicClock` store for browsers (`localStorage`) mirroring `FileStore` semantics, so a dashboard or an Electron renderer can keep its high-water mark across page loads and catch a wound-back clock instead of having the check available but unusable.

## 2026-09-27

- Browser build on WebCrypto Ed25519 (`offline-license/web`) for Electron renderers and dashboards, running the same test vectors as Node, so a license can be checked where no Node API is in reach without a second implementation drifting from the first.

## 2026-09-26

- Configurable grace period after `expiresAt` (`{ graceSeconds }`) returning `expired_in_grace`, so a product can warn about a late renewal instead of blocking a paying customer the moment the license lapses.

## 2026-09-25

- License file envelope: JSON `{ version, token, issuer, notes }` with `readLicenseFile` / `writeLicenseFile`, so a license ships as a file a person can read and a later format can be refused instead of misread.

## 2026-09-24

- Key rotation: `verify` accepts a list of public keys, `kid` in claims selects one and an unknown `kid` is `invalid_signature`, so a signing key can be replaced over an overlap period instead of on a flag day.

## 2026-09-23

- CLI (`offline-license keygen | issue | verify`) built on `node:util` `parseArgs`, zero dependencies, with tests that spawn it, so issuing and checking a license no longer needs a hand-written Node script.
