# Changelog

## 2026-09-26

- Configurable grace period after `expiresAt` (`{ graceSeconds }`) returning `expired_in_grace`, so a product can warn about a late renewal instead of blocking a paying customer the moment the license lapses.

## 2026-09-25

- License file envelope: JSON `{ version, token, issuer, notes }` with `readLicenseFile` / `writeLicenseFile`, so a license ships as a file a person can read and a later format can be refused instead of misread.

## 2026-09-24

- Key rotation: `verify` accepts a list of public keys, `kid` in claims selects one and an unknown `kid` is `invalid_signature`, so a signing key can be replaced over an overlap period instead of on a flag day.

## 2026-09-23

- CLI (`offline-license keygen | issue | verify`) built on `node:util` `parseArgs`, zero dependencies, with tests that spawn it, so issuing and checking a license no longer needs a hand-written Node script.
