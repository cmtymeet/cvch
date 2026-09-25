# Changelog

## Unreleased

- Repository transferred to github.com/corbet-foss/cvch (old cmtymeet URLs redirect); package metadata points there.

## 0.2.1

- Package metadata points at the current GitHub repository.
- Released from CI through crates.io trusted publishing.

## 0.2.0

- New `SpendStore` trait + `redeem()` audited path + `Redemption` type.
  Host implements atomic durable claims (e.g. cvld receipt domain);
  no store ships in the library. Failed verification burns nothing.
- 8 fixture tests, no live issuance.

## 0.1.1

- Hardened tests: malformed/forged rejection paths, receipt determinism,
  community scoping, attestation sponsor/voucher unlinkability.
- No API changes.

## 0.1.0 — initial scaffold

- Sponsor-signed vouchers with expiry, single-use receipt id for host
  atomic store, member-bound binding, attestation bytes without sponsor
  identity for cvld issuance.
- Fixture-only tests, no live issuance.
- Licensed LGPL-3.0-only WITH LGPL-3.0-linking-exception.
