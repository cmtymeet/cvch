# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- cvch is a reusable voucher helper for cvld/cfrm admission. cfrm owns
  community rules (who may sponsor, quotas, expiry policy); cvch proves
  one-use member-bound redemption without revealing sponsor identity to
  the operator or the redeemer graph.
- Sponsor identity must never enter attestation output, logs, errors or
  fixtures. One voucher redeems once; concurrent attempts cannot both
  succeed — the host owns the atomic store (issue-once semantics like
  cvld receiptStore). Device count must not multiply redemptions.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception: combined works
  may link statically or dynamically without relinking duties; library
  modifications stay LGPL. Do not add implementation code available
  only under the full GPL or AGPL.
- No live issuance in tests. Fixtures only.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds per task status; use GHA, Crow fallback while GHA is down.
- Validate single-use atomicity hooks, member binding, expiry, sponsor
  unlinkability and uniform errors with fixtures.
