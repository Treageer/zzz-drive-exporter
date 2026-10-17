# Plan

## Current Goal

Prepare `v0.2.0` for release from the current one-login-first CNPRODWin3.2.0 implementation.
The remote currently has `v0.1.0`; v0.2.0 includes the pending dual-export changes as well.

## Scope

- Live target: CNPRODWin3.2.0 / `0x0F5D`.
- Single-session recovery first, historical paired recovery only as fallback.
- Write ZOOD v1 and zzz_calculator native v1 from one decoded inventory.
- Keep captures, exports, pads/seeds, and private logs out of Git and download archives.
- Preserve historical offline schemas without claiming older-version live support.

## Acceptance Evidence And Remaining Gates

- 2026-10-18: user-operated capture automatically stopped at a complete 145,929-byte response;
  CLI reported 2,321 discs via single-session recovery; both saved JSON arrays contain 2,321.
- This does not yet establish cross-account, changed-inventory, small-inventory, in-game
  field-by-field accuracy, or target-application import acceptance for CN 3.2.
- Current preparation is documentation and packaging only. No new game/capture execution,
  test suite, rebuild, or clean-checkout reproducibility run is authorized in this pass.
- Before publication: review the exact source diff, complete or explicitly defer verification
  gates, commit/tag the intended source, and ensure the asset corresponds to that source.
