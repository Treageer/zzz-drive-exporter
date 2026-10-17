# Changelog

## 0.2.0 - 2026-10-18

- Prefer one-session pad recovery from the long drive-disc response, with MT19937-64 and strict
  protobuf validation; retain two-session recovery only as a fallback.
- Distinguish single-session exports from paired fallback exports in the CLI outcome.
- Support CNPRODWin3.2.0 command `0x0F5D` for live capture and single-session export.
- Record a user-operated CN 3.2 login capture: automatic stop at a complete 145,929-byte response,
  2,321 decoded discs, and 2,321 records in each output without paired fallback.
- Document unverified account-switch, inventory-change, and small-inventory cases, and the lack
  of an automatic capture timeout.
- Write `exports/zzz-drives-zood-v1.json` and
  `exports/zzz-drives-zzz-calculator-v1.json` from one successful inventory decode.
- Add native `zzz-calculator-drive-disc-export` v1 output with normalized actual stat values.
- Replace the two fixed default snapshot files on later successful runs.
- Correct ZOOD property mapping for Anomaly Mastery, Physical/Fire/Ice/Electric/Ether DMG, and
  Wind DMG.
- Validate the historical CN 3.1.0 inventory as 2029/2029 records through the current
  `zzz_calculator` native importer.

## 0.1.0 - 2026-08-16

- Capture ZZZ gateway UDP traffic through Windows `pktmon` with a port-level filter.
- Stop automatically after a complete CN 3.1.0 drive-disc response is reassembled.
- Recover per-login MT19937-64 session pads from two unchanged-inventory sessions.
- Decode current drive-disc protobuf records and export optimizer-compatible `ZOOD v1` JSON.
- Preserve captures locally for automatic baseline discovery and troubleshooting.
