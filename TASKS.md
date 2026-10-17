# Tasks

## v0.2.0 Dual Export

- [x] Inspect the current `zzz_calculator` README and native import implementation.
- [x] Confirm current Zenless Optimizer ZOOD stat keys, including Wind DMG.
- [x] Define fixed default filenames and the one-EXE/two-JSON behavior.
- [x] Finish the dual-export implementation and focused Rust tests.
- [x] Update README, changelog, release notes, and release checklist.
- [x] Run Rust formatting, tests, Clippy, and release build.
- [x] Export a historical CN 3.1.0 inventory and validate both files against their target schemas.
- [x] Review the final diff before committing or publishing.

## Later Version Updates

- [ ] Re-capture two unchanged-inventory login sessions after the game protocol changes.
- [ ] Update only the current protocol schema, constants, command ID, and set mappings.
- [ ] Re-run both format integrations before publishing a new release.

## v0.2.0 CN 3.2 Release Preparation - 2026-10-18

- [x] Record the user-operated CN 3.2 single-session success (2,321 discs).
- [x] Read saved metadata: complete target response and 2,321 records in both output arrays.
- [x] Replace candidate-only support text with the narrow confirmed acceptance scope.
- [x] Document current live-only target, fallback behavior, and missing capture timeout.
- [x] Prepare versioned EXE, ZIP, and SHA256SUMS from the existing user-run binary.
- [x] Check the EXE copy hash and ZIP entry allowlist; account data is excluded.
- [x] Review source changes and exclude private capture/export/session artifacts from the source allowlist.
- [x] Prepare Chinese Release draft and an ignored local manual-publishing runbook.
- [x] Prepare the local source commit and annotated v0.2.0 tag for user-operated push.
- [ ] Establish clean-checkout source/binary reproducibility before claiming a reproducible build.
- [ ] User: push main and v0.2.0, upload three assets, review and publish the GitHub Release.
- [ ] Complete controlled account-switch, inventory-change, and small-inventory acceptance.
- [ ] Check representative CN 3.2 fields against the game UI and import both target formats.

The earlier v0.2 dual-export verification checklist is historical and is not evidence of a new
CN 3.2 test run. No tests, builds, or live captures were run during this preparation pass.
