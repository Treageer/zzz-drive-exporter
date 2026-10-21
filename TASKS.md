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

## CN 3.3 Current-Version Repair - 2026-10-21

- [x] Confirm installed CNPRODWin3.3.0 from version_info and config.ini (read-only).
- [x] Locate user-operated capture; current binary waits for stale CN 3.2 command 0x0F5D.
- [x] Identify the current drive-disc response and exact schema/XOR constants.
- [x] Preserve a bounded snapshot of already captured messages; do not start live capture.
- [x] Update current-version stop condition, decoder, and statistical prior only.
- [x] Validate the saved current-session response offline without historical pads/templates.
- [x] Build a separate repaired executable when needed; do not replace the running old file.
- [ ] User manually verifies one fresh login and checks the exported inventory.

Scope: current CN 3.3 only; no future-version autodetection or broad compatibility framework.
Do not operate the game, start capture, or run the full test suite in this pass.

本轮结果：CN 3.3 / 0x06D0，144264 字节，2335 条。独立初始快照不含 pad／明文／库存，
单会话恢复 MT 200/200，两个格式的 UID、等级、部位、锁定一致。恢复后才作历史身份比对：
对旧版输出 UID 去除 3.2 的传输混淆后，2321 条共同物品 ID 与等级全部一致，新增 14 条。
旧版锁定读取本来全为 false，不能作为当前锁定语义的真值；需游戏抽查。
