# Decisions

## 2026-08-16 - One Executable Produces Two Import Files

Context: The exporter already captures and decrypts the full Drive Disc inventory. A second target
format does not require another capture process or another executable.

Decision: Continue developing the same standalone `zzz-drive-exporter` binary. A successful decode
writes both ZOOD v1 and zzz_calculator native v1 JSON from the same `equip.json` data.

Consequences: Both outputs always describe the same capture. A failure to build either document
prevents the export operation from being reported as successful.

## 2026-08-16 - Fixed Snapshot Filenames

Context: Timestamped filenames hide the format and accumulate old account inventories.

Decision: Use `zzz-drives-zood-v1.json` and `zzz-drives-zzz-calculator-v1.json`. Default runs replace
these current-inventory snapshots. Explicit custom paths remain protected unless `--force` is used.

Consequences: Users get predictable import paths while custom automation retains overwrite safety.

## 2026-08-16 - Use zzz_calculator Native Export v1

Context: `zzz_calculator` accepts both OCR-oriented ZZZ Scanner arrays and its own versioned native
format.

Decision: Emit `zzz-calculator-drive-disc-export` version 1 with stable UID strings, target-native
set IDs, Chinese set names, normalized stat identifiers, actual stat values, levels, rarities, and
lock state. Keep the confirmed display name `荆棘玫瑰` while using target set ID `zzz_wiki_2121`
to bridge its internal `棘刺玫瑰` alias.

Consequences: The integration is explicit and versioned. Its contract must be rechecked if the
upstream calculator changes `DRIVE_DISC_EXPORT_VERSION`.

## 2026-08-16 - Correct Protocol Property Mapping

Context: The original exporter treated property `31402` as Physical DMG and shifted later elemental
properties. Current game-server enums identify it as Anomaly Mastery; `31503` through `31903` are
Physical, Fire, Ice, Electric, and Ether DMG, while `32303` is Wind DMG.

Decision: Correct both exporters to use the protocol enum and current target schema keys.

Consequences: v0.2.0 fixes affected main-stat identities in ZOOD output and produces consistent
values in both target formats.

## 2026-10-18 - Promote CN 3.2 From Candidate To One-Sample Confirmed Support

Context: A user-operated login capture reached the configured `0x0F5D` stop condition and the
CLI reported single-session recovery of 2,321 discs. Saved metadata confirms a complete
145,929-byte response, and both output arrays contain 2,321 records.

Decision: Keep the unpublished `v0.2.0` version and describe CNPRODWin3.2.0 as the current live
target with one confirmed account/inventory sample. Retain explicit limitations for cross-account,
changed inventories, small inventories, field accuracy, and downstream import acceptance.

Consequences: Release preparation packages the existing user-run binary without initiating tests,
builds, or captures. Publication and clean-source reproducibility remain separate gates. Raw
captures, exports, pads/seeds, account identifiers, and private logs are never release assets.

## 2026-10-18 - Local Commit And Draft, User-Operated Publication

Decision: Following user authorization, prepare a reviewed local source commit, an annotated
v0.2.0 tag, and a Chinese Release draft. The user executes Git push, GitHub authentication,
asset upload, and final publication. Do not execute a remote write in this pass.

Consequences: Keep the machine-specific publishing runbook in ignored dist/v0.2.0, not public
source. Keep release notes explicit that the existing user-run executable was packaged without
a new test/build or clean-source reproducibility check. No code/runtime behavior is changed.

## 2026-10-21 - 只适配当前 CN 3.3，先用已有抓包验收

背景：客户端已更新为 CNPRODWin3.3.0，旧程序等待 CN 3.2 命令 0x0F5D。
用户已有抓包包含完整 0x06D0 长响应，不能把未自动停止简单归因于 pktmon 丢包警告。

决策：更新当前 stop condition、schema 与统计先验；公开协议定义只作为候选来源，
以已捕获正文的递推、完整解析与域约束为验收依据。CN 实际状态字段及套装列表
与参考定义存在差别，按抓包校准；UID 用当前 XOR 常量还原。

影响：通过单会话无旧资产输入的离线导出，不启动新抓包。新二进制独立命名，
不替换仍运行的旧 EXE；自动停止和字段含义最终仍需用户手动现场确认。
