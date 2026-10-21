# zzz-drive-exporter

Windows command-line tool that passively captures Zenless Zone Zero login traffic and exports
the decoded Drive Disc inventory to two import-ready JSON formats:

- `ZOOD v1` for [Zenless Optimizer](https://frzyc.github.io/zenless-optimizer/#/discs)
- `zzz-calculator-drive-disc-export` v1 for
  [zzz_calculator](https://github.com/ZztIsolation/zzz_calculator)

The executable does not inject into the game, read process memory, modify traffic, automate input,
or upload captured data. It uses Windows `pktmon`, so it must run from an elevated terminal.

## Supported Version

The current live-capture target is the Chinese PC client `CNPRODWin3.3.0`, using drive-disc
response command `0x06D0` (v0.2.1). CN 3.2's old `0x0F5D` stop condition no longer matches.
On 2026-10-21, the repaired decoder recovered the pad from one already-captured complete
144,264-byte response and exported 2,335 discs to both formats without historical pad/plaintext
inputs or paired fallback. A fresh live capture with the repaired EXE still needs user verification.

This release only adapts the current version; it does not add future-version detection.
Small inventories and target-application imports are not broadly accepted. Historical schemas
remain for offline use; current live capture targets CN 3.3 only. Protocol updates may require
another targeted repair.

## Download

Download the Windows executable from the GitHub Releases page. Run it from an Administrator
PowerShell so `captures/` and `exports/` are created next to your current terminal directory:

```powershell
cd C:\path\to\zzz-drive-exporter
.\zzz-drive-exporter.exe
```

## Capture And Export

1. Start the game and wait at the login/start screen. Do not log in yet.
2. Start `zzz-drive-exporter.exe` as Administrator.
3. Wait for `Capture started`, then log in and enter the game.
4. Do not press `Ctrl+C`. The first capture stops automatically after the complete drive-disc
   response arrives.
5. The exporter first attempts to recover the session pad from this single response. If the
   statistical candidate passes MT19937-64 recurrence and protobuf/inventory parsing, both files
   are written immediately. This path does not use an earlier account or inventory baseline, but
   success on account changes, inventory changes, and small inventories is not yet established.
6. Only if single-session recovery cannot be validated does it search for, or request, a second
   unchanged-inventory login session and use the historical paired method as a fallback.

Each login uses a different session pad. The old paired method remains available as a fallback,
but the normal path is one login capture and does not assume a matching account, unchanged
inventory, or historical plaintext template.

For the paired fallback only, changes such as obtaining, deleting, leveling, dismantling, locking,
unlocking, or re-equipping a drive disc can invalidate an older baseline. If you choose that
fallback, keep the account, game version, and inventory unchanged between its two logins.

There is currently no capture timeout. If the expected response never arrives, press `Ctrl+C` once
to interrupt and retain the local capture for diagnosis. Interrupted captures may be incomplete;
interrupting is not the normal successful completion path.

## Output

- `exports/zzz-drives-zood-v1.json`: `ZOOD v1` for Zenless Optimizer.
- `exports/zzz-drives-zzz-calculator-v1.json`: native version 1 Drive Disc export for
  `ZztIsolation/zzz_calculator`.
- `captures/*`: reassembled login messages and local decryption intermediates used for pairing.

The two default JSON files are current-inventory snapshots. A later successful run replaces both
files. Each custom path is protected independently and needs `--force` if that file already exists.
Use `--output` and `--calculator-output` to choose custom paths.

Do not publish `captures/`. It contains network endpoints, complete reassembled messages, session
pads/seeds after pairing, and the decoded inventory. The final export does not contain a password
or login token, but it contains drive-disc item IDs and detailed account inventory information.

## Build From Source

Install the stable Rust toolchain and the MSVC C++ build tools, then run:

```powershell
cargo fmt --check
cargo test
cargo build --release
```

The executable is created at:

```text
target/release/zzz-drive-exporter.exe
```

Process an existing exporter capture without starting `pktmon` (omit `--baseline` so the
single-session path is attempted first):

```powershell
.\target\release\zzz-drive-exporter.exe `
  --from-capture captures\<current> `
  --output exports\test-zood-v1.json `
  --calculator-output exports\test-zzz-calculator-v1.json
```

To explicitly use the historical paired fallback instead, add `--baseline captures\<baseline>`.
That option bypasses the single-session attempt.

## Project Layout

- `src/main.rs`: single-login-first CLI with an optional two-login fallback.
- `src/export_api.rs`: live capture orchestration, baseline discovery, and both JSON conversions.
- `src/core.rs`: verified KCP, command, pad-validation, and drive-disc decoder core.
- `src/session_pad.rs`: MT19937-64 session-pad recovery.
- `resources/zzz_cn31_disc_sets.json`: Zenless Optimizer and zzz_calculator set mappings for the
  supported version.
- `PLAN.md`, `TASKS.md`, `DECISIONS.md`: concise maintainer context for the next version update.
- `RELEASING.md`: maintainer release checklist.

## Disclaimer

This is an unofficial community project. Zenless Zone Zero and related names are trademarks of
their respective owners. Users are responsible for reviewing applicable game terms and local law.

## License

Distributed under the GNU Affero General Public License v3.0 only. See `LICENSE` and
`THIRD_PARTY_NOTICES.md`.
