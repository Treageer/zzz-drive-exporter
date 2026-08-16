# zzz-drive-exporter

Windows command-line tool that passively captures Zenless Zone Zero login traffic and exports
drive discs as optimizer-compatible `ZOOD v1` JSON.

The executable does not inject into the game, read process memory, modify traffic, automate input,
or upload captured data. It uses Windows `pktmon`, so it must run from an elevated terminal.

## Supported Version

The current decoder is verified for the Chinese PC client `CNPRODWin3.1.0`. Protocol command IDs,
protobuf fields, and XOR constants can change after a game update. Old-version compatibility is not
a release goal; each release targets the current verified game version.

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
5. If no compatible historical capture exists, the program remains open and asks for a second
   login. Keep the drive-disc inventory unchanged, completely exit and restart the game, and wait
   at the login screen.
6. Return to the exporter and press `Enter`. After the second `Capture started`, log in again.
7. The importer-ready file is written to `exports/zzz-drives-*.json`.

Each login uses a different session pad. A fresh installation therefore normally needs two login
captures with the same account, game version, and unchanged drive-disc inventory. A historical
capture can replace the first capture only when its inventory response is byte-identical.

Changes such as obtaining, deleting, leveling, dismantling, locking, unlocking, or re-equipping a
drive disc can invalidate an older baseline. If the inventory changes, complete another two-login
pair without making changes between those two logins.

## Output

- `exports/*.json`: final `ZOOD v1` document for Zenless Optimizer.
- `captures/*`: reassembled login messages and local decryption intermediates used for pairing.

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

Process an existing exporter capture pair without starting `pktmon`:

```powershell
.\target\release\zzz-drive-exporter.exe `
  --from-capture captures\<current> `
  --baseline captures\<baseline> `
  --output exports\test.json
```

## Project Layout

- `src/main.rs`: end-user two-login workflow and CLI.
- `src/export_api.rs`: live capture orchestration, baseline discovery, and ZOOD conversion.
- `src/core.rs`: verified KCP, command, pad-validation, and drive-disc decoder core.
- `src/session_pad.rs`: MT19937-64 session-pad recovery.
- `resources/zzz_cn31_disc_sets.json`: optimizer set-key mapping for the supported version.
- `RELEASING.md`: maintainer release checklist.

## Disclaimer

This is an unofficial community project. Zenless Zone Zero and related names are trademarks of
their respective owners. Users are responsible for reviewing applicable game terms and local law.

## License

Distributed under the GNU Affero General Public License v3.0 only. See `LICENSE` and
`THIRD_PARTY_NOTICES.md`.
