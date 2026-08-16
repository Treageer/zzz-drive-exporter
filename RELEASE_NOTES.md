# zzz-drive-exporter v0.1.0

First public release targeting the Chinese PC client `CNPRODWin3.1.0`.

## Features

- Passively captures only the ZZZ gateway UDP port through Windows `pktmon`.
- Automatically stops after the complete drive-disc response is reassembled.
- Guides the user through the required two-login workflow when no compatible baseline exists.
- Recovers the per-login MT19937-64 session pad and validates it against both sessions.
- Exports optimizer-compatible `ZOOD v1` JSON with 3.1 drive-disc set mappings.

## Requirements

- Windows 10 or Windows 11.
- Run from an Administrator PowerShell.
- Keep the drive-disc inventory unchanged between the two login captures.

## Privacy

`captures/` remains local but contains sensitive account/session traffic and decoded inventory
intermediates. Do not upload or share it. Only the EXE, ZIP, checksum file, and public source belong
in a GitHub release.

## Known Limitations

- Protocol support is version-specific and currently verified only for `CNPRODWin3.1.0`.
- The executable is not digitally signed, so Windows may show a SmartScreen warning.
- A changed drive-disc inventory normally requires a new pair of login captures.

SHA-256 hashes are provided in `SHA256SUMS.txt`.
