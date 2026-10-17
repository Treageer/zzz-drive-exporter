# Release Checklist

GitHub Releases require a pushed commit and tag. Do not create an online release from uncommitted
or locally modified source.

## 1. Verify The Source Tree

```powershell
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
git status --short
```

Confirm that `captures/`, `exports/`, `target/`, `dist/`, session pads, decoded inventories, and
personal logs are not tracked:

```powershell
git ls-files | Select-String 'captures|exports|target|dist|equip\.json|session_xorpad|session_seeds'
```

The command should print nothing.

## 2. Verify A Clean Checkout

After the first commit exists, clone the repository into a separate temporary directory and run:

```powershell
cargo test
cargo build --release
```

Do not publish a binary that cannot be reproduced from the tagged source.

## 3. Prepare Artifacts

Use a versioned filename and calculate its checksum:

```powershell
New-Item -ItemType Directory -Force dist
Copy-Item target\release\zzz-drive-exporter.exe `
  dist\zzz-drive-exporter-v0.2.0-windows-x86_64.exe
Get-FileHash dist\zzz-drive-exporter-v0.2.0-windows-x86_64.exe -Algorithm SHA256
```

Optionally package the executable together with `README.md`, `LICENSE`, and
`THIRD_PARTY_NOTICES.md` in a ZIP archive.

## 4. Commit And Tag

Review every staged file before committing:

```powershell
git add .
git status
git diff --cached
git commit -m "Release v0.2.0"
git push -u origin main
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

## 5. Create The GitHub Release

Open `Releases` on GitHub, choose `Draft a new release`, select tag `v0.2.0`, and upload the
versioned EXE, ZIP, and checksum file. Paste `RELEASE_NOTES.md` into the release description and
update its supported version and limitations for later releases. Release notes should state:

- supported game version;
- Windows and Administrator requirements;
- the normal single-login-first workflow and optional unchanged-inventory paired fallback;
- capture-data privacy warning;
- known limitations and protocol version sensitivity.

## 2026-10-18 Preparation Status

The CN 3.2 sample was captured by the user. This preparation pass only reads local artifact
metadata and updates documentation/packages the existing executable; it does not rerun the
commands in sections 1/2 or claim their completion. Those commands are pre-publication gates,
not permission to start tests while the user is using the PC.

- Current version: v0.2.0, current live target: CNPRODWin3.2.0 / 0x0F5D.
- Existing executable: the release build used for the successful user-operated capture.
- Package only the EXE and public documentation/license notices, never entire project folders.
- Do not publish until the intended source diff is reviewed, binary provenance is resolved,
  and the user confirms remote publication.
- Do not treat a matching filename/version or modification time alone as proof that a binary
  was built from the exact tagged source. A clean rebuild remains the reproducibility gate.

## User-Operated Publication Handoff

Local-only preparation now includes the reviewed source commit, an annotated v0.2.0 tag,
a Chinese RELEASE_NOTES.md draft, and a machine-specific runbook under ignored dist/v0.2.0.
The user performs push/authentication, uploads EXE/ZIP/SHA256SUMS.txt, and publishes on GitHub.
No remote writes, tests, builds, game launches, or captures are part of this handoff.
