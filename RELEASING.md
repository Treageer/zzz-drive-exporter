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
  dist\zzz-drive-exporter-v0.1.0-windows-x86_64.exe
Get-FileHash dist\zzz-drive-exporter-v0.1.0-windows-x86_64.exe -Algorithm SHA256
```

Optionally package the executable together with `README.md`, `LICENSE`, and
`THIRD_PARTY_NOTICES.md` in a ZIP archive.

## 4. Commit And Tag

Review every staged file before committing:

```powershell
git add .
git status
git diff --cached
git commit -m "Release v0.1.0"
git push -u origin main
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## 5. Create The GitHub Release

Open `Releases` on GitHub, choose `Draft a new release`, select tag `v0.1.0`, and upload the
versioned EXE, ZIP, and checksum file. Paste `RELEASE_NOTES.md` into the release description and
update its supported version and limitations for later releases. Release notes should state:

- supported game version;
- Windows and Administrator requirements;
- the normal two-login workflow;
- capture-data privacy warning;
- known limitations and protocol version sensitivity.
