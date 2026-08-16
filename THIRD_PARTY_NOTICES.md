# Third-Party Notices

This project uses Rust crates distributed under their respective licenses. The complete resolved
dependency list is recorded in `Cargo.lock`.

Notable direct dependencies:

- `pktmon` - MIT License
- `mhy-kcp` / `kcp` - MIT License
- `anyhow`, `chrono`, `clap`, `futures`, `hex`, `serde`, and `serde_json` - MIT OR Apache-2.0
- `tokio`, `tracing`, and `tracing-subscriber` - MIT License

The packet-capture architecture was informed by the following MIT-licensed projects. Their source
code is not bundled in this repository:

- Irminsul, Copyright (c) 2025 Erik Gilling
- Reliquary Archiver, Copyright (c) 2024 IceDynamix

The protocol research compared behavior with `yixuan-rs`, which is distributed under the GNU
Affero General Public License v3. The standalone exporter does not depend on or vendor the
`yixuan-encryption` crate. This repository is nevertheless distributed under AGPL-3.0-only as a
conservative licensing choice for the resulting research implementation.

Zenless Zone Zero and related names are trademarks of their respective owners. This project is an
unofficial community tool and is not affiliated with, endorsed by, or sponsored by HoYoverse.
