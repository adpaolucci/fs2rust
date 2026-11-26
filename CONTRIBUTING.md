# Contributing to `fs2rust`

Thank you for your interest in contributing to `fs2rust`!

## Code Architecture
The workspace consists of 9 modular crates under `crates/`:
- `fs2rust-core`: Shared errors, config, `FileSystemOps` traits, `PolicyContext` guards, FILETIME decoders, and stderr logging.
- `fs2rust-search`: 6 `#![forbid(unsafe_code)]` filesystem search, bulk timestamp/attribute, folder report, `.lnk` parser, and multi-hash tools (+ 4 mutating actions).
- `fs2rust-ntfs`: 11 NTFS, disk counter, ETW `Kernel-File`, S.M.A.R.T., ADS/`$MFT`, reparse/hardlink, Property System, and `$UsnJrnl` tools (+ 4 mutating actions).
- `fs2rust-data`: 7 `#![forbid(unsafe_code)]` CSV/diff/query/EXIF/codegen/HTML-to-text/contact tools.
- `fs2rust-report`: Multi-format reporting and SHA-256/512 Merkle chain-of-custody manifests.
- `fs2rust-mcp`: Policy-gated JSON-RPC 2.0 stdio MCP server (`ReadOnlyOnly` default).
- `fs2rust-cli`: `clap` 4.6 derive CLI (`fs2rust`).
- `fs2rust-win32` & `fs2rust-iced`: Dual desktop GUI hosts built on `guap-gui-win32` and `guap-gui-iced`.

## Safety & Scope Rules
- **No DLL Injection / API Hooking**: Never introduce process injection or global API hooking; live telemetry uses standard Win32/IOCTL/ETW APIs only.
- **No Credential Extraction**: `fs2rust` strictly excludes password/credential extraction, DPAPI/Vault/LSA secret dumping, or retired legacy tools.
- **Mutating Policy Gates**: Every mutating operation must implement `guap_mcp::ActionCommand` with `dry_run` support and explicit confirmation flags (`-y` / `--allow-mutating` + `--confirm-destructive`).

## Verification Commands
```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test --workspace --offline
```
