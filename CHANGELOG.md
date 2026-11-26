# Changelog

All notable changes to `fs2rust` will be documented in this file.

## [0.1.0] - 2026-11-24
### Added
- Initial 9-crate workspace release covering all 24 tools across `fs2rust-search` (6), `fs2rust-ntfs` (11), and `fs2rust-data` (7).
- `fs2rust-core`: Shared errors, `FileSystemOps` abstraction, `PolicyContext` path/mutation guards, FILETIME decoders, wildcard matcher, and stderr `tracing` setup.
- `fs2rust-report`: `guap-export` integration across all 7 formats plus CSV formula neutralization and SHA-256/512 Merkle chain-of-custody manifests.
- `fs2rust-mcp`: JSON-RPC 2.0 (`2024-11-05`) stdio server registering all 24 `TableProvider`s and 8 mutating `ActionCommand`s with `-32003` policy gates.
- `fs2rust-cli`, `fs2rust-win32`, and `fs2rust-iced`: Unified CLI (`fs2rust`) and dual native Win32 (`winsafe`) / cross-platform Iced (`0.14`) desktop consoles.
