# `fs2rust`

24-tool pure-Rust filesystem search, NTFS/disk/ETW telemetry, and structured data utility suite built on `guap-kit` (Rust Edition 2024, Apache-2.0).

## Workspace Crates (9)
- `crates/fs2rust-core`: Shared errors, configuration, `FileSystemOps` (`OsFileSystem` / `MockFileSystem`), `PolicyContext` path/mutation guards, wildcard matcher, FILETIME decoders, and stderr logging.
- `crates/fs2rust-search`: 6 `#![forbid(unsafe_code)]` tools (`SearchMyFiles`, `BulkFileChanger`, `FolderTimeUpdate`, `FoldersReport`, `ShortcutsMan` `[MS-SHLLINK]`, `HashMyFiles`) + 4 policy-gated mutating `ActionCommand`s.
- `crates/fs2rust-ntfs`: 11 NTFS & disk telemetry tools (`DriveLetterView`, `DiskCountersView`, `FileActivityWatch` ETW `Kernel-File`, `FolderChangesView`, `FileAccessErrorView`, `AppReadWriteCounter`, `DiskSmartView` ATA/NVMe, `AlternateStreamView` + `$MFT`, `NTFSLinksView`, `PropertySystemView`, `UsnJournalView`) + 4 policy-gated mutating `ActionCommand`s.
- `crates/fs2rust-data`: 7 `#![forbid(unsafe_code)]` structured data tools (`CSVFileView`, `TableTextCompare`, `GetNir`, pure-Rust `ExifDataView`, `SimpleCodeGenerator`, `HTMLAsText`, `AddrView`).
- `crates/fs2rust-report`: `guap-export` integration across 7 formats (`csv`, `tsv`, `json`, `jsonl`, `html`, `html-vertical`, `markdown`) with CSV formula neutralization and SHA-256/512 Merkle custody manifests.
- `crates/fs2rust-mcp`: Policy-gated JSON-RPC 2.0 (`2024-11-05`) stdio MCP server (`ReadOnlyOnly` default, `-32003` enforcement).
- `crates/fs2rust-cli`: `clap` 4.6 derive CLI (`fs2rust`).
- `crates/fs2rust-win32`: Native Win32 (`winsafe`) desktop console (`fs2rust-win32`) with Common-Controls v6 manifest.
- `crates/fs2rust-iced`: Cross-platform Iced `0.14` desktop console (`fs2rust-iced`).

## Quick Usage
```powershell
fs2rust --help
fs2rust list
fs2rust data csv --path sample.csv --format json
fs2rust search hash --target . --format markdown
fs2rust mcp --tools
```
