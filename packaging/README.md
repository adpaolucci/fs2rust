# Packaging Manifests (`WinGet` & `Homebrew`)

This directory stores ready-to-submit package manager manifests matching published GitHub Releases for **`fs2rust`**.

## 1. Windows Package Manager (`winget`)

```powershell
winget validate --manifest .\packaging\winget\manifests\a\adpaolucci\fs2rust\0.1.0
wingetcreate submit .\packaging\winget\manifests\a\adpaolucci\fs2rust\0.1.0
```

Installed portable command aliases: `fs2rust`, `fs2rust-win32`, `fs2rust-iced`, `fs2rust-mcp`.

## 2. Homebrew (`macOS` & `Linux`)

```bash
brew install adpaolucci/tap/fs2rust
brew install --formula ./packaging/homebrew/fs2rust.rb
brew test fs2rust
```
