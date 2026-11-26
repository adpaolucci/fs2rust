class Fs2rust < Formula
  desc "24-tool pure-Rust filesystem search, NTFS/disk telemetry, and structured data suite"
  homepage "https://fs2rust.guap.ca"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/fs2rust/releases/download/v0.1.0/fs2rust-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/adpaolucci/fs2rust/releases/download/v0.1.0/fs2rust-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/fs2rust/releases/download/v0.1.0/fs2rust-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "fs2rust"
    bin.install "fs2rust-iced"
    bin.install "fs2rust-mcp"
    doc.install "README.md", "CHANGELOG.md"
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "fs2rust", shell_output("#{bin}/fs2rust --help")
    assert_match "search_my_files", shell_output("#{bin}/fs2rust mcp --tools --offline")
  end
end
