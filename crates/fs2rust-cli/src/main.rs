#![forbid(unsafe_code)]

fn main() -> anyhow::Result<()> {
    fs2rust_cli::run_from_env()
}
