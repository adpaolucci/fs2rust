#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;
use fs2rust_core::init_logging;
use fs2rust_mcp::{print_tools_manifest_json, serve_mcp_stdio};
use guap_mcp::PolicyMode;

#[derive(Parser, Debug)]
#[command(name = "fs2rust-mcp", version, about = "fs2rust MCP JSON-RPC 2.0 stdio server")]
struct Args {
    /// Print tool schemas as JSON and exit
    #[arg(long)]
    tools: bool,
    /// Enable mutating ActionCommands (still requires confirm_destructive=true)
    #[arg(long)]
    allow_mutating: bool,
    /// Use offline synthetic backends and sample fixtures
    #[arg(long)]
    offline: bool,
    /// Optional root paths for search/folder/shortcut providers
    #[arg(long = "root")]
    roots: Vec<PathBuf>,
    /// Verbose stderr logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_logging(args.verbose);
    let policy = if args.allow_mutating {
        PolicyMode::AllowMutating
    } else {
        PolicyMode::ReadOnlyOnly
    };
    if args.tools {
        println!("{}", print_tools_manifest_json(policy, args.offline, args.roots)?);
        return Ok(());
    }
    serve_mcp_stdio(policy, args.offline, args.roots)
}
