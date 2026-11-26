use tracing_subscriber::EnvFilter;

/// Initialize structured tracing logs directed exclusively to `stderr`
/// so `stdout` remains clean for MCP JSON-RPC stdio and CLI output streams.
pub fn init_logging(verbose: bool) {
    let default_level = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
