#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use fs2rust_core::{FileSystemOps, OsFileSystem};
use fs2rust_data::{
    AddrViewProvider, CodegenInput, CodegenTarget, CodegenTemplate, CsvTableProvider, CsvViewOptions, EscapeMode,
    ExifDataViewProvider, HtmlAsTextOptions, HtmlAsTextProvider, SimpleCodeGeneratorProvider, TableCompareOptions,
    TableCompareProvider, TableInput, TabularQueryProvider, TabularQueryRequest, TabularQuerySource,
};
use fs2rust_mcp::{
    SuiteWiring, build_fs2rust_registry, build_suite_wiring, build_synthetic_suite_wiring, print_tools_manifest_json,
    registry_from_wiring, serve_mcp_stdio,
};
use fs2rust_ntfs::{
    AlternateStreamConfig, AlternateStreamViewProvider, AppReadWriteConfig, AppReadWriteCounterProvider,
    DiskCountersConfig, DiskCountersProvider, DiskSmartConfig, DiskSmartViewProvider, DriveLetterConfig,
    DriveLetterProvider, FileAccessErrorConfig, FileAccessErrorViewProvider, FileActivityConfig,
    FileActivityWatchProvider, FolderChangesConfig, FolderChangesViewProvider, LiveNtfsBackend, NtfsBackend,
    NtfsLinksConfig, NtfsLinksViewProvider, PropertySystemConfig, PropertySystemViewProvider, UsnJournalConfig,
    UsnJournalViewProvider,
};
use fs2rust_report::{default_export_options, render_table_report, write_bundle_report, write_table_report};
use fs2rust_search::{
    BulkChangeSpec, BulkFileTimePreviewProvider, FolderTimeSource, FolderTimeUpdateConfig,
    FolderTimeUpdatePreviewProvider, FoldersReportConfig, FoldersReportProvider, HashFilesConfig, HashFilesProvider,
    SearchFilesConfig, SearchFilesProvider, ShortcutsConfig, ShortcutsProvider, TimestampChange,
};
use guap_export::{ExportFormat, write_custody_manifest_json};
use guap_mcp::PolicyMode;
use guap_table::{GuapQuery, TableProvider, TableQuery};
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(
    name = "fs2rust",
    version,
    about = "24-tool pure-Rust filesystem search, NTFS/disk telemetry, and structured data suite"
)]
pub struct Cli {
    /// Allow mutating ActionCommands (required with --confirm-destructive)
    #[arg(short = 'y', long, global = true)]
    pub allow_mutating: bool,

    /// Explicit destructive confirmation required by MCP/action policy gates
    #[arg(long, global = true)]
    pub confirm_destructive: bool,

    /// Preview mutating actions without modifying filesystem/volume state
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Output format: csv, tsv, json, jsonl, html, html-vertical, markdown (md)
    #[arg(long, global = true, default_value = "markdown")]
    pub format: String,

    /// Write table output to file and compute SHA-256/512 custody hashes
    #[arg(short = 'o', long, visible_alias = "output", global = true)]
    pub export: Option<PathBuf>,

    /// Write SHA-256/SHA-512 Merkle CustodyManifest JSON to path
    #[arg(long, global = true)]
    pub custody: Option<PathBuf>,

    /// Tabular filter expression (e.g. "size_bytes > 100" or "filename ~ txt")
    #[arg(long, global = true)]
    pub filter: Option<String>,

    /// Sort column specification (e.g. "size_bytes:desc" or "~filename")
    #[arg(long, global = true)]
    pub sort: Option<String>,

    /// Maximum rows to display/export
    #[arg(long, global = true)]
    pub limit: Option<usize>,

    /// Use offline synthetic backends and sample fixtures
    #[arg(long, global = true)]
    pub offline: bool,

    /// Verbose stderr logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Filesystem search, bulk timestamp/attribute, folder report, shortcut, and multi-hash tools (6)
    Search {
        #[command(subcommand)]
        sub: SearchSub,
    },
    /// Drive letters, disk counters, ETW file/error watch, folder changes, SMART, ADS, links, props, USN (11)
    Ntfs {
        #[command(subcommand)]
        sub: NtfsSub,
    },
    /// CSV viewer, table diff, tabular query, EXIF, codegen, HTML-to-text, and contact book tools (7)
    Data {
        #[command(subcommand)]
        sub: DataSub,
    },
    /// Run or inspect the JSON-RPC 2.0 (2024-11-05) stdio MCP server
    Mcp(McpArgs),
    /// Launch the desktop GUI (Win32 native by default, or --iced)
    Gui(GuiArgs),
    /// Execute a registered mutating ActionCommand under policy gates
    Action(ActionArgs),
    /// List all 24 tools and 8 mutating actions across search, ntfs, and data
    #[command(visible_alias = "catalog")]
    List,
    /// Export a multi-table bundle + SHA-256/512 custody_manifest.json into --export directory
    Export(ExportBundleArgs),
    /// Print host platform and offline/live capability diagnostics
    Diag,
}

#[derive(Subcommand, Debug)]
pub enum SearchSub {
    /// Multi-threaded file search & duplicate grouping
    Files(SearchFilesArgs),
    /// Preview or apply bulk timestamp & attribute changes
    #[command(visible_alias = "bulk-change")]
    BulkTime(BulkTimeArgs),
    /// Preview or apply bottom-up folder timestamps
    FolderTime(FolderTimeArgs),
    /// Directory size, size-on-disk, and count aggregator
    #[command(visible_alias = "folders")]
    Report(FoldersReportArgs),
    /// Pure-Rust [MS-SHLLINK] .lnk parser, target fixer, and broken deleter
    Shortcuts(ShortcutsArgs),
    /// Single-pass MD5, SHA-1, SHA-256, SHA-512, and CRC32 hasher
    Hash(HashArgs),
}

#[derive(Args, Debug)]
pub struct SearchFilesArgs {
    /// Root directories to scan
    #[arg(long = "root", visible_alias = "path")]
    pub roots: Vec<PathBuf>,
    /// Include filename wildcard patterns (e.g. "*.rs")
    #[arg(long = "pattern")]
    pub patterns: Vec<String>,
    /// Maximum traversal depth
    #[arg(long)]
    pub max_depth: Option<usize>,
    /// Compute SHA-256 hashes
    #[arg(long)]
    pub sha256: bool,
    /// Group duplicate files by size/SHA-256
    #[arg(long)]
    pub duplicates: bool,
}

#[derive(Args, Debug)]
pub struct BulkTimeArgs {
    /// Target file or directory paths
    #[arg(long = "target", visible_alias = "path")]
    pub targets: Vec<PathBuf>,
    /// Recurse into subdirectories
    #[arg(long)]
    pub recursive: bool,
    /// Set modified timestamp (RFC3339 string, e.g. 2026-11-24T00:00:00Z)
    #[arg(long)]
    pub modified: Option<String>,
    /// Set created timestamp (RFC3339 string)
    #[arg(long)]
    pub created: Option<String>,
    /// Apply changes (requires -y --confirm-destructive unless --dry-run is used)
    #[arg(long)]
    pub apply: bool,
}

#[derive(Args, Debug)]
pub struct FolderTimeArgs {
    /// Root folder path
    #[arg(long, visible_alias = "path")]
    pub root: Option<PathBuf>,
    /// Propagation mode: newest_file_only | newest_file_or_subdir
    #[arg(long, default_value = "newest_file_only")]
    pub source: String,
    /// Maximum depth
    #[arg(long)]
    pub max_depth: Option<usize>,
    /// Apply folder timestamp updates (requires -y --confirm-destructive unless --dry-run is used)
    #[arg(long)]
    pub apply: bool,
}

#[derive(Args, Debug)]
pub struct FoldersReportArgs {
    /// Root folder path
    #[arg(long, visible_alias = "path")]
    pub root: Option<PathBuf>,
    /// Breakdown depth
    #[arg(long, default_value_t = 1)]
    pub depth: usize,
}

#[derive(Args, Debug)]
pub struct ShortcutsArgs {
    /// Root directories to scan for .lnk files
    #[arg(long = "root", visible_alias = "path")]
    pub roots: Vec<PathBuf>,
    /// Fix target path of a specific .lnk file
    #[arg(long)]
    pub fix_shortcut: Option<PathBuf>,
    /// New target path used with --fix-shortcut
    #[arg(long)]
    pub new_target: Option<String>,
    /// Delete specified .lnk file(s) (requires -y --confirm-destructive unless --dry-run)
    #[arg(long = "delete")]
    pub delete_paths: Vec<PathBuf>,
    /// Only delete shortcuts whose target does not exist
    #[arg(long, default_value_t = true)]
    pub only_if_broken: bool,
}

#[derive(Args, Debug)]
pub struct HashArgs {
    /// Target file or directory paths
    #[arg(long = "target", visible_alias = "path")]
    pub targets: Vec<PathBuf>,
    /// Include wildcard patterns
    #[arg(long = "pattern")]
    pub patterns: Vec<String>,
    /// Maximum traversal depth
    #[arg(long)]
    pub max_depth: Option<usize>,
}

#[derive(Subcommand, Debug)]
pub enum NtfsSub {
    /// Logical drives, volume GUIDs, and MountedDevices
    Drives(DrivesArgs),
    /// IOCTL_DISK_PERFORMANCE read/write counters & queue depth
    #[command(visible_alias = "disk-counters")]
    Counters(DiskCountersArgs),
    /// ETW Microsoft-Windows-Kernel-File activity monitor
    #[command(visible_alias = "file-activity")]
    FileWatch(EtwWatchArgs),
    /// ReadDirectoryChangesW directory change monitor
    #[command(visible_alias = "folder-changes")]
    FolderWatch(FolderWatchArgs),
    /// ETW Kernel-File non-zero NTSTATUS error monitor
    #[command(visible_alias = "file-errors")]
    AccessErr(EtwWatchArgs),
    /// Per-process GetProcessIoCounters & I/O rate view
    AppIo(AppIoArgs),
    /// ATA S.M.A.R.T. & NVMe health log attributes
    Smart(DiskSmartArgs),
    /// NTFS Alternate Data Streams (FindFirstStreamW / $MFT)
    Ads(AdsArgs),
    /// Symlinks, junctions, reparse points, and hardlinks
    Links(LinksArgs),
    /// Windows Property System (IPropertyStore / propsys.dll)
    Props(PropsArgs),
    /// NTFS USN Journal View — $UsnJrnl:$J USN_RECORD_V2/V3 reader
    Usn(UsnArgs),
}

#[derive(Args, Debug)]
pub struct DrivesArgs {
    /// Assign volume GUID to mount point (requires -y --confirm-destructive unless --dry-run)
    #[arg(long)]
    pub assign_mount: Option<String>,
    /// Volume GUID path for --assign-mount
    #[arg(long)]
    pub volume_guid: Option<String>,
    /// Remove mount point (requires -y --confirm-destructive unless --dry-run)
    #[arg(long)]
    pub remove_mount: Option<String>,
}

#[derive(Args, Debug)]
pub struct DiskCountersArgs {
    /// Physical/logical device paths (e.g. \\.\PhysicalDrive0)
    #[arg(long = "device")]
    pub devices: Vec<String>,
}

#[derive(Args, Debug)]
pub struct EtwWatchArgs {
    /// Capture window in milliseconds
    #[arg(long, default_value_t = 300)]
    pub duration_ms: u64,
    /// Optional PID filter
    #[arg(long)]
    pub pid: Option<u32>,
}

#[derive(Args, Debug)]
pub struct FolderWatchArgs {
    /// Directory to watch
    #[arg(long, visible_alias = "path", default_value = ".")]
    pub dir: PathBuf,
    /// Watch window in milliseconds
    #[arg(long, default_value_t = 300)]
    pub duration_ms: u64,
}

#[derive(Args, Debug)]
pub struct AppIoArgs {
    /// Optional PID filter
    #[arg(long)]
    pub pid: Option<u32>,
    /// Sampling interval in milliseconds (0 for instant snapshot)
    #[arg(long, default_value_t = 0)]
    pub interval_ms: u64,
}

#[derive(Args, Debug)]
pub struct DiskSmartArgs {
    /// PhysicalDrive indices (e.g. --disk 0)
    #[arg(long = "disk")]
    pub disks: Vec<u32>,
}

#[derive(Args, Debug)]
pub struct AdsArgs {
    /// Host file or directory paths
    #[arg(long = "path")]
    pub paths: Vec<PathBuf>,
    /// Recurse into subdirectories
    #[arg(long)]
    pub recursive: bool,
    /// Delete named ADS stream (requires --path <single_file> and -y --confirm-destructive unless --dry-run)
    #[arg(long)]
    pub delete_stream: Option<String>,
}

#[derive(Args, Debug)]
pub struct LinksArgs {
    /// Paths to inspect
    #[arg(long = "path")]
    pub paths: Vec<PathBuf>,
    /// Recurse into subdirectories
    #[arg(long)]
    pub recursive: bool,
    /// Skip hardlink count enumeration
    #[arg(long)]
    pub no_hardlinks: bool,
}

#[derive(Args, Debug)]
pub struct PropsArgs {
    /// Target file paths
    #[arg(long = "path")]
    pub paths: Vec<PathBuf>,
    /// Canonical property name to set (e.g. System.Title)
    #[arg(long)]
    pub set_name: Option<String>,
    /// Value to assign to --set-name
    #[arg(long)]
    pub set_value: Option<String>,
}

#[derive(Args, Debug)]
pub struct UsnArgs {
    /// Volume drive or device path (e.g. C:)
    #[arg(long, default_value = "C:")]
    pub volume: String,
    /// Starting USN cursor
    #[arg(long, default_value_t = 0)]
    pub start_usn: i64,
    /// Maximum USN records to return
    #[arg(long, default_value_t = 256)]
    pub max_records: usize,
}

#[derive(Subcommand, Debug)]
pub enum DataSub {
    /// Auto-delimiter & typed CSV/TSV viewer
    Csv(DataPathArgs),
    /// Diff two CSV/TSV/JSONL files
    #[command(visible_alias = "compare")]
    Diff(DataDiffArgs),
    /// Tabular expression query evaluator
    Query(DataQueryArgs),
    /// Pure-Rust JPEG/TIFF EXIF IFD inspector
    Exif(DataPathArgs),
    /// Template snippet generator from JSON or CSV
    Codegen(DataCodegenArgs),
    /// Pure-Rust HTML-to-text & link footnote extractor
    #[command(visible_alias = "html")]
    Html2text(DataPathArgs),
    /// Pure-Rust .vcf, .ldif, and contact .csv reader
    Addr(DataPathArgs),
}

#[derive(Args, Debug)]
pub struct DataPathArgs {
    /// Input file path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DataDiffArgs {
    /// Left input file (.csv/.tsv/.jsonl)
    #[arg(long)]
    pub left: Option<PathBuf>,
    /// Right input file (.csv/.tsv/.jsonl)
    #[arg(long)]
    pub right: Option<PathBuf>,
    /// Optional comma-separated key column names
    #[arg(long)]
    pub keys: Option<String>,
}

#[derive(Args, Debug)]
pub struct DataQueryArgs {
    /// Input file path (.csv/.tsv/.jsonl)
    #[arg(long)]
    pub path: Option<PathBuf>,
    /// Comma-separated columns to project
    #[arg(long)]
    pub columns: Option<String>,
    /// Filter expression
    #[arg(long = "where")]
    pub where_expr: Option<String>,
    /// Sort expression
    #[arg(long)]
    pub sort_expr: Option<String>,
    /// Top N rows
    #[arg(long)]
    pub top: Option<usize>,
}

#[derive(Args, Debug)]
pub struct DataCodegenArgs {
    /// Input JSON file path (array of objects)
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Input CSV file path
    #[arg(long)]
    pub csv: Option<PathBuf>,
    /// Body template string with {{field}} placeholders
    #[arg(long, default_value = "{{name}}={{value}}")]
    pub template: String,
    /// Rule label
    #[arg(long, default_value = "cli_rule")]
    pub rule_name: String,
}

#[derive(Args, Debug)]
pub struct McpArgs {
    /// Print MCP tool/action definitions as JSON and exit
    #[arg(long)]
    pub tools: bool,
    /// Enable mutating actions (still requires confirm_destructive=true per call)
    #[arg(long)]
    pub allow_mutating: bool,
}

#[derive(Args, Debug)]
pub struct GuiArgs {
    /// Launch cross-platform Iced 0.14 GUI instead of native Win32 GUI
    #[arg(long)]
    pub iced: bool,
}

#[derive(Args, Debug)]
pub struct ActionArgs {
    /// Registered ActionCommand ID (e.g. bulk_file_time_apply)
    #[arg(long)]
    pub id: String,
    /// JSON object of arguments for the action
    #[arg(long, default_value = "{}")]
    pub args: String,
}

#[derive(Args, Debug)]
pub struct ExportBundleArgs {
    /// Export all 24 suite providers into --export directory
    #[arg(long)]
    pub all: bool,
}

fn build_table_query(cli: &Cli, provider: &dyn TableProvider) -> Result<TableQuery> {
    let schema = provider.schema();
    let mut gq = GuapQuery::new();
    if let Some(ref f) = cli.filter {
        gq.filter_expr = Some(f.clone());
    }
    if let Some(ref s) = cli.sort {
        let normalized = if let Some(col) = s.strip_prefix('~') {
            format!("-{col}")
        } else {
            s.clone()
        };
        gq.sort = GuapQuery::parse_sort(&normalized).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    gq.limit = cli.limit;
    gq.to_table_query(&schema).map_err(|e| anyhow::anyhow!("{e}"))
}

fn emit_provider_output(cli: &Cli, provider: &dyn TableProvider) -> Result<()> {
    let req = build_table_query(cli, provider)?;
    let data = provider.query(&req)?;
    let fmt = ExportFormat::parse(&cli.format)?;
    let opts = default_export_options(None);

    if let Some(ref export_path) = cli.export {
        let manifest = write_table_report(&data, export_path, fmt, &opts)?;
        if let Some(ref custody_path) = cli.custody {
            write_custody_manifest_json(&manifest, custody_path)?;
        }
        eprintln!(
            "Exported {} rows to {} (merkle_sha256={})",
            data.rows.len(),
            export_path.display(),
            manifest.merkle_root_sha256
        );
    } else {
        let bytes = render_table_report(&data, fmt, &opts)?;
        let text = String::from_utf8(bytes)?;
        print!("{text}");
    }
    Ok(())
}

fn emit_action_result(cli: &Cli, val: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(val)?;
    if let Some(ref export_path) = cli.export {
        if let Some(parent) = export_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(export_path, text.as_bytes())?;
    } else {
        println!("{text}");
    }
    Ok(())
}

fn dispatch_gated_action(cli: &Cli, wiring: SuiteWiring, action_id: &str, mut args: Value) -> Result<()> {
    if cli.dry_run {
        let cmd = wiring
            .actions
            .iter()
            .find(|a| a.command_id() == action_id)
            .with_context(|| format!("unknown action '{action_id}'"))?;
        let res = cmd
            .execute(&args, true)
            .map_err(|e| anyhow::anyhow!("action dry-run error: {e}"))?;
        return emit_action_result(cli, &res);
    }

    if !cli.allow_mutating {
        bail!(
            "policy denied (-32003): mutating action '{action_id}' requires --allow-mutating (-y) and --confirm-destructive (or --dry-run)"
        );
    }
    if !cli.confirm_destructive {
        bail!("policy denied (-32003): mutating action '{action_id}' requires --confirm-destructive");
    }

    let reg = registry_from_wiring(PolicyMode::AllowMutating, wiring);
    if let Some(obj) = args.as_object_mut() {
        obj.insert("confirm_destructive".to_string(), Value::Bool(true));
        obj.insert("dry_run".to_string(), Value::Bool(false));
    }
    match reg.dispatch(action_id, &args) {
        Ok(res) => emit_action_result(cli, &res),
        Err(err) => bail!("policy/action error ({}): {}", err.code, err.message),
    }
}

fn launch_sibling_gui(iced: bool) -> Result<()> {
    let exe_name = if iced {
        if cfg!(windows) {
            "fs2rust-iced.exe"
        } else {
            "fs2rust-iced"
        }
    } else if cfg!(windows) {
        "fs2rust-win32.exe"
    } else {
        "fs2rust-iced"
    };
    let current = std::env::current_exe().context("resolve current executable path")?;
    let sibling = current
        .parent()
        .map(|p| p.join(exe_name))
        .unwrap_or_else(|| PathBuf::from(exe_name));

    let target = if sibling.is_file() {
        sibling
    } else {
        PathBuf::from(exe_name)
    };
    let mut child = Command::new(&target)
        .spawn()
        .with_context(|| format!("failed to launch GUI executable '{}'", target.display()))?;
    let status = child.wait()?;
    if !status.success() {
        bail!("GUI exited with status {status}");
    }
    Ok(())
}

fn find_synthetic_provider(tool_id: &str) -> Result<Arc<dyn TableProvider>> {
    let wiring = build_synthetic_suite_wiring();
    wiring
        .providers
        .into_iter()
        .find(|p| p.tool_id() == tool_id)
        .with_context(|| format!("missing synthetic provider '{tool_id}'"))
}

fn run_search(cli: &Cli, sub: &SearchSub) -> Result<()> {
    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    let wiring_for_action = || {
        if cli.offline {
            build_synthetic_suite_wiring()
        } else {
            build_suite_wiring(false, Vec::new())
        }
    };

    match sub {
        SearchSub::Files(args) => {
            if cli.offline && args.roots.is_empty() {
                let p = find_synthetic_provider("search_files")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let roots = if args.roots.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                args.roots.clone()
            };
            let cfg = SearchFilesConfig {
                roots,
                include_patterns: args.patterns.clone(),
                max_depth: args.max_depth,
                compute_sha256: args.sha256 || args.duplicates,
                group_duplicates: args.duplicates,
                ..SearchFilesConfig::default()
            };
            let p = SearchFilesProvider::new(cfg);
            emit_provider_output(cli, &p)
        }
        SearchSub::BulkTime(args) => {
            if args.apply {
                let mut payload = json!({
                    "targets": args.targets.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
                    "recursive": args.recursive,
                });
                if let Some(ref m) = args.modified {
                    payload["modified"] = json!(m);
                }
                if let Some(ref c) = args.created {
                    payload["created"] = json!(c);
                }
                return dispatch_gated_action(cli, wiring_for_action(), "bulk_file_time_apply", payload);
            }
            if cli.offline && args.targets.is_empty() {
                let p = find_synthetic_provider("bulk_file_time")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let modified = match &args.modified {
                Some(s) => TimestampChange::SetExact(
                    chrono::DateTime::parse_from_rfc3339(s)
                        .context("invalid --modified RFC3339 timestamp")?
                        .with_timezone(&chrono::Utc),
                ),
                None => TimestampChange::Keep,
            };
            let created = match &args.created {
                Some(s) => TimestampChange::SetExact(
                    chrono::DateTime::parse_from_rfc3339(s)
                        .context("invalid --created RFC3339 timestamp")?
                        .with_timezone(&chrono::Utc),
                ),
                None => TimestampChange::Keep,
            };
            let spec = BulkChangeSpec {
                targets: args.targets.clone(),
                recursive: args.recursive,
                created,
                modified,
                ..BulkChangeSpec::default()
            };
            let p = BulkFileTimePreviewProvider::new(spec, os_fs);
            emit_provider_output(cli, &p)
        }
        SearchSub::FolderTime(args) => {
            if args.apply {
                let root = args
                    .root
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|| ".".to_string());
                let payload = json!({
                    "root": root,
                    "source": args.source,
                    "max_depth": args.max_depth,
                });
                return dispatch_gated_action(cli, wiring_for_action(), "folder_time_update_apply", payload);
            }
            if cli.offline && args.root.is_none() {
                let p = find_synthetic_provider("folder_time_update")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let source = match args.source.as_str() {
                "newest_file_or_subdir" => FolderTimeSource::NewestFileOrSubdir,
                _ => FolderTimeSource::NewestFileOnly,
            };
            let cfg = FolderTimeUpdateConfig {
                root: args.root.clone().unwrap_or_else(|| PathBuf::from(".")),
                source,
                max_depth: args.max_depth,
                ..FolderTimeUpdateConfig::default()
            };
            let p = FolderTimeUpdatePreviewProvider::new(cfg, os_fs);
            emit_provider_output(cli, &p)
        }
        SearchSub::Report(args) => {
            if cli.offline && args.root.is_none() {
                let p = find_synthetic_provider("folders_report")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = FoldersReportConfig {
                root: args.root.clone().unwrap_or_else(|| PathBuf::from(".")),
                depth: args.depth,
                ..FoldersReportConfig::default()
            };
            let p = FoldersReportProvider::new(cfg, os_fs);
            emit_provider_output(cli, &p)
        }
        SearchSub::Shortcuts(args) => {
            if let (Some(sc), Some(nt)) = (&args.fix_shortcut, &args.new_target) {
                let payload = json!({
                    "shortcut_path": sc.to_string_lossy(),
                    "new_target": nt,
                });
                return dispatch_gated_action(cli, wiring_for_action(), "shortcuts_fix_target", payload);
            }
            if !args.delete_paths.is_empty() {
                let payload = json!({
                    "shortcut_paths": args.delete_paths.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
                    "only_if_broken": args.only_if_broken,
                });
                return dispatch_gated_action(cli, wiring_for_action(), "shortcuts_delete", payload);
            }
            if cli.offline && args.roots.is_empty() {
                let p = find_synthetic_provider("shortcuts_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = ShortcutsConfig {
                scan_roots: args.roots.clone(),
                ..ShortcutsConfig::default()
            };
            let p = ShortcutsProvider::with_backend(cfg, os_fs);
            emit_provider_output(cli, &p)
        }
        SearchSub::Hash(args) => {
            if cli.offline && args.targets.is_empty() {
                let p = find_synthetic_provider("hash_files")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = HashFilesConfig {
                targets: args.targets.clone(),
                include_patterns: args.patterns.clone(),
                max_depth: args.max_depth,
                ..HashFilesConfig::default()
            };
            let p = HashFilesProvider::new(cfg);
            emit_provider_output(cli, &p)
        }
    }
}

fn run_ntfs(cli: &Cli, sub: &NtfsSub) -> Result<()> {
    let wiring_for_action = || build_suite_wiring(cli.offline, Vec::new());
    let live_backend: Arc<dyn NtfsBackend> = Arc::new(LiveNtfsBackend);

    match sub {
        NtfsSub::Drives(args) => {
            if let (Some(mp), Some(vg)) = (&args.assign_mount, &args.volume_guid) {
                return dispatch_gated_action(
                    cli,
                    wiring_for_action(),
                    "drive_letter_assign",
                    json!({ "mount_point": mp, "volume_guid": vg }),
                );
            }
            if let Some(mp) = &args.remove_mount {
                return dispatch_gated_action(
                    cli,
                    wiring_for_action(),
                    "drive_letter_remove",
                    json!({ "mount_point": mp }),
                );
            }
            if cli.offline {
                let p = find_synthetic_provider("drive_letter_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let p = DriveLetterProvider::new(DriveLetterConfig::default(), live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::Counters(args) => {
            if cli.offline {
                let p = find_synthetic_provider("disk_counters_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = DiskCountersConfig {
                device_paths: args.devices.clone(),
                ..DiskCountersConfig::default()
            };
            let p = DiskCountersProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::FileWatch(args) => {
            if cli.offline {
                let p = find_synthetic_provider("file_activity_watch")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = FileActivityConfig {
                duration_ms: args.duration_ms,
                pid_filter: args.pid,
                ..FileActivityConfig::default()
            };
            let p = FileActivityWatchProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::FolderWatch(args) => {
            if cli.offline {
                let p = find_synthetic_provider("folder_changes_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = FolderChangesConfig {
                watch_dir: args.dir.clone(),
                duration_ms: args.duration_ms,
                ..FolderChangesConfig::default()
            };
            let p = FolderChangesViewProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::AccessErr(args) => {
            if cli.offline {
                let p = find_synthetic_provider("file_access_error_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = FileAccessErrorConfig {
                duration_ms: args.duration_ms,
                pid_filter: args.pid,
                ..FileAccessErrorConfig::default()
            };
            let p = FileAccessErrorViewProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::AppIo(args) => {
            if cli.offline {
                let p = find_synthetic_provider("app_read_write_counter")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = AppReadWriteConfig {
                sample_interval_ms: args.interval_ms,
                pid_filter: args.pid,
                ..AppReadWriteConfig::default()
            };
            let p = AppReadWriteCounterProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::Smart(args) => {
            if cli.offline {
                let p = find_synthetic_provider("disk_smart_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = DiskSmartConfig {
                disk_indices: args.disks.clone(),
                ..DiskSmartConfig::default()
            };
            let p = DiskSmartViewProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::Ads(args) => {
            if let Some(stream) = &args.delete_stream {
                let host = args
                    .paths
                    .first()
                    .map(|p| p.to_string_lossy().into_owned())
                    .context("--delete-stream requires --path <file>")?;
                return dispatch_gated_action(
                    cli,
                    wiring_for_action(),
                    "alternate_stream_delete",
                    json!({ "file_path": host, "stream_name": stream }),
                );
            }
            if cli.offline && args.paths.is_empty() {
                let p = find_synthetic_provider("alternate_stream_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = AlternateStreamConfig {
                target_paths: args.paths.clone(),
                recursive: args.recursive,
                ..AlternateStreamConfig::default()
            };
            let p = AlternateStreamViewProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::Links(args) => {
            if cli.offline && args.paths.is_empty() {
                let p = find_synthetic_provider("ntfs_links_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = NtfsLinksConfig {
                target_paths: args.paths.clone(),
                recursive: args.recursive,
                include_hardlinks: !args.no_hardlinks,
                ..NtfsLinksConfig::default()
            };
            let p = NtfsLinksViewProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::Props(args) => {
            if let (Some(name), Some(val)) = (&args.set_name, &args.set_value) {
                let host = args
                    .paths
                    .first()
                    .map(|p| p.to_string_lossy().into_owned())
                    .context("--set-name/--set-value requires --path <file>")?;
                return dispatch_gated_action(
                    cli,
                    wiring_for_action(),
                    "property_system_set",
                    json!({ "file_path": host, "canonical_name": name, "value": val }),
                );
            }
            if cli.offline && args.paths.is_empty() {
                let p = find_synthetic_provider("property_system_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = PropertySystemConfig {
                file_paths: args.paths.clone(),
                ..PropertySystemConfig::default()
            };
            let p = PropertySystemViewProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
        NtfsSub::Usn(args) => {
            if cli.offline {
                let p = find_synthetic_provider("usn_journal_view")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let cfg = UsnJournalConfig {
                volume: args.volume.clone(),
                start_usn: args.start_usn,
                max_records: args.max_records,
                ..UsnJournalConfig::default()
            };
            let p = UsnJournalViewProvider::new(cfg, live_backend);
            emit_provider_output(cli, &p)
        }
    }
}

fn run_data(cli: &Cli, sub: &DataSub) -> Result<()> {
    match sub {
        DataSub::Csv(args) => {
            let Some(ref path) = args.path else {
                let p = find_synthetic_provider("fs2rust.data.csv_file_view")?;
                return emit_provider_output(cli, p.as_ref());
            };
            let p = CsvTableProvider::from_path(path, CsvViewOptions::default())?;
            emit_provider_output(cli, &p)
        }
        DataSub::Diff(args) => {
            let (Some(left), Some(right)) = (&args.left, &args.right) else {
                let p = find_synthetic_provider("fs2rust.data.table_text_compare")?;
                return emit_provider_output(cli, p.as_ref());
            };
            let to_input = |p: &PathBuf| -> TableInput {
                let ext = p
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                match ext.as_str() {
                    "tsv" | "tab" => TableInput::Tsv { path: p.clone() },
                    "jsonl" | "ndjson" => TableInput::Jsonl { path: p.clone() },
                    _ => TableInput::Csv {
                        path: p.clone(),
                        options: CsvViewOptions::default(),
                    },
                }
            };
            let mut opts = TableCompareOptions::default();
            if let Some(ref keys) = args.keys {
                let cols: Vec<String> = keys
                    .split(',')
                    .map(|k| k.trim().to_string())
                    .filter(|k| !k.is_empty())
                    .collect();
                if !cols.is_empty() {
                    opts.key_mode = fs2rust_data::CompareKeyMode::Columns(cols);
                }
            }
            let p = TableCompareProvider::compare(to_input(left), to_input(right), opts)?;
            emit_provider_output(cli, &p)
        }
        DataSub::Query(args) => {
            let Some(ref path) = args.path else {
                let p = find_synthetic_provider("fs2rust.data.query")?;
                return emit_provider_output(cli, p.as_ref());
            };
            let req = TabularQueryRequest {
                columns: args.columns.as_ref().map(|c| {
                    c.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }),
                where_expr: args.where_expr.clone(),
                sort: args.sort_expr.clone(),
                top: args.top,
                ..TabularQueryRequest::default()
            };
            let p = TabularQueryProvider::from_source(TabularQuerySource::AutoFile(path.clone()), &req)?;
            emit_provider_output(cli, &p)
        }
        DataSub::Exif(args) => {
            let Some(ref path) = args.path else {
                let p = find_synthetic_provider("fs2rust.data.exif_data_view")?;
                return emit_provider_output(cli, p.as_ref());
            };
            let p = ExifDataViewProvider::from_paths(vec![path.clone()]);
            emit_provider_output(cli, &p)
        }
        DataSub::Codegen(args) => {
            if args.json.is_none() && args.csv.is_none() {
                let p = find_synthetic_provider("fs2rust.data.simple_code_generator")?;
                return emit_provider_output(cli, p.as_ref());
            }
            let input = if let Some(ref jp) = args.json {
                CodegenInput::Json {
                    json_text: std::fs::read_to_string(jp)?,
                }
            } else if let Some(ref cp) = args.csv {
                CodegenInput::Csv {
                    bytes: std::fs::read(cp)?,
                    options: CsvViewOptions::default(),
                }
            } else {
                unreachable!()
            };
            let template = CodegenTemplate {
                rule_name: args.rule_name.clone(),
                target: CodegenTarget::Custom,
                header_template: String::new(),
                body_template: args.template.clone(),
                footer_template: String::new(),
                separator: "\n".to_string(),
                escape_mode: EscapeMode::Auto,
                strict_placeholders: false,
            };
            let p = SimpleCodeGeneratorProvider::from_input(&input, &template)?;
            emit_provider_output(cli, &p)
        }
        DataSub::Html2text(args) => {
            let Some(ref path) = args.path else {
                let p = find_synthetic_provider("fs2rust.data.html_as_text")?;
                return emit_provider_output(cli, p.as_ref());
            };
            let p = HtmlAsTextProvider::from_paths(std::slice::from_ref(path), &HtmlAsTextOptions::default())?;
            emit_provider_output(cli, &p)
        }
        DataSub::Addr(args) => {
            let Some(ref path) = args.path else {
                let p = find_synthetic_provider("fs2rust.data.addr_view")?;
                return emit_provider_output(cli, p.as_ref());
            };
            let p = AddrViewProvider::from_path(path)?;
            emit_provider_output(cli, &p)
        }
    }
}

pub fn run_cli(cli: Cli) -> Result<()> {
    let Some(command) = cli.command.as_ref() else {
        return launch_sibling_gui(false);
    };

    match command {
        Commands::Search { sub } => run_search(&cli, sub),
        Commands::Ntfs { sub } => run_ntfs(&cli, sub),
        Commands::Data { sub } => run_data(&cli, sub),
        Commands::Mcp(args) => {
            let allow = cli.allow_mutating || args.allow_mutating;
            let policy = if allow {
                PolicyMode::AllowMutating
            } else {
                PolicyMode::ReadOnlyOnly
            };
            if args.tools {
                println!("{}", print_tools_manifest_json(policy, cli.offline, Vec::new())?);
                return Ok(());
            }
            serve_mcp_stdio(policy, cli.offline, Vec::new())
        }
        Commands::Gui(args) => launch_sibling_gui(args.iced),
        Commands::Action(args) => {
            let wiring = build_suite_wiring(cli.offline, Vec::new());
            let val: Value = serde_json::from_str(&args.args).context("invalid JSON passed to --args")?;
            dispatch_gated_action(&cli, wiring, &args.id, val)
        }
        Commands::List => {
            let wiring = build_suite_wiring(cli.offline, Vec::new());
            for (idx, p) in wiring.providers.iter().enumerate() {
                println!("{:>2}. {:<32} {}", idx + 1, p.tool_id(), p.description());
            }
            println!("\nMutating Actions:");
            for (idx, a) in wiring.actions.iter().enumerate() {
                println!("{:>2}. {:<32} {}", idx + 1, a.command_id(), a.description());
            }
            println!(
                "\nTotal tools: {}, mutating actions: {}",
                wiring.providers.len(),
                wiring.actions.len()
            );
            Ok(())
        }
        Commands::Export(args) => {
            let out_dir = cli
                .export
                .clone()
                .context("export requires --export <DIRECTORY> (or -o <DIRECTORY>)")?;
            let fmt = ExportFormat::parse(&cli.format)?;
            let opts = default_export_options(None);
            let wiring = build_suite_wiring(cli.offline || args.all, Vec::new());
            let mut tables = Vec::with_capacity(wiring.providers.len());
            for p in &wiring.providers {
                if let Ok(data) = p.query(&TableQuery::default()) {
                    tables.push(data);
                }
            }
            let manifest = write_bundle_report(&tables, &out_dir, fmt, &opts)?;
            if let Some(ref custody_path) = cli.custody {
                write_custody_manifest_json(&manifest, custody_path)?;
            }
            eprintln!(
                "Exported {} tables to {} (merkle_sha256={})",
                manifest.artifact_count,
                out_dir.display(),
                manifest.merkle_root_sha256
            );
            Ok(())
        }
        Commands::Diag => {
            let report = json!({
                "suite": "fs2rust",
                "version": env!("CARGO_PKG_VERSION"),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "tools_count": 24,
                "actions_count": 8,
                "offline": cli.offline,
                "r4_compliant": true,
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

pub fn run_from_env() -> Result<()> {
    let cli = Cli::parse();
    fs2rust_core::init_logging(cli.verbose);
    let _ = ctrlc::set_handler(|| {
        std::process::exit(130);
    });
    let _ = build_fs2rust_registry(PolicyMode::ReadOnlyOnly, cli.offline, Vec::new());
    run_cli(cli)
}
