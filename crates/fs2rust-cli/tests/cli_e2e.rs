#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use chrono::{TimeZone, Utc};
use clap::{CommandFactory, Parser};
use fs2rust_cli::{Cli, Commands, McpArgs, run_cli};
use fs2rust_mcp::build_synthetic_lnk_bytes;
use serde_json::{Value, json};
use tempfile::tempdir;

#[test]
fn clap_debug_assert_and_all_24_subcommands_parse() {
    Cli::command().debug_assert();

    let all_cases: &[&[&str]] = &[
        // 6 search tools (+ aliases)
        &["fs2rust", "search", "files", "--root", "."],
        &["fs2rust", "search", "bulk-time", "--target", "a.txt"],
        &["fs2rust", "search", "bulk-change", "--target", "a.txt"],
        &["fs2rust", "search", "folder-time", "--root", "."],
        &["fs2rust", "search", "report", "--root", "."],
        &["fs2rust", "search", "folders", "--root", "."],
        &["fs2rust", "search", "shortcuts", "--root", "."],
        &["fs2rust", "search", "hash", "--target", "a.txt"],
        // 11 ntfs tools (+ aliases)
        &["fs2rust", "ntfs", "drives"],
        &["fs2rust", "ntfs", "counters"],
        &["fs2rust", "ntfs", "disk-counters"],
        &["fs2rust", "ntfs", "file-watch", "--duration-ms", "100"],
        &["fs2rust", "ntfs", "file-activity", "--duration-ms", "100"],
        &["fs2rust", "ntfs", "folder-watch", "--dir", "."],
        &["fs2rust", "ntfs", "folder-changes", "--dir", "."],
        &["fs2rust", "ntfs", "access-err"],
        &["fs2rust", "ntfs", "file-errors"],
        &["fs2rust", "ntfs", "app-io"],
        &["fs2rust", "ntfs", "smart"],
        &["fs2rust", "ntfs", "ads", "--path", "a.txt"],
        &["fs2rust", "ntfs", "links", "--path", "."],
        &["fs2rust", "ntfs", "props", "--path", "a.txt"],
        &["fs2rust", "ntfs", "usn", "--volume", "C:"],
        // 7 data tools (+ aliases)
        &["fs2rust", "data", "csv", "--path", "a.csv"],
        &["fs2rust", "data", "diff", "--left", "a.csv", "--right", "b.csv"],
        &["fs2rust", "data", "compare", "--left", "a.csv", "--right", "b.csv"],
        &["fs2rust", "data", "query", "--path", "a.csv"],
        &["fs2rust", "data", "exif", "--path", "a.jpg"],
        &["fs2rust", "data", "codegen", "--json", "a.json"],
        &["fs2rust", "data", "html2text", "--path", "a.html"],
        &["fs2rust", "data", "html", "--path", "a.html"],
        &["fs2rust", "data", "addr", "--path", "a.vcf"],
        // surfaces + helpers
        &["fs2rust", "mcp", "--tools", "--allow-mutating"],
        &["fs2rust", "gui", "--iced"],
        &["fs2rust", "list"],
        &["fs2rust", "diag"],
        &["fs2rust", "export", "--all", "-o", "out_dir"],
    ];

    for argv in all_cases {
        Cli::try_parse_from(*argv).unwrap_or_else(|e| panic!("failed to parse {argv:?}: {e}"));
    }

    let p_mcp = Cli::try_parse_from([
        "fs2rust",
        "-y",
        "--confirm-destructive",
        "--dry-run",
        "--format",
        "json",
        "-o",
        "out.json",
        "--custody",
        "custody.json",
        "mcp",
        "--tools",
    ])
    .unwrap();
    assert!(p_mcp.allow_mutating);
    assert!(p_mcp.confirm_destructive);
    assert!(p_mcp.dry_run);
    assert!(matches!(
        p_mcp.command,
        Some(Commands::Mcp(McpArgs { tools: true, .. }))
    ));
}

#[test]
fn cli_offline_exports_and_custody_manifests_succeed() {
    let tmp = tempdir().unwrap();
    let sample_csv = tmp.path().join("sample.csv");
    fs::write(&sample_csv, "name,formula,count\nalpha,=1+1,10\nbeta,ok,20\n").unwrap();

    let out_csv = tmp.path().join("out.csv");
    let custody_json = tmp.path().join("out.custody.json");
    let cli_csv = Cli::try_parse_from([
        "fs2rust",
        "--format",
        "csv",
        "-o",
        out_csv.to_str().unwrap(),
        "--custody",
        custody_json.to_str().unwrap(),
        "data",
        "csv",
        "--path",
        sample_csv.to_str().unwrap(),
    ])
    .unwrap();
    run_cli(cli_csv).unwrap();

    let exported = fs::read_to_string(&out_csv).unwrap();
    assert!(
        exported.contains("'=1+1"),
        "expected CSV formula neutralization: {exported}"
    );
    let custody: Value = serde_json::from_str(&fs::read_to_string(&custody_json).unwrap()).unwrap();
    assert_eq!(custody["merkle_root_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(custody["merkle_root_sha512"].as_str().unwrap().len(), 128);

    // Search + Hash + Markdown export
    let hash_md = tmp.path().join("hashes.md");
    let cli_hash = Cli::try_parse_from([
        "fs2rust",
        "--format",
        "markdown",
        "--export",
        hash_md.to_str().unwrap(),
        "search",
        "hash",
        "--target",
        sample_csv.to_str().unwrap(),
    ])
    .unwrap();
    run_cli(cli_hash).unwrap();
    let md_txt = fs::read_to_string(&hash_md).unwrap();
    assert!(md_txt.contains("sample.csv"));
}

#[test]
fn cli_policy_gates_dry_run_and_tempdir_mutations_work() {
    let tmp = tempdir().unwrap();
    let target_file = tmp.path().join("mutable.txt");
    fs::write(&target_file, b"payload").unwrap();

    let lnk_file = tmp.path().join("broken.lnk");
    fs::write(
        &lnk_file,
        build_synthetic_lnk_bytes(r"C:\NonExistent\missing_app.exe", r"C:\NonExistent", ""),
    )
    .unwrap();

    let new_mtime = "2026-03-15T10:00:00Z";
    let expected_dt = Utc.with_ymd_and_hms(2026, 3, 15, 10, 0, 0).unwrap();

    // 1. Mutating without -y -> PolicyDenied (-32003)
    let denied = Cli::try_parse_from([
        "fs2rust",
        "search",
        "bulk-time",
        "--target",
        target_file.to_str().unwrap(),
        "--modified",
        new_mtime,
        "--apply",
    ])
    .unwrap();
    let err1 = run_cli(denied).unwrap_err();
    assert!(err1.to_string().contains("-32003"), "unexpected err1: {err1}");

    // 2. -y without --confirm-destructive -> still denied (-32003)
    let half = Cli::try_parse_from([
        "fs2rust",
        "-y",
        "search",
        "bulk-time",
        "--target",
        target_file.to_str().unwrap(),
        "--modified",
        new_mtime,
        "--apply",
    ])
    .unwrap();
    let err2 = run_cli(half).unwrap_err();
    assert!(err2.to_string().contains("-32003"), "unexpected err2: {err2}");

    // 3. --dry-run succeeds with zero side effects
    let dry_out = tmp.path().join("dry.json");
    let dry = Cli::try_parse_from([
        "fs2rust",
        "--dry-run",
        "-o",
        dry_out.to_str().unwrap(),
        "search",
        "shortcuts",
        "--delete",
        lnk_file.to_str().unwrap(),
    ])
    .unwrap();
    run_cli(dry).unwrap();
    let dry_val: Value = serde_json::from_str(&fs::read_to_string(&dry_out).unwrap()).unwrap();
    assert_eq!(dry_val["mode"], json!("dry_run"));
    assert!(lnk_file.is_file(), "dry-run must not delete .lnk file");

    // 4. -y --confirm-destructive mutates tempdir target_file and deletes broken.lnk
    let apply_out = tmp.path().join("apply.json");
    let apply_time = Cli::try_parse_from([
        "fs2rust",
        "-y",
        "--confirm-destructive",
        "-o",
        apply_out.to_str().unwrap(),
        "search",
        "bulk-time",
        "--target",
        target_file.to_str().unwrap(),
        "--modified",
        new_mtime,
        "--apply",
    ])
    .unwrap();
    run_cli(apply_time).unwrap();
    let apply_val: Value = serde_json::from_str(&fs::read_to_string(&apply_out).unwrap()).unwrap();
    assert_eq!(apply_val["mode"], json!("applied"));
    assert_eq!(apply_val["succeeded"], json!(1));
    let actual_mtime: chrono::DateTime<Utc> = fs::metadata(&target_file).unwrap().modified().unwrap().into();
    assert_eq!(actual_mtime.timestamp(), expected_dt.timestamp());

    let del_lnk = Cli::try_parse_from([
        "fs2rust",
        "-y",
        "--confirm-destructive",
        "search",
        "shortcuts",
        "--delete",
        lnk_file.to_str().unwrap(),
    ])
    .unwrap();
    run_cli(del_lnk).unwrap();
    assert!(!lnk_file.exists(), "expected broken.lnk to be deleted");
}

#[test]
fn real_fs2rust_binary_e2e_help_tools_exports_and_mcp_stdio() {
    let bin = env!("CARGO_BIN_EXE_fs2rust");
    let tmp = tempdir().unwrap();

    // 1. --help
    let help = Command::new(bin).arg("--help").output().unwrap();
    assert!(help.status.success());
    let help_out = String::from_utf8_lossy(&help.stdout);
    assert!(help_out.contains("fs2rust"));
    assert!(help_out.contains("search"));
    assert!(help_out.contains("ntfs"));
    assert!(help_out.contains("data"));

    // 2. mcp --tools -> exact 32 tools (24 TableProviders + 8 ActionCommands)
    let tools_out = Command::new(bin)
        .args(["mcp", "--tools", "--offline"])
        .output()
        .unwrap();
    assert!(tools_out.status.success());
    let tools: Value = serde_json::from_slice(&tools_out.stdout).unwrap();
    assert_eq!(tools.as_array().unwrap().len(), 32);

    // 3. Offline domain subcommand -> JSON + custody manifest
    let sample_csv = tmp.path().join("cli.csv");
    fs::write(&sample_csv, "col_a,col_b\nx,1\ny,2\n").unwrap();
    let out_json = tmp.path().join("cli.json");
    let custody_json = tmp.path().join("cli.custody.json");
    let csv_run = Command::new(bin)
        .args([
            "--format",
            "json",
            "-o",
            out_json.to_str().unwrap(),
            "--custody",
            custody_json.to_str().unwrap(),
            "data",
            "csv",
            "--path",
            sample_csv.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        csv_run.status.success(),
        "csv_run failed: {}",
        String::from_utf8_lossy(&csv_run.stderr)
    );
    assert!(out_json.is_file());
    assert!(custody_json.is_file());

    // 4. Policy denial when calling mutating action without -y
    let target = tmp.path().join("f.txt");
    fs::write(&target, b"abc").unwrap();
    let denied = Command::new(bin)
        .args([
            "action",
            "--id",
            "bulk_file_time_apply",
            "--args",
            &json!({ "targets": [target.to_string_lossy()] }).to_string(),
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    let stderr_txt = String::from_utf8_lossy(&denied.stderr);
    assert!(stderr_txt.contains("-32003"), "stderr: {stderr_txt}");

    // 5. Real child-process MCP stdio JSON-RPC pipe (ReadOnlyOnly)
    let mut ro_child = Command::new(bin)
        .args(["mcp", "--offline"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let ro_payload = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05", "capabilities": {} }
        })
        .to_string(),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }).to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "fs2rust.data.csv_file_view", "arguments": {} }
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "bulk_file_time_apply",
                "arguments": { "targets": ["/mock/alpha.txt"], "confirm_destructive": true }
            }
        })
        .to_string(),
    ]
    .join("\n")
        + "\n";

    ro_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(ro_payload.as_bytes())
        .unwrap();
    drop(ro_child.stdin.take());
    let ro_output = ro_child.wait_with_output().unwrap();
    assert!(ro_output.status.success());
    let ro_resps: Vec<Value> = String::from_utf8(ro_output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect();
    assert_eq!(ro_resps.len(), 4);
    assert_eq!(ro_resps[0]["result"]["protocolVersion"], json!("2024-11-05"));
    assert_eq!(ro_resps[1]["result"]["tools"].as_array().unwrap().len(), 32);
    assert_eq!(ro_resps[2]["result"]["isError"], json!(false));
    assert_eq!(ro_resps[3]["error"]["code"], json!(-32003));

    // 6. Real child-process MCP stdio JSON-RPC pipe (--allow-mutating)
    let mut mut_child = Command::new(bin)
        .args(["mcp", "--offline", "--allow-mutating"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut_payload = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "alternate_stream_delete",
                "arguments": { "file_path": "/mock/alpha.txt", "stream_name": "Zone.Identifier" }
            }
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "alternate_stream_delete",
                "arguments": {
                    "file_path": "/mock/alpha.txt",
                    "stream_name": "Zone.Identifier",
                    "confirm_destructive": true,
                    "dry_run": false
                }
            }
        })
        .to_string(),
    ]
    .join("\n")
        + "\n";

    mut_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(mut_payload.as_bytes())
        .unwrap();
    drop(mut_child.stdin.take());
    let mut_output = mut_child.wait_with_output().unwrap();
    assert!(mut_output.status.success());
    let mut_resps: Vec<Value> = String::from_utf8(mut_output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect();
    assert_eq!(mut_resps.len(), 2);
    assert_eq!(mut_resps[0]["error"]["code"], json!(-32003));
    assert_eq!(mut_resps[1]["result"]["isError"], json!(false));
}
