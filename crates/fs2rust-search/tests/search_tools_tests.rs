use chrono::{TimeZone, Utc};
use fs2rust_core::{FileAttributes, FileSystemOps, FileTimestamps, MockFileSystem, OsFileSystem, PolicyContext};
use fs2rust_search::bulk_file_time::{
    BulkChangeSpec, BulkFileTimeAction, BulkFileTimePreviewProvider, TimestampChange,
};
use fs2rust_search::folder_time_update::{
    FolderTimeSource, FolderTimeUpdateAction, FolderTimeUpdateConfig, FolderTimeUpdatePreviewProvider,
};
use fs2rust_search::folders_report::{FoldersReportConfig, FoldersReportProvider};
use fs2rust_search::hash_files::{HashAlgorithmSet, HashFilesConfig, HashFilesProvider};
use fs2rust_search::register_search_tools_with_backend;
use fs2rust_search::search_files::{ContentSearchMode, SearchFilesConfig, SearchFilesProvider, parse_hex_pattern};
use fs2rust_search::shortcuts::{
    ExtraDataBlock, LinkInfo, LinkTargetIdList, SHELL_LINK_CLSID, SHELL_LINK_HEADER_SIZE, ShellLinkFile,
    ShellLinkHeader, ShortcutsConfig, ShortcutsDeleteAction, ShortcutsFixAction, ShortcutsProvider, ShowCommand,
    StringData, extra_sig, link_flags,
};
use guap_mcp::{ActionCommand, JsonRpcError, McpServerRegistry, McpToolError, PolicyMode};
use guap_table::{CellValue, TableProvider, TableQuery};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[test]
fn search_files_cross_chunk_binary_grep_and_duplicates() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let ignored_dir = root.join("node_modules");
    std::fs::create_dir(&ignored_dir).unwrap();
    std::fs::write(ignored_dir.join("skip.bin"), b"\xDE\xAD\xBE\xEF").unwrap();

    // Build a file where 0xDE 0xAD 0xBE 0xEF straddles the 64 KiB (65536) chunk boundary!
    let mut cross_chunk = vec![b'A'; 65_534];
    cross_chunk.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    cross_chunk.extend_from_slice(b"tail");
    let target_bin = root.join("cross.bin");
    std::fs::write(&target_bin, &cross_chunk).unwrap();

    // Non-matching binary
    std::fs::write(root.join("other.bin"), b"no magic bytes here").unwrap();

    let hex_needle = parse_hex_pattern("DE AD BE EF").unwrap();
    let provider = SearchFilesProvider::new(SearchFilesConfig {
        roots: vec![root.to_path_buf()],
        include_patterns: vec!["*.bin".to_string()],
        exclude_dirs: vec!["node_modules".to_string()],
        content_filter: Some(ContentSearchMode::BinaryHex(hex_needle)),
        compute_sha256: true,
        threads: 2,
        ..SearchFilesConfig::default()
    });

    let data = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(data.total_rows, 1);
    assert_eq!(data.rows[0].cells[0], CellValue::Text("cross.bin".to_string()));
    assert_eq!(data.rows[0].cells[8], CellValue::Uint(65_534));
    assert!(
        data.rows[0]
            .raw_bytes
            .as_ref()
            .unwrap()
            .starts_with(&[0xDE, 0xAD, 0xBE, 0xEF])
    );
    assert!(matches!(data.rows[0].cells[9], CellValue::Text(ref h) if h.len() == 64));

    // Duplicate grouping + plain-text case-insensitive + regex
    let dup_dir = root.join("dups");
    std::fs::create_dir(&dup_dir).unwrap();
    std::fs::write(dup_dir.join("a.txt"), b"Hello Forensic World 123").unwrap();
    std::fs::write(dup_dir.join("b.txt"), b"Hello Forensic World 123").unwrap();
    std::fs::write(dup_dir.join("c.txt"), b"Unique forensic note").unwrap();

    let dup_provider = SearchFilesProvider::new(SearchFilesConfig {
        roots: vec![dup_dir],
        content_filter: Some(ContentSearchMode::PlainText {
            needle: "FORENSIC".to_string(),
            case_sensitive: false,
        }),
        group_duplicates: true,
        ..SearchFilesConfig::default()
    });
    let dup_data = dup_provider.query(&TableQuery::default()).unwrap();
    assert_eq!(dup_data.total_rows, 3);
    assert_eq!(dup_data.rows[0].cells[10], CellValue::Uint(1));
    assert_eq!(dup_data.rows[1].cells[10], CellValue::Uint(1));
    assert_eq!(dup_data.rows[2].cells[10], CellValue::Null);

    let re_provider = SearchFilesProvider::new(SearchFilesConfig {
        roots: vec![root.join("dups")],
        content_filter: Some(ContentSearchMode::Regex(r"World \d{3}".to_string())),
        ..SearchFilesConfig::default()
    });
    assert_eq!(re_provider.query(&TableQuery::default()).unwrap().total_rows, 2);
}

#[test]
fn bulk_file_time_mock_readonly_ordering_and_live_windows() {
    let mock = Arc::new(MockFileSystem::new());
    let file_path = Path::new("C:\\mock\\locked.txt");
    let t0 = Utc.with_ymd_and_hms(2024, 3, 1, 10, 0, 0).unwrap();
    let t1 = Utc.with_ymd_and_hms(2025, 8, 20, 15, 30, 0).unwrap();

    mock.insert_file(
        file_path,
        b"data".to_vec(),
        FileTimestamps {
            created: Some(t0),
            modified: Some(t0),
            accessed: Some(t0),
        },
        FileAttributes::from_raw(FileAttributes::READONLY | FileAttributes::ARCHIVE),
    );

    let preview = BulkFileTimePreviewProvider::new(
        BulkChangeSpec {
            targets: vec![file_path.to_path_buf()],
            recursive: false,
            created: TimestampChange::Keep,
            modified: TimestampChange::SetExact(t1),
            accessed: TimestampChange::ShiftSeconds(60),
            set_attrs: FileAttributes::parse_flags("H").unwrap(),
            clear_attrs: FileAttributes::parse_flags("R").unwrap(),
        },
        mock.clone(),
    );
    let preview_data = preview.query(&TableQuery::default()).unwrap();
    assert_eq!(preview_data.total_rows, 1);
    assert_eq!(preview_data.rows[0].cells[9], CellValue::Bool(true));
    assert_eq!(preview_data.rows[0].cells[10], CellValue::Text("Preview".to_string()));
    // Preview must NOT mutate mock state
    assert_eq!(mock.metadata(file_path).unwrap().timestamps.modified, Some(t0));

    // Apply via ActionCommand (ReadOnly cleared before SetFileTime, Hidden applied)
    let action = BulkFileTimeAction::new(mock.clone());
    let res = action
        .execute(
            &json!({
                "targets": ["C:\\mock\\locked.txt"],
                "modified": { "set_exact": t1.to_rfc3339() },
                "accessed": { "copy_from": "modified" },
                "set_attributes": ["H"],
                "clear_attributes": ["R"]
            }),
            false,
        )
        .unwrap();
    assert_eq!(res["succeeded"], 1);
    let after = mock.metadata(file_path).unwrap();
    assert!(!after.attributes.read_only);
    assert!(after.attributes.hidden);
    assert_eq!(after.timestamps.modified, Some(t1));

    // Live OS filesystem test on Windows (SetFileTime + SetFileAttributesW)
    let tmp = tempfile::tempdir().unwrap();
    let real_file = tmp.path().join("live_bulk.txt");
    std::fs::write(&real_file, b"live test").unwrap();
    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    let live_action = BulkFileTimeAction::new(os_fs.clone());
    let live_res = live_action
        .execute(
            &json!({
                "targets": [real_file.to_string_lossy()],
                "modified": t1.to_rfc3339(),
                "set_attributes": ["R", "H"],
            }),
            false,
        )
        .unwrap();
    assert_eq!(live_res["succeeded"], 1);
    let real_meta = os_fs.metadata(&real_file).unwrap();
    assert_eq!(real_meta.timestamps.modified, Some(t1));
    assert!(real_meta.attributes.read_only);
    #[cfg(windows)]
    assert!(real_meta.attributes.hidden);

    // Clear READONLY so tempdir cleans up cleanly
    os_fs.set_attributes(&real_file, &FileAttributes::default()).unwrap();
}

#[test]
fn mcp_registry_policy_gate_enforces_32003_on_mutating_search_actions() {
    let mock = Arc::new(MockFileSystem::new());
    let file_path = Path::new("C:\\mock\\gate.txt");
    let t0 = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
    mock.insert_file(
        file_path,
        b"abc".to_vec(),
        FileTimestamps {
            created: Some(t0),
            modified: Some(t0),
            accessed: Some(t0),
        },
        FileAttributes::default(),
    );

    let mut reg = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
    register_search_tools_with_backend(
        &mut reg,
        mock.clone(),
        SearchFilesConfig::default(),
        BulkChangeSpec::default(),
        FolderTimeUpdateConfig::default(),
        FoldersReportConfig::default(),
        ShortcutsConfig::default(),
        HashFilesConfig::default(),
    );

    let err = reg
        .dispatch(
            "bulk_file_time_apply",
            &json!({
                "targets": ["C:\\mock\\gate.txt"],
                "modified": "2025-01-01T00:00:00Z",
                "confirm_destructive": true
            }),
        )
        .unwrap_err();
    assert_eq!(err.code, JsonRpcError::POLICY_DENIED);

    reg.set_policy(PolicyMode::AllowMutating);
    let err2 = reg
        .dispatch(
            "bulk_file_time_apply",
            &json!({
                "targets": ["C:\\mock\\gate.txt"],
                "modified": "2025-01-01T00:00:00Z"
            }),
        )
        .unwrap_err();
    assert_eq!(err2.code, JsonRpcError::POLICY_DENIED);

    let ok = reg
        .dispatch(
            "bulk_file_time_apply",
            &json!({
                "targets": ["C:\\mock\\gate.txt"],
                "modified": "2025-01-01T00:00:00Z",
                "confirm_destructive": true,
                "dry_run": false
            }),
        )
        .unwrap();
    assert_eq!(ok["succeeded"], 1);
}

#[test]
fn folder_time_update_propagates_newest_child_bottom_up() {
    let mock = Arc::new(MockFileSystem::new());
    let t_old = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    let t_newer = Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap();
    let t_dir_future = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

    let root = Path::new("C:\\ftu");
    let sub = Path::new("C:\\ftu\\sub");
    let f1 = Path::new("C:\\ftu\\sub\\old.txt");
    let f2 = Path::new("C:\\ftu\\sub\\new.txt");

    mock.insert_dir(
        root,
        FileTimestamps {
            modified: Some(t_dir_future),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );
    mock.insert_dir(
        sub,
        FileTimestamps {
            modified: Some(t_dir_future),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );
    mock.insert_file(
        f1,
        b"1".to_vec(),
        FileTimestamps {
            modified: Some(t_old),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );
    mock.insert_file(
        f2,
        b"2".to_vec(),
        FileTimestamps {
            modified: Some(t_newer),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );

    let cfg = FolderTimeUpdateConfig {
        root: root.to_path_buf(),
        source: FolderTimeSource::NewestFileOnly,
        ..FolderTimeUpdateConfig::default()
    };
    let preview = FolderTimeUpdatePreviewProvider::new(cfg, mock.clone());
    let p_data = preview.query(&TableQuery::default()).unwrap();
    assert_eq!(p_data.total_rows, 2);
    assert_eq!(p_data.rows[0].cells[3], CellValue::Timestamp(t_newer));
    assert_eq!(p_data.rows[1].cells[3], CellValue::Timestamp(t_newer));
    assert_eq!(mock.metadata(root).unwrap().timestamps.modified, Some(t_dir_future));

    let action = FolderTimeUpdateAction::new(mock.clone());
    let applied = action.execute(&json!({ "root": "C:\\ftu" }), false).unwrap();
    assert_eq!(applied["updated"], 2);
    assert_eq!(mock.metadata(sub).unwrap().timestamps.modified, Some(t_newer));
    assert_eq!(mock.metadata(root).unwrap().timestamps.modified, Some(t_newer));

    // Live Windows directory mtime update check (FILE_FLAG_BACKUP_SEMANTICS)
    let tmp = tempfile::tempdir().unwrap();
    let live_sub = tmp.path().join("child");
    std::fs::create_dir(&live_sub).unwrap();
    let live_file = live_sub.join("data.txt");
    std::fs::write(&live_file, b"payload").unwrap();
    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    os_fs
        .set_timestamps(
            &live_file,
            &FileTimestamps {
                modified: Some(t_newer),
                ..FileTimestamps::default()
            },
        )
        .unwrap();
    let live_action = FolderTimeUpdateAction::new(os_fs.clone());
    let live_res = live_action
        .execute(&json!({ "root": tmp.path().to_string_lossy() }), false)
        .unwrap();
    assert_eq!(live_res["failed"], 0);
    assert_eq!(os_fs.metadata(&live_sub).unwrap().timestamps.modified, Some(t_newer));
}

#[test]
fn folders_report_aggregates_counts_compressed_size_and_percentages() {
    let mock = Arc::new(MockFileSystem::new());
    let root = Path::new("C:\\rep");
    let sub_a = Path::new("C:\\rep\\alpha");
    let sub_b = Path::new("C:\\rep\\beta");
    let nested = Path::new("C:\\rep\\alpha\\nested");
    let ts = FileTimestamps::default();

    mock.insert_dir(root, ts, FileAttributes::default());
    mock.insert_dir(sub_a, ts, FileAttributes::default());
    mock.insert_dir(sub_b, ts, FileAttributes::default());
    mock.insert_dir(nested, ts, FileAttributes::default());

    mock.insert_file_with_compressed(
        Path::new("C:\\rep\\root.txt"),
        vec![0u8; 100],
        Some(100),
        ts,
        FileAttributes::default(),
    );
    mock.insert_file_with_compressed(
        Path::new("C:\\rep\\alpha\\a.bin"),
        vec![0u8; 200],
        Some(50),
        ts,
        FileAttributes::default(),
    );
    mock.insert_file_with_compressed(
        Path::new("C:\\rep\\alpha\\nested\\n.bin"),
        vec![0u8; 300],
        Some(150),
        ts,
        FileAttributes::default(),
    );
    mock.insert_file_with_compressed(
        Path::new("C:\\rep\\beta\\b.bin"),
        vec![0u8; 400],
        Some(400),
        ts,
        FileAttributes::default(),
    );

    let provider = FoldersReportProvider::new(
        FoldersReportConfig {
            root: root.to_path_buf(),
            depth: 1,
            include_root_files_row: true,
            follow_symlinks: false,
            threads: 2,
        },
        mock,
    );
    let data = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(data.total_rows, 3); // alpha (500), beta (400), (root files) (100) => total 1000
    assert_eq!(data.rows[0].cells[0], CellValue::Text("alpha".to_string()));
    assert_eq!(data.rows[0].cells[2], CellValue::Uint(2));
    assert_eq!(data.rows[0].cells[3], CellValue::Uint(1));
    assert_eq!(data.rows[0].cells[4], CellValue::Bytes(500));
    assert_eq!(data.rows[0].cells[5], CellValue::Bytes(200));
    assert_eq!(data.rows[0].cells[6], CellValue::Float(50.0));

    let pct_sum: f64 = data
        .rows
        .iter()
        .filter_map(|r| match r.cells[6] {
            CellValue::Float(f) => Some(f),
            _ => None,
        })
        .sum();
    assert!((pct_sum - 100.0).abs() < 0.01);
}

fn build_synthetic_ansi_lnk(local_path: &str, name: &str, args: &str) -> Vec<u8> {
    let flags = link_flags::HAS_LINK_INFO | link_flags::HAS_NAME | link_flags::HAS_ARGUMENTS;
    let mut out = Vec::new();
    out.extend_from_slice(&SHELL_LINK_HEADER_SIZE.to_le_bytes());
    out.extend_from_slice(&SHELL_LINK_CLSID);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // attrs
    out.extend_from_slice(&0u64.to_le_bytes()); // ctime
    out.extend_from_slice(&0u64.to_le_bytes()); // atime
    out.extend_from_slice(&0u64.to_le_bytes()); // wtime
    out.extend_from_slice(&0u32.to_le_bytes()); // file_size
    out.extend_from_slice(&0i32.to_le_bytes()); // icon_idx
    out.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand::Normal
    out.extend_from_slice(&0u16.to_le_bytes()); // hotkey
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // Minimal ANSI LinkInfo (header_size = 0x1C)
    let vol_off = 0x1Cu32;
    let local_off = vol_off + 17;
    let suffix_off = local_off + local_path.len() as u32 + 1;
    let total_size = suffix_off + 1;
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&0x1Cu32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
    out.extend_from_slice(&vol_off.to_le_bytes());
    out.extend_from_slice(&local_off.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&suffix_off.to_le_bytes());
    // VolumeID (17 bytes)
    out.extend_from_slice(&17u32.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    out.extend_from_slice(&16u32.to_le_bytes());
    out.push(0);
    // LocalBasePath + suffix
    out.extend_from_slice(local_path.as_bytes());
    out.push(0);
    out.push(0);

    // ANSI StringData (name, args)
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(args.len() as u16).to_le_bytes());
    out.extend_from_slice(args.as_bytes());

    // Terminal ExtraData block
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

#[test]
fn shortcuts_view_parses_unicode_ansi_env_darwin_and_fixes_broken_lnk() {
    let tmp = tempfile::tempdir().unwrap();
    let real_target = tmp.path().join("real_app.exe");
    std::fs::write(&real_target, b"MZ").unwrap();

    let missing_target = tmp.path().join("missing_app.exe");
    let broken_lnk_path = tmp.path().join("broken.lnk");

    let unicode_lnk = ShellLinkFile {
        header: ShellLinkHeader {
            show_command: ShowCommand::Maximized,
            hot_key: (0x06 << 8) | (b'K' as u16), // Ctrl+Alt+K
            ..ShellLinkHeader::default()
        },
        id_list: Some(LinkTargetIdList {
            raw_id_list: vec![0x00, 0x00],
            items: vec![],
            pidl_path_hint: None,
        }),
        link_info: Some(LinkInfo {
            flags: 0x01,
            drive_type: Some(3),
            drive_serial: Some(42),
            volume_label: Some("OS".to_string()),
            local_base_path: Some(missing_target.to_string_lossy().into_owned()),
            network_share_name: None,
            common_path_suffix: Some(String::new()),
        }),
        string_data: StringData {
            name: Some("Broken App".to_string()),
            relative_path: None,
            working_dir: Some(tmp.path().to_string_lossy().into_owned()),
            cmd_args: Some("--check".to_string()),
            icon_location: Some("app.ico".to_string()),
        },
        extra_data: vec![ExtraDataBlock::Tracker {
            machine_id: "WORKSTATION".to_string(),
            droid: [[1u8; 16], [2u8; 16]],
            droid_birth: [[3u8; 16], [4u8; 16]],
        }],
    };
    std::fs::write(&broken_lnk_path, unicode_lnk.to_bytes().unwrap()).unwrap();

    // ANSI .lnk fixture
    let ansi_bytes = build_synthetic_ansi_lnk("C:\\Windows\\notepad.exe", "Notepad", "/A");
    let ansi_parsed = ShellLinkFile::parse(&ansi_bytes).unwrap();
    assert_eq!(ansi_parsed.string_data.name.as_deref(), Some("Notepad"));
    assert_eq!(ansi_parsed.string_data.cmd_args.as_deref(), Some("/A"));
    assert_eq!(
        ansi_parsed.resolve_target(Path::new("x.lnk"), None).target_path,
        "C:\\Windows\\notepad.exe"
    );

    // EnvVariable + Darwin extra blocks fixture
    let env_lnk = ShellLinkFile {
        header: ShellLinkHeader::default(),
        id_list: None,
        link_info: None,
        string_data: StringData::default(),
        extra_data: vec![ExtraDataBlock::EnvironmentVariable {
            target_ansi: "%APP_ROOT%\\bin\\tool.exe".to_string(),
            target_unicode: "%APP_ROOT%\\bin\\tool.exe".to_string(),
        }],
    };
    let env_parsed = ShellLinkFile::parse(&env_lnk.to_bytes().unwrap()).unwrap();
    let mut overrides = BTreeMap::new();
    overrides.insert("APP_ROOT".to_string(), "D:\\Tools".to_string());
    assert_eq!(
        env_parsed
            .resolve_target(Path::new("x.lnk"), Some(&overrides))
            .target_path,
        "D:\\Tools\\bin\\tool.exe"
    );

    let darwin_lnk = ShellLinkFile {
        header: ShellLinkHeader::default(),
        id_list: None,
        link_info: None,
        string_data: StringData::default(),
        extra_data: vec![ExtraDataBlock::Darwin {
            data_ansi: "[ProductCode]>Feature".to_string(),
            data_unicode: "[ProductCode]>Feature".to_string(),
        }],
    };
    let darwin_parsed = ShellLinkFile::parse(&darwin_lnk.to_bytes().unwrap()).unwrap();
    let darwin_resolved = darwin_parsed.resolve_target(Path::new("x.lnk"), None);
    assert!(darwin_resolved.virtual_target);
    assert_eq!(darwin_resolved.kind, "DarwinMSI");
    let _ = extra_sig::DARWIN;

    // Provider detects broken target
    let provider = ShortcutsProvider::new(ShortcutsConfig {
        scan_roots: vec![tmp.path().to_path_buf()],
        ..ShortcutsConfig::default()
    });
    let table = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(table.total_rows, 1);
    assert_eq!(table.rows[0].cells[2], CellValue::Bool(false));
    assert_eq!(table.rows[0].cells[6], CellValue::Text("Ctrl+Alt+K".to_string()));
    assert_eq!(table.rows[0].cells[7], CellValue::Text("Maximized".to_string()));

    // Fix action (dry-run then apply)
    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    let fix = ShortcutsFixAction::new(os_fs.clone());
    let dry = fix
        .execute(
            &json!({
                "shortcut_path": broken_lnk_path.to_string_lossy(),
                "new_target": real_target.to_string_lossy(),
            }),
            true,
        )
        .unwrap();
    assert_eq!(dry["mode"], "dry_run");
    assert_eq!(
        provider.query(&TableQuery::default()).unwrap().rows[0].cells[2],
        CellValue::Bool(false)
    );

    fix.execute(
        &json!({
            "shortcut_path": broken_lnk_path.to_string_lossy(),
            "new_target": real_target.to_string_lossy(),
        }),
        false,
    )
    .unwrap();
    assert_eq!(
        provider.query(&TableQuery::default()).unwrap().rows[0].cells[2],
        CellValue::Bool(true)
    );

    // Delete action with only_if_broken = true refuses valid shortcut
    let del = ShortcutsDeleteAction::new(os_fs);
    let skip_res = del
        .execute(
            &json!({
                "shortcut_paths": [broken_lnk_path.to_string_lossy()],
                "only_if_broken": true
            }),
            false,
        )
        .unwrap();
    assert_eq!(skip_res["skipped"], 1);
    assert!(broken_lnk_path.exists());

    // When target is deleted, only_if_broken = true deletes shortcut
    std::fs::remove_file(&real_target).unwrap();
    let del_res = del
        .execute(
            &json!({
                "shortcut_paths": [broken_lnk_path.to_string_lossy()],
                "only_if_broken": true
            }),
            false,
        )
        .unwrap();
    assert_eq!(del_res["deleted"], 1);
    assert!(!broken_lnk_path.exists());
}

#[test]
fn hash_files_matches_rfc_nist_vectors_and_groups_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let empty_f = tmp.path().join("01_empty.bin");
    let abc1_f = tmp.path().join("02_abc.txt");
    let abc2_f = tmp.path().join("03_abc_copy.txt");
    let big_f = tmp.path().join("04_big.bin");

    std::fs::write(&empty_f, b"").unwrap();
    std::fs::write(&abc1_f, b"abc").unwrap();
    std::fs::write(&abc2_f, b"abc").unwrap();
    std::fs::write(&big_f, vec![0x5Au8; 131_072]).unwrap();

    let provider = HashFilesProvider::new(HashFilesConfig {
        targets: vec![tmp.path().to_path_buf()],
        algorithms: HashAlgorithmSet::default(),
        threads: 2,
        ..HashFilesConfig::default()
    });
    let data = provider.query(&TableQuery::default()).unwrap();
    assert_eq!(data.total_rows, 4);

    // 01_empty.bin
    assert_eq!(
        data.rows[0].cells[2],
        CellValue::Text("d41d8cd98f00b204e9800998ecf8427e".to_string())
    );
    assert_eq!(
        data.rows[0].cells[3],
        CellValue::Text("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string())
    );
    assert_eq!(
        data.rows[0].cells[4],
        CellValue::Text("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string())
    );
    assert_eq!(data.rows[0].cells[6], CellValue::Text("00000000".to_string()));
    assert_eq!(data.rows[0].cells[9], CellValue::Null);

    // 02_abc.txt & 03_abc_copy.txt
    assert_eq!(
        data.rows[1].cells[2],
        CellValue::Text("900150983cd24fb0d6963f7d28e17f72".to_string())
    );
    assert_eq!(
        data.rows[1].cells[3],
        CellValue::Text("a9993e364706816aba3e25717850c26c9cd0d89d".to_string())
    );
    assert_eq!(
        data.rows[1].cells[4],
        CellValue::Text("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string())
    );
    assert_eq!(data.rows[1].cells[6], CellValue::Text("352441c2".to_string()));
    assert_eq!(data.rows[1].cells[9], CellValue::Uint(1));
    assert_eq!(data.rows[2].cells[9], CellValue::Uint(1));
    assert_eq!(data.rows[1].raw_bytes.as_deref(), Some(b"abc".as_slice()));

    // 04_big.bin (> 128 KiB streaming pass, raw_bytes capped at 256B)
    assert_eq!(data.rows[3].cells[7], CellValue::Bytes(131_072));
    assert_eq!(data.rows[3].raw_bytes.as_ref().unwrap().len(), 256);
}

#[test]
fn mutating_actions_enforce_policy_context_allowed_roots() {
    let mock = Arc::new(MockFileSystem::new());
    let allowed_dir = Path::new("C:\\allowed");
    let secret_file = Path::new("C:\\secret\\file.txt");
    let lnk = ShellLinkFile {
        header: ShellLinkHeader::default(),
        id_list: None,
        link_info: None,
        string_data: StringData::default(),
        extra_data: vec![],
    }
    .to_bytes()
    .unwrap();

    mock.insert_dir(allowed_dir, FileTimestamps::default(), FileAttributes::default());
    mock.insert_file(secret_file, lnk, FileTimestamps::default(), FileAttributes::default());

    let policy = PolicyContext {
        allowed_roots: vec![PathBuf::from(r"C:\allowed")],
        ..PolicyContext::allow_mutating(false, true)
    };

    let bulk = BulkFileTimeAction::new(mock.clone()).with_policy(policy.clone());
    let err = bulk
        .execute(
            &json!({
                "targets": [r"C:\allowed\..\secret\file.txt"],
                "set_attributes": ["H"]
            }),
            false,
        )
        .unwrap_err();
    assert!(matches!(err, McpToolError::PolicyDenied(_)));

    let ftu = FolderTimeUpdateAction::new(mock.clone()).with_policy(policy.clone());
    let err = ftu
        .execute(&json!({ "root": r"C:\allowed\..\secret" }), false)
        .unwrap_err();
    assert!(matches!(err, McpToolError::PolicyDenied(_)));

    let fix = ShortcutsFixAction::new(mock.clone()).with_policy(policy.clone());
    let err = fix
        .execute(
            &json!({
                "shortcut_path": r"C:\allowed\..\secret\file.txt",
                "new_target": r"C:\new.exe"
            }),
            false,
        )
        .unwrap_err();
    assert!(matches!(err, McpToolError::PolicyDenied(_)));

    let del = ShortcutsDeleteAction::new(mock).with_policy(policy);
    let err = del
        .execute(
            &json!({
                "shortcut_paths": [r"C:\allowed\..\secret\file.txt"],
                "only_if_broken": false
            }),
            false,
        )
        .unwrap_err();
    assert!(matches!(err, McpToolError::PolicyDenied(_)));
}

#[test]
fn shortcuts_view_mock_backend_fix_delete_unknown_and_net_unicode() {
    let tmp = tempfile::tempdir().unwrap();
    let real_disk_only_target = tmp.path().join("only_on_host_disk.exe");
    std::fs::write(&real_disk_only_target, b"MZ").unwrap();

    let mock = Arc::new(MockFileSystem::new());
    let mock_dir = Path::new(r"C:\mock_lnk");
    let test_lnk = Path::new(r"C:\mock_lnk\test.lnk");
    let empty_lnk = Path::new(r"C:\mock_lnk\empty.lnk");
    let host_target_lnk = Path::new(r"C:\mock_lnk\host_target.lnk");
    mock.insert_dir(mock_dir, FileTimestamps::default(), FileAttributes::default());

    let initial_lnk = ShellLinkFile {
        header: ShellLinkHeader::default(),
        id_list: None,
        link_info: Some(LinkInfo {
            flags: 0x01,
            drive_type: Some(3),
            drive_serial: Some(1),
            volume_label: Some(String::new()),
            local_base_path: Some(r"C:\mock_lnk\old.exe".to_string()),
            network_share_name: None,
            common_path_suffix: Some(String::new()),
        }),
        string_data: StringData::default(),
        extra_data: vec![],
    };
    mock.insert_file(
        test_lnk,
        initial_lnk.to_bytes().unwrap(),
        FileTimestamps::default(),
        FileAttributes::default(),
    );

    // FixAction writes strictly through MockFileSystem without touching host disk
    let fix = ShortcutsFixAction::new(mock.clone());
    let fix_res = fix
        .execute(
            &json!({
                "shortcut_path": r"C:\mock_lnk\test.lnk",
                "new_target": r"C:\mock_lnk\new.exe"
            }),
            false,
        )
        .unwrap();
    assert_eq!(fix_res["mode"], "applied");
    let reparsed = ShellLinkFile::parse(&mock.read_bytes(test_lnk).unwrap()).unwrap();
    assert_eq!(
        reparsed.resolve_target(test_lnk, None).target_path,
        r"C:\mock_lnk\new.exe"
    );

    // Empty / unresolvable .lnk ("Unknown") must have virtual_target = false and be treated as broken
    let unknown_lnk = ShellLinkFile {
        header: ShellLinkHeader::default(),
        id_list: None,
        link_info: None,
        string_data: StringData::default(),
        extra_data: vec![],
    };
    let unknown_resolved = unknown_lnk.resolve_target(empty_lnk, None);
    assert_eq!(unknown_resolved.kind, "Unknown");
    assert!(!unknown_resolved.virtual_target);
    mock.insert_file(
        empty_lnk,
        unknown_lnk.to_bytes().unwrap(),
        FileTimestamps::default(),
        FileAttributes::default(),
    );

    let provider = ShortcutsProvider::with_backend(
        ShortcutsConfig {
            scan_roots: vec![mock_dir.to_path_buf()],
            ..ShortcutsConfig::default()
        },
        mock.clone(),
    );
    let rows = provider.query(&TableQuery::default()).unwrap();
    let expected_empty = empty_lnk
        .to_string_lossy()
        .replace(['/', '\\'], std::path::MAIN_SEPARATOR_STR);
    let empty_row = rows
        .rows
        .iter()
        .find(|r| r.cells[0] == CellValue::Text(expected_empty.clone()))
        .unwrap();
    assert_eq!(empty_row.cells[2], CellValue::Bool(false));

    // DeleteAction checks target existence strictly via MockFileSystem (no host Path::exists fallback)
    let host_pointing_lnk = initial_lnk.with_updated_target(&real_disk_only_target.to_string_lossy(), None, None);
    mock.insert_file(
        host_target_lnk,
        host_pointing_lnk.to_bytes().unwrap(),
        FileTimestamps::default(),
        FileAttributes::default(),
    );

    let del = ShortcutsDeleteAction::new(mock.clone());
    let del_res = del
        .execute(
            &json!({
                "shortcut_paths": [r"C:\mock_lnk\empty.lnk", r"C:\mock_lnk\host_target.lnk"],
                "only_if_broken": true
            }),
            false,
        )
        .unwrap();
    assert_eq!(del_res["deleted"], 2);
    assert!(!mock.exists(empty_lnk));
    assert!(!mock.exists(host_target_lnk));

    // CommonNetworkRelativeLink with NetNameOffset > 0x14 and NetNameOffsetUnicode
    let mut lnk_bytes = Vec::new();
    lnk_bytes.extend_from_slice(&SHELL_LINK_HEADER_SIZE.to_le_bytes());
    lnk_bytes.extend_from_slice(&SHELL_LINK_CLSID);
    lnk_bytes.extend_from_slice(&link_flags::HAS_LINK_INFO.to_le_bytes());
    lnk_bytes.extend_from_slice(&[0u8; 52]); // rest of 76-byte header

    let share_ansi = b"\\\\NAS\\Share\0";
    let share_uni: Vec<u8> = "\\\\NAS\\Share\u{8CC7}\u{6599}\0"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let net_hdr_size = 28u32; // includes NetNameOffsetUnicode + DeviceNameOffsetUnicode (> 0x14)
    let net_name_off = net_hdr_size;
    let net_name_u_off = net_name_off + share_ansi.len() as u32;
    let net_total_size = net_name_u_off + share_uni.len() as u32;

    let info_hdr_size = 0x1Cu32;
    let net_off = info_hdr_size;
    let suffix_off = net_off + net_total_size;
    let info_total_size = suffix_off + 1;

    lnk_bytes.extend_from_slice(&info_total_size.to_le_bytes());
    lnk_bytes.extend_from_slice(&info_hdr_size.to_le_bytes());
    lnk_bytes.extend_from_slice(&0x02u32.to_le_bytes()); // CommonNetworkRelativeLinkOnly
    lnk_bytes.extend_from_slice(&0u32.to_le_bytes());
    lnk_bytes.extend_from_slice(&0u32.to_le_bytes());
    lnk_bytes.extend_from_slice(&net_off.to_le_bytes());
    lnk_bytes.extend_from_slice(&suffix_off.to_le_bytes());

    lnk_bytes.extend_from_slice(&net_total_size.to_le_bytes());
    lnk_bytes.extend_from_slice(&0x02u32.to_le_bytes());
    lnk_bytes.extend_from_slice(&net_name_off.to_le_bytes());
    lnk_bytes.extend_from_slice(&0u32.to_le_bytes());
    lnk_bytes.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    lnk_bytes.extend_from_slice(&net_name_u_off.to_le_bytes());
    lnk_bytes.extend_from_slice(&0u32.to_le_bytes());
    lnk_bytes.extend_from_slice(share_ansi);
    lnk_bytes.extend_from_slice(&share_uni);
    lnk_bytes.push(0); // empty suffix
    lnk_bytes.extend_from_slice(&0u32.to_le_bytes()); // ExtraData terminal

    let parsed_net = ShellLinkFile::parse(&lnk_bytes).unwrap();
    assert_eq!(
        parsed_net
            .link_info
            .as_ref()
            .and_then(|l| l.network_share_name.as_deref()),
        Some("\\\\NAS\\Share\u{8CC7}\u{6599}")
    );
}

#[test]
fn folder_time_update_newest_file_or_subdir_converges_in_one_pass() {
    let mock = Arc::new(MockFileSystem::new());
    let t_2020 = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    let t_2021 = Utc.with_ymd_and_hms(2021, 5, 1, 0, 0, 0).unwrap();
    let t_2025 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
    let t_2026 = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();

    let root = Path::new(r"C:\conv");
    let sub1 = Path::new(r"C:\conv\sub1");
    let sub2 = Path::new(r"C:\conv\sub1\sub2");
    let file = Path::new(r"C:\conv\sub1\sub2\file.txt");

    mock.insert_dir(
        root,
        FileTimestamps {
            modified: Some(t_2020),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );
    mock.insert_dir(
        sub1,
        FileTimestamps {
            modified: Some(t_2026),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );
    mock.insert_dir(
        sub2,
        FileTimestamps {
            modified: Some(t_2025),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );
    mock.insert_file(
        file,
        b"payload".to_vec(),
        FileTimestamps {
            modified: Some(t_2021),
            ..FileTimestamps::default()
        },
        FileAttributes::default(),
    );

    let action = FolderTimeUpdateAction::new(mock.clone());
    let pass1 = action
        .execute(&json!({ "root": r"C:\conv", "source": "newest_file_or_subdir" }), false)
        .unwrap();
    assert_eq!(pass1["updated"], 3);
    assert_eq!(mock.metadata(sub2).unwrap().timestamps.modified, Some(t_2021));
    assert_eq!(mock.metadata(sub1).unwrap().timestamps.modified, Some(t_2021));
    assert_eq!(mock.metadata(root).unwrap().timestamps.modified, Some(t_2021));

    let pass2 = action
        .execute(&json!({ "root": r"C:\conv", "source": "newest_file_or_subdir" }), false)
        .unwrap();
    assert_eq!(pass2["updated"], 0);
}

#[test]
fn bulk_file_time_shift_overflow_and_backend_error_propagation() {
    let mock = Arc::new(MockFileSystem::new());
    let root = Path::new(r"C:\bfc_err");
    let locked_dir = Path::new(r"C:\bfc_err\denied");
    let file = Path::new(r"C:\bfc_err\ok.txt");
    let ts = FileTimestamps {
        modified: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
        ..FileTimestamps::default()
    };

    mock.insert_dir(root, ts, FileAttributes::default());
    mock.insert_dir(locked_dir, ts, FileAttributes::default());
    mock.insert_file(file, b"ok".to_vec(), ts, FileAttributes::default());
    mock.deny_path(locked_dir, "simulated ACL denial");

    let overflow_preview = BulkFileTimePreviewProvider::new(
        BulkChangeSpec {
            targets: vec![file.to_path_buf()],
            recursive: false,
            modified: TimestampChange::ShiftSeconds(i64::MAX),
            ..BulkChangeSpec::default()
        },
        mock.clone(),
    );
    assert!(overflow_preview.query(&TableQuery::default()).is_err());

    let denied_preview = BulkFileTimePreviewProvider::new(
        BulkChangeSpec {
            targets: vec![root.to_path_buf()],
            recursive: true,
            ..BulkChangeSpec::default()
        },
        mock,
    );
    assert!(denied_preview.query(&TableQuery::default()).is_err());
}

#[test]
fn folders_report_depth_gt_1_parent_percentages_and_symlink_cycle_guard() {
    let mock = Arc::new(MockFileSystem::new());
    let root = Path::new(r"C:\rep2");
    let alpha = Path::new(r"C:\rep2\alpha");
    let nested = Path::new(r"C:\rep2\alpha\nested");
    let beta = Path::new(r"C:\rep2\beta");
    let ts = FileTimestamps::default();

    mock.insert_dir(root, ts, FileAttributes::default());
    mock.insert_dir(alpha, ts, FileAttributes::default());
    mock.insert_dir(nested, ts, FileAttributes::default());
    mock.insert_dir(beta, ts, FileAttributes::default());
    mock.insert_file(
        Path::new(r"C:\rep2\root.bin"),
        vec![0u8; 100],
        ts,
        FileAttributes::default(),
    );
    mock.insert_file(
        Path::new(r"C:\rep2\alpha\a.bin"),
        vec![0u8; 200],
        ts,
        FileAttributes::default(),
    );
    mock.insert_file(
        Path::new(r"C:\rep2\alpha\nested\n.bin"),
        vec![0u8; 300],
        ts,
        FileAttributes::default(),
    );
    mock.insert_file(
        Path::new(r"C:\rep2\beta\b.bin"),
        vec![0u8; 400],
        ts,
        FileAttributes::default(),
    );

    let provider = FoldersReportProvider::new(
        FoldersReportConfig {
            root: root.to_path_buf(),
            depth: 2,
            include_root_files_row: true,
            follow_symlinks: false,
            threads: 2,
        },
        mock,
    );
    let data = provider.query(&TableQuery::default()).unwrap();
    let nested_row = data
        .rows
        .iter()
        .find(|r| r.cells[0] == CellValue::Text("nested".to_string()))
        .unwrap();
    // nested = 300 bytes out of immediate parent alpha (500 bytes) => 60.0%
    assert_eq!(nested_row.cells[6], CellValue::Float(60.0));

    let alpha_row = data
        .rows
        .iter()
        .find(|r| r.cells[0] == CellValue::Text("alpha".to_string()))
        .unwrap();
    assert_eq!(alpha_row.cells[6], CellValue::Float(50.0));

    // Real symlink cycle check when symlink creation is permitted on host OS
    let tmp = tempfile::tempdir().unwrap();
    let sub = tmp.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("data.txt"), b"12345").unwrap();
    let link = sub.join("loop_to_root");
    #[cfg(windows)]
    let link_res = std::os::windows::fs::symlink_dir(tmp.path(), &link);
    #[cfg(unix)]
    let link_res = std::os::unix::fs::symlink(tmp.path(), &link);

    if link_res.is_ok() {
        let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
        let rep = FoldersReportProvider::new(
            FoldersReportConfig {
                root: tmp.path().to_path_buf(),
                depth: 3,
                include_root_files_row: true,
                follow_symlinks: true,
                threads: 1,
            },
            os_fs.clone(),
        );
        let rep_data = rep.query(&TableQuery::default()).unwrap();
        assert!(rep_data.total_rows >= 1);

        let ftu = FolderTimeUpdatePreviewProvider::new(
            FolderTimeUpdateConfig {
                root: tmp.path().to_path_buf(),
                follow_symlinks: true,
                ..FolderTimeUpdateConfig::default()
            },
            os_fs,
        );
        assert!(ftu.query(&TableQuery::default()).is_ok());
    }
}

#[test]
fn directory_junction_follow_symlinks_false_and_true_with_cycle_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let local_sub = root.join("local_sub");
    let ext_dir = tmp.path().join("external");
    std::fs::create_dir_all(&local_sub).unwrap();
    std::fs::create_dir_all(&ext_dir).unwrap();

    let ext_file = ext_dir.join("ext.bin");
    std::fs::write(&ext_file, vec![b'X'; 400]).unwrap();
    std::fs::write(local_sub.join("local.bin"), vec![b'L'; 100]).unwrap();

    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    let t_old = Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap();
    let t_ext_newer = Utc.with_ymd_and_hms(2025, 9, 10, 12, 0, 0).unwrap();
    os_fs
        .set_timestamps(
            &local_sub.join("local.bin"),
            &FileTimestamps {
                modified: Some(t_old),
                ..FileTimestamps::default()
            },
        )
        .unwrap();
    os_fs
        .set_timestamps(
            &ext_file,
            &FileTimestamps {
                modified: Some(t_ext_newer),
                ..FileTimestamps::default()
            },
        )
        .unwrap();

    let ext_link = root.join("ext_link");
    let loop_link = ext_dir.join("loop_to_root");

    #[cfg(windows)]
    let links_ok = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &ext_link.to_string_lossy(),
            &ext_dir.to_string_lossy(),
        ])
        .output()
        .is_ok_and(|o| o.status.success())
        && std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &loop_link.to_string_lossy(),
                &root.to_string_lossy(),
            ])
            .output()
            .is_ok_and(|o| o.status.success());

    #[cfg(unix)]
    let links_ok = std::os::unix::fs::symlink(&ext_dir, &ext_link).is_ok()
        && std::os::unix::fs::symlink(&root, &loop_link).is_ok();

    if !links_ok {
        return;
    }

    // 1. FoldersReportProvider with follow_symlinks = false does NOT follow ext_link
    let rep_no_follow = FoldersReportProvider::new(
        FoldersReportConfig {
            root: root.clone(),
            depth: 2,
            include_root_files_row: true,
            follow_symlinks: false,
            threads: 1,
        },
        os_fs.clone(),
    )
    .query(&TableQuery::default())
    .unwrap();
    assert!(
        !rep_no_follow
            .rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("ext_link".to_string()))
    );
    assert_eq!(rep_no_follow.rows.len(), 1);
    assert_eq!(rep_no_follow.rows[0].cells[4], CellValue::Bytes(100));

    // 2. FoldersReportProvider with follow_symlinks = true follows ext_link and breaks cycle at loop_to_root
    let rep_follow = FoldersReportProvider::new(
        FoldersReportConfig {
            root: root.clone(),
            depth: 2,
            include_root_files_row: true,
            follow_symlinks: true,
            threads: 1,
        },
        os_fs.clone(),
    )
    .query(&TableQuery::default())
    .unwrap();
    let ext_row = rep_follow
        .rows
        .iter()
        .find(|r| r.cells[0] == CellValue::Text("ext_link".to_string()))
        .unwrap();
    assert_eq!(ext_row.cells[2], CellValue::Uint(1)); // ext.bin only; loop_to_root guarded
    assert_eq!(ext_row.cells[4], CellValue::Bytes(400));

    // 3. FolderTimeUpdatePreviewProvider with follow_symlinks = false ignores ext_link (neither recurses nor counts it as a file)
    let ftu_no_follow = FolderTimeUpdatePreviewProvider::new(
        FolderTimeUpdateConfig {
            root: root.clone(),
            follow_symlinks: false,
            ..FolderTimeUpdateConfig::default()
        },
        os_fs.clone(),
    )
    .query(&TableQuery::default())
    .unwrap();
    let root_row_nf = ftu_no_follow
        .rows
        .iter()
        .find(|r| r.cells[0] == CellValue::Text(root.to_string_lossy().into_owned()))
        .unwrap();
    assert_eq!(root_row_nf.cells[4], CellValue::Uint(1)); // only local.bin

    // 4. FolderTimeUpdatePreviewProvider with follow_symlinks = true follows ext_link safely with cycle guard
    let ftu_follow = FolderTimeUpdatePreviewProvider::new(
        FolderTimeUpdateConfig {
            root: root.clone(),
            source: FolderTimeSource::NewestFileOrSubdir,
            follow_symlinks: true,
            ..FolderTimeUpdateConfig::default()
        },
        os_fs.clone(),
    )
    .query(&TableQuery::default())
    .unwrap();
    let root_row_f = ftu_follow
        .rows
        .iter()
        .find(|r| r.cells[0] == CellValue::Text(root.to_string_lossy().into_owned()))
        .unwrap();
    assert_eq!(root_row_f.cells[4], CellValue::Uint(2)); // local.bin + ext.bin
    assert_eq!(root_row_f.cells[3], CellValue::Timestamp(t_ext_newer));

    // 5. Bulk file time recursive preview must NOT follow junctions
    let bulk_preview = BulkFileTimePreviewProvider::new(
        BulkChangeSpec {
            targets: vec![root.clone()],
            recursive: true,
            ..BulkChangeSpec::default()
        },
        os_fs,
    )
    .query(&TableQuery::default())
    .unwrap();
    assert!(
        !bulk_preview
            .rows
            .iter()
            .any(|r| r.cells[0].to_string().contains("ext.bin"))
    );

    // 6. SearchFiles follow_symlinks = false vs true
    let smf_no_follow = SearchFilesProvider::new(SearchFilesConfig {
        roots: vec![root.clone()],
        follow_symlinks: false,
        ..SearchFilesConfig::default()
    })
    .query(&TableQuery::default())
    .unwrap();
    assert_eq!(smf_no_follow.total_rows, 1);

    let smf_follow = SearchFilesProvider::new(SearchFilesConfig {
        roots: vec![root],
        follow_symlinks: true,
        ..SearchFilesConfig::default()
    })
    .query(&TableQuery::default())
    .unwrap();
    assert_eq!(smf_follow.total_rows, 2);

    let _ = std::fs::remove_dir(&ext_link);
    let _ = std::fs::remove_dir(&loop_link);
}

#[test]
fn dangling_junctions_are_not_counted_as_files_under_follow_symlinks_true() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let empty_with_dangling = root.join("empty_with_dangling");
    let doomed_target_sub = tmp.path().join("doomed_target_sub");
    let doomed_target_root = tmp.path().join("doomed_target_root");
    std::fs::create_dir_all(&empty_with_dangling).unwrap();
    std::fs::create_dir_all(&doomed_target_sub).unwrap();
    std::fs::create_dir_all(&doomed_target_root).unwrap();

    let dangling_sub_link = empty_with_dangling.join("dangling_link");
    let dangling_root_link = root.join("dangling_root_link");

    #[cfg(windows)]
    let links_ok = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &dangling_sub_link.to_string_lossy(),
            &doomed_target_sub.to_string_lossy(),
        ])
        .output()
        .is_ok_and(|o| o.status.success())
        && std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &dangling_root_link.to_string_lossy(),
                &doomed_target_root.to_string_lossy(),
            ])
            .output()
            .is_ok_and(|o| o.status.success());

    #[cfg(unix)]
    let links_ok = std::os::unix::fs::symlink(&doomed_target_sub, &dangling_sub_link).is_ok()
        && std::os::unix::fs::symlink(&doomed_target_root, &dangling_root_link).is_ok();

    if !links_ok {
        return;
    }

    // Delete targets so both junctions/symlinks become dangling.
    std::fs::remove_dir_all(&doomed_target_sub).unwrap();
    std::fs::remove_dir_all(&doomed_target_root).unwrap();

    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    let old_mtime = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    os_fs
        .set_timestamps(
            &empty_with_dangling,
            &FileTimestamps {
                modified: Some(old_mtime),
                ..FileTimestamps::default()
            },
        )
        .unwrap();

    // 1. FoldersReportProvider with follow_symlinks: true must report files_count == 0
    //    and must not emit a (root files) row from dangling_root_link.
    let rep = FoldersReportProvider::new(
        FoldersReportConfig {
            root: root.clone(),
            depth: 2,
            include_root_files_row: true,
            follow_symlinks: true,
            threads: 1,
        },
        os_fs.clone(),
    )
    .query(&TableQuery::default())
    .unwrap();
    assert!(
        !rep.rows
            .iter()
            .any(|r| r.cells[0] == CellValue::Text("(root files)".to_string()))
    );
    let sub_row = rep
        .rows
        .iter()
        .find(|r| r.cells[0] == CellValue::Text("empty_with_dangling".to_string()))
        .unwrap();
    assert_eq!(sub_row.cells[2], CellValue::Uint(0));
    assert_eq!(sub_row.cells[4], CellValue::Bytes(0));

    // 2. FolderTimeUpdatePreviewProvider + FolderTimeUpdateAction with follow_symlinks: true
    //    and update_empty_dirs: false must report files_scanned == 0, updated == 0, and leave mtime intact.
    let preview = FolderTimeUpdatePreviewProvider::new(
        FolderTimeUpdateConfig {
            root: root.clone(),
            follow_symlinks: true,
            update_empty_dirs: false,
            ..FolderTimeUpdateConfig::default()
        },
        os_fs.clone(),
    )
    .query(&TableQuery::default())
    .unwrap();
    for row in &preview.rows {
        assert_eq!(row.cells[4], CellValue::Uint(0));
        assert_eq!(row.cells[6], CellValue::Text("NoChange".to_string()));
    }

    let action = FolderTimeUpdateAction::new(os_fs.clone());
    let apply_res = action
        .execute(
            &json!({
                "root": root.to_string_lossy(),
                "follow_symlinks": true,
                "update_empty_dirs": false
            }),
            false,
        )
        .unwrap();
    assert_eq!(apply_res["updated"], 0);
    assert_eq!(apply_res["failed"], 0);
    assert_eq!(
        os_fs.metadata(&empty_with_dangling).unwrap().timestamps.modified,
        Some(old_mtime)
    );

    let _ = std::fs::remove_dir(&dangling_sub_link);
    let _ = std::fs::remove_dir(&dangling_root_link);
}
