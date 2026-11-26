#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{TimeZone, Utc};
use fs2rust_core::{
    FileAttributes, FileSystemOps, FileTimestamps, FsError, MockFileSystem, OsFileSystem, PolicyContext,
};
use fs2rust_data::{
    AddrViewProvider, CodegenInput, CodegenTarget, CodegenTemplate, ContactFormat, CsvTableProvider, CsvViewOptions,
    EscapeMode, ExifDataViewProvider, GetNirRequest, GetNirSource, GetNirTableProvider, HtmlAsTextOptions,
    HtmlAsTextProvider, SimpleCodeGeneratorProvider, TableCompareOptions, TableCompareProvider, TableInput,
};
use fs2rust_ntfs::{
    AdsEntry, AlternateStreamConfig, AlternateStreamDeleteAction, AlternateStreamViewProvider, AppReadWriteConfig,
    AppReadWriteCounterProvider, DiskCountersConfig, DiskCountersProvider, DiskPerformanceRecord, DiskSmartConfig,
    DiskSmartRecord, DiskSmartViewProvider, DriveLetterAssignAction, DriveLetterConfig, DriveLetterEntry,
    DriveLetterProvider, DriveLetterRemoveAction, FileAccessErrorConfig, FileAccessErrorViewProvider,
    FileActivityConfig, FileActivityWatchProvider, FilePropertyEntry, FolderChangeAction, FolderChangeEntry,
    FolderChangesConfig, FolderChangesViewProvider, IoCounters, KernelFileRawEvent, LiveNtfsBackend,
    MountedDeviceTarget, NtfsBackend, NtfsLinkEntry, NtfsLinksConfig, NtfsLinksViewProvider, NtfsToolsConfig,
    ProcessIoSnapshot, PropertySystemConfig, PropertySystemSetAction, PropertySystemViewProvider, UsnJournalConfig,
    UsnJournalViewProvider, UsnQueryMode, UsnRecord,
};
use fs2rust_search::{
    BulkChangeSpec, BulkFileChangerAction, BulkFileChangerPreviewProvider, FolderTimeSource, FolderTimeUpdateAction,
    FolderTimeUpdateConfig, FolderTimeUpdatePreviewProvider, FoldersReportConfig, FoldersReportProvider,
    HashMyFilesConfig, HashMyFilesProvider, SearchMyFilesConfig, SearchMyFilesProvider, ShellLinkFile, ShellLinkHeader,
    ShortcutsManConfig, ShortcutsManDeleteAction, ShortcutsManFixAction, ShortcutsManProvider, StringData,
    TimestampChange,
};
use guap_mcp::{ActionCommand, McpServerRegistry, PolicyMode};
use guap_table::{ColumnDef, ColumnType, TableData, TableProvider, TableSchema};

#[derive(Clone)]
pub struct SuiteWiring {
    pub providers: Vec<Arc<dyn TableProvider>>,
    pub actions: Vec<Arc<dyn ActionCommand>>,
}

static SYNTHETIC_SEARCH_ROOT: OnceLock<PathBuf> = OnceLock::new();

pub fn synthetic_search_root() -> PathBuf {
    SYNTHETIC_SEARCH_ROOT
        .get_or_init(|| {
            let dir = std::env::temp_dir().join("fs2rust_synthetic_search_root");
            let sub = dir.join("sub");
            let _ = std::fs::create_dir_all(&sub);
            let _ = std::fs::write(dir.join("alpha.txt"), b"fs2rust synthetic search alpha\n");
            let _ = std::fs::write(sub.join("beta.txt"), b"fs2rust synthetic search beta\n");
            let lnk = build_synthetic_lnk_bytes(r"C:\Tools\fs2rust-demo.exe", r"C:\Tools", "--help");
            let _ = std::fs::write(dir.join("demo.lnk"), lnk);
            dir
        })
        .clone()
}

pub fn build_synthetic_lnk_bytes(target: &str, working_dir: &str, args: &str) -> Vec<u8> {
    let link = ShellLinkFile {
        header: ShellLinkHeader::default(),
        id_list: None,
        link_info: Some(fs2rust_search::LinkInfo {
            flags: 1,
            drive_type: Some(3),
            drive_serial: Some(0x1234_5678),
            volume_label: Some("SYS".to_string()),
            local_base_path: Some(target.to_string()),
            network_share_name: None,
            common_path_suffix: Some(String::new()),
        }),
        string_data: StringData {
            name: Some("FS2Rust Synthetic Shortcut".to_string()),
            relative_path: None,
            working_dir: Some(working_dir.to_string()),
            cmd_args: Some(args.to_string()),
            icon_location: None,
        },
        extra_data: Vec::new(),
    };
    link.to_bytes().unwrap_or_default()
}

pub fn build_synthetic_jpeg_exif_bytes() -> Vec<u8> {
    // Minimal valid JPEG SOI + APP1 ("Exif\0\0" + TIFF II header + 2 IFD0 ASCII tags: Make, Model) + EOI.
    let make_val = b"GUAP\0\0"; // 6 bytes (>4 -> stored at offset)
    let model_val = b"FS2RustCam\0\0"; // 12 bytes
    // TIFF layout (little-endian):
    // 0..8: "II" + 42 + offset(8)
    // 8..10: entry count = 2
    // 10..22: Tag 0x010F (Make), type 2 (ASCII), count 5, value offset 38
    // 22..34: Tag 0x0110 (Model), type 2 (ASCII), count 11, value offset 44
    // 34..38: next IFD = 0
    // 38..44: "GUAP\0\0"
    // 44..56: "FS2RustCam\0\0"
    let mut tiff = Vec::with_capacity(56);
    tiff.extend_from_slice(b"II");
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());

    // Tag 0x010F Make
    tiff.extend_from_slice(&0x010Fu16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&5u32.to_le_bytes());
    tiff.extend_from_slice(&38u32.to_le_bytes());

    // Tag 0x0110 Model
    tiff.extend_from_slice(&0x0110u16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&11u32.to_le_bytes());
    tiff.extend_from_slice(&44u32.to_le_bytes());

    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(make_val);
    tiff.extend_from_slice(model_val);

    let app1_payload_len = 2 + 6 + tiff.len(); // length field itself (2) + "Exif\0\0" (6) + tiff
    let mut jpeg = Vec::with_capacity(2 + 2 + app1_payload_len + 2);
    jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI
    jpeg.extend_from_slice(&[0xFF, 0xE1]); // APP1
    jpeg.extend_from_slice(&(app1_payload_len as u16).to_be_bytes());
    jpeg.extend_from_slice(b"Exif\0\0");
    jpeg.extend_from_slice(&tiff);
    jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI
    jpeg
}

#[derive(Debug, Default)]
pub struct MockNtfsBackend {
    pub mounted: Mutex<Vec<(String, String)>>,
    pub deleted_ads: Mutex<Vec<String>>,
    pub set_props: Mutex<Vec<(PathBuf, String, String)>>,
}

impl MockNtfsBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sample_data() -> Self {
        Self::default()
    }
}

impl NtfsBackend for MockNtfsBackend {
    fn list_drive_letters(&self) -> Result<Vec<DriveLetterEntry>, FsError> {
        Ok(vec![DriveLetterEntry {
            drive_letter: r"C:\".to_string(),
            drive_type: "Fixed".to_string(),
            volume_guid: r"\\?\Volume{11111111-2222-3333-4444-555555555555}\".to_string(),
            volume_label: "System".to_string(),
            filesystem: "NTFS".to_string(),
            serial_number: "ABCD-1234".to_string(),
            total_size: Some(500_000_000_000),
            free_space: Some(250_000_000_000),
            device_target: r"\Device\HarddiskVolume3".to_string(),
            partition_scheme: "GPT".to_string(),
            connected: true,
            mounted_device_target: Some(MountedDeviceTarget::GptPartitionGuid {
                partition_guid: "{11111111-2222-3333-4444-555555555555}".to_string(),
            }),
        }])
    }

    fn set_volume_mount_point(&self, mount_point: &str, volume_guid: &str) -> Result<(), FsError> {
        self.mounted
            .lock()
            .unwrap()
            .push((mount_point.to_string(), volume_guid.to_string()));
        Ok(())
    }

    fn delete_volume_mount_point(&self, mount_point: &str) -> Result<(), FsError> {
        self.mounted.lock().unwrap().retain(|(mp, _)| mp != mount_point);
        Ok(())
    }

    fn query_disk_counters(&self, _device_paths: &[String]) -> Result<Vec<DiskPerformanceRecord>, FsError> {
        Ok(vec![DiskPerformanceRecord {
            device: r"\\.\PhysicalDrive0".to_string(),
            storage_device_number: 0,
            storage_manager: "PartMgr".to_string(),
            read_count: 1024,
            write_count: 512,
            bytes_read: 4_194_304,
            bytes_written: 2_097_152,
            read_time_ms: 14,
            write_time_ms: 9,
            idle_time_ms: 500,
            queue_depth: 1,
            split_count: 0,
            query_time_100ns: 1_000_000,
        }])
    }

    fn capture_kernel_file_events(
        &self,
        _duration_ms: u64,
        _max_events: usize,
        include_op_end: bool,
    ) -> Result<Vec<KernelFileRawEvent>, FsError> {
        let ts = Utc.with_ymd_and_hms(2026, 11, 24, 1, 0, 0).unwrap();
        Ok(vec![KernelFileRawEvent {
            event_id: if include_op_end { 24 } else { 15 },
            pid: 4242,
            tid: 88,
            timestamp: ts,
            irp_ptr: 0xFFFF_AA00_0000_1000,
            file_object: 0xFFFF_BB00_0000_2000,
            file_key: 0x100,
            io_size: 4096,
            nt_status: if include_op_end { 0xC000_0034 } else { 0 },
            io_flags: 0,
            file_path: r"C:\Work\sample.txt".to_string(),
            process_name: "worker.exe".to_string(),
        }])
    }

    fn watch_folder_changes(
        &self,
        watch_dir: &Path,
        _recursive: bool,
        _duration_ms: u64,
        _max_events: usize,
    ) -> Result<Vec<FolderChangeEntry>, FsError> {
        let ts = Utc.with_ymd_and_hms(2026, 11, 24, 1, 0, 0).unwrap();
        Ok(vec![FolderChangeEntry {
            timestamp: ts,
            action: FolderChangeAction::Modified,
            path: "sample.txt".to_string(),
            full_path: watch_dir.join("sample.txt").to_string_lossy().into_owned(),
            old_size: Some(128),
            new_size: Some(256),
            attributes: "A".to_string(),
            extension: "txt".to_string(),
            source: "SyntheticMock".to_string(),
        }])
    }

    fn snapshot_process_io(&self) -> Result<Vec<ProcessIoSnapshot>, FsError> {
        Ok(vec![ProcessIoSnapshot {
            pid: 4242,
            process_name: "worker.exe".to_string(),
            process_path: r"C:\Apps\worker.exe".to_string(),
            counters: IoCounters {
                read_operation_count: 10,
                write_operation_count: 5,
                other_operation_count: 2,
                read_transfer_count: 8192,
                write_transfer_count: 4096,
                other_transfer_count: 512,
            },
            access_denied: false,
        }])
    }

    fn list_process_names(&self) -> Result<HashMap<u32, String>, FsError> {
        Ok(HashMap::from([(4242, "worker.exe".to_string())]))
    }

    fn query_disk_smart(&self, _disk_indices: &[u32]) -> Result<Vec<DiskSmartRecord>, FsError> {
        Ok(vec![DiskSmartRecord {
            device: r"\\.\PhysicalDrive0".to_string(),
            model: "GUAP NVMe SSD".to_string(),
            serial: "GUAP-0001".to_string(),
            firmware: "1.0".to_string(),
            bus_protocol: "NVMe".to_string(),
            attribute_id: "NVMe:Temp".to_string(),
            attribute_name: "Composite Temperature (C)".to_string(),
            current: Some(100),
            worst: Some(100),
            threshold: Some(0),
            raw_value: 36,
            raw_hex: vec![36, 0, 0, 0, 0, 0],
            health_status: "OK".to_string(),
            flags: "0x00".to_string(),
            detail_extra: serde_json::Value::String("Synthetic SMART record".to_string()),
        }])
    }

    fn enumerate_ads(
        &self,
        _target_paths: &[PathBuf],
        _recursive: bool,
        _include_default_data: bool,
    ) -> Result<Vec<AdsEntry>, FsError> {
        Ok(vec![AdsEntry {
            file_path: r"C:\Work\download.zip".to_string(),
            stream_name: ":Zone.Identifier:$DATA".to_string(),
            full_stream_path: r"C:\Work\download.zip:Zone.Identifier".to_string(),
            stream_size: 26,
            allocated_size: 26,
            resident: true,
            mft_record: Some(42),
            attributes: "-".to_string(),
            content_preview: "[ZoneTransfer]\r\nZoneId=3".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        }])
    }

    fn delete_ads(&self, full_stream_path: &str) -> Result<(), FsError> {
        self.deleted_ads.lock().unwrap().push(full_stream_path.to_string());
        Ok(())
    }

    fn inspect_ntfs_links(
        &self,
        _target_paths: &[PathBuf],
        _recursive: bool,
        _include_hardlinks: bool,
    ) -> Result<Vec<NtfsLinkEntry>, FsError> {
        Ok(vec![NtfsLinkEntry {
            link_path: r"C:\Work\latest".to_string(),
            link_type: "Junction".to_string(),
            target_path: r"C:\Work\v1".to_string(),
            substitute_name: r"\??\C:\Work\v1".to_string(),
            print_name: r"C:\Work\v1".to_string(),
            is_relative: false,
            target_exists: true,
            hard_link_count: 1,
            file_id: 1001,
            reparse_tag: 0xA000_0003u32.to_le_bytes().to_vec(),
        }])
    }

    fn read_file_properties(&self, file_path: &Path) -> Result<Vec<FilePropertyEntry>, FsError> {
        Ok(vec![FilePropertyEntry {
            file_path: file_path.to_string_lossy().into_owned(),
            canonical_name: "System.Title".to_string(),
            property_key: "{F29F85E0-4FF9-1068-AB91-08002B27B3D9} 2".to_string(),
            display_name: "Title".to_string(),
            value_type: "VT_LPWSTR".to_string(),
            value: "Sample Document".to_string(),
            read_only_prop: false,
        }])
    }

    fn set_file_property(
        &self,
        file_path: &Path,
        canonical_name: &str,
        value: &str,
    ) -> Result<FilePropertyEntry, FsError> {
        self.set_props
            .lock()
            .unwrap()
            .push((file_path.to_path_buf(), canonical_name.to_string(), value.to_string()));
        Ok(FilePropertyEntry {
            file_path: file_path.to_string_lossy().into_owned(),
            canonical_name: canonical_name.to_string(),
            property_key: "{F29F85E0-4FF9-1068-AB91-08002B27B3D9} 2".to_string(),
            display_name: canonical_name.to_string(),
            value_type: "VT_LPWSTR".to_string(),
            value: value.to_string(),
            read_only_prop: false,
        })
    }

    fn read_usn_journal(
        &self,
        _device_path: &str,
        _start_usn: i64,
        _reason_mask: u32,
        _max_records: usize,
        _mode: UsnQueryMode,
    ) -> Result<Vec<UsnRecord>, FsError> {
        let ts = Utc.with_ymd_and_hms(2026, 11, 24, 1, 0, 0).unwrap();
        Ok(vec![UsnRecord {
            usn: 4096,
            timestamp: ts,
            file_name: "sample.txt".to_string(),
            reason: 0x8000_0100,
            reason_flags: "FILE_CREATE|CLOSE".to_string(),
            mft_entry: 55,
            parent_mft_entry: 5,
            file_id_hex: "0x0000000000000037".to_string(),
            parent_file_id_hex: "0x0000000000000005".to_string(),
            file_attributes: 0x20,
            attributes_text: "A".to_string(),
            major_version: 2,
            minor_version: 0,
            source_info: "-".to_string(),
        }])
    }
}

fn default_codegen_template() -> CodegenTemplate {
    CodegenTemplate {
        rule_name: "rust_struct".to_string(),
        target: CodegenTarget::Rust,
        header_template: String::new(),
        body_template: "pub const {{name}}: &str = \"{{value}}\";".to_string(),
        footer_template: String::new(),
        separator: "\n".to_string(),
        escape_mode: EscapeMode::Auto,
        strict_placeholders: false,
    }
}

fn build_default_data_providers(synthetic: bool) -> Vec<Arc<dyn TableProvider>> {
    if synthetic {
        let csv_bytes = b"name,size,active\nalpha.txt,128,true\nbeta.log,256,false\n";
        let csv_provider = CsvTableProvider::from_bytes("synthetic.csv", csv_bytes, CsvViewOptions::default())
            .expect("synthetic csv parses");

        let left_csv = CsvTableProvider::from_bytes(
            "left.csv",
            b"id,name,size\n1,alpha.txt,128\n2,beta.log,256\n",
            CsvViewOptions::default(),
        )
        .expect("left csv parses");
        let right_csv = CsvTableProvider::from_bytes(
            "right.csv",
            b"id,name,size\n1,alpha.txt,128\n2,beta.log,512\n3,gamma.md,64\n",
            CsvViewOptions::default(),
        )
        .expect("right csv parses");
        let compare_provider = TableCompareProvider::compare(
            TableInput::Provider(Arc::new(left_csv)),
            TableInput::Provider(Arc::new(right_csv)),
            TableCompareOptions::default(),
        )
        .expect("synthetic compare succeeds");

        let getnir_provider =
            GetNirTableProvider::from_source(GetNirSource::StdinBytes(csv_bytes.to_vec()), &GetNirRequest::default())
                .expect("synthetic getnir succeeds");

        let exif_provider = ExifDataViewProvider::from_bytes("synthetic.jpg", build_synthetic_jpeg_exif_bytes());

        let codegen_provider = SimpleCodeGeneratorProvider::from_input(
            &CodegenInput::Json {
                json_text: r#"[{"name":"SAMPLE_KEY","value":"fs2rust"}]"#.to_string(),
            },
            &default_codegen_template(),
        )
        .expect("synthetic codegen succeeds");

        let html_provider = HtmlAsTextProvider::from_bytes(
            "synthetic.html",
            b"<html><head><title>FS2Rust Sample</title></head><body><h1>Hello</h1><p>Visit <a href=\"https://fs2rust.guap.ca\">FS2Rust</a>.</p></body></html>",
            &HtmlAsTextOptions::default(),
        );

        let addr_provider = AddrViewProvider::from_bytes(
            "synthetic.vcf",
            b"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ada Lovelace\r\nEMAIL:ada@example.org\r\nORG:Analytical Engine\r\nEND:VCARD\r\n",
            ContactFormat::VCard,
        )
        .expect("synthetic vcard parses");

        return vec![
            Arc::new(csv_provider),
            Arc::new(compare_provider),
            Arc::new(getnir_provider),
            Arc::new(exif_provider),
            Arc::new(codegen_provider),
            Arc::new(html_provider),
            Arc::new(addr_provider),
        ];
    }

    let sample_csv = b"column_1,column_2\n";
    let csv_provider = CsvTableProvider::from_bytes("sample.csv", sample_csv, CsvViewOptions::default())
        .expect("sample csv header parses");

    let empty_schema = TableSchema::new(
        "sample_table",
        "Sample Table",
        vec![
            ColumnDef::new("column_1", "Column 1", ColumnType::Text),
            ColumnDef::new("column_2", "Column 2", ColumnType::Text),
        ],
    );
    let empty_table = TableData {
        schema: empty_schema,
        rows: Vec::new(),
        total_rows: 0,
    };
    let compare_provider = TableCompareProvider::compare(
        TableInput::TableData(empty_table.clone()),
        TableInput::TableData(empty_table),
        TableCompareOptions::default(),
    )
    .expect("empty table compare succeeds");

    let getnir_provider =
        GetNirTableProvider::from_source(GetNirSource::StdinBytes(sample_csv.to_vec()), &GetNirRequest::default())
            .expect("empty getnir succeeds");

    let exif_provider = ExifDataViewProvider::from_paths(Vec::new());
    let codegen_provider = SimpleCodeGeneratorProvider::from_input(
        &CodegenInput::Json {
            json_text: "[]".to_string(),
        },
        &default_codegen_template(),
    )
    .expect("empty codegen succeeds");
    let html_provider =
        HtmlAsTextProvider::from_paths(&[], &HtmlAsTextOptions::default()).expect("empty html_as_text succeeds");
    let addr_provider = AddrViewProvider::from_records(Vec::new());

    vec![
        Arc::new(csv_provider),
        Arc::new(compare_provider),
        Arc::new(getnir_provider),
        Arc::new(exif_provider),
        Arc::new(codegen_provider),
        Arc::new(html_provider),
        Arc::new(addr_provider),
    ]
}

pub fn build_suite_wiring(offline: bool, roots: Vec<PathBuf>) -> SuiteWiring {
    if offline {
        return build_synthetic_suite_wiring();
    }

    let default_root = roots.first().cloned().unwrap_or_else(|| PathBuf::from("."));
    let os_fs: Arc<dyn FileSystemOps> = Arc::new(OsFileSystem);
    let ntfs_backend: Arc<dyn NtfsBackend> = Arc::new(LiveNtfsBackend);

    let search_cfg = SearchMyFilesConfig {
        roots: roots.clone(),
        max_depth: Some(4),
        ..SearchMyFilesConfig::default()
    };
    let bulk_spec = BulkChangeSpec::default();
    let folder_time_cfg = FolderTimeUpdateConfig {
        root: default_root.clone(),
        max_depth: Some(1),
        ..FolderTimeUpdateConfig::default()
    };
    let folders_report_cfg = FoldersReportConfig {
        root: default_root,
        depth: 1,
        ..FoldersReportConfig::default()
    };
    let shortcuts_cfg = ShortcutsManConfig {
        scan_roots: roots,
        ..ShortcutsManConfig::default()
    };
    let hash_cfg = HashMyFilesConfig::default();

    let ntfs_cfg = NtfsToolsConfig::default();
    let policy = ntfs_cfg.action_policy.clone();

    let mut providers: Vec<Arc<dyn TableProvider>> = vec![
        // fs2rust-search (6)
        Arc::new(SearchMyFilesProvider::new(search_cfg)),
        Arc::new(BulkFileChangerPreviewProvider::new(bulk_spec, Arc::clone(&os_fs))),
        Arc::new(FolderTimeUpdatePreviewProvider::new(
            folder_time_cfg,
            Arc::clone(&os_fs),
        )),
        Arc::new(FoldersReportProvider::new(folders_report_cfg, Arc::clone(&os_fs))),
        Arc::new(ShortcutsManProvider::with_backend(shortcuts_cfg, Arc::clone(&os_fs))),
        Arc::new(HashMyFilesProvider::new(hash_cfg)),
        // fs2rust-ntfs (11)
        Arc::new(DriveLetterProvider::new(
            ntfs_cfg.drive_letter,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(DiskCountersProvider::new(
            ntfs_cfg.disk_counters,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(FileActivityWatchProvider::new(
            ntfs_cfg.file_activity,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(FolderChangesViewProvider::new(
            ntfs_cfg.folder_changes,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(FileAccessErrorViewProvider::new(
            ntfs_cfg.file_access_error,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(AppReadWriteCounterProvider::new(
            ntfs_cfg.app_read_write,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(DiskSmartViewProvider::new(
            ntfs_cfg.disk_smart,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(AlternateStreamViewProvider::new(
            ntfs_cfg.alternate_stream,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(NtfsLinksViewProvider::new(
            ntfs_cfg.ntfs_links,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(PropertySystemViewProvider::new(
            ntfs_cfg.property_system,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(UsnJournalViewProvider::new(
            ntfs_cfg.usn_journal,
            Arc::clone(&ntfs_backend),
        )),
    ];
    providers.extend(build_default_data_providers(false));

    let actions: Vec<Arc<dyn ActionCommand>> = vec![
        // fs2rust-search (4)
        Arc::new(BulkFileChangerAction::new(Arc::clone(&os_fs))),
        Arc::new(FolderTimeUpdateAction::new(Arc::clone(&os_fs))),
        Arc::new(ShortcutsManFixAction::new(Arc::clone(&os_fs))),
        Arc::new(ShortcutsManDeleteAction::new(os_fs)),
        // fs2rust-ntfs (4)
        Arc::new(DriveLetterAssignAction::new(Arc::clone(&ntfs_backend)).with_policy(policy.clone())),
        Arc::new(DriveLetterRemoveAction::new(Arc::clone(&ntfs_backend)).with_policy(policy.clone())),
        Arc::new(AlternateStreamDeleteAction::new(Arc::clone(&ntfs_backend)).with_policy(policy.clone())),
        Arc::new(PropertySystemSetAction::new(ntfs_backend).with_policy(policy)),
    ];

    SuiteWiring { providers, actions }
}

pub fn build_synthetic_suite_wiring() -> SuiteWiring {
    let (wiring, _, _) = build_synthetic_suite_wiring_with_mocks();
    wiring
}

pub fn build_synthetic_suite_wiring_with_mocks() -> (SuiteWiring, Arc<MockFileSystem>, Arc<MockNtfsBackend>) {
    let disk_root = synthetic_search_root();
    let mock_fs = Arc::new(MockFileSystem::new());
    let ts_old = FileTimestamps {
        created: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        modified: Some(Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap()),
        accessed: Some(Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap()),
    };
    let ts_new = FileTimestamps {
        created: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        modified: Some(Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0).unwrap()),
        accessed: Some(Utc.with_ymd_and_hms(2026, 6, 15, 12, 0, 0).unwrap()),
    };
    let attrs = FileAttributes::default();
    mock_fs.insert_dir("/mock", ts_old, attrs);
    mock_fs.insert_dir("/mock/sub", ts_old, attrs);
    mock_fs.insert_file("/mock/alpha.txt", b"hello fs2rust alpha\n".to_vec(), ts_old, attrs);
    mock_fs.insert_file("/mock/sub/beta.txt", b"hello fs2rust beta\n".to_vec(), ts_new, attrs);
    let lnk_bytes = build_synthetic_lnk_bytes(r"C:\Missing\target.exe", r"C:\Missing", "--check");
    mock_fs.insert_file("/mock/broken.lnk", lnk_bytes, ts_old, attrs);

    let fs_backend: Arc<dyn FileSystemOps> = Arc::clone(&mock_fs) as Arc<dyn FileSystemOps>;
    let ntfs_mock = Arc::new(MockNtfsBackend::with_sample_data());
    let ntfs_backend: Arc<dyn NtfsBackend> = Arc::clone(&ntfs_mock) as Arc<dyn NtfsBackend>;

    let search_cfg = SearchMyFilesConfig {
        roots: vec![disk_root.clone()],
        ..SearchMyFilesConfig::default()
    };
    let bulk_spec = BulkChangeSpec {
        targets: vec![PathBuf::from("/mock/alpha.txt")],
        modified: TimestampChange::ShiftSeconds(60),
        ..BulkChangeSpec::default()
    };
    let folder_time_cfg = FolderTimeUpdateConfig {
        root: PathBuf::from("/mock"),
        source: FolderTimeSource::NewestFileOrSubdir,
        ..FolderTimeUpdateConfig::default()
    };
    let folders_report_cfg = FoldersReportConfig {
        root: PathBuf::from("/mock"),
        depth: 2,
        ..FoldersReportConfig::default()
    };
    let shortcuts_cfg = ShortcutsManConfig {
        scan_roots: vec![PathBuf::from("/mock")],
        ..ShortcutsManConfig::default()
    };
    let hash_cfg = HashMyFilesConfig {
        targets: vec![disk_root],
        ..HashMyFilesConfig::default()
    };

    let sample_ts = Utc.with_ymd_and_hms(2026, 11, 24, 1, 0, 0).unwrap();
    let sample_kernel_events = vec![
        KernelFileRawEvent {
            event_id: 15,
            pid: 4242,
            tid: 1,
            timestamp: sample_ts,
            irp_ptr: 0x1000,
            file_object: 0x2000,
            file_key: 0x3000,
            io_size: 4096,
            nt_status: 0,
            io_flags: 0,
            file_path: r"C:\Work\alpha.txt".to_string(),
            process_name: "worker.exe".to_string(),
        },
        KernelFileRawEvent {
            event_id: 24,
            pid: 4242,
            tid: 1,
            timestamp: sample_ts,
            irp_ptr: 0x1000,
            file_object: 0x2000,
            file_key: 0x3000,
            io_size: 0,
            nt_status: 0xC000_0034,
            io_flags: 0,
            file_path: r"C:\Work\missing.txt".to_string(),
            process_name: "worker.exe".to_string(),
        },
    ];

    let ntfs_cfg = NtfsToolsConfig {
        drive_letter: DriveLetterConfig {
            offline_entries: Some(ntfs_mock.list_drive_letters().unwrap()),
            ..DriveLetterConfig::default()
        },
        disk_counters: DiskCountersConfig {
            offline_records: Some(ntfs_mock.query_disk_counters(&[]).unwrap()),
            ..DiskCountersConfig::default()
        },
        file_activity: FileActivityConfig {
            offline_events: Some(sample_kernel_events.clone()),
            ..FileActivityConfig::default()
        },
        folder_changes: FolderChangesConfig {
            offline_changes: Some(ntfs_mock.watch_folder_changes(Path::new("/mock"), true, 0, 16).unwrap()),
            ..FolderChangesConfig::default()
        },
        file_access_error: FileAccessErrorConfig {
            offline_events: Some(sample_kernel_events),
            ..FileAccessErrorConfig::default()
        },
        app_read_write: AppReadWriteConfig {
            offline_t1: Some(ntfs_mock.snapshot_process_io().unwrap()),
            ..AppReadWriteConfig::default()
        },
        disk_smart: DiskSmartConfig {
            offline_records: Some(ntfs_mock.query_disk_smart(&[]).unwrap()),
            ..DiskSmartConfig::default()
        },
        alternate_stream: AlternateStreamConfig {
            offline_records: Some(ntfs_mock.enumerate_ads(&[], false, false).unwrap()),
            ..AlternateStreamConfig::default()
        },
        ntfs_links: NtfsLinksConfig {
            offline_entries: Some(ntfs_mock.inspect_ntfs_links(&[], false, true).unwrap()),
            ..NtfsLinksConfig::default()
        },
        property_system: PropertySystemConfig {
            offline_entries: Some(ntfs_mock.read_file_properties(Path::new("/mock/alpha.txt")).unwrap()),
            ..PropertySystemConfig::default()
        },
        usn_journal: UsnJournalConfig {
            offline_records: Some(
                ntfs_mock
                    .read_usn_journal("C:", 0, 0, 64, UsnQueryMode::Journal)
                    .unwrap(),
            ),
            ..UsnJournalConfig::default()
        },
        action_policy: PolicyContext::default(),
    };
    let policy = ntfs_cfg.action_policy.clone();

    let mut providers: Vec<Arc<dyn TableProvider>> = vec![
        // fs2rust-search (6)
        Arc::new(SearchMyFilesProvider::new(search_cfg)),
        Arc::new(BulkFileChangerPreviewProvider::new(bulk_spec, Arc::clone(&fs_backend))),
        Arc::new(FolderTimeUpdatePreviewProvider::new(
            folder_time_cfg,
            Arc::clone(&fs_backend),
        )),
        Arc::new(FoldersReportProvider::new(folders_report_cfg, Arc::clone(&fs_backend))),
        Arc::new(ShortcutsManProvider::with_backend(
            shortcuts_cfg,
            Arc::clone(&fs_backend),
        )),
        Arc::new(HashMyFilesProvider::new(hash_cfg)),
        // fs2rust-ntfs (11)
        Arc::new(DriveLetterProvider::new(
            ntfs_cfg.drive_letter,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(DiskCountersProvider::new(
            ntfs_cfg.disk_counters,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(FileActivityWatchProvider::new(
            ntfs_cfg.file_activity,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(FolderChangesViewProvider::new(
            ntfs_cfg.folder_changes,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(FileAccessErrorViewProvider::new(
            ntfs_cfg.file_access_error,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(AppReadWriteCounterProvider::new(
            ntfs_cfg.app_read_write,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(DiskSmartViewProvider::new(
            ntfs_cfg.disk_smart,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(AlternateStreamViewProvider::new(
            ntfs_cfg.alternate_stream,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(NtfsLinksViewProvider::new(
            ntfs_cfg.ntfs_links,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(PropertySystemViewProvider::new(
            ntfs_cfg.property_system,
            Arc::clone(&ntfs_backend),
        )),
        Arc::new(UsnJournalViewProvider::new(
            ntfs_cfg.usn_journal,
            Arc::clone(&ntfs_backend),
        )),
    ];
    providers.extend(build_default_data_providers(true));

    let actions: Vec<Arc<dyn ActionCommand>> = vec![
        // fs2rust-search (4)
        Arc::new(BulkFileChangerAction::new(Arc::clone(&fs_backend))),
        Arc::new(FolderTimeUpdateAction::new(Arc::clone(&fs_backend))),
        Arc::new(ShortcutsManFixAction::new(Arc::clone(&fs_backend))),
        Arc::new(ShortcutsManDeleteAction::new(fs_backend)),
        // fs2rust-ntfs (4)
        Arc::new(DriveLetterAssignAction::new(Arc::clone(&ntfs_backend)).with_policy(policy.clone())),
        Arc::new(DriveLetterRemoveAction::new(Arc::clone(&ntfs_backend)).with_policy(policy.clone())),
        Arc::new(AlternateStreamDeleteAction::new(Arc::clone(&ntfs_backend)).with_policy(policy.clone())),
        Arc::new(PropertySystemSetAction::new(ntfs_backend).with_policy(policy)),
    ];

    (SuiteWiring { providers, actions }, mock_fs, ntfs_mock)
}

pub fn registry_from_wiring(policy: PolicyMode, wiring: SuiteWiring) -> McpServerRegistry {
    let mut reg = McpServerRegistry::new(policy).with_server_info("fs2rust", env!("CARGO_PKG_VERSION"));
    for provider in wiring.providers {
        reg.register_table(provider);
    }
    for action in wiring.actions {
        reg.register_action(action);
    }
    reg
}

pub fn build_fs2rust_registry(policy: PolicyMode, offline: bool, roots: Vec<PathBuf>) -> McpServerRegistry {
    let wiring = build_suite_wiring(offline, roots);
    registry_from_wiring(policy, wiring)
}

pub fn print_tools_manifest_json(policy: PolicyMode, offline: bool, roots: Vec<PathBuf>) -> anyhow::Result<String> {
    let reg = build_fs2rust_registry(policy, offline, roots);
    Ok(serde_json::to_string_pretty(&reg.list_tools())?)
}

pub fn serve_mcp_stdio(policy: PolicyMode, offline: bool, roots: Vec<PathBuf>) -> anyhow::Result<()> {
    let reg = build_fs2rust_registry(policy, offline, roots);
    reg.serve_stdio()
}

#[cfg(test)]
mod tests {
    use guap_mcp::MCP_PROTOCOL_VERSION;
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn registers_all_24_tables_and_8_actions_with_32003_policy_gates() {
        let (wiring, mock_fs, ntfs_mock) = build_synthetic_suite_wiring_with_mocks();
        assert_eq!(wiring.providers.len(), 24, "expected exactly 24 TableProviders");
        assert_eq!(wiring.actions.len(), 8, "expected exactly 8 ActionCommands");

        let mut reg = registry_from_wiring(PolicyMode::ReadOnlyOnly, wiring);

        // 1. initialize (2024-11-05)
        let init_resp = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": MCP_PROTOCOL_VERSION }
            }))
            .unwrap();
        assert_eq!(init_resp["result"]["protocolVersion"], json!(MCP_PROTOCOL_VERSION));

        // 2. notifications/initialized -> None
        let notif_resp = reg.handle_jsonrpc_request(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
        assert!(notif_resp.is_none());

        // 3. ping
        let ping_resp = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "ping"
            }))
            .unwrap();
        assert!(ping_resp.get("error").is_none());

        // 4. tools/list -> 24 + 8 = 32 tools with readOnlyHint/destructiveHint + dry_run/confirm_destructive
        let list_resp = reg
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list"
            }))
            .unwrap();
        let tools = list_resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 32);

        let mut ro_count = 0usize;
        let mut mut_count = 0usize;
        for t in tools {
            let ro = t["annotations"]["readOnlyHint"].as_bool().unwrap();
            let dest = t["annotations"]["destructiveHint"].as_bool().unwrap();
            if ro {
                assert!(!dest);
                ro_count += 1;
            } else {
                assert!(dest);
                let props = &t["inputSchema"]["properties"];
                assert!(props.get("dry_run").is_some(), "missing dry_run on {}", t["name"]);
                assert!(
                    props.get("confirm_destructive").is_some(),
                    "missing confirm_destructive on {}",
                    t["name"]
                );
                mut_count += 1;
            }
        }
        assert_eq!(ro_count, 24);
        assert_eq!(mut_count, 8);

        // 5. Read-only table queries across search, ntfs, data
        for table_name in [
            "search_my_files",
            "drive_letter_view",
            "disk_smart_view",
            "fs2rust.data.csv_file_view",
            "fs2rust.data.exif_data_view",
        ] {
            let resp = reg
                .handle_jsonrpc_request(&json!({
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": { "name": table_name, "arguments": {} }
                }))
                .unwrap();
            assert!(resp.get("error").is_none(), "error calling {table_name}: {resp}");
            assert_eq!(resp["result"]["isError"], json!(false));
        }

        // 6. All 8 mutating actions exercised across ReadOnlyOnly, AllowMutating unconfirmed, dry_run, and apply
        let action_cases: Vec<(&str, Value)> = vec![
            (
                "bulk_file_changer_apply",
                json!({ "targets": ["/mock/alpha.txt"], "set_attributes": ["ReadOnly"] }),
            ),
            (
                "folder_time_update_apply",
                json!({ "root": "/mock", "source": "newest_file_or_subdir" }),
            ),
            (
                "shortcuts_man_fix_target",
                json!({ "shortcut_path": "/mock/broken.lnk", "new_target": r"C:\Tools\new.exe" }),
            ),
            (
                "shortcuts_man_delete",
                json!({ "shortcut_paths": ["/mock/broken.lnk"], "only_if_broken": true }),
            ),
            (
                "drive_letter_assign",
                json!({
                    "mount_point": "Z:\\",
                    "volume_guid": "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\"
                }),
            ),
            ("drive_letter_remove", json!({ "mount_point": "Z:\\" })),
            (
                "alternate_stream_delete",
                json!({ "file_path": "/mock/alpha.txt", "stream_name": "Zone.Identifier" }),
            ),
            (
                "property_system_set",
                json!({ "file_path": "/mock/alpha.txt", "canonical_name": "System.Title", "value": "Updated" }),
            ),
        ];
        assert_eq!(action_cases.len(), 8);

        // (a) ReadOnlyOnly blocks even with confirm_destructive=true
        reg.set_policy(PolicyMode::ReadOnlyOnly);
        for (name, base_args) in &action_cases {
            let mut args = base_args.clone();
            args["confirm_destructive"] = json!(true);
            let resp = reg
                .handle_jsonrpc_request(&json!({
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": args }
                }))
                .unwrap();
            assert_eq!(resp["error"]["code"], json!(-32003), "expected -32003 for {name}");
        }

        // (b) AllowMutating without confirm_destructive=true still returns -32003
        reg.set_policy(PolicyMode::AllowMutating);
        for (name, base_args) in &action_cases {
            let resp = reg
                .handle_jsonrpc_request(&json!({
                    "jsonrpc": "2.0",
                    "id": 30,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": base_args }
                }))
                .unwrap();
            assert_eq!(
                resp["error"]["code"],
                json!(-32003),
                "expected -32003 without confirm_destructive for {name}"
            );
        }

        // (c) AllowMutating + confirm_destructive=true + dry_run=true -> succeeds with 0 mutations
        for (name, base_args) in &action_cases {
            let mut args = base_args.clone();
            args["confirm_destructive"] = json!(true);
            args["dry_run"] = json!(true);
            let resp = reg
                .handle_jsonrpc_request(&json!({
                    "jsonrpc": "2.0",
                    "id": 40,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": args }
                }))
                .unwrap();
            assert!(resp.get("error").is_none(), "dry_run failed for {name}: {resp}");
            assert_eq!(resp["result"]["isError"], json!(false));
        }
        assert!(ntfs_mock.mounted.lock().unwrap().is_empty());
        assert!(ntfs_mock.deleted_ads.lock().unwrap().is_empty());
        assert!(ntfs_mock.set_props.lock().unwrap().is_empty());
        assert!(mock_fs.exists(Path::new("/mock/broken.lnk")));

        // (d) AllowMutating + confirm_destructive=true + dry_run=false -> applies on mock backends
        for (name, base_args) in &action_cases {
            let mut args = base_args.clone();
            args["confirm_destructive"] = json!(true);
            args["dry_run"] = json!(false);
            let resp = reg
                .handle_jsonrpc_request(&json!({
                    "jsonrpc": "2.0",
                    "id": 50,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": args }
                }))
                .unwrap();
            assert!(resp.get("error").is_none(), "apply failed for {name}: {resp}");
            assert_eq!(resp["result"]["isError"], json!(false));
        }
        assert_eq!(ntfs_mock.deleted_ads.lock().unwrap().len(), 1);
        assert_eq!(ntfs_mock.set_props.lock().unwrap().len(), 1);
        assert!(!mock_fs.exists(Path::new("/mock/broken.lnk")));
    }
}
