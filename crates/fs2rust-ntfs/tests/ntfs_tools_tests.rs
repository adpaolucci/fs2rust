use chrono::{TimeZone, Utc};
use fs2rust_core::{FileAttributes, FileEntry, FileTimestamps, FsError, PolicyContext, datetime_to_windows_filetime};
use fs2rust_ntfs::{
    AdsEntry, AlternateStreamConfig, AlternateStreamDeleteAction, AppReadWriteConfig, DiskCountersConfig,
    DiskPerformanceRecord, DiskSmartConfig, DriveLetterAssignAction, DriveLetterConfig, DriveLetterEntry,
    DriveLetterRemoveAction, FileAccessErrorConfig, FileActivityConfig, FilePropertyEntry, FolderChangeAction,
    FolderChangeEntry, FolderChangesConfig, FolderSnapshot, IoCounters, KERNEL_FILE_MAGIC, KernelFileRawEvent,
    LiveNtfsBackend, MountedDeviceTarget, NtfsBackend, NtfsLinkEntry, NtfsLinksConfig, NtfsToolsConfig,
    ProcessIoSnapshot, PropertySystemConfig, PropertySystemSetAction, ReparseKind, UsnJournalConfig, UsnQueryMode,
    UsnRecord, ata_checksum_valid, ata_page_to_records, compute_io_rates, correlate_file_access_errors,
    correlate_file_activity, decode_ntstatus, decode_usn_reasons, encode_kernel_file_wire_record, normalize_ads_target,
    nvme_log_to_records, parse_ata_smart_attributes, parse_disk_performance, parse_file_notify_buffer,
    parse_io_counters, parse_kernel_file_wire_stream, parse_mft_ads_records, parse_mft_file_record_ads,
    parse_mounted_device_value, parse_nvme_health_log, parse_reparse_data_buffer, parse_serialized_property_storage,
    parse_usn_ioctl_buffer, parse_usn_journal_stream, register_ntfs_tools_with_backend,
};
use guap_mcp::{ActionCommand, McpServerRegistry, PolicyMode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct MockNtfsBackend {
    mounted: Mutex<Vec<(String, String)>>,
    deleted_ads: Mutex<Vec<String>>,
    set_props: Mutex<Vec<(PathBuf, String, String)>>,
}

impl MockNtfsBackend {
    fn new() -> Self {
        Self {
            mounted: Mutex::new(Vec::new()),
            deleted_ads: Mutex::new(Vec::new()),
            set_props: Mutex::new(Vec::new()),
        }
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
            read_count: 100,
            write_count: 50,
            bytes_read: 409_600,
            bytes_written: 204_800,
            read_time_ms: 12,
            write_time_ms: 8,
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
        _include_op_end: bool,
    ) -> Result<Vec<KernelFileRawEvent>, FsError> {
        Ok(vec![])
    }

    fn watch_folder_changes(
        &self,
        _watch_dir: &Path,
        _recursive: bool,
        _duration_ms: u64,
        _max_events: usize,
    ) -> Result<Vec<FolderChangeEntry>, FsError> {
        Ok(vec![])
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

    fn query_disk_smart(&self, _disk_indices: &[u32]) -> Result<Vec<fs2rust_ntfs::DiskSmartRecord>, FsError> {
        Ok(vec![])
    }

    fn enumerate_ads(
        &self,
        _target_paths: &[PathBuf],
        _recursive: bool,
        _include_default_data: bool,
    ) -> Result<Vec<AdsEntry>, FsError> {
        Ok(vec![])
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
        Ok(vec![])
    }

    fn read_file_properties(&self, file_path: &Path) -> Result<Vec<FilePropertyEntry>, FsError> {
        Ok(vec![FilePropertyEntry {
            file_path: file_path.to_string_lossy().to_string(),
            canonical_name: "System.Title".to_string(),
            property_key: "{F29F85E0-4FF9-1068-AB91-08002B27B3D9} 2".to_string(),
            display_name: "Title".to_string(),
            value_type: "VT(31)".to_string(),
            value: "Sample Title".to_string(),
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
            file_path: file_path.to_string_lossy().to_string(),
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
        Ok(vec![])
    }
}

fn finalize_ata_checksum(buf: &mut [u8; 512]) {
    let sum: u8 = buf[..511].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    buf[511] = 0u8.wrapping_sub(sum);
}

#[test]
fn disk_smart_ata_and_nvme_parsers_handle_valid_corrupt_and_truncated_fixtures() {
    let mut attr = [0u8; 512];
    attr[0..2].copy_from_slice(&0x0010u16.to_le_bytes());
    let slots: &[(u8, u16, u8, u8, [u8; 6])] = &[
        (0x05, 0x0033, 98, 98, [3, 0, 0, 0, 0, 0]),
        (0x09, 0x0032, 95, 95, 4321u64.to_le_bytes()[0..6].try_into().unwrap()),
        (0xC2, 0x0022, 62, 50, [38, 0, 22, 0, 48, 0]),
        (0xE7, 0x0001, 5, 5, [5, 0, 0, 0, 0, 0]),
    ];
    for (i, (id, flags, cur, worst, raw)) in slots.iter().enumerate() {
        let b = 2 + i * 12;
        attr[b] = *id;
        attr[b + 1..b + 3].copy_from_slice(&flags.to_le_bytes());
        attr[b + 3] = *cur;
        attr[b + 4] = *worst;
        attr[b + 5..b + 11].copy_from_slice(raw);
    }
    finalize_ata_checksum(&mut attr);
    assert!(ata_checksum_valid(&attr));

    let mut thresh = [0u8; 512];
    thresh[0..2].copy_from_slice(&0x0010u16.to_le_bytes());
    thresh[2] = 0x05;
    thresh[3] = 36;
    thresh[14] = 0xE7;
    thresh[15] = 10;
    finalize_ata_checksum(&mut thresh);

    let page = parse_ata_smart_attributes(&attr, Some(&thresh), true).unwrap();
    assert!(page.checksum_valid);
    assert_eq!(page.attributes.len(), 4);
    assert_eq!(page.attributes[0].health_status, "Caution"); // 0x05 raw=3
    assert_eq!(page.attributes[1].raw_value, 4321);
    assert_eq!(page.attributes[2].temperature_c, Some(38));
    assert_eq!(page.attributes[3].health_status, "Critical"); // 0xE7 cur=5 <= thresh=10, pre_fail=true
    let ata_recs = ata_page_to_records(r"\\.\PhysicalDrive0", "TestSSD", "SN1", "FW1", &page);
    assert_eq!(ata_recs.len(), 4);

    // Corrupt checksum
    let mut bad_attr = attr;
    bad_attr[511] ^= 0x55;
    assert!(!ata_checksum_valid(&bad_attr));
    assert!(matches!(
        parse_ata_smart_attributes(&bad_attr, Some(&thresh), true),
        Err(FsError::Parse(_))
    ));
    let lenient = parse_ata_smart_attributes(&bad_attr, Some(&thresh), false).unwrap();
    assert!(!lenient.checksum_valid);
    assert_eq!(lenient.attributes[0].health_status, "ChecksumError");

    // Truncated 511-byte buffer
    assert!(matches!(
        parse_ata_smart_attributes(&attr[..511], None, false),
        Err(FsError::Parse(_))
    ));

    // NVMe LID 0x02 fixture
    let mut nvme = [0u8; 512];
    nvme[0] = 0x01; // SpareBelowThreshold
    nvme[1..3].copy_from_slice(&315u16.to_le_bytes()); // 315 K = 41.85 C
    nvme[3] = 8; // available_spare
    nvme[4] = 10; // threshold
    nvme[5] = 92; // percentage_used
    nvme[32..48].copy_from_slice(&2000u128.to_le_bytes());
    nvme[128..144].copy_from_slice(&1234u128.to_le_bytes());
    nvme[160..176].copy_from_slice(&2u128.to_le_bytes());
    nvme[200..202].copy_from_slice(&310u16.to_le_bytes());

    let nvme_log = parse_nvme_health_log(&nvme).unwrap();
    assert!((nvme_log.composite_temperature_c.unwrap() - 41.85).abs() < 0.01);
    assert_eq!(nvme_log.data_bytes_read, (2000u128 * 512_000).to_string());
    assert_eq!(nvme_log.power_on_hours_u64, 1234);
    assert_eq!(nvme_log.media_errors_u64, 2);
    let nvme_recs = nvme_log_to_records(r"\\.\PhysicalDrive1", "TestNVMe", "NV1", "1.0", &nvme_log);
    assert_eq!(nvme_recs.len(), 5);
    assert!(matches!(parse_nvme_health_log(&nvme[..511]), Err(FsError::Parse(_))));
}

fn build_synthetic_mft_ads_record() -> Vec<u8> {
    let mut rec = vec![0u8; 1024];
    rec[0..4].copy_from_slice(b"FILE");
    let usa_off = 0x30u16;
    let usa_count = 3u16;
    let usn = 0x00ABu16;
    rec[0x04..0x06].copy_from_slice(&usa_off.to_le_bytes());
    rec[0x06..0x08].copy_from_slice(&usa_count.to_le_bytes());
    rec[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes()); // first_attr_offset
    rec[0x16..0x18].copy_from_slice(&0x0001u16.to_le_bytes()); // IN_USE
    rec[0x1C..0x20].copy_from_slice(&1024u32.to_le_bytes()); // bytes_allocated
    rec[0x2C..0x30].copy_from_slice(&42u32.to_le_bytes()); // mft_record_number

    // $FILE_NAME attribute at 0x38
    let mut off = 0x38usize;
    let fname: Vec<u16> = "invoice.pdf".encode_utf16().collect();
    let fn_payload_len = 0x42 + fname.len() * 2;
    let fn_attr_len = ((24 + fn_payload_len) + 7) & !7;
    rec[off..off + 4].copy_from_slice(&0x30u32.to_le_bytes());
    rec[off + 4..off + 8].copy_from_slice(&(fn_attr_len as u32).to_le_bytes());
    rec[off + 8] = 0; // resident
    rec[off + 0x10..off + 0x14].copy_from_slice(&(fn_payload_len as u32).to_le_bytes());
    rec[off + 0x14..off + 0x16].copy_from_slice(&24u16.to_le_bytes());
    rec[off + 24 + 0x40] = fname.len() as u8;
    rec[off + 24 + 0x41] = 3; // Win32&DOS
    for (i, u) in fname.iter().enumerate() {
        let p = off + 24 + 0x42 + i * 2;
        rec[p..p + 2].copy_from_slice(&u.to_le_bytes());
    }
    off += fn_attr_len;

    // Unnamed non-resident $DATA
    let nr_len = 72usize;
    rec[off..off + 4].copy_from_slice(&0x80u32.to_le_bytes());
    rec[off + 4..off + 8].copy_from_slice(&(nr_len as u32).to_le_bytes());
    rec[off + 8] = 1;
    rec[off + 0x20..off + 0x22].copy_from_slice(&64u16.to_le_bytes());
    rec[off + 0x28..off + 0x30].copy_from_slice(&106_496u64.to_le_bytes());
    rec[off + 0x30..off + 0x38].copy_from_slice(&104_857u64.to_le_bytes());
    off += nr_len;

    // Named resident $DATA: Zone.Identifier
    let zname: Vec<u16> = "Zone.Identifier".encode_utf16().collect();
    let zpayload = b"[ZoneTransfer]\r\nZoneId=3\r\n";
    let z_name_off = 24usize;
    let z_content_off = z_name_off + zname.len() * 2;
    let z_attr_len = ((z_content_off + zpayload.len()) + 7) & !7;
    rec[off..off + 4].copy_from_slice(&0x80u32.to_le_bytes());
    rec[off + 4..off + 8].copy_from_slice(&(z_attr_len as u32).to_le_bytes());
    rec[off + 8] = 0;
    rec[off + 9] = zname.len() as u8;
    rec[off + 0x0A..off + 0x0C].copy_from_slice(&(z_name_off as u16).to_le_bytes());
    rec[off + 0x10..off + 0x14].copy_from_slice(&(zpayload.len() as u32).to_le_bytes());
    rec[off + 0x14..off + 0x16].copy_from_slice(&(z_content_off as u16).to_le_bytes());
    for (i, u) in zname.iter().enumerate() {
        let p = off + z_name_off + i * 2;
        rec[p..p + 2].copy_from_slice(&u.to_le_bytes());
    }
    rec[off + z_content_off..off + z_content_off + zpayload.len()].copy_from_slice(zpayload);
    off += z_attr_len;

    // Named non-resident $DATA spanning across 512B sector tail (510..512)
    let pname: Vec<u16> = "payload.bin".encode_utf16().collect();
    let p_name_off = 64usize;
    let p_attr_len = 512usize.saturating_sub(off) + 32; // crosses offset 510..512!
    rec[off..off + 4].copy_from_slice(&0x80u32.to_le_bytes());
    rec[off + 4..off + 8].copy_from_slice(&(p_attr_len as u32).to_le_bytes());
    rec[off + 8] = 1;
    rec[off + 9] = pname.len() as u8;
    rec[off + 0x0A..off + 0x0C].copy_from_slice(&(p_name_off as u16).to_le_bytes());
    rec[off + 0x20..off + 0x22].copy_from_slice(&((p_name_off + pname.len() * 2) as u16).to_le_bytes());
    rec[off + 0x28..off + 0x30].copy_from_slice(&12_288u64.to_le_bytes());
    rec[off + 0x30..off + 0x38].copy_from_slice(&8_192u64.to_le_bytes());
    for (i, u) in pname.iter().enumerate() {
        let p = off + p_name_off + i * 2;
        rec[p..p + 2].copy_from_slice(&u.to_le_bytes());
    }
    off += p_attr_len;

    rec[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    rec[0x18..0x1C].copy_from_slice(&((off + 8) as u32).to_le_bytes());

    // Simulate NTFS sector fixup: save original tail bytes in USA and place USN at 510..512 and 1022..1024.
    let s1_tail = [rec[510], rec[511]];
    let s2_tail = [rec[1022], rec[1023]];
    rec[0x30..0x32].copy_from_slice(&usn.to_le_bytes());
    rec[0x32..0x34].copy_from_slice(&s1_tail);
    rec[0x34..0x36].copy_from_slice(&s2_tail);
    rec[510..512].copy_from_slice(&usn.to_le_bytes());
    rec[1022..1024].copy_from_slice(&usn.to_le_bytes());
    rec
}

#[test]
fn mft_ads_parser_restores_usa_fixups_and_blocks_infinite_loops() {
    let rec = build_synthetic_mft_ads_record();
    let ads = parse_mft_ads_records(&rec).unwrap();
    assert_eq!(ads.len(), 2);
    assert_eq!(ads[0].file_path, "invoice.pdf");
    assert_eq!(ads[0].stream_name, ":Zone.Identifier:$DATA");
    assert_eq!(ads[0].full_stream_path, "invoice.pdf:Zone.Identifier");
    assert!(ads[0].resident);
    assert_eq!(ads[0].mft_record, Some(42));
    assert!(ads[0].content_preview.contains("ZoneId=3"));
    assert_eq!(ads[0].sha256.len(), 64);

    assert_eq!(ads[1].stream_name, ":payload.bin:$DATA");
    assert!(!ads[1].resident);
    assert_eq!(ads[1].stream_size, 8192);
    assert_eq!(ads[1].allocated_size, 12_288);

    // USA mismatch error
    let mut bad_usa = rec.clone();
    bad_usa[510] ^= 0xFF;
    assert!(matches!(parse_mft_file_record_ads(&bad_usa), Err(FsError::Parse(_))));

    // Zero attr_len infinite-loop guard
    let mut zero_attr = rec;
    // Corrupt first attribute length at 0x38 + 4 to 0
    zero_attr[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(parse_mft_file_record_ads(&zero_attr), Err(FsError::Parse(_))));

    // Refuse default ::$DATA stream and separator traversal
    assert!(matches!(
        normalize_ads_target(r"C:\test\a.txt", "::$DATA"),
        Err(FsError::PolicyDenied(_))
    ));
    assert!(matches!(
        normalize_ads_target(r"C:\test\a.txt", r"..\evil"),
        Err(FsError::InvalidArgument(_))
    ));
}

#[test]
fn reparse_data_buffer_parser_handles_symlink_junction_appexeclink_and_bounds() {
    // 1. Symlink (relative)
    let sub: Vec<u16> = r"..\rel\file.txt".encode_utf16().collect();
    let print: Vec<u16> = r"..\rel\file.txt".encode_utf16().collect();
    let sub_bytes = sub.len() * 2;
    let print_bytes = print.len() * 2;
    let mut sym_buf = Vec::new();
    sym_buf.extend_from_slice(&0xA000_000Cu32.to_le_bytes());
    sym_buf.extend_from_slice(&((12 + sub_bytes + print_bytes) as u16).to_le_bytes());
    sym_buf.extend_from_slice(&0u16.to_le_bytes());
    sym_buf.extend_from_slice(&0u16.to_le_bytes());
    sym_buf.extend_from_slice(&(sub_bytes as u16).to_le_bytes());
    sym_buf.extend_from_slice(&(sub_bytes as u16).to_le_bytes());
    sym_buf.extend_from_slice(&(print_bytes as u16).to_le_bytes());
    sym_buf.extend_from_slice(&1u32.to_le_bytes()); // SYMLINK_FLAG_RELATIVE
    for u in sub.iter().chain(print.iter()) {
        sym_buf.extend_from_slice(&u.to_le_bytes());
    }
    let parsed_sym = parse_reparse_data_buffer(&sym_buf, false).unwrap();
    assert_eq!(parsed_sym.kind, ReparseKind::SymbolicLinkFile);
    assert!(parsed_sym.is_relative);
    assert_eq!(parsed_sym.resolved_target, r"..\rel\file.txt");

    // 2. Junction (NO Flags field, PathBuffer at offset 16!)
    let jsub: Vec<u16> = r"\??\D:\Data".encode_utf16().collect();
    let jprint: Vec<u16> = r"D:\Data".encode_utf16().collect();
    let jsub_b = jsub.len() * 2;
    let jprint_b = jprint.len() * 2;
    let mut j_buf = Vec::new();
    j_buf.extend_from_slice(&0xA000_0003u32.to_le_bytes());
    j_buf.extend_from_slice(&((8 + jsub_b + jprint_b) as u16).to_le_bytes());
    j_buf.extend_from_slice(&0u16.to_le_bytes());
    j_buf.extend_from_slice(&0u16.to_le_bytes());
    j_buf.extend_from_slice(&(jsub_b as u16).to_le_bytes());
    j_buf.extend_from_slice(&(jsub_b as u16).to_le_bytes());
    j_buf.extend_from_slice(&(jprint_b as u16).to_le_bytes());
    for u in jsub.iter().chain(jprint.iter()) {
        j_buf.extend_from_slice(&u.to_le_bytes());
    }
    let parsed_j = parse_reparse_data_buffer(&j_buf, true).unwrap();
    assert_eq!(parsed_j.kind, ReparseKind::Junction);
    assert_eq!(parsed_j.substitute_name, r"\??\D:\Data");
    assert_eq!(parsed_j.print_name, r"D:\Data");
    assert_eq!(parsed_j.resolved_target, r"D:\Data");

    // 3. APPEXECLINK
    let mut app_buf = Vec::new();
    let mut app_payload = Vec::new();
    app_payload.extend_from_slice(&3u32.to_le_bytes());
    for s in [
        "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
        "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App",
        r"C:\Program Files\WindowsApps\wt.exe",
    ] {
        for u in s.encode_utf16().chain(std::iter::once(0)) {
            app_payload.extend_from_slice(&u.to_le_bytes());
        }
    }
    app_buf.extend_from_slice(&0x8000_001Bu32.to_le_bytes());
    app_buf.extend_from_slice(&(app_payload.len() as u16).to_le_bytes());
    app_buf.extend_from_slice(&0u16.to_le_bytes());
    app_buf.extend_from_slice(&app_payload);
    let parsed_app = parse_reparse_data_buffer(&app_buf, false).unwrap();
    assert_eq!(parsed_app.kind, ReparseKind::AppExecLink);
    assert_eq!(parsed_app.resolved_target, r"C:\Program Files\WindowsApps\wt.exe");

    // 4. Unknown third-party REPARSE_GUID_DATA_BUFFER
    let mut third_party = vec![0u8; 32];
    third_party[0..4].copy_from_slice(&0x0000_0042u32.to_le_bytes());
    third_party[4..6].copy_from_slice(&8u16.to_le_bytes());
    let parsed_other = parse_reparse_data_buffer(&third_party, false).unwrap();
    assert_eq!(parsed_other.kind, ReparseKind::OtherReparse);
    assert!(parsed_other.guid.is_some());

    // 5. Out-of-bounds SubstituteNameLength
    let mut oob = j_buf.clone();
    oob[10..12].copy_from_slice(&999u16.to_le_bytes());
    assert!(matches!(parse_reparse_data_buffer(&oob, true), Err(FsError::Parse(_))));
}

fn build_usn_v2_record(frn: u64, parent_frn: u64, usn: i64, reason: u32, name: &str) -> Vec<u8> {
    let name_u16: Vec<u16> = name.encode_utf16().collect();
    let fn_len = name_u16.len() * 2;
    let rec_len = (60 + fn_len + 7) & !7;
    let mut rec = vec![0u8; rec_len];
    rec[0..4].copy_from_slice(&(rec_len as u32).to_le_bytes());
    rec[4..6].copy_from_slice(&2u16.to_le_bytes());
    rec[8..16].copy_from_slice(&frn.to_le_bytes());
    rec[16..24].copy_from_slice(&parent_frn.to_le_bytes());
    rec[24..32].copy_from_slice(&usn.to_le_bytes());
    let ft = datetime_to_windows_filetime(Utc.with_ymd_and_hms(2026, 11, 23, 12, 0, 0).unwrap()).unwrap();
    rec[32..40].copy_from_slice(&ft.to_le_bytes());
    rec[40..44].copy_from_slice(&reason.to_le_bytes());
    rec[52..56].copy_from_slice(&0x20u32.to_le_bytes()); // ARCHIVE
    rec[56..58].copy_from_slice(&(fn_len as u16).to_le_bytes());
    rec[58..60].copy_from_slice(&60u16.to_le_bytes());
    for (i, u) in name_u16.iter().enumerate() {
        rec[60 + i * 2..62 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    rec
}

fn build_usn_v3_record(frn: u128, parent_frn: u128, usn: i64, reason: u32, name: &str) -> Vec<u8> {
    let name_u16: Vec<u16> = name.encode_utf16().collect();
    let fn_len = name_u16.len() * 2;
    let rec_len = (76 + fn_len + 7) & !7;
    let mut rec = vec![0u8; rec_len];
    rec[0..4].copy_from_slice(&(rec_len as u32).to_le_bytes());
    rec[4..6].copy_from_slice(&3u16.to_le_bytes());
    rec[8..24].copy_from_slice(&frn.to_le_bytes());
    rec[24..40].copy_from_slice(&parent_frn.to_le_bytes());
    rec[40..48].copy_from_slice(&usn.to_le_bytes());
    let ft = datetime_to_windows_filetime(Utc.with_ymd_and_hms(2026, 11, 23, 12, 5, 0).unwrap()).unwrap();
    rec[48..56].copy_from_slice(&ft.to_le_bytes());
    rec[56..60].copy_from_slice(&reason.to_le_bytes());
    rec[68..72].copy_from_slice(&0x10u32.to_le_bytes()); // DIRECTORY
    rec[72..74].copy_from_slice(&(fn_len as u16).to_le_bytes());
    rec[74..76].copy_from_slice(&76u16.to_le_bytes());
    for (i, u) in name_u16.iter().enumerate() {
        rec[76 + i * 2..78 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    rec
}

#[test]
fn usn_journal_parser_handles_sparse_zeros_v2_v3_ioctl_cursor_and_truncation() {
    let mut stream = vec![0u8; 4096]; // leading sparse 4 KiB zeros
    let v2 = build_usn_v2_record((3u64 << 48) | 1024, (1u64 << 48) | 5, 10_000, 0x8000_0102, "notes.txt");
    stream.extend_from_slice(&v2);
    // Zero-pad to 8192 page boundary
    stream.resize(8192, 0);
    let v3 = build_usn_v3_record(
        0x0001_0000_0000_0000_0000_0000_0000_0888,
        5,
        10_500,
        0x0000_3000,
        "renamed_dir",
    );
    stream.extend_from_slice(&v3);

    let parsed = parse_usn_journal_stream(&stream).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].major_version, 2);
    assert_eq!(parsed[0].mft_entry, 1024);
    assert_eq!(parsed[0].file_name, "notes.txt");
    assert_eq!(decode_usn_reasons(0x8000_0102), "DATA_EXTEND|FILE_CREATE|CLOSE");
    assert_eq!(parsed[1].major_version, 3);
    assert_eq!(parsed[1].mft_entry, 0x0888);
    assert_eq!(parsed[1].file_name, "renamed_dir");

    // FSCTL_READ_USN_JOURNAL 8-byte next_usn cursor
    let mut ioctl_buf = Vec::new();
    ioctl_buf.extend_from_slice(&20_000i64.to_le_bytes());
    ioctl_buf.extend_from_slice(&v2);
    let (next_usn, ioctl_recs) = parse_usn_ioctl_buffer(&ioctl_buf).unwrap();
    assert_eq!(next_usn, 20_000);
    assert_eq!(ioctl_recs.len(), 1);

    // Truncated V2 record < 60B
    let mut bad_v2 = vec![0u8; 52];
    bad_v2[0..4].copy_from_slice(&52u32.to_le_bytes());
    bad_v2[4..6].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(parse_usn_journal_stream(&bad_v2), Err(FsError::Parse(_))));
}

#[test]
fn etw_file_wire_stream_correlation_and_ntstatus_decoder() {
    let ts = Utc.with_ymd_and_hms(2026, 11, 23, 14, 0, 0).unwrap();
    let ft = datetime_to_windows_filetime(ts).unwrap();
    let raw_events = vec![
        KernelFileRawEvent {
            event_id: 12, // Create
            pid: 1000,
            tid: 1,
            timestamp: ts,
            irp_ptr: 0xDEAD_0001,
            file_object: 0xF001,
            file_key: 0xABCD_0001,
            io_size: 0,
            nt_status: 0,
            io_flags: 0,
            file_path: r"C:\Work\secret.docx".to_string(),
            process_name: "word.exe".to_string(),
        },
        KernelFileRawEvent {
            event_id: 15, // Read (uses FileKey without inline path!)
            pid: 1000,
            tid: 1,
            timestamp: ts,
            irp_ptr: 0xDEAD_0002,
            file_object: 0xF001,
            file_key: 0xABCD_0001,
            io_size: 4096,
            nt_status: 0,
            io_flags: 0,
            file_path: String::new(),
            process_name: "word.exe".to_string(),
        },
        KernelFileRawEvent {
            event_id: 16, // Write
            pid: 1000,
            tid: 1,
            timestamp: ts,
            irp_ptr: 0xDEAD_0003,
            file_object: 0xF001,
            file_key: 0xABCD_0001,
            io_size: 8192,
            nt_status: 0,
            io_flags: 0,
            file_path: String::new(),
            process_name: "word.exe".to_string(),
        },
        KernelFileRawEvent {
            event_id: 14, // Close
            pid: 1000,
            tid: 1,
            timestamp: ts,
            irp_ptr: 0xDEAD_0004,
            file_object: 0xF001,
            file_key: 0xABCD_0001,
            io_size: 0,
            nt_status: 0,
            io_flags: 0,
            file_path: String::new(),
            process_name: "word.exe".to_string(),
        },
        // OperationEnd error correlation via IrpPtr
        KernelFileRawEvent {
            event_id: 12,
            pid: 1000,
            tid: 1,
            timestamp: ts,
            irp_ptr: 0xBEEF_9999,
            file_object: 0xF002,
            file_key: 0xABCD_0002,
            io_size: 0,
            nt_status: 0,
            io_flags: 0,
            file_path: r"C:\Windows\System32\locked.dat".to_string(),
            process_name: "word.exe".to_string(),
        },
        KernelFileRawEvent {
            event_id: 24, // OperationEnd
            pid: 1000,
            tid: 1,
            timestamp: ts,
            irp_ptr: 0xBEEF_9999,
            file_object: 0,
            file_key: 0,
            io_size: 0,
            nt_status: 0xC000_0022,
            io_flags: 0,
            file_path: String::new(),
            process_name: "word.exe".to_string(),
        },
    ];

    let mut wire = Vec::new();
    wire.extend_from_slice(KERNEL_FILE_MAGIC);
    wire.extend_from_slice(&(raw_events.len() as u32).to_le_bytes());
    for ev in &raw_events {
        wire.extend_from_slice(&encode_kernel_file_wire_record(ev, ft));
    }
    let decoded_wire = parse_kernel_file_wire_stream(&wire).unwrap();
    assert_eq!(decoded_wire.len(), raw_events.len());

    let pid_names = HashMap::from([(1000, "word.exe".to_string())]);
    let activity = correlate_file_activity(&decoded_wire, &pid_names);
    let doc_act = activity.iter().find(|a| a.file_path == r"C:\Work\secret.docx").unwrap();
    assert_eq!(doc_act.open_count, 1);
    assert_eq!(doc_act.close_count, 1);
    assert_eq!(doc_act.read_count, 1);
    assert_eq!(doc_act.write_count, 1);
    assert_eq!(doc_act.read_bytes, 4096);
    assert_eq!(doc_act.write_bytes, 8192);

    let errs = correlate_file_access_errors(&decoded_wire, &pid_names, false);
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].file_path, r"C:\Windows\System32\locked.dat");
    assert_eq!(errs[0].nt_status_name, "STATUS_ACCESS_DENIED");
    assert_eq!(errs[0].operation, "Create");

    // Verify all required NTSTATUS codes decode cleanly
    for (code, expected) in [
        (0x0000_0000, "STATUS_SUCCESS"),
        (0x0000_0103, "STATUS_PENDING"),
        (0xC000_0034, "STATUS_OBJECT_NAME_NOT_FOUND"),
        (0xC000_0022, "STATUS_ACCESS_DENIED"),
        (0xC000_0043, "STATUS_SHARING_VIOLATION"),
        (0xC000_003A, "STATUS_OBJECT_PATH_NOT_FOUND"),
        (0xC000_00BA, "STATUS_FILE_IS_A_DIRECTORY"),
        (0xC000_000D, "STATUS_INVALID_PARAMETER"),
        (0xC000_000F, "STATUS_NO_SUCH_FILE"),
        (0xC000_0035, "STATUS_OBJECT_NAME_COLLISION"),
        (0xC000_0056, "STATUS_DELETE_PENDING"),
        (0xDEAD_BEEF, "STATUS_UNKNOWN"),
    ] {
        assert_eq!(decode_ntstatus(code).name, expected);
    }
}

#[test]
fn app_io_folder_changes_mounted_devices_disk_counters_and_propsys_parsers() {
    // 1. IO_COUNTERS 48B + rate
    let mut io_b0 = Vec::new();
    for v in [10u64, 5, 1, 1000, 2000, 50] {
        io_b0.extend_from_slice(&v.to_le_bytes());
    }
    let c0 = parse_io_counters(&io_b0).unwrap();
    let mut io_b1 = Vec::new();
    for v in [20u64, 15, 2, 5000, 10_000, 100] {
        io_b1.extend_from_slice(&v.to_le_bytes());
    }
    let c1 = parse_io_counters(&io_b1).unwrap();
    assert!(matches!(parse_io_counters(&io_b0[..47]), Err(FsError::Parse(_))));
    let s0 = vec![ProcessIoSnapshot {
        pid: 77,
        process_name: "app.exe".to_string(),
        process_path: r"C:\app.exe".to_string(),
        counters: c0,
        access_denied: false,
    }];
    let s1 = vec![ProcessIoSnapshot {
        pid: 77,
        process_name: "app.exe".to_string(),
        process_path: r"C:\app.exe".to_string(),
        counters: c1,
        access_denied: false,
    }];
    let rates = compute_io_rates(Some(&s0), &s1, 2000, None);
    assert!((rates[0].read_rate_bps - 2000.0).abs() < 0.01);
    assert!((rates[0].write_rate_bps - 4000.0).abs() < 0.01);

    // 2. FILE_NOTIFY_INFORMATION + loop guard + FolderSnapshot::diff
    let ts = Utc::now();
    let f1: Vec<u16> = "added.txt".encode_utf16().collect();
    let f2: Vec<u16> = "modified.txt".encode_utf16().collect();
    let e1_len = (12 + f1.len() * 2 + 3) & !3;
    let e2_len = 12 + f2.len() * 2;
    let mut fni = vec![0u8; e1_len + e2_len];
    fni[0..4].copy_from_slice(&(e1_len as u32).to_le_bytes());
    fni[4..8].copy_from_slice(&1u32.to_le_bytes()); // Added
    fni[8..12].copy_from_slice(&((f1.len() * 2) as u32).to_le_bytes());
    for (i, u) in f1.iter().enumerate() {
        fni[12 + i * 2..14 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    fni[e1_len..e1_len + 4].copy_from_slice(&0u32.to_le_bytes());
    fni[e1_len + 4..e1_len + 8].copy_from_slice(&3u32.to_le_bytes()); // Modified
    fni[e1_len + 8..e1_len + 12].copy_from_slice(&((f2.len() * 2) as u32).to_le_bytes());
    for (i, u) in f2.iter().enumerate() {
        fni[e1_len + 12 + i * 2..e1_len + 14 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    let parsed_fni = parse_file_notify_buffer(Path::new(r"C:\Watch"), &fni, ts).unwrap();
    assert_eq!(parsed_fni.len(), 2);
    assert_eq!(parsed_fni[0].action, FolderChangeAction::Added);
    assert_eq!(parsed_fni[1].action, FolderChangeAction::Modified);

    // Loop guard: NextEntryOffset = 4 (< 12)
    let mut bad_fni = fni.clone();
    bad_fni[0..4].copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        parse_file_notify_buffer(Path::new(r"C:\Watch"), &bad_fni, ts),
        Err(FsError::Parse(_))
    ));

    let same_time = Utc.with_ymd_and_hms(2026, 11, 23, 10, 0, 0).unwrap();
    let before = vec![FileEntry {
        path: PathBuf::from(r"C:\Watch\old.txt"),
        name: "old.txt".to_string(),
        extension: "txt".to_string(),
        size: 123,
        compressed_size: None,
        is_dir: false,
        attributes: FileAttributes::default(),
        timestamps: FileTimestamps {
            modified: Some(same_time),
            ..Default::default()
        },
        is_symlink: false,
    }];
    let after = vec![
        FileEntry {
            path: PathBuf::from(r"C:\Watch\new.txt"),
            name: "new.txt".to_string(),
            extension: "txt".to_string(),
            size: 123,
            compressed_size: None,
            is_dir: false,
            attributes: FileAttributes::default(),
            timestamps: FileTimestamps {
                modified: Some(same_time),
                ..Default::default()
            },
            is_symlink: false,
        },
        FileEntry {
            path: PathBuf::from(r"C:\Watch\extra.bin"),
            name: "extra.bin".to_string(),
            extension: "bin".to_string(),
            size: 50,
            compressed_size: None,
            is_dir: false,
            attributes: FileAttributes::default(),
            timestamps: FileTimestamps::default(),
            is_symlink: false,
        },
    ];
    let diff = FolderSnapshot::diff(&before, &after, ts);
    assert!(
        diff.iter()
            .any(|d| d.action == FolderChangeAction::RenamedOld && d.path == "old.txt")
    );
    assert!(
        diff.iter()
            .any(|d| d.action == FolderChangeAction::RenamedNew && d.path == "new.txt")
    );
    assert!(
        diff.iter()
            .any(|d| d.action == FolderChangeAction::Added && d.path == "extra.bin")
    );

    // 3. MountedDevices (12B MBR, 24B DMIO:ID:, UTF-16LE, RawHex)
    let mut mbr = Vec::new();
    mbr.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    mbr.extend_from_slice(&1_048_576u64.to_le_bytes());
    assert_eq!(
        parse_mounted_device_value(&mbr),
        MountedDeviceTarget::MbrPartition {
            disk_signature: 0x1A2B_3C4D,
            partition_offset: 1_048_576,
        }
    );
    let mut gpt = b"DMIO:ID:".to_vec();
    gpt.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    assert!(matches!(
        parse_mounted_device_value(&gpt),
        MountedDeviceTarget::GptPartitionGuid { .. }
    ));
    let mut dev_u16 = Vec::new();
    for u in r"\??\USBSTOR#Disk&Ven_Test".encode_utf16().chain(std::iter::once(0)) {
        dev_u16.extend_from_slice(&u.to_le_bytes());
    }
    assert!(matches!(
        parse_mounted_device_value(&dev_u16),
        MountedDeviceTarget::DevicePath(_)
    ));
    assert!(matches!(
        parse_mounted_device_value(&[1, 2, 3, 4, 5]),
        MountedDeviceTarget::RawHex(_)
    ));

    // 4. DISK_PERFORMANCE (88B & 84B + truncated 83B)
    let mut dp = vec![0u8; 88];
    dp[0..8].copy_from_slice(&102_400i64.to_le_bytes());
    dp[8..16].copy_from_slice(&51_200i64.to_le_bytes());
    dp[16..24].copy_from_slice(&250_000i64.to_le_bytes()); // 25ms
    dp[24..32].copy_from_slice(&100_000i64.to_le_bytes()); // 10ms
    dp[40..44].copy_from_slice(&12u32.to_le_bytes());
    dp[44..48].copy_from_slice(&6u32.to_le_bytes());
    dp[48..52].copy_from_slice(&2u32.to_le_bytes());
    dp[64..68].copy_from_slice(&0u32.to_le_bytes());
    for (i, u) in "PartMgr ".encode_utf16().take(8).enumerate() {
        dp[68 + i * 2..70 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    let rec88 = parse_disk_performance(r"\\.\PhysicalDrive0", &dp).unwrap();
    assert_eq!(rec88.storage_manager, "PartMgr");
    assert_eq!(rec88.read_time_ms, 25);
    assert_eq!(rec88.queue_depth, 2);
    assert!(parse_disk_performance(r"\\.\PhysicalDrive0", &dp[..84]).is_ok());
    assert!(matches!(
        parse_disk_performance(r"\\.\PhysicalDrive0", &dp[..83]),
        Err(FsError::Parse(_))
    ));

    // 5. 1SPS SERIALIZEDPROPERTYSTORAGE parser
    let mut sps = Vec::new();
    let title_u16: Vec<u16> = "Quarterly Report".encode_utf16().chain(std::iter::once(0)).collect();
    let mut prop_entry = Vec::new();
    let val_size = 13 + 4 + title_u16.len() * 2;
    prop_entry.extend_from_slice(&(val_size as u32).to_le_bytes());
    prop_entry.extend_from_slice(&2u32.to_le_bytes()); // PID 2 = System.Title
    prop_entry.push(0); // reserved
    prop_entry.extend_from_slice(&0x001Fu16.to_le_bytes()); // VT_LPWSTR
    prop_entry.extend_from_slice(&0u16.to_le_bytes()); // 2-byte padding before value payload
    prop_entry.extend_from_slice(&(title_u16.len() as u32).to_le_bytes());
    for u in title_u16 {
        prop_entry.extend_from_slice(&u.to_le_bytes());
    }
    let total_sps_size = 24 + prop_entry.len() + 4;
    sps.extend_from_slice(&(total_sps_size as u32).to_le_bytes());
    sps.extend_from_slice(b"1SPS");
    // {F29F85E0-4FF9-1068-AB91-08002B27B3D9} in LE
    sps.extend_from_slice(&[
        0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
    ]);
    sps.extend_from_slice(&prop_entry);
    sps.extend_from_slice(&0u32.to_le_bytes());

    let blocks = parse_serialized_property_storage(&sps).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].entries.len(), 1);
    assert_eq!(blocks[0].entries[0].canonical_name, "System.Title");
    assert_eq!(blocks[0].entries[0].value, "Quarterly Report");
}

#[test]
fn mcp_registry_exposes_all_11_tables_and_enforces_policy_gates_on_all_4_actions() {
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().to_path_buf();
    let outside = tempfile::tempdir().unwrap();

    let policy = PolicyContext {
        mode: PolicyMode::AllowMutating,
        dry_run: false,
        confirm_destructive: true,
        allowed_roots: vec![allowed.clone()],
        max_entries: None,
    };

    let backend = Arc::new(MockNtfsBackend::new());
    let cfg = NtfsToolsConfig {
        drive_letter: DriveLetterConfig::default(),
        disk_counters: DiskCountersConfig::default(),
        file_activity: FileActivityConfig {
            offline_events: Some(vec![]),
            ..Default::default()
        },
        folder_changes: FolderChangesConfig {
            watch_dir: allowed.clone(),
            policy: policy.clone(),
            offline_changes: Some(vec![]),
            ..Default::default()
        },
        file_access_error: FileAccessErrorConfig {
            offline_events: Some(vec![]),
            ..Default::default()
        },
        app_read_write: AppReadWriteConfig::default(),
        disk_smart: DiskSmartConfig {
            offline_records: Some(vec![]),
            ..Default::default()
        },
        alternate_stream: AlternateStreamConfig {
            target_paths: vec![allowed.clone()],
            policy: policy.clone(),
            ..Default::default()
        },
        ntfs_links: NtfsLinksConfig {
            target_paths: vec![allowed.clone()],
            policy: policy.clone(),
            ..Default::default()
        },
        property_system: PropertySystemConfig {
            file_paths: vec![allowed.join("doc.txt")],
            policy: policy.clone(),
            ..Default::default()
        },
        usn_journal: UsnJournalConfig {
            offline_records: Some(vec![]),
            ..Default::default()
        },
        action_policy: policy.clone(),
    };

    // 1. ReadOnlyOnly registry rejects all 4 mutating actions with -32003
    let mut ro_reg = McpServerRegistry::new(PolicyMode::ReadOnlyOnly);
    register_ntfs_tools_with_backend(&mut ro_reg, Arc::clone(&backend) as Arc<dyn NtfsBackend>, cfg.clone());

    let tools_val = ro_reg.list_tools();
    let tools_arr = tools_val.as_array().unwrap();
    let expected_tables = [
        "drive_letter_view",
        "disk_counters_view",
        "file_activity_watch",
        "folder_changes_view",
        "file_access_error_view",
        "app_read_write_counter",
        "disk_smart_view",
        "alternate_stream_view",
        "ntfs_links_view",
        "property_system_view",
        "usn_journal_view",
    ];
    for t in expected_tables {
        assert!(
            tools_arr.iter().any(|x| x["name"].as_str() == Some(t)),
            "missing table tool {t}"
        );
        let res = ro_reg.dispatch(t, &json!({}));
        assert!(res.is_ok(), "table tool {t} dispatch failed: {:?}", res.err());
    }

    let allowed_mp = allowed.join("mnt");
    let allowed_file = allowed.join("doc.txt");
    let vol_guid = r"\\?\Volume{11111111-2222-3333-4444-555555555555}\";

    for (cmd, args) in [
        (
            "drive_letter_assign",
            json!({"mount_point": allowed_mp.to_string_lossy(), "volume_guid": vol_guid, "confirm_destructive": true}),
        ),
        (
            "drive_letter_remove",
            json!({"mount_point": allowed_mp.to_string_lossy(), "confirm_destructive": true}),
        ),
        (
            "alternate_stream_delete",
            json!({"file_path": allowed_file.to_string_lossy(), "stream_name": "Zone.Identifier", "confirm_destructive": true}),
        ),
        (
            "property_system_set",
            json!({"file_path": allowed_file.to_string_lossy(), "canonical_name": "System.Title", "value": "New", "confirm_destructive": true}),
        ),
    ] {
        let err = ro_reg.dispatch(cmd, &args).unwrap_err();
        assert_eq!(err.code, -32003, "expected -32003 in ReadOnlyOnly for {cmd}");
    }

    // 2. AllowMutating without confirm_destructive rejects with -32003
    let mut rw_reg = McpServerRegistry::new(PolicyMode::AllowMutating);
    register_ntfs_tools_with_backend(&mut rw_reg, Arc::clone(&backend) as Arc<dyn NtfsBackend>, cfg);

    let err_no_confirm = rw_reg
        .dispatch(
            "alternate_stream_delete",
            &json!({"file_path": allowed_file.to_string_lossy(), "stream_name": "Zone.Identifier"}),
        )
        .unwrap_err();
    assert_eq!(err_no_confirm.code, -32003);

    // 3. Dry run preview works without mutating
    let dry: Value = rw_reg
        .dispatch(
            "alternate_stream_delete",
            &json!({"file_path": allowed_file.to_string_lossy(), "stream_name": "Zone.Identifier", "dry_run": true, "confirm_destructive": true}),
        )
        .unwrap();
    assert_eq!(dry["mode"].as_str(), Some("dry_run"));
    assert!(backend.deleted_ads.lock().unwrap().is_empty());

    // 4. PolicyContext::allowed_roots escape rejection (outside path + ADS escape)
    let outside_file = outside.path().join("secret.txt");
    let escape_err = rw_reg
        .dispatch(
            "alternate_stream_delete",
            &json!({"file_path": outside_file.to_string_lossy(), "stream_name": "Zone.Identifier", "confirm_destructive": true}),
        )
        .unwrap_err();
    assert_eq!(escape_err.code, -32003);

    let prop_escape = rw_reg
        .dispatch(
            "property_system_set",
            &json!({"file_path": outside_file.to_string_lossy(), "canonical_name": "System.Title", "value": "X", "confirm_destructive": true}),
        )
        .unwrap_err();
    assert_eq!(prop_escape.code, -32003);

    let mount_escape = rw_reg
        .dispatch(
            "drive_letter_assign",
            &json!({"mount_point": outside.path().join("mnt").to_string_lossy(), "volume_guid": vol_guid, "confirm_destructive": true}),
        )
        .unwrap_err();
    assert_eq!(mount_escape.code, -32003);

    // Refuses deleting default ::$DATA stream
    let default_stream_err = rw_reg
        .dispatch(
            "alternate_stream_delete",
            &json!({"file_path": allowed_file.to_string_lossy(), "stream_name": "::$DATA", "confirm_destructive": true}),
        )
        .unwrap_err();
    assert_eq!(default_stream_err.code, -32003);

    // 5. Confirmed execution succeeds via mock backend
    let _ = rw_reg
        .dispatch(
            "drive_letter_assign",
            &json!({"mount_point": allowed_mp.to_string_lossy(), "volume_guid": vol_guid, "confirm_destructive": true}),
        )
        .unwrap();
    assert_eq!(backend.mounted.lock().unwrap().len(), 1);

    let _ = rw_reg
        .dispatch(
            "drive_letter_remove",
            &json!({"mount_point": allowed_mp.to_string_lossy(), "confirm_destructive": true}),
        )
        .unwrap();
    assert!(backend.mounted.lock().unwrap().is_empty());

    let _ = rw_reg
        .dispatch(
            "alternate_stream_delete",
            &json!({"file_path": allowed_file.to_string_lossy(), "stream_name": "Zone.Identifier", "confirm_destructive": true}),
        )
        .unwrap();
    assert_eq!(backend.deleted_ads.lock().unwrap().len(), 1);

    let _ = rw_reg
        .dispatch(
            "property_system_set",
            &json!({"file_path": allowed_file.to_string_lossy(), "canonical_name": "System.Title", "value": "Verified", "confirm_destructive": true}),
        )
        .unwrap();
    assert_eq!(backend.set_props.lock().unwrap().len(), 1);

    // Also verify direct ActionCommand::execute rejects missing confirm_destructive when called directly
    let direct_del =
        AlternateStreamDeleteAction::new(Arc::clone(&backend) as Arc<dyn NtfsBackend>).with_policy(PolicyContext {
            mode: PolicyMode::AllowMutating,
            dry_run: false,
            confirm_destructive: false,
            allowed_roots: vec![allowed.clone()],
            max_entries: None,
        });
    assert!(
        direct_del
            .execute(
                &json!({"file_path": allowed_file.to_string_lossy(), "stream_name": "Zone.Identifier"}),
                false
            )
            .is_err()
    );
    let _ = DriveLetterAssignAction::new(Arc::clone(&backend) as Arc<dyn NtfsBackend>);
    let _ = DriveLetterRemoveAction::new(Arc::clone(&backend) as Arc<dyn NtfsBackend>);
    let _ = PropertySystemSetAction::new(backend);
}

#[cfg(windows)]
#[test]
fn live_win32_unprivileged_and_tempdir_smoke_tests() {
    let backend = LiveNtfsBackend;

    // 1. Live drive letter enumeration always succeeds for logical drives on Windows
    let drives = backend.list_drive_letters().unwrap();
    assert!(!drives.is_empty());

    // 2. Live process I/O counter enumerates processes cleanly (handles protected PIDs gracefully)
    let procs = backend.snapshot_process_io().unwrap();
    assert!(!procs.is_empty());

    // 3. Live folder change watch bounded timeout exits cleanly without hanging
    let tmp = tempfile::tempdir().unwrap();
    let changes = backend.watch_folder_changes(tmp.path(), false, 40, 64).unwrap();
    assert!(changes.is_empty());

    // 4. Live alternate data streams + delete on tempdir (NTFS host)
    let host_file = tmp.path().join("doc.txt");
    std::fs::write(&host_file, b"primary content").unwrap();
    let ads_path = format!("{}:Zone.Identifier", host_file.display());
    if std::fs::write(&ads_path, b"[ZoneTransfer]\r\nZoneId=3\r\n").is_ok() {
        let streams = backend
            .enumerate_ads(std::slice::from_ref(&host_file), false, false)
            .unwrap();
        assert!(streams.iter().any(|s| s.stream_name.contains("Zone.Identifier")));
        backend.delete_ads(&ads_path).unwrap();
        let after = backend
            .enumerate_ads(std::slice::from_ref(&host_file), false, false)
            .unwrap();
        assert!(!after.iter().any(|s| s.stream_name.contains("Zone.Identifier")));
    }

    // 5. Live property system read on tempdir file
    let props = backend.read_file_properties(&tmp.path().join("doc.txt"));
    assert!(props.is_ok() || matches!(props, Err(FsError::PermissionDenied(_) | FsError::Unsupported(_))));

    // 6. Live hardlinks & NTFS junction inspection
    let link_orig = tmp.path().join("orig.txt");
    let link_sib = tmp.path().join("sibling.txt");
    std::fs::write(&link_orig, b"hardlink data").unwrap();
    if std::fs::hard_link(&link_orig, &link_sib).is_ok() {
        let links = backend.inspect_ntfs_links(&[link_orig], false, true).unwrap();
        assert!(
            links
                .iter()
                .any(|l| l.link_type == "HardLink" && l.hard_link_count >= 2)
        );
    }

    let outside_dir = tempfile::tempdir().unwrap();
    let junc_path = tmp.path().join("junc");
    let mklink_ok = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junc_path)
        .arg(outside_dir.path())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if mklink_ok {
        let links = backend
            .inspect_ntfs_links(std::slice::from_ref(&junc_path), false, false)
            .unwrap();
        assert!(links.iter().any(|l| l.link_type == "Junction" && l.target_exists));

        // Verify host:stream ADS escape through a junction is blocked by PolicyContext
        let escape_host = junc_path.join("outside.txt");
        let policy_del =
            AlternateStreamDeleteAction::new(Arc::new(MockNtfsBackend::new())).with_policy(PolicyContext {
                mode: PolicyMode::AllowMutating,
                dry_run: false,
                confirm_destructive: true,
                allowed_roots: vec![tmp.path().to_path_buf()],
                max_entries: None,
            });
        let res = policy_del.execute(
            &json!({
                "file_path": escape_host.to_string_lossy(),
                "stream_name": "Zone.Identifier",
                "confirm_destructive": true,
            }),
            false,
        );
        assert!(res.is_err());
    }

    // 7. Privileged paths (ETW, SMART, DiskCounters, USN) must degrade gracefully without panicking or hanging
    let _ = backend.capture_kernel_file_events(60, 128, false);
    let _ = backend.query_disk_counters(&[]);
    let _ = backend.query_disk_smart(&[0]);
    let _ = backend.read_usn_journal(r"\\.\C:", 0, u32::MAX, 32, UsnQueryMode::Journal);
}

#[test]
fn propsys_1sps_rejects_corrupt_magic_and_truncated_entries() {
    let mut bad_magic = vec![0u8; 32];
    bad_magic[0..4].copy_from_slice(&32u32.to_le_bytes());
    bad_magic[4..8].copy_from_slice(b"BAD!");
    assert!(matches!(
        parse_serialized_property_storage(&bad_magic),
        Err(FsError::Parse(_))
    ));

    let mut bad_val_sz = vec![0u8; 32];
    bad_val_sz[0..4].copy_from_slice(&32u32.to_le_bytes());
    bad_val_sz[4..8].copy_from_slice(b"1SPS");
    bad_val_sz[24..28].copy_from_slice(&4u32.to_le_bytes()); // < 13
    assert!(matches!(
        parse_serialized_property_storage(&bad_val_sz),
        Err(FsError::Parse(_))
    ));
}
