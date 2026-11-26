#![deny(unsafe_op_in_unsafe_fn)]

use crate::app_io::{IoCounters, ProcessIoSnapshot};
use crate::bin_util::{decode_utf16le_nul, read_u32_le};
use crate::disk_counters::{DiskPerformanceRecord, parse_disk_performance};
use crate::disk_smart::{
    DiskSmartRecord, ata_page_to_records, nvme_log_to_records, parse_ata_smart_attributes, parse_nvme_health_log,
};
use crate::drive_letter::{DriveLetterEntry, MountedDeviceTarget, parse_mounted_device_value};
use crate::etw_file::KernelFileRawEvent;
use crate::folder_changes::{FolderChangeEntry, parse_file_notify_buffer};
use crate::mft_ads::AdsEntry;
use crate::property_system::FilePropertyEntry;
use crate::reparse::{NtfsLinkEntry, parse_reparse_data_buffer};
use crate::usn_journal::{UsnQueryMode, UsnRecord, parse_usn_ioctl_buffer};
use chrono::{DateTime, Utc};
use fs2rust_core::{FsError, windows_filetime_to_datetime};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::io::Read;
use std::mem::{ManuallyDrop, size_of, zeroed};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_INVALID_FUNCTION,
    ERROR_INVALID_PARAMETER, ERROR_JOURNAL_NOT_ACTIVE, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, ERROR_NO_MORE_ITEMS,
    ERROR_NOT_A_REPARSE_POINT, ERROR_NOT_READY, ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND, ERROR_PRIVILEGE_NOT_HELD,
    ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE, HANDLE, PROPERTYKEY, WAIT_OBJECT_0, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DeleteFileW, DeleteVolumeMountPointW, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FindClose, FindFirstFileNameW, FindFirstStreamW, FindNextFileNameW, FindNextStreamW, FindStreamInfoStandard,
    GetDiskFreeSpaceExW, GetDriveTypeW, GetFileInformationByHandle, GetLogicalDrives, GetVolumeInformationW,
    GetVolumeNameForVolumeMountPointW, OPEN_EXISTING, QueryDosDeviceW, ReadDirectoryChangesW, SetVolumeMountPointW,
    WIN32_FIND_STREAM_DATA,
};
use windows::Win32::System::Com::StructuredStorage::{
    PROPVARIANT, PROPVARIANT_0_0, PROPVARIANT_0_0_0, PropVariantClear, PropVariantToStringAlloc,
};
use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemAlloc, CoTaskMemFree, CoUninitialize, IBindCtx,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, PropertyStruct, StartTraceW,
    TDH_INTYPE_ANSISTRING, TDH_INTYPE_FILETIME, TDH_INTYPE_HEXINT32, TDH_INTYPE_HEXINT64, TDH_INTYPE_INT8,
    TDH_INTYPE_INT16, TDH_INTYPE_INT32, TDH_INTYPE_INT64, TDH_INTYPE_POINTER, TDH_INTYPE_SIZET, TDH_INTYPE_UINT8,
    TDH_INTYPE_UINT16, TDH_INTYPE_UINT32, TDH_INTYPE_UINT64, TDH_INTYPE_UNICODESTRING, TRACE_EVENT_INFO,
    TdhGetEventInformation, TdhGetProperty, TdhGetPropertySize,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::IO::{CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Ioctl::{
    DISK_PERFORMANCE, FSCTL_ENUM_USN_DATA, FSCTL_GET_REPARSE_POINT, FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL,
    IOCTL_DISK_PERFORMANCE, IOCTL_STORAGE_QUERY_PROPERTY, MFT_ENUM_DATA_V0, PropertyStandardQuery, ProtocolTypeNvme,
    READ_ATTRIBUTES, READ_THRESHOLDS, READ_USN_JOURNAL_DATA_V0, SENDCMDINPARAMS, SENDCMDOUTPARAMS, SMART_CMD,
    SMART_CYL_HI, SMART_CYL_LOW, SMART_RCV_DRIVE_DATA, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY,
    STORAGE_PROTOCOL_DATA_DESCRIPTOR, STORAGE_PROTOCOL_SPECIFIC_DATA, StorageDeviceProperty,
    StorageDeviceProtocolSpecificProperty, USN_JOURNAL_DATA_V0,
};
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegEnumValueW, RegOpenKeyExW};
use windows::Win32::System::Threading::{
    CreateEventW, GetProcessIoCounters, IO_COUNTERS, OpenProcess, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, WaitForSingleObject,
};
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::{
    GPS_DEFAULT, GPS_READWRITE, IPropertyDescription, IPropertyStore, PDFF_DEFAULT, PSCoerceToCanonicalValue,
    PSGetNameFromPropertyKey, PSGetPropertyDescription, PSGetPropertyKeyFromName, SHGetPropertyStoreFromParsingName,
};
use windows::core::{GUID, HSTRING, Interface, PCWSTR, PWSTR};

const KERNEL_FILE_GUID: GUID = GUID::from_u128(0xEDD08927_9CC4_4E65_B970_C2560FB5C289);
const RPC_E_CHANGED_MODE_HRESULT: i32 = 0x8001_0106u32 as i32;
const E_ACCESSDENIED_HRESULT: i32 = 0x8007_0005u32 as i32;
const STG_E_ACCESSDENIED_HRESULT: i32 = 0x8003_0005u32 as i32;

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct OwnedFindHandle(HANDLE);

impl Drop for OwnedFindHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            unsafe {
                let _ = FindClose(self.0);
            }
        }
    }
}

struct OwnedHKey(HKEY);

impl Drop for OwnedHKey {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

struct ComApartmentGuard {
    should_uninit: bool,
}

impl ComApartmentGuard {
    fn init() -> Result<Self, FsError> {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_ok() {
            Ok(Self { should_uninit: true })
        } else if hr.0 == RPC_E_CHANGED_MODE_HRESULT {
            Ok(Self { should_uninit: false })
        } else {
            Err(FsError::Unsupported(format!(
                "CoInitializeEx failed: HRESULT 0x{:08X}",
                hr.0 as u32
            )))
        }
    }
}

impl Drop for ComApartmentGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

struct OwnedCoTaskPwstr(PWSTR);

impl OwnedCoTaskPwstr {
    fn to_string_lossy(&self) -> String {
        if self.0.is_null() {
            return String::new();
        }
        unsafe { self.0.to_string().unwrap_or_default() }
    }
}

impl Drop for OwnedCoTaskPwstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CoTaskMemFree(Some(self.0.0.cast::<c_void>()));
            }
        }
    }
}

struct OwnedPropVariant(PROPVARIANT);

impl Drop for OwnedPropVariant {
    fn drop(&mut self) {
        unsafe {
            let _ = PropVariantClear(&mut self.0);
        }
    }
}

fn map_win32_err(op: &str, err: WIN32_ERROR) -> FsError {
    if err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_SHARING_VIOLATION {
        FsError::PermissionDenied(format!("{op} failed with Win32 code {}", err.0))
    } else if err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND || err == ERROR_JOURNAL_NOT_ACTIVE {
        FsError::SourceUnavailable(format!("{op} failed with Win32 code {}", err.0))
    } else if err == ERROR_INVALID_FUNCTION || err == ERROR_NOT_SUPPORTED {
        FsError::Unsupported(format!("{op} unsupported (Win32 code {})", err.0))
    } else if err == ERROR_INVALID_PARAMETER {
        FsError::InvalidArgument(format!("{op} invalid parameter (Win32 code {})", err.0))
    } else {
        FsError::Io(std::io::Error::from_raw_os_error(err.0 as i32))
    }
}

fn map_windows_core_err(op: &str, err: &windows::core::Error) -> FsError {
    let code = err.code().0;
    let win32_code = (code as u32) & 0xFFFF;
    if code == E_ACCESSDENIED_HRESULT
        || code == STG_E_ACCESSDENIED_HRESULT
        || win32_code == ERROR_ACCESS_DENIED.0
        || win32_code == ERROR_PRIVILEGE_NOT_HELD.0
    {
        FsError::PermissionDenied(format!("{op}: {err}"))
    } else if win32_code == ERROR_FILE_NOT_FOUND.0
        || win32_code == ERROR_PATH_NOT_FOUND.0
        || win32_code == ERROR_JOURNAL_NOT_ACTIVE.0
    {
        FsError::SourceUnavailable(format!("{op}: {err}"))
    } else if win32_code == ERROR_INVALID_FUNCTION.0 || win32_code == ERROR_NOT_SUPPORTED.0 {
        FsError::Unsupported(format!("{op}: {err}"))
    } else {
        FsError::Io(std::io::Error::from_raw_os_error(code))
    }
}

fn wide_buf_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn read_mounted_devices_registry() -> HashMap<String, (Vec<u8>, MountedDeviceTarget)> {
    let mut map = HashMap::new();
    let subkey = HSTRING::from(r"SYSTEM\MountedDevices");
    let mut hkey = HKEY::default();
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &subkey, Some(0), KEY_READ, &mut hkey) };
    if status != WIN32_ERROR(0) {
        return map;
    }
    let _guard = OwnedHKey(hkey);

    let mut idx = 0u32;
    loop {
        let mut name_buf = [0u16; 512];
        let mut name_len = name_buf.len() as u32;
        let mut val_type = 0u32;
        let mut data_buf = vec![0u8; 1024];
        let mut data_len = data_buf.len() as u32;
        let err = unsafe {
            RegEnumValueW(
                hkey,
                idx,
                Some(PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut val_type),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if err == ERROR_NO_MORE_ITEMS {
            break;
        }
        if err == WIN32_ERROR(0) {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            data_buf.truncate(data_len as usize);
            let parsed = parse_mounted_device_value(&data_buf);
            map.insert(name, (data_buf, parsed));
        }
        idx += 1;
    }
    map
}

pub fn list_drive_letters() -> Result<Vec<DriveLetterEntry>, FsError> {
    let reg_map = read_mounted_devices_registry();
    let mask = unsafe { GetLogicalDrives() };
    let mut entries = Vec::new();

    for bit in 0..26u8 {
        if (mask & (1u32 << bit)) == 0 {
            continue;
        }
        let letter = (b'A' + bit) as char;
        let root_str = format!(r"{letter}:\");
        let root_w = HSTRING::from(&root_str);
        let drive_type_code = unsafe { GetDriveTypeW(&root_w) };
        let drive_type = match drive_type_code {
            2 => "Removable",
            3 => "Fixed",
            4 => "Remote",
            5 => "CDRom",
            6 => "RamDisk",
            1 => "NoRootDir",
            _ => "Unknown",
        }
        .to_string();

        let dos_name_w = HSTRING::from(format!("{letter}:"));
        let mut dos_buf = [0u16; 512];
        let dos_len = unsafe { QueryDosDeviceW(&dos_name_w, Some(&mut dos_buf)) };
        let dos_target = if dos_len > 0 {
            wide_buf_to_string(&dos_buf[..dos_len as usize])
        } else {
            String::new()
        };

        let mut guid_buf = [0u16; 128];
        let volume_guid = if unsafe { GetVolumeNameForVolumeMountPointW(&root_w, &mut guid_buf) }.is_ok() {
            wide_buf_to_string(&guid_buf)
        } else {
            String::new()
        };

        let mut label_buf = [0u16; 260];
        let mut fs_buf = [0u16; 128];
        let mut serial_raw = 0u32;
        let vol_res = unsafe {
            GetVolumeInformationW(
                &root_w,
                Some(&mut label_buf),
                Some(&mut serial_raw),
                None,
                None,
                Some(&mut fs_buf),
            )
        };

        let (connected, volume_label, filesystem, serial_number) = match vol_res {
            Ok(()) => (
                true,
                wide_buf_to_string(&label_buf),
                wide_buf_to_string(&fs_buf),
                format!("{:04X}-{:04X}", serial_raw >> 16, serial_raw & 0xFFFF),
            ),
            Err(e) => {
                let is_not_ready = ((e.code().0 as u32) & 0xFFFF) == ERROR_NOT_READY.0;
                (
                    !is_not_ready && drive_type_code != 5 && drive_type_code != 2,
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }
        };

        let mut total_bytes_val = 0u64;
        let mut free_bytes_val = 0u64;
        let (total_size, free_space) = if connected
            && unsafe { GetDiskFreeSpaceExW(&root_w, None, Some(&mut total_bytes_val), Some(&mut free_bytes_val)) }
                .is_ok()
        {
            (Some(total_bytes_val), Some(free_bytes_val))
        } else {
            (None, None)
        };

        let reg_key = format!(r"\DosDevices\{letter}:");
        let reg_target = reg_map.get(&reg_key).map(|(_, t)| t.clone());
        let partition_scheme = reg_target
            .as_ref()
            .map(|t| t.scheme_name().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let device_target = if !dos_target.is_empty() {
            dos_target
        } else {
            reg_target
                .as_ref()
                .map(MountedDeviceTarget::display_target)
                .unwrap_or_default()
        };

        entries.push(DriveLetterEntry {
            drive_letter: root_str,
            drive_type,
            volume_guid,
            volume_label,
            filesystem,
            serial_number,
            total_size,
            free_space,
            device_target,
            partition_scheme,
            connected,
            mounted_device_target: reg_target,
        });
    }

    Ok(entries)
}

pub fn set_volume_mount_point(mount_point: &str, volume_guid: &str) -> Result<(), FsError> {
    let mp_w = HSTRING::from(mount_point);
    let vg_w = HSTRING::from(volume_guid);
    unsafe { SetVolumeMountPointW(&mp_w, &vg_w) }.map_err(|e| map_windows_core_err("SetVolumeMountPointW", &e))
}

pub fn delete_volume_mount_point(mount_point: &str) -> Result<(), FsError> {
    let mp_w = HSTRING::from(mount_point);
    unsafe { DeleteVolumeMountPointW(&mp_w) }.map_err(|e| map_windows_core_err("DeleteVolumeMountPointW", &e))
}

pub fn query_disk_counters(device_paths: &[String]) -> Result<Vec<DiskPerformanceRecord>, FsError> {
    let targets: Vec<String> = if device_paths.is_empty() {
        (0..16u32).map(|i| format!(r"\\.\PhysicalDrive{i}")).collect()
    } else {
        device_paths.to_vec()
    };

    let mut out = Vec::new();
    let mut saw_access_denied = false;
    let mut saw_disabled = false;

    for dev in targets {
        let dev_w = HSTRING::from(&dev);
        let handle_res = unsafe {
            CreateFileW(
                &dev_w,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };
        let handle = match handle_res {
            Ok(h) => OwnedHandle(h),
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == ERROR_ACCESS_DENIED.0 {
                    saw_access_denied = true;
                }
                continue;
            }
        };

        let mut buf = [0u8; size_of::<DISK_PERFORMANCE>()];
        let mut bytes_ret = 0u32;
        let io_res = unsafe {
            DeviceIoControl(
                handle.0,
                IOCTL_DISK_PERFORMANCE,
                None,
                0,
                Some(buf.as_mut_ptr().cast()),
                buf.len() as u32,
                Some(&mut bytes_ret),
                None,
            )
        };
        match io_res {
            Ok(()) => {
                if let Ok(rec) = parse_disk_performance(&dev, &buf[..bytes_ret as usize]) {
                    out.push(rec);
                }
            }
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == ERROR_ACCESS_DENIED.0 {
                    saw_access_denied = true;
                } else if code == ERROR_INVALID_FUNCTION.0 || code == ERROR_NOT_SUPPORTED.0 {
                    saw_disabled = true;
                }
            }
        }
    }

    if out.is_empty() {
        if saw_access_denied {
            return Err(FsError::PermissionDenied(
                "IOCTL_DISK_PERFORMANCE denied; run elevated as Administrator".to_string(),
            ));
        }
        if saw_disabled {
            return Err(FsError::SourceUnavailable(
                "disk performance counters disabled (run 'diskperf -y' elevated to enable)".to_string(),
            ));
        }
    }
    Ok(out)
}

#[derive(Default)]
struct EtwFileSink {
    stop_flag: AtomicBool,
    max_events: usize,
    events: Mutex<Vec<KernelFileRawEvent>>,
}

unsafe fn read_tdh_str_at(buf: &[u8], offset: u32) -> String {
    let off = offset as usize;
    if offset == 0 || off >= buf.len() {
        return String::new();
    }
    decode_utf16le_nul(&buf[off..])
}

unsafe fn extract_kernel_file_tdh(
    rec: &EVENT_RECORD,
    event_id: u16,
    pid: u32,
    timestamp: DateTime<Utc>,
) -> KernelFileRawEvent {
    let mut irp_ptr = 0u64;
    let mut file_object = 0u64;
    let mut file_key = 0u64;
    let mut io_size = 0u32;
    let mut nt_status = 0u32;
    let mut io_flags = 0u32;
    let mut file_path = String::new();

    unsafe {
        let mut info_sz = 0u32;
        let st = TdhGetEventInformation(rec, None, None, &mut info_sz);
        if info_sz > 0 && (st == 0 || st == 122) {
            let mut buf = vec![0u8; info_sz as usize];
            let info_ptr = buf.as_mut_ptr().cast::<TRACE_EVENT_INFO>();
            if TdhGetEventInformation(rec, None, Some(info_ptr), &mut info_sz) == 0 {
                let info = &*info_ptr;
                let count = (info.TopLevelPropertyCount as usize).min(64);
                let prop_arr = info.EventPropertyInfoArray.as_ptr();

                for i in 0..count {
                    let epi = &*prop_arr.add(i);
                    if (epi.Flags.0 & PropertyStruct.0) != 0 {
                        continue;
                    }
                    let name_off = epi.NameOffset as usize;
                    if name_off >= buf.len() {
                        continue;
                    }
                    let name = read_tdh_str_at(&buf, epi.NameOffset);
                    if name.is_empty() {
                        continue;
                    }
                    let name_ptr = buf.as_ptr().add(name_off).cast::<u16>();
                    let desc = windows::Win32::System::Diagnostics::Etw::PROPERTY_DATA_DESCRIPTOR {
                        PropertyName: name_ptr as u64,
                        ArrayIndex: u32::MAX,
                        Reserved: 0,
                    };
                    let mut prop_sz = 0u32;
                    if TdhGetPropertySize(rec, None, &[desc], &mut prop_sz) != 0 || prop_sz == 0 || prop_sz > 65_536 {
                        continue;
                    }
                    let mut pbuf = vec![0u8; prop_sz as usize];
                    if TdhGetProperty(rec, None, &[desc], &mut pbuf) != 0 {
                        continue;
                    }
                    let in_type = i32::from(epi.Anonymous1.nonStructType.InType);
                    let as_u64 = |b: &[u8]| -> Option<u64> {
                        if in_type == TDH_INTYPE_UINT8.0 || in_type == TDH_INTYPE_INT8.0 {
                            b.first().copied().map(u64::from)
                        } else if (in_type == TDH_INTYPE_UINT16.0 || in_type == TDH_INTYPE_INT16.0) && b.len() >= 2 {
                            Some(u64::from(u16::from_le_bytes([b[0], b[1]])))
                        } else if (in_type == TDH_INTYPE_UINT32.0
                            || in_type == TDH_INTYPE_INT32.0
                            || in_type == TDH_INTYPE_HEXINT32.0)
                            && b.len() >= 4
                        {
                            read_u32_le(b, 0).ok().map(u64::from)
                        } else if (in_type == TDH_INTYPE_UINT64.0
                            || in_type == TDH_INTYPE_INT64.0
                            || in_type == TDH_INTYPE_HEXINT64.0
                            || in_type == TDH_INTYPE_FILETIME.0)
                            && b.len() >= 8
                        {
                            Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                        } else if in_type == TDH_INTYPE_POINTER.0 || in_type == TDH_INTYPE_SIZET.0 {
                            if b.len() >= 8 {
                                Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                            } else if b.len() >= 4 {
                                read_u32_le(b, 0).ok().map(u64::from)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                    if in_type == TDH_INTYPE_UNICODESTRING.0 {
                        let s = decode_utf16le_nul(&pbuf);
                        if matches!(name.as_str(), "FileName" | "OpenPath" | "FilePath" | "TargetName")
                            && file_path.is_empty()
                        {
                            file_path = s;
                        }
                    } else if in_type == TDH_INTYPE_ANSISTRING.0 {
                        let end = pbuf.iter().position(|&b| b == 0).unwrap_or(pbuf.len());
                        let s = String::from_utf8_lossy(&pbuf[..end]).to_string();
                        if matches!(name.as_str(), "FileName" | "OpenPath" | "FilePath" | "TargetName")
                            && file_path.is_empty()
                        {
                            file_path = s;
                        }
                    } else if let Some(val) = as_u64(&pbuf) {
                        match name.as_str() {
                            "IrpPtr" | "Irp" => irp_ptr = val,
                            "FileObject" => file_object = val,
                            "FileKey" => file_key = val,
                            "IoSize" | "TransferSize" => io_size = val.min(u64::from(u32::MAX)) as u32,
                            "Status" | "NtStatus" => nt_status = val as u32,
                            "IoFlags" | "Flags" => io_flags = val as u32,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    KernelFileRawEvent {
        event_id,
        pid,
        tid: rec.EventHeader.ThreadId,
        timestamp,
        irp_ptr,
        file_object,
        file_key,
        io_size,
        nt_status,
        io_flags,
        file_path,
        process_name: String::new(),
    }
}

unsafe extern "system" fn etw_buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    let lf = unsafe { &*logfile };
    if lf.Context.is_null() {
        return 0;
    }
    let sink = unsafe { &*(lf.Context.cast::<EtwFileSink>()) };
    u32::from(!sink.stop_flag.load(Ordering::Acquire))
}

unsafe extern "system" fn etw_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = unsafe { &*record };
    if rec.UserContext.is_null() {
        return;
    }
    let sink = unsafe { &*(rec.UserContext.cast::<EtwFileSink>()) };
    if sink.stop_flag.load(Ordering::Acquire) {
        return;
    }
    let pid = rec.EventHeader.ProcessId;
    let event_id = rec.EventHeader.EventDescriptor.Id;
    let ts_raw = rec.EventHeader.TimeStamp;
    let timestamp = u64::try_from(ts_raw)
        .ok()
        .and_then(windows_filetime_to_datetime)
        .unwrap_or_else(Utc::now);

    let ev = unsafe { extract_kernel_file_tdh(rec, event_id, pid, timestamp) };
    if let Ok(mut guard) = sink.events.lock() {
        if guard.len() < sink.max_events {
            guard.push(ev);
        }
        if guard.len() >= sink.max_events {
            sink.stop_flag.store(true, Ordering::Release);
        }
    }
}

struct EtwSessionGuard {
    trace_handle: CONTROLTRACE_HANDLE,
    consumer_handle: Option<PROCESSTRACE_HANDLE>,
    name_w: Vec<u16>,
    prop_u64: Vec<u64>,
}

impl Drop for EtwSessionGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = EnableTraceEx2(
                self.trace_handle,
                &KERNEL_FILE_GUID,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER.0,
                0,
                0,
                0,
                0,
                None::<*const ENABLE_TRACE_PARAMETERS>,
            );
            let props = self.prop_u64.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
            let _ = ControlTraceW(
                self.trace_handle,
                PCWSTR(self.name_w.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
            if let Some(ch) = self.consumer_handle.take() {
                let _ = CloseTrace(ch);
            }
        }
    }
}

pub fn capture_kernel_file_events(
    duration_ms: u64,
    max_events: usize,
    include_op_end: bool,
) -> Result<Vec<KernelFileRawEvent>, FsError> {
    let session_name = format!("fs2rust-ntfs-kfile-{}", std::process::id());
    let name_w: Vec<u16> = session_name.encode_utf16().chain(std::iter::once(0)).collect();
    let prop_bytes = size_of::<EVENT_TRACE_PROPERTIES>() + name_w.len() * 2 + 128;
    let prop_words = prop_bytes.div_ceil(size_of::<u64>());
    let mut prop_u64 = vec![0u64; prop_words];
    let total_prop_bytes = prop_u64.len() * size_of::<u64>();

    let sink_ptr = Box::into_raw(Box::new(EtwFileSink {
        stop_flag: AtomicBool::new(false),
        max_events: max_events.clamp(1, 65_536),
        events: Mutex::new(Vec::new()),
    }));

    unsafe {
        let props = &mut *(prop_u64.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>());
        props.Wnode.BufferSize = total_prop_bytes as u32;
        props.Wnode.Flags = 0x0002_0000; // WNODE_FLAG_TRACED_GUID
        props.Wnode.ClientContext = 2; // UTC SystemTime / FILETIME
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.FlushTimer = 1;
        props.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name_w.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );

        let mut trace_handle = CONTROLTRACE_HANDLE::default();
        let err = StartTraceW(&mut trace_handle, PCWSTR(name_w.as_ptr()), props);
        if err != WIN32_ERROR(0) {
            drop(Box::from_raw(sink_ptr));
            if err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD {
                return Err(FsError::PermissionDenied(format!(
                    "StartTraceW('{session_name}') denied (Win32 {}); run as Administrator or join 'Performance Log Users'",
                    err.0
                )));
            }
            return Err(map_win32_err("StartTraceW", err));
        }

        let mut guard = EtwSessionGuard {
            trace_handle,
            consumer_handle: None,
            name_w: name_w.clone(),
            prop_u64,
        };

        let keywords = if include_op_end { 0x1F70u64 } else { 0x1F30u64 };
        let enable_err = EnableTraceEx2(
            trace_handle,
            &KERNEL_FILE_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            5, // TRACE_LEVEL_VERBOSE
            keywords,
            0,
            0,
            None::<*const ENABLE_TRACE_PARAMETERS>,
        );
        if enable_err != WIN32_ERROR(0) {
            drop(guard);
            drop(Box::from_raw(sink_ptr));
            return Err(map_win32_err("EnableTraceEx2(Kernel-File)", enable_err));
        }

        let mut log_name_w = name_w;
        let mut logfile: EVENT_TRACE_LOGFILEW = zeroed();
        logfile.LoggerName = PWSTR(log_name_w.as_mut_ptr());
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_record_callback);
        logfile.BufferCallback = Some(etw_buffer_callback);
        logfile.Context = sink_ptr.cast();

        let consumer = OpenTraceW(&mut logfile);
        if consumer.Value == u64::MAX {
            drop(guard);
            drop(Box::from_raw(sink_ptr));
            return Err(FsError::SourceUnavailable(format!(
                "OpenTraceW('{session_name}') failed"
            )));
        }
        guard.consumer_handle = Some(consumer);

        let wait_ms = duration_ms.clamp(50, 30_000);
        let sink_ref = &*sink_ptr;
        std::thread::scope(|s| {
            let worker = s.spawn(move || {
                let handles = [consumer];
                let _ = ProcessTrace(&handles, None, None);
            });

            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
            while std::time::Instant::now() < deadline && !sink_ref.stop_flag.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            sink_ref.stop_flag.store(true, Ordering::Release);
            let props_ptr = guard.prop_u64.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
            let _ = ControlTraceW(
                guard.trace_handle,
                PCWSTR(guard.name_w.as_ptr()),
                props_ptr,
                EVENT_TRACE_CONTROL_STOP,
            );
            if let Some(ch) = guard.consumer_handle.take() {
                let _ = CloseTrace(ch);
            }
            let _ = worker.join();
        });

        drop(guard);
        let sink = Box::from_raw(sink_ptr);
        let events = sink.events.into_inner().unwrap_or_default();
        Ok(events)
    }
}

pub fn watch_folder_changes(
    watch_dir: &Path,
    recursive: bool,
    duration_ms: u64,
    max_events: usize,
) -> Result<Vec<FolderChangeEntry>, FsError> {
    let dir_w = HSTRING::from(watch_dir.as_os_str());
    let h_dir = unsafe {
        CreateFileW(
            &dir_w,
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            None,
        )
    }
    .map_err(|e| map_windows_core_err("CreateFileW(watch_dir)", &e))?;
    let h_dir = OwnedHandle(h_dir);

    let event =
        unsafe { CreateEventW(None, true, false, None) }.map_err(|e| map_windows_core_err("CreateEventW", &e))?;
    let event = OwnedHandle(event);

    let mut buf = vec![0u8; 65_536];
    let mut all_entries = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(duration_ms.clamp(25, 30_000));
    let notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_ATTRIBUTES
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE;

    while all_entries.len() < max_events {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        overlapped.hEvent = event.0;

        let issued = unsafe {
            ReadDirectoryChangesW(
                h_dir.0,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                recursive,
                notify_filter,
                None,
                Some(&mut overlapped),
                None,
            )
        };
        if let Err(e) = issued {
            return Err(map_windows_core_err("ReadDirectoryChangesW", &e));
        }

        let wait_ms = remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32;
        let wait_res = unsafe { WaitForSingleObject(event.0, wait_ms) };
        if wait_res == WAIT_OBJECT_0 {
            let mut bytes_ret = 0u32;
            if let Err(e) = unsafe { GetOverlappedResult(h_dir.0, &overlapped, &mut bytes_ret, false) } {
                return Err(map_windows_core_err("GetOverlappedResult", &e));
            }
            if bytes_ret == 0 {
                tracing::warn!(
                    path = %watch_dir.display(),
                    "ReadDirectoryChangesW buffer overflow (ERROR_NOTIFY_ENUM_DIR)"
                );
                continue;
            }
            let parsed = parse_file_notify_buffer(watch_dir, &buf[..bytes_ret as usize], Utc::now())?;
            all_entries.extend(parsed);
        } else {
            // Timeout or error: cancel pending async I/O and await completion before dropping buf.
            let mut bytes_ret = 0u32;
            unsafe {
                let _ = CancelIoEx(h_dir.0, Some(&overlapped));
                let _ = GetOverlappedResult(h_dir.0, &overlapped, &mut bytes_ret, true);
            }
            if bytes_ret > 0
                && let Ok(parsed) = parse_file_notify_buffer(watch_dir, &buf[..bytes_ret as usize], Utc::now())
            {
                all_entries.extend(parsed);
            }
            break;
        }
    }

    all_entries.truncate(max_events);
    Ok(all_entries)
}

pub fn list_process_names() -> Result<HashMap<u32, String>, FsError> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| map_windows_core_err("CreateToolhelp32Snapshot", &e))?;
    let snap = OwnedHandle(snap);

    let mut pe = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { zeroed() }
    };
    let mut map = HashMap::new();
    if unsafe { Process32FirstW(snap.0, &mut pe) }.is_ok() {
        loop {
            let name = wide_buf_to_string(&pe.szExeFile);
            map.insert(pe.th32ProcessID, name);
            if unsafe { Process32NextW(snap.0, &mut pe) }.is_err() {
                break;
            }
        }
    }
    Ok(map)
}

pub fn snapshot_process_io() -> Result<Vec<ProcessIoSnapshot>, FsError> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| map_windows_core_err("CreateToolhelp32Snapshot", &e))?;
    let snap = OwnedHandle(snap);

    let mut pe = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { zeroed() }
    };
    let mut out = Vec::new();
    if unsafe { Process32FirstW(snap.0, &mut pe) }.is_ok() {
        loop {
            let pid = pe.th32ProcessID;
            let process_name = wide_buf_to_string(&pe.szExeFile);
            let mut process_path = String::new();
            let mut counters = IoCounters::default();
            let mut access_denied = false;

            if pid != 0 {
                match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
                    Ok(h_proc) => {
                        let h_proc = OwnedHandle(h_proc);
                        let mut path_buf = [0u16; 1024];
                        let mut path_len = path_buf.len() as u32;
                        if unsafe {
                            QueryFullProcessImageNameW(
                                h_proc.0,
                                PROCESS_NAME_FORMAT(0),
                                PWSTR(path_buf.as_mut_ptr()),
                                &mut path_len,
                            )
                        }
                        .is_ok()
                        {
                            process_path = String::from_utf16_lossy(&path_buf[..path_len as usize]);
                        }
                        let mut io = IO_COUNTERS::default();
                        if unsafe { GetProcessIoCounters(h_proc.0, &mut io) }.is_ok() {
                            counters = IoCounters {
                                read_operation_count: io.ReadOperationCount,
                                write_operation_count: io.WriteOperationCount,
                                other_operation_count: io.OtherOperationCount,
                                read_transfer_count: io.ReadTransferCount,
                                write_transfer_count: io.WriteTransferCount,
                                other_transfer_count: io.OtherTransferCount,
                            };
                        } else {
                            access_denied = true;
                        }
                    }
                    Err(_) => {
                        access_denied = true;
                    }
                }
            } else {
                access_denied = true;
            }

            out.push(ProcessIoSnapshot {
                pid,
                process_name,
                process_path,
                counters,
                access_denied,
            });

            if unsafe { Process32NextW(snap.0, &mut pe) }.is_err() {
                break;
            }
        }
    }
    Ok(out)
}

fn read_cstr_at(buf: &[u8], offset: u32) -> String {
    let off = offset as usize;
    if offset == 0 || off >= buf.len() {
        return String::new();
    }
    let slice = &buf[off..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).trim().to_string()
}

pub fn query_disk_smart(disk_indices: &[u32]) -> Result<Vec<DiskSmartRecord>, FsError> {
    let indices: Vec<u32> = if disk_indices.is_empty() {
        (0..16).collect()
    } else {
        disk_indices.to_vec()
    };

    let mut out = Vec::new();
    let mut saw_access_denied = false;
    let mut saw_unsupported = false;

    for idx in indices {
        let dev_path = format!(r"\\.\PhysicalDrive{idx}");
        let dev_w = HSTRING::from(&dev_path);
        let handle = match unsafe {
            CreateFileW(
                &dev_w,
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        } {
            Ok(h) => OwnedHandle(h),
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == ERROR_ACCESS_DENIED.0 {
                    // Fallback to metadata-only open for StorageDeviceProperty probe.
                    match unsafe {
                        CreateFileW(
                            &dev_w,
                            0,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            None,
                            OPEN_EXISTING,
                            FILE_FLAGS_AND_ATTRIBUTES(0),
                            None,
                        )
                    } {
                        Ok(h) => OwnedHandle(h),
                        Err(_) => {
                            saw_access_denied = true;
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            }
        };

        let mut model = String::new();
        let mut serial = String::new();
        let mut firmware = String::new();
        let mut bus_type_raw = 0i32;

        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut desc_u64 = vec![0u64; 512];
        let mut bytes_ret = 0u32;
        if unsafe {
            DeviceIoControl(
                handle.0,
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some((&raw const query).cast()),
                size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                Some(desc_u64.as_mut_ptr().cast()),
                (desc_u64.len() * 8) as u32,
                Some(&mut bytes_ret),
                None,
            )
        }
        .is_ok()
            && (bytes_ret as usize) >= size_of::<STORAGE_DEVICE_DESCRIPTOR>()
        {
            let desc_bytes = unsafe { std::slice::from_raw_parts(desc_u64.as_ptr().cast::<u8>(), bytes_ret as usize) };
            let desc = unsafe { &*(desc_u64.as_ptr().cast::<STORAGE_DEVICE_DESCRIPTOR>()) };
            let vendor = read_cstr_at(desc_bytes, desc.VendorIdOffset);
            let product = read_cstr_at(desc_bytes, desc.ProductIdOffset);
            model = [vendor, product]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            serial = read_cstr_at(desc_bytes, desc.SerialNumberOffset);
            firmware = read_cstr_at(desc_bytes, desc.ProductRevisionOffset);
            bus_type_raw = desc.BusType.0;
        }

        // 17 = BusTypeNvme
        if bus_type_raw == 17 {
            let addl_off = std::mem::offset_of!(STORAGE_PROPERTY_QUERY, AdditionalParameters);
            let total_in = addl_off + size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>();
            let total_out = size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() + 512;
            let mut in_u64 = vec![0u64; total_in.div_ceil(8)];
            let mut out_u64 = vec![0u64; total_out.div_ceil(8)];
            unsafe {
                let q = &mut *(in_u64.as_mut_ptr().cast::<STORAGE_PROPERTY_QUERY>());
                q.PropertyId = StorageDeviceProtocolSpecificProperty;
                q.QueryType = PropertyStandardQuery;
                let proto = &mut *(in_u64
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(addl_off)
                    .cast::<STORAGE_PROTOCOL_SPECIFIC_DATA>());
                proto.ProtocolType = ProtocolTypeNvme;
                proto.DataType = 2; // NVMeDataTypeLogPage
                proto.ProtocolDataRequestValue = 2; // NVME_LOG_PAGE_HEALTH_INFO
                proto.ProtocolDataRequestSubValue = 0;
                proto.ProtocolDataOffset = size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>() as u32;
                proto.ProtocolDataLength = 512;
            }
            let mut ret = 0u32;
            match unsafe {
                DeviceIoControl(
                    handle.0,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    Some(in_u64.as_ptr().cast()),
                    total_in as u32,
                    Some(out_u64.as_mut_ptr().cast()),
                    total_out as u32,
                    Some(&mut ret),
                    None,
                )
            } {
                Ok(()) => {
                    let out_bytes = unsafe { std::slice::from_raw_parts(out_u64.as_ptr().cast::<u8>(), ret as usize) };
                    let proto_off = std::mem::offset_of!(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData);
                    if out_bytes.len() >= size_of::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>() {
                        let data_desc = unsafe { &*(out_u64.as_ptr().cast::<STORAGE_PROTOCOL_DATA_DESCRIPTOR>()) };
                        let log_start =
                            proto_off.saturating_add(data_desc.ProtocolSpecificData.ProtocolDataOffset as usize);
                        let log_end = log_start.saturating_add(512);
                        if log_end <= out_bytes.len()
                            && let Ok(nvme) = parse_nvme_health_log(&out_bytes[log_start..log_end])
                        {
                            out.extend(nvme_log_to_records(&dev_path, &model, &serial, &firmware, &nvme));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    let code = (e.code().0 as u32) & 0xFFFF;
                    if code == ERROR_ACCESS_DENIED.0 {
                        saw_access_denied = true;
                    } else {
                        saw_unsupported = true;
                    }
                }
            }
        }

        // ATA SMART_RCV_DRIVE_DATA (READ_ATTRIBUTES 0xD0 + READ_THRESHOLDS 0xD1)
        let mut attr_in = SENDCMDINPARAMS {
            cBufferSize: 512,
            bDriveNumber: idx as u8,
            ..Default::default()
        };
        attr_in.irDriveRegs.bFeaturesReg = READ_ATTRIBUTES as u8;
        attr_in.irDriveRegs.bSectorCountReg = 1;
        attr_in.irDriveRegs.bSectorNumberReg = 1;
        attr_in.irDriveRegs.bCylLowReg = SMART_CYL_LOW as u8;
        attr_in.irDriveRegs.bCylHighReg = SMART_CYL_HI as u8;
        attr_in.irDriveRegs.bCommandReg = SMART_CMD as u8;

        let out_sz = size_of::<SENDCMDOUTPARAMS>() + 512;
        let mut attr_out_buf = vec![0u8; out_sz];
        let mut ret = 0u32;
        let attr_res = unsafe {
            DeviceIoControl(
                handle.0,
                SMART_RCV_DRIVE_DATA,
                Some((&raw const attr_in).cast()),
                size_of::<SENDCMDINPARAMS>() as u32,
                Some(attr_out_buf.as_mut_ptr().cast()),
                attr_out_buf.len() as u32,
                Some(&mut ret),
                None,
            )
        };
        match attr_res {
            Ok(()) if (ret as usize) >= size_of::<SENDCMDOUTPARAMS>() + 511 => {
                let offset = std::mem::offset_of!(SENDCMDOUTPARAMS, bBuffer);
                let attr_512 = &attr_out_buf[offset..offset + 512];

                let mut thresh_in = attr_in;
                thresh_in.irDriveRegs.bFeaturesReg = READ_THRESHOLDS as u8;
                let mut thresh_out_buf = vec![0u8; out_sz];
                let mut thresh_ret = 0u32;
                let thresh_slice = unsafe {
                    DeviceIoControl(
                        handle.0,
                        SMART_RCV_DRIVE_DATA,
                        Some((&raw const thresh_in).cast()),
                        size_of::<SENDCMDINPARAMS>() as u32,
                        Some(thresh_out_buf.as_mut_ptr().cast()),
                        thresh_out_buf.len() as u32,
                        Some(&mut thresh_ret),
                        None,
                    )
                }
                .ok()
                .filter(|_| (thresh_ret as usize) >= size_of::<SENDCMDOUTPARAMS>() + 511)
                .map(|_| &thresh_out_buf[offset..offset + 512]);

                if let Ok(page) = parse_ata_smart_attributes(attr_512, thresh_slice, false) {
                    out.extend(ata_page_to_records(&dev_path, &model, &serial, &firmware, &page));
                }
            }
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == ERROR_ACCESS_DENIED.0 {
                    saw_access_denied = true;
                } else {
                    saw_unsupported = true;
                }
            }
            _ => {
                saw_unsupported = true;
            }
        }
    }

    if out.is_empty() {
        if saw_access_denied {
            return Err(FsError::PermissionDenied(
                "S.M.A.R.T./NVMe physical drive access denied; run elevated as Administrator".to_string(),
            ));
        }
        if saw_unsupported {
            return Err(FsError::Unsupported(
                "S.M.A.R.T./NVMe health query not supported by physical drive controller".to_string(),
            ));
        }
    }
    Ok(out)
}

fn collect_paths(roots: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>, FsError> {
    let mut out = Vec::new();
    for root in roots {
        if !root.exists() {
            return Err(FsError::SourceUnavailable(format!(
                "path '{}' does not exist",
                root.display()
            )));
        }
        out.push(root.clone());
        if root.is_dir() {
            let mut stack = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    for entry in rd.flatten() {
                        let p = entry.path();
                        let is_symlink = std::fs::symlink_metadata(&p)
                            .map(|m| m.file_type().is_symlink())
                            .unwrap_or(false);
                        out.push(p.clone());
                        if recursive && p.is_dir() && !is_symlink {
                            stack.push(p);
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

fn read_stream_preview_and_hash(full_stream_path: &str) -> (String, String) {
    let Ok(mut f) = std::fs::File::open(full_stream_path) else {
        return (String::new(), String::new());
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 4096];
    let mut preview = String::new();
    let mut first = true;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                if first {
                    first = false;
                    let plen = n.min(128);
                    preview = String::from_utf8_lossy(&buf[..plen])
                        .replace('\r', "\\r")
                        .replace('\n', "\\n");
                }
            }
            Err(_) => break,
        }
    }
    (preview, hex::encode(hasher.finalize()))
}

pub fn enumerate_ads(
    target_paths: &[PathBuf],
    recursive: bool,
    include_default_data: bool,
) -> Result<Vec<AdsEntry>, FsError> {
    let paths = collect_paths(target_paths, recursive)?;
    let mut out = Vec::new();

    for path in paths {
        let path_str = path.to_string_lossy().to_string();
        let path_w = HSTRING::from(path.as_os_str());
        let mut data = WIN32_FIND_STREAM_DATA::default();
        let h_res =
            unsafe { FindFirstStreamW(&path_w, FindStreamInfoStandard, (&raw mut data).cast::<c_void>(), None) };
        let h = match h_res {
            Ok(h) => OwnedFindHandle(h),
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == ERROR_HANDLE_EOF.0 || code == ERROR_FILE_NOT_FOUND.0 {
                    continue;
                }
                if code == ERROR_INVALID_PARAMETER.0 || code == ERROR_NOT_SUPPORTED.0 {
                    return Err(FsError::Unsupported(format!(
                        "Alternate Data Streams unsupported on '{}'",
                        path.display()
                    )));
                }
                continue;
            }
        };

        loop {
            let stream_name = wide_buf_to_string(&data.cStreamName);
            let is_default = stream_name.eq_ignore_ascii_case("::$DATA");
            if include_default_data || !is_default {
                let clean_suffix = stream_name
                    .strip_suffix(":$DATA")
                    .or_else(|| stream_name.strip_suffix(":$data"))
                    .unwrap_or(&stream_name);
                let full_stream_path = if is_default {
                    path_str.clone()
                } else {
                    format!("{path_str}{clean_suffix}")
                };
                let (content_preview, sha256) = if is_default {
                    (String::new(), String::new())
                } else {
                    read_stream_preview_and_hash(&full_stream_path)
                };
                let size = u64::try_from(data.StreamSize).unwrap_or(0);
                out.push(AdsEntry {
                    file_path: path_str.clone(),
                    stream_name,
                    full_stream_path,
                    stream_size: size,
                    allocated_size: size,
                    resident: size < 1024,
                    mft_record: None,
                    attributes: "-".to_string(),
                    content_preview,
                    sha256,
                });
            }

            if let Err(e) = unsafe { FindNextStreamW(h.0, (&raw mut data).cast::<c_void>()) } {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == ERROR_HANDLE_EOF.0 || code == ERROR_NO_MORE_FILES.0 {
                    break;
                }
                break;
            }
        }
    }

    Ok(out)
}

pub fn delete_ads(full_stream_path: &str) -> Result<(), FsError> {
    let w = HSTRING::from(full_stream_path);
    unsafe { DeleteFileW(&w) }.map_err(|e| map_windows_core_err("DeleteFileW(ADS)", &e))
}

fn enumerate_hardlinks_for_file(path: &Path) -> Vec<String> {
    let path_w = HSTRING::from(path.as_os_str());
    let mut cap = 512usize;
    let mut buf = vec![0u16; cap];
    let mut len = cap as u32;
    let h = match unsafe { FindFirstFileNameW(&path_w, 0, &mut len, PWSTR(buf.as_mut_ptr())) } {
        Ok(h) => OwnedFindHandle(h),
        Err(e) => {
            if ((e.code().0 as u32) & 0xFFFF) == ERROR_MORE_DATA.0 && len > 0 {
                cap = (len as usize).max(512);
                buf.resize(cap, 0);
                len = cap as u32;
                match unsafe { FindFirstFileNameW(&path_w, 0, &mut len, PWSTR(buf.as_mut_ptr())) } {
                    Ok(h2) => OwnedFindHandle(h2),
                    Err(_) => return Vec::new(),
                }
            } else {
                return Vec::new();
            }
        }
    };

    let drive_prefix = path
        .to_string_lossy()
        .get(0..2)
        .filter(|s| s.as_bytes().get(1) == Some(&b':'))
        .unwrap_or("")
        .to_string();

    let mut links = Vec::new();
    let push_link = |raw_buf: &[u16], raw_len: u32, list: &mut Vec<String>| {
        let s = wide_buf_to_string(&raw_buf[..raw_buf.len().min(raw_len as usize)]);
        if !s.is_empty() {
            if s.starts_with('\\') && !drive_prefix.is_empty() {
                list.push(format!("{drive_prefix}{s}"));
            } else {
                list.push(s);
            }
        }
    };
    push_link(&buf, len, &mut links);

    loop {
        len = buf.len() as u32;
        match unsafe { FindNextFileNameW(h.0, &mut len, PWSTR(buf.as_mut_ptr())) } {
            Ok(()) => push_link(&buf, len, &mut links),
            Err(e) => {
                let code = (e.code().0 as u32) & 0xFFFF;
                if code == ERROR_MORE_DATA.0 && len > 0 {
                    buf.resize(len as usize + 16, 0);
                    len = buf.len() as u32;
                    if unsafe { FindNextFileNameW(h.0, &mut len, PWSTR(buf.as_mut_ptr())) }.is_ok() {
                        push_link(&buf, len, &mut links);
                        continue;
                    }
                }
                break;
            }
        }
    }
    links
}

pub fn inspect_ntfs_links(
    target_paths: &[PathBuf],
    recursive: bool,
    include_hardlinks: bool,
) -> Result<Vec<NtfsLinkEntry>, FsError> {
    let paths = collect_paths(target_paths, recursive)?;
    let mut out = Vec::new();

    for path in paths {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let is_reparse = meta.file_type().is_symlink() || {
            use std::os::windows::fs::MetadataExt;
            (meta.file_attributes() & 0x0400) != 0
        };
        let is_dir = meta.is_dir();

        let path_w = HSTRING::from(path.as_os_str());
        let Ok(h_raw) = (unsafe {
            CreateFileW(
                &path_w,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }) else {
            continue;
        };
        let h = OwnedHandle(h_raw);

        let mut file_info = BY_HANDLE_FILE_INFORMATION::default();
        let (file_id, link_count) = if unsafe { GetFileInformationByHandle(h.0, &mut file_info) }.is_ok() {
            (
                (u64::from(file_info.nFileIndexHigh) << 32) | u64::from(file_info.nFileIndexLow),
                file_info.nNumberOfLinks,
            )
        } else {
            (0, 1)
        };

        if is_reparse {
            let mut rbuf = vec![0u8; 16_384];
            let mut ret = 0u32;
            match unsafe {
                DeviceIoControl(
                    h.0,
                    FSCTL_GET_REPARSE_POINT,
                    None,
                    0,
                    Some(rbuf.as_mut_ptr().cast()),
                    rbuf.len() as u32,
                    Some(&mut ret),
                    None,
                )
            } {
                Ok(()) => {
                    if let Ok(parsed) = parse_reparse_data_buffer(&rbuf[..ret as usize], is_dir) {
                        let target_exists = if parsed.is_relative {
                            path.parent()
                                .map(|p| p.join(&parsed.resolved_target).exists())
                                .unwrap_or(false)
                        } else {
                            !parsed.resolved_target.is_empty() && Path::new(&parsed.resolved_target).exists()
                        };
                        out.push(NtfsLinkEntry {
                            link_path: path.to_string_lossy().to_string(),
                            link_type: parsed.kind.as_str().to_string(),
                            target_path: parsed.resolved_target,
                            substitute_name: parsed.substitute_name,
                            print_name: parsed.print_name,
                            is_relative: parsed.is_relative,
                            target_exists,
                            hard_link_count: link_count,
                            file_id,
                            reparse_tag: parsed.tag.to_be_bytes().to_vec(),
                        });
                    }
                }
                Err(e) => {
                    let code = (e.code().0 as u32) & 0xFFFF;
                    if code != ERROR_NOT_A_REPARSE_POINT.0 {
                        tracing::debug!(path = %path.display(), code, "FSCTL_GET_REPARSE_POINT failed");
                    }
                }
            }
        }

        if include_hardlinks && !is_dir && link_count > 1 {
            let siblings = enumerate_hardlinks_for_file(&path);
            for sib in siblings {
                if !sib.eq_ignore_ascii_case(&path.to_string_lossy()) {
                    out.push(NtfsLinkEntry {
                        link_path: path.to_string_lossy().to_string(),
                        link_type: "HardLink".to_string(),
                        target_path: sib.clone(),
                        substitute_name: sib,
                        print_name: String::new(),
                        is_relative: false,
                        target_exists: true,
                        hard_link_count: link_count,
                        file_id,
                        reparse_tag: Vec::new(),
                    });
                }
            }
        }
    }

    Ok(out)
}

fn canonicalize_for_shell(path: &Path) -> Result<String, FsError> {
    if !path.exists() {
        return Err(FsError::SourceUnavailable(format!(
            "file '{}' does not exist",
            path.display()
        )));
    }
    let abs = std::fs::canonicalize(path).map_err(|e| FsError::from_io(path, e))?;
    let s = abs.to_string_lossy();
    Ok(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
}

fn format_property_key(key: &PROPERTYKEY) -> String {
    let g = key.fmtid;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}} {}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
        key.pid
    )
}

pub fn read_file_properties(file_path: &Path) -> Result<Vec<FilePropertyEntry>, FsError> {
    let _com = ComApartmentGuard::init()?;
    let clean_path = canonicalize_for_shell(file_path)?;
    let path_w = HSTRING::from(&clean_path);

    let store: IPropertyStore = unsafe {
        SHGetPropertyStoreFromParsingName::<_, Option<&IBindCtx>, IPropertyStore>(&path_w, None, GPS_DEFAULT)
    }
    .map_err(|e| map_windows_core_err("SHGetPropertyStoreFromParsingName", &e))?;

    let count = unsafe { store.GetCount() }.map_err(|e| map_windows_core_err("IPropertyStore::GetCount", &e))?;
    let mut entries = Vec::with_capacity(count as usize);

    for i in 0..count {
        let mut key = PROPERTYKEY::default();
        if unsafe { store.GetAt(i, &mut key) }.is_err() {
            continue;
        }
        let prop_key_str = format_property_key(&key);
        let canonical_name = unsafe { PSGetNameFromPropertyKey(&key) }
            .ok()
            .map(|pw| OwnedCoTaskPwstr(pw).to_string_lossy())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| prop_key_str.clone());

        let mut display_name = canonical_name.clone();
        let mut desc_ptr: *mut c_void = std::ptr::null_mut();
        let desc_opt: Option<IPropertyDescription> =
            if unsafe { PSGetPropertyDescription(&key, &IPropertyDescription::IID, &mut desc_ptr) }.is_ok()
                && !desc_ptr.is_null()
            {
                let d: IPropertyDescription = unsafe { IPropertyDescription::from_raw(desc_ptr) };
                if let Ok(dn) = unsafe { d.GetDisplayName() } {
                    let s = OwnedCoTaskPwstr(dn).to_string_lossy();
                    if !s.is_empty() {
                        display_name = s;
                    }
                }
                Some(d)
            } else {
                None
            };

        let pv = match unsafe { store.GetValue(&key) } {
            Ok(v) => OwnedPropVariant(v),
            Err(_) => continue,
        };
        let vt = unsafe { pv.0.Anonymous.Anonymous.vt.0 };
        let value = if let Some(desc) = &desc_opt {
            unsafe { desc.FormatForDisplay(&pv.0, PDFF_DEFAULT) }
                .ok()
                .map(|pw| OwnedCoTaskPwstr(pw).to_string_lossy())
                .unwrap_or_else(|| {
                    unsafe { PropVariantToStringAlloc(&pv.0) }
                        .ok()
                        .map(|pw| OwnedCoTaskPwstr(pw).to_string_lossy())
                        .unwrap_or_default()
                })
        } else {
            unsafe { PropVariantToStringAlloc(&pv.0) }
                .ok()
                .map(|pw| OwnedCoTaskPwstr(pw).to_string_lossy())
                .unwrap_or_default()
        };

        entries.push(FilePropertyEntry {
            file_path: clean_path.clone(),
            canonical_name,
            property_key: prop_key_str,
            display_name,
            value_type: format!("VT({vt})"),
            value,
            read_only_prop: false,
        });
    }

    Ok(entries)
}

pub fn set_file_property(file_path: &Path, canonical_name: &str, value: &str) -> Result<FilePropertyEntry, FsError> {
    let _com = ComApartmentGuard::init()?;
    let clean_path = canonicalize_for_shell(file_path)?;
    let path_w = HSTRING::from(&clean_path);
    let name_w = HSTRING::from(canonical_name);

    let mut key = PROPERTYKEY::default();
    unsafe { PSGetPropertyKeyFromName(&name_w, &mut key) }
        .map_err(|e| FsError::InvalidArgument(format!("unknown property '{canonical_name}': {e}")))?;

    let store: IPropertyStore = unsafe {
        SHGetPropertyStoreFromParsingName::<_, Option<&IBindCtx>, IPropertyStore>(&path_w, None, GPS_READWRITE)
    }
    .map_err(|e| map_windows_core_err("SHGetPropertyStoreFromParsingName(GPS_READWRITE)", &e))?;

    let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide.len() * 2;
    let raw_mem = unsafe { CoTaskMemAlloc(byte_len) };
    if raw_mem.is_null() {
        return Err(FsError::Io(std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            "CoTaskMemAlloc failed",
        )));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), raw_mem.cast::<u16>(), wide.len());
    }
    let mut pv = PROPVARIANT::default();
    pv.Anonymous.Anonymous = ManuallyDrop::new(PROPVARIANT_0_0 {
        vt: VT_LPWSTR,
        wReserved1: 0,
        wReserved2: 0,
        wReserved3: 0,
        Anonymous: PROPVARIANT_0_0_0 {
            pwszVal: PWSTR(raw_mem.cast::<u16>()),
        },
    });
    let mut owned_pv = OwnedPropVariant(pv);

    let _ = unsafe { PSCoerceToCanonicalValue(&key, &mut owned_pv.0) };
    unsafe { store.SetValue(&key, &owned_pv.0) }.map_err(|e| map_windows_core_err("IPropertyStore::SetValue", &e))?;
    unsafe { store.Commit() }.map_err(|e| map_windows_core_err("IPropertyStore::Commit", &e))?;

    Ok(FilePropertyEntry {
        file_path: clean_path,
        canonical_name: canonical_name.to_string(),
        property_key: format_property_key(&key),
        display_name: canonical_name.to_string(),
        value_type: "VT_LPWSTR".to_string(),
        value: value.to_string(),
        read_only_prop: false,
    })
}

pub fn read_usn_journal(
    device_path: &str,
    start_usn: i64,
    reason_mask: u32,
    max_records: usize,
    mode: UsnQueryMode,
) -> Result<Vec<UsnRecord>, FsError> {
    let dev_w = HSTRING::from(device_path);
    let h = unsafe {
        CreateFileW(
            &dev_w,
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| map_windows_core_err("CreateFileW(USN volume)", &e))?;
    let h = OwnedHandle(h);

    let mut journal_data = USN_JOURNAL_DATA_V0::default();
    let mut ret = 0u32;
    unsafe {
        DeviceIoControl(
            h.0,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some((&raw mut journal_data).cast()),
            size_of::<USN_JOURNAL_DATA_V0>() as u32,
            Some(&mut ret),
            None,
        )
    }
    .map_err(|e| map_windows_core_err("FSCTL_QUERY_USN_JOURNAL", &e))?;

    let mut records = Vec::new();
    let mut buf = vec![0u8; 65_536];
    let limit = max_records.clamp(1, 100_000);

    match mode {
        UsnQueryMode::Journal => {
            let mut cur_usn = start_usn.max(journal_data.FirstUsn);
            for _ in 0..1024 {
                if records.len() >= limit {
                    break;
                }
                let input = READ_USN_JOURNAL_DATA_V0 {
                    StartUsn: cur_usn,
                    ReasonMask: reason_mask,
                    ReturnOnlyOnClose: 0,
                    Timeout: 0,
                    BytesToWaitFor: 0,
                    UsnJournalID: journal_data.UsnJournalID,
                };
                let mut bytes_ret = 0u32;
                match unsafe {
                    DeviceIoControl(
                        h.0,
                        FSCTL_READ_USN_JOURNAL,
                        Some((&raw const input).cast()),
                        size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
                        Some(buf.as_mut_ptr().cast()),
                        buf.len() as u32,
                        Some(&mut bytes_ret),
                        None,
                    )
                } {
                    Ok(()) => {
                        let (next_usn, batch) = parse_usn_ioctl_buffer(&buf[..bytes_ret as usize])?;
                        let empty = batch.is_empty();
                        records.extend(batch);
                        if empty || next_usn <= cur_usn {
                            break;
                        }
                        cur_usn = next_usn;
                    }
                    Err(e) => {
                        let code = (e.code().0 as u32) & 0xFFFF;
                        if code == ERROR_HANDLE_EOF.0 {
                            break;
                        }
                        return Err(map_windows_core_err("FSCTL_READ_USN_JOURNAL", &e));
                    }
                }
            }
        }
        UsnQueryMode::EnumMft => {
            let mut cur_frn = 0u64;
            for _ in 0..1024 {
                if records.len() >= limit {
                    break;
                }
                let input = MFT_ENUM_DATA_V0 {
                    StartFileReferenceNumber: cur_frn,
                    LowUsn: 0,
                    HighUsn: journal_data.NextUsn,
                };
                let mut bytes_ret = 0u32;
                match unsafe {
                    DeviceIoControl(
                        h.0,
                        FSCTL_ENUM_USN_DATA,
                        Some((&raw const input).cast()),
                        size_of::<MFT_ENUM_DATA_V0>() as u32,
                        Some(buf.as_mut_ptr().cast()),
                        buf.len() as u32,
                        Some(&mut bytes_ret),
                        None,
                    )
                } {
                    Ok(()) => {
                        let (next_frn, batch) = parse_usn_ioctl_buffer(&buf[..bytes_ret as usize])?;
                        let next_u64 = next_frn as u64;
                        let empty = batch.is_empty();
                        records.extend(batch);
                        if empty || next_u64 <= cur_frn {
                            break;
                        }
                        cur_frn = next_u64;
                    }
                    Err(e) => {
                        let code = (e.code().0 as u32) & 0xFFFF;
                        if code == ERROR_HANDLE_EOF.0 {
                            break;
                        }
                        return Err(map_windows_core_err("FSCTL_ENUM_USN_DATA", &e));
                    }
                }
            }
        }
    }

    records.truncate(limit);
    Ok(records)
}

#[allow(dead_code)]
fn _unused_btreemap_marker() -> BTreeMap<String, String> {
    BTreeMap::new()
}
