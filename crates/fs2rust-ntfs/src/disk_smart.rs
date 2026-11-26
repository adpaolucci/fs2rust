#![forbid(unsafe_code)]

use crate::backend::NtfsBackend;
use crate::bin_util::{read_u8, read_u16_le, read_u32_le, read_u128_le};
use fs2rust_core::FsError;
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

pub fn ata_attribute_name(id: u8) -> String {
    match id {
        0x01 => "Read Error Rate".to_string(),
        0x02 => "Throughput Performance".to_string(),
        0x03 => "Spin-Up Time".to_string(),
        0x04 => "Start/Stop Count".to_string(),
        0x05 => "Reallocated Sectors Count".to_string(),
        0x07 => "Seek Error Rate".to_string(),
        0x08 => "Seek Time Performance".to_string(),
        0x09 => "Power-On Hours".to_string(),
        0x0A => "Spin Retry Count".to_string(),
        0x0B => "Recalibration Retries".to_string(),
        0x0C => "Power Cycle Count".to_string(),
        0xAA => "Available Reserved Space".to_string(),
        0xAB => "SSD Program Fail Count".to_string(),
        0xAC => "SSD Erase Fail Count".to_string(),
        0xAD => "SSD Wear Leveling Count".to_string(),
        0xAE => "Unexpected Power Loss Count".to_string(),
        0xB7 => "SATA Downshift Error Count".to_string(),
        0xB8 => "End-to-End Error".to_string(),
        0xBB => "Reported Uncorrectable Errors".to_string(),
        0xBC => "Command Timeout".to_string(),
        0xBD => "High Fly Writes".to_string(),
        0xBE => "Airflow Temperature (C)".to_string(),
        0xBF => "G-Sense Error Rate".to_string(),
        0xC0 => "Power-Off Retract Count".to_string(),
        0xC1 => "Load/Unload Cycle Count".to_string(),
        0xC2 => "Temperature (C)".to_string(),
        0xC3 => "Hardware ECC Recovered".to_string(),
        0xC4 => "Reallocation Event Count".to_string(),
        0xC5 => "Current Pending Sector Count".to_string(),
        0xC6 => "Offline Uncorrectable Sector Count".to_string(),
        0xC7 => "UltraDMA CRC Error Count".to_string(),
        0xC8 => "Multi-Zone Error Rate".to_string(),
        0xE7 => "SSD Life Left".to_string(),
        0xE9 => "Media Wearout Indicator".to_string(),
        0xF1 => "Total LBAs Written".to_string(),
        0xF2 => "Total LBAs Read".to_string(),
        other => format!("Vendor Specific (0x{other:02X})"),
    }
}

pub fn ata_checksum_valid(bytes: &[u8]) -> bool {
    bytes.len() >= 512 && bytes[..512].iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartAttribute {
    pub id: u8,
    pub name: String,
    pub flags: u16,
    pub pre_fail: bool,
    pub online: bool,
    pub current: u8,
    pub worst: u8,
    pub threshold: Option<u8>,
    pub raw_bytes: [u8; 6],
    pub raw_value: u64,
    pub temperature_c: Option<i32>,
    pub health_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtaSmartPage {
    pub version: u16,
    pub checksum_valid: bool,
    pub threshold_checksum_valid: Option<bool>,
    pub offline_data_collection_status: u8,
    pub self_test_exec_status: u8,
    pub attributes: Vec<SmartAttribute>,
}

pub fn parse_ata_smart_thresholds(
    thresh_512: &[u8],
    strict_checksum: bool,
) -> Result<(bool, HashMap<u8, u8>), FsError> {
    if thresh_512.len() < 512 {
        return Err(FsError::Parse(format!(
            "ATA SMART thresholds buffer too short: {} bytes (need 512)",
            thresh_512.len()
        )));
    }
    let valid = ata_checksum_valid(thresh_512);
    if strict_checksum && !valid {
        return Err(FsError::Parse("ATA SMART thresholds checksum mismatch".to_string()));
    }
    let mut map = HashMap::new();
    for i in 0..30 {
        let base = 2 + i * 12;
        let id = read_u8(thresh_512, base)?;
        if id == 0 {
            continue;
        }
        let threshold = read_u8(thresh_512, base + 1)?;
        map.insert(id, threshold);
    }
    Ok((valid, map))
}

pub fn parse_ata_smart_attributes(
    attr_512: &[u8],
    thresh_512: Option<&[u8]>,
    strict_checksum: bool,
) -> Result<AtaSmartPage, FsError> {
    if attr_512.len() < 512 {
        return Err(FsError::Parse(format!(
            "ATA SMART attribute buffer too short: {} bytes (need 512)",
            attr_512.len()
        )));
    }
    let checksum_valid = ata_checksum_valid(attr_512);
    if strict_checksum && !checksum_valid {
        return Err(FsError::Parse("ATA SMART attribute checksum mismatch".to_string()));
    }
    let (threshold_checksum_valid, thresholds) = if let Some(tb) = thresh_512 {
        let (tv, tm) = parse_ata_smart_thresholds(tb, strict_checksum)?;
        (Some(tv), tm)
    } else {
        (None, HashMap::new())
    };

    let version = read_u16_le(attr_512, 0)?;
    let offline_data_collection_status = read_u8(attr_512, 362)?;
    let self_test_exec_status = read_u8(attr_512, 363)?;
    let mut attributes = Vec::new();

    for i in 0..30 {
        let base = 2 + i * 12;
        let id = read_u8(attr_512, base)?;
        if id == 0 {
            continue;
        }
        let flags = read_u16_le(attr_512, base + 1)?;
        let pre_fail = (flags & 0x0001) != 0;
        let online = (flags & 0x0002) != 0;
        let current = read_u8(attr_512, base + 3)?;
        let worst = read_u8(attr_512, base + 4)?;
        let mut raw_bytes = [0u8; 6];
        raw_bytes.copy_from_slice(&attr_512[base + 5..base + 11]);
        let raw_value = u64::from_le_bytes([
            raw_bytes[0],
            raw_bytes[1],
            raw_bytes[2],
            raw_bytes[3],
            raw_bytes[4],
            raw_bytes[5],
            0,
            0,
        ]);
        let threshold = thresholds.get(&id).copied();
        let temperature_c = if id == 0xC2 || id == 0xBE {
            Some(i32::from(raw_bytes[0] as i8))
        } else {
            None
        };

        let health_status = if !checksum_valid {
            "ChecksumError".to_string()
        } else if let Some(th) = threshold
            && th > 0
            && current <= th
        {
            if pre_fail {
                "Critical".to_string()
            } else {
                "Caution".to_string()
            }
        } else if matches!(id, 0x05 | 0xC4 | 0xC5 | 0xC6) && raw_value > 0 {
            "Caution".to_string()
        } else {
            "OK".to_string()
        };

        attributes.push(SmartAttribute {
            id,
            name: ata_attribute_name(id),
            flags,
            pre_fail,
            online,
            current,
            worst,
            threshold,
            raw_bytes,
            raw_value,
            temperature_c,
            health_status,
        });
    }

    Ok(AtaSmartPage {
        version,
        checksum_valid,
        threshold_checksum_valid,
        offline_data_collection_status,
        self_test_exec_status,
        attributes,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NvmeHealthLog {
    pub critical_warning: u8,
    pub composite_temperature_k: u16,
    pub composite_temperature_c: Option<f64>,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub endurance_group_critical_warning: u8,
    pub data_units_read: String,
    pub data_bytes_read: String,
    pub data_units_written: String,
    pub data_bytes_written: String,
    pub host_read_commands: String,
    pub host_write_commands: String,
    pub controller_busy_time_min: String,
    pub power_cycles: String,
    pub power_on_hours: String,
    pub unsafe_shutdowns: String,
    pub media_and_data_integrity_errors: String,
    pub error_info_log_entries: String,
    pub warning_composite_temp_time_min: u32,
    pub critical_composite_temp_time_min: u32,
    pub temperature_sensors_c: Vec<Option<f64>>,
    pub data_units_read_u64: u64,
    pub data_units_written_u64: u64,
    pub power_on_hours_u64: u64,
    pub media_errors_u64: u64,
}

/// Parse a 512-byte NVMe SMART / Health Information Log Page (`LID 0x02`).
pub fn parse_nvme_health_log(log_512: &[u8]) -> Result<NvmeHealthLog, FsError> {
    if log_512.len() < 512 {
        return Err(FsError::Parse(format!(
            "NVMe health log buffer too short: {} bytes (need 512)",
            log_512.len()
        )));
    }
    let critical_warning = read_u8(log_512, 0)?;
    let composite_temperature_k = read_u16_le(log_512, 1)?;
    let composite_temperature_c = if composite_temperature_k > 0 {
        Some(f64::from(composite_temperature_k) - 273.15)
    } else {
        None
    };
    let available_spare = read_u8(log_512, 3)?;
    let available_spare_threshold = read_u8(log_512, 4)?;
    let percentage_used = read_u8(log_512, 5)?;
    let endurance_group_critical_warning = read_u8(log_512, 6)?;

    let data_units_read = read_u128_le(log_512, 32)?;
    let data_units_written = read_u128_le(log_512, 48)?;
    let host_read_commands = read_u128_le(log_512, 64)?;
    let host_write_commands = read_u128_le(log_512, 80)?;
    let controller_busy_time = read_u128_le(log_512, 96)?;
    let power_cycles = read_u128_le(log_512, 112)?;
    let power_on_hours = read_u128_le(log_512, 128)?;
    let unsafe_shutdowns = read_u128_le(log_512, 144)?;
    let media_errors = read_u128_le(log_512, 160)?;
    let error_log_entries = read_u128_le(log_512, 176)?;
    let warning_temp_time = read_u32_le(log_512, 192)?;
    let critical_temp_time = read_u32_le(log_512, 196)?;

    let mut sensors = Vec::with_capacity(8);
    for idx in 0..8 {
        let k = read_u16_le(log_512, 200 + idx * 2)?;
        sensors.push(if k > 0 { Some(f64::from(k) - 273.15) } else { None });
    }

    let data_bytes_read = data_units_read.saturating_mul(512_000);
    let data_bytes_written = data_units_written.saturating_mul(512_000);

    Ok(NvmeHealthLog {
        critical_warning,
        composite_temperature_k,
        composite_temperature_c,
        available_spare,
        available_spare_threshold,
        percentage_used,
        endurance_group_critical_warning,
        data_units_read: data_units_read.to_string(),
        data_bytes_read: data_bytes_read.to_string(),
        data_units_written: data_units_written.to_string(),
        data_bytes_written: data_bytes_written.to_string(),
        host_read_commands: host_read_commands.to_string(),
        host_write_commands: host_write_commands.to_string(),
        controller_busy_time_min: controller_busy_time.to_string(),
        power_cycles: power_cycles.to_string(),
        power_on_hours: power_on_hours.to_string(),
        unsafe_shutdowns: unsafe_shutdowns.to_string(),
        media_and_data_integrity_errors: media_errors.to_string(),
        error_info_log_entries: error_log_entries.to_string(),
        warning_composite_temp_time_min: warning_temp_time,
        critical_composite_temp_time_min: critical_temp_time,
        temperature_sensors_c: sensors,
        data_units_read_u64: u64::try_from(data_units_read).unwrap_or(u64::MAX),
        data_units_written_u64: u64::try_from(data_units_written).unwrap_or(u64::MAX),
        power_on_hours_u64: u64::try_from(power_on_hours).unwrap_or(u64::MAX),
        media_errors_u64: u64::try_from(media_errors).unwrap_or(u64::MAX),
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskSmartRecord {
    pub device: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub bus_protocol: String,
    pub attribute_id: String,
    pub attribute_name: String,
    pub current: Option<u64>,
    pub worst: Option<u64>,
    pub threshold: Option<u64>,
    pub raw_value: u64,
    pub raw_hex: Vec<u8>,
    pub health_status: String,
    pub flags: String,
    pub detail_extra: Value,
}

pub fn ata_page_to_records(
    device: &str,
    model: &str,
    serial: &str,
    firmware: &str,
    page: &AtaSmartPage,
) -> Vec<DiskSmartRecord> {
    page.attributes
        .iter()
        .map(|attr| {
            let mut flag_parts = Vec::new();
            if attr.pre_fail {
                flag_parts.push("PreFail");
            }
            if attr.online {
                flag_parts.push("Online");
            }
            let flags = if flag_parts.is_empty() {
                "-".to_string()
            } else {
                flag_parts.join("|")
            };
            DiskSmartRecord {
                device: device.to_string(),
                model: model.to_string(),
                serial: serial.to_string(),
                firmware: firmware.to_string(),
                bus_protocol: "ATA".to_string(),
                attribute_id: format!("0x{:02X}", attr.id),
                attribute_name: attr.name.clone(),
                current: Some(u64::from(attr.current)),
                worst: Some(u64::from(attr.worst)),
                threshold: attr.threshold.map(u64::from),
                raw_value: attr.raw_value,
                raw_hex: attr.raw_bytes.to_vec(),
                health_status: attr.health_status.clone(),
                flags,
                detail_extra: json!({
                    "checksum_valid": page.checksum_valid,
                    "threshold_checksum_valid": page.threshold_checksum_valid,
                    "temperature_c": attr.temperature_c,
                }),
            }
        })
        .collect()
}

pub fn nvme_log_to_records(
    device: &str,
    model: &str,
    serial: &str,
    firmware: &str,
    log: &NvmeHealthLog,
) -> Vec<DiskSmartRecord> {
    let overall_health =
        if log.critical_warning != 0 || log.available_spare < log.available_spare_threshold || log.media_errors_u64 > 0
        {
            "Critical".to_string()
        } else if log.percentage_used >= 90 {
            "Caution".to_string()
        } else {
            "OK".to_string()
        };
    let warning_str = if log.critical_warning == 0 {
        "None".to_string()
    } else {
        format!("0x{:02X}", log.critical_warning)
    };
    let detail = serde_json::to_value(log).unwrap_or(Value::Null);
    let temp_c_rounded = log
        .composite_temperature_c
        .map(|c| c.round().max(0.0) as u64)
        .unwrap_or(0);

    vec![
        DiskSmartRecord {
            device: device.to_string(),
            model: model.to_string(),
            serial: serial.to_string(),
            firmware: firmware.to_string(),
            bus_protocol: "NVMe".to_string(),
            attribute_id: "NVMe:Temp".to_string(),
            attribute_name: "Composite Temperature (C)".to_string(),
            current: Some(temp_c_rounded),
            worst: None,
            threshold: None,
            raw_value: u64::from(log.composite_temperature_k),
            raw_hex: log.composite_temperature_k.to_le_bytes().to_vec(),
            health_status: if (log.critical_warning & 0x02) != 0 {
                "Critical".to_string()
            } else {
                overall_health.clone()
            },
            flags: warning_str.clone(),
            detail_extra: detail.clone(),
        },
        DiskSmartRecord {
            device: device.to_string(),
            model: model.to_string(),
            serial: serial.to_string(),
            firmware: firmware.to_string(),
            bus_protocol: "NVMe".to_string(),
            attribute_id: "NVMe:Spare".to_string(),
            attribute_name: "Available Spare (%)".to_string(),
            current: Some(u64::from(log.available_spare)),
            worst: None,
            threshold: Some(u64::from(log.available_spare_threshold)),
            raw_value: u64::from(log.available_spare),
            raw_hex: vec![log.available_spare],
            health_status: if log.available_spare < log.available_spare_threshold {
                "Critical".to_string()
            } else {
                "OK".to_string()
            },
            flags: warning_str.clone(),
            detail_extra: detail.clone(),
        },
        DiskSmartRecord {
            device: device.to_string(),
            model: model.to_string(),
            serial: serial.to_string(),
            firmware: firmware.to_string(),
            bus_protocol: "NVMe".to_string(),
            attribute_id: "NVMe:Used".to_string(),
            attribute_name: "Percentage Used (%)".to_string(),
            current: Some(u64::from(100u8.saturating_sub(log.percentage_used.min(100)))),
            worst: None,
            threshold: None,
            raw_value: u64::from(log.percentage_used),
            raw_hex: vec![log.percentage_used],
            health_status: if log.percentage_used >= 95 {
                "Caution".to_string()
            } else {
                "OK".to_string()
            },
            flags: warning_str.clone(),
            detail_extra: detail.clone(),
        },
        DiskSmartRecord {
            device: device.to_string(),
            model: model.to_string(),
            serial: serial.to_string(),
            firmware: firmware.to_string(),
            bus_protocol: "NVMe".to_string(),
            attribute_id: "NVMe:POH".to_string(),
            attribute_name: "Power-On Hours".to_string(),
            current: Some(100),
            worst: None,
            threshold: None,
            raw_value: log.power_on_hours_u64,
            raw_hex: log.power_on_hours_u64.to_le_bytes().to_vec(),
            health_status: overall_health.clone(),
            flags: warning_str.clone(),
            detail_extra: detail.clone(),
        },
        DiskSmartRecord {
            device: device.to_string(),
            model: model.to_string(),
            serial: serial.to_string(),
            firmware: firmware.to_string(),
            bus_protocol: "NVMe".to_string(),
            attribute_id: "NVMe:MediaErr".to_string(),
            attribute_name: "Media and Data Integrity Errors".to_string(),
            current: Some(if log.media_errors_u64 == 0 { 100 } else { 1 }),
            worst: None,
            threshold: Some(0),
            raw_value: log.media_errors_u64,
            raw_hex: log.media_errors_u64.to_le_bytes().to_vec(),
            health_status: if log.media_errors_u64 > 0 {
                "Critical".to_string()
            } else {
                "OK".to_string()
            },
            flags: warning_str,
            detail_extra: detail,
        },
    ]
}

#[derive(Debug, Clone, Default)]
pub struct DiskSmartConfig {
    pub disk_indices: Vec<u32>,
    pub offline_records: Option<Vec<DiskSmartRecord>>,
}

pub fn disk_smart_schema() -> TableSchema {
    TableSchema::new(
        "disk_smart_view",
        "DiskSmartView - ATA S.M.A.R.T. & NVMe Health Log Attributes",
        vec![
            ColumnDef::new("device", "Device", ColumnType::Text).with_width_hint(140),
            ColumnDef::new("model", "Model", ColumnType::Text).with_width_hint(180),
            ColumnDef::new("bus_protocol", "Protocol", ColumnType::Text).with_width_hint(70),
            ColumnDef::new("attribute_id", "Attr ID", ColumnType::Text).with_width_hint(90),
            ColumnDef::new("attribute_name", "Attribute Name", ColumnType::Text).with_width_hint(220),
            ColumnDef::new("current", "Current", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("worst", "Worst", ColumnType::Uint).with_width_hint(75),
            ColumnDef::new("threshold", "Threshold", ColumnType::Uint).with_width_hint(85),
            ColumnDef::new("raw_value", "Raw Value", ColumnType::Uint).with_width_hint(130),
            ColumnDef::new("raw_hex", "Raw Hex", ColumnType::Hex).with_width_hint(130),
            ColumnDef::new("health_status", "Health", ColumnType::Text).with_width_hint(95),
            ColumnDef::new("flags", "Flags", ColumnType::Text).with_width_hint(110),
        ],
    )
    .with_default_sort(0, SortDirection::Asc)
}

pub struct DiskSmartViewProvider {
    config: DiskSmartConfig,
    backend: Arc<dyn NtfsBackend>,
}

impl DiskSmartViewProvider {
    pub fn new(config: DiskSmartConfig, backend: Arc<dyn NtfsBackend>) -> Self {
        Self { config, backend }
    }
}

impl TableProvider for DiskSmartViewProvider {
    fn tool_id(&self) -> &'static str {
        "disk_smart_view"
    }

    fn description(&self) -> &'static str {
        "Read ATA S.M.A.R.T. attributes/thresholds and NVMe Health Log Page 0x02 telemetry from physical drives"
    }

    fn schema(&self) -> TableSchema {
        disk_smart_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let records = if let Some(offline) = &self.config.offline_records {
            offline.clone()
        } else {
            self.backend
                .query_disk_smart(&self.config.disk_indices)
                .map_err(TableError::from)?
        };
        let rows: Vec<Row> = records
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                Row::new(
                    idx as u64 + 1,
                    vec![
                        CellValue::Text(r.device.clone()),
                        CellValue::Text(r.model.clone()),
                        CellValue::Text(r.bus_protocol.clone()),
                        CellValue::Text(r.attribute_id.clone()),
                        CellValue::Text(r.attribute_name.clone()),
                        r.current.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        r.worst.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        r.threshold.map(CellValue::Uint).unwrap_or(CellValue::Null),
                        CellValue::Uint(r.raw_value),
                        CellValue::Hex(r.raw_hex.clone()),
                        CellValue::Text(r.health_status.clone()),
                        CellValue::Text(r.flags.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(r).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&self.schema(), &rows, req)
    }
}
