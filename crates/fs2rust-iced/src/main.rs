#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use fs2rust_core::init_logging;
use fs2rust_mcp::build_suite_wiring;
use guap_gui_iced::{IcedSuiteConfig, run_iced_suite};

fn main() -> anyhow::Result<()> {
    init_logging(false);
    let offline = std::env::args().any(|a| a == "--offline");
    let wiring = build_suite_wiring(offline, Vec::new());
    let suite_cfg = IcedSuiteConfig {
        app_title: "fs2rust — Filesystem, NTFS & Data Console (Iced)".to_string(),
        dark_mode: true,
        window_size: (1360.0, 820.0),
    };
    run_iced_suite(suite_cfg, wiring.providers).map_err(|e| anyhow::anyhow!("Iced GUI error: {e}"))
}

#[cfg(test)]
mod tests {
    use fs2rust_mcp::build_synthetic_suite_wiring;
    use guap_export::ExportFormat;
    use guap_gui_iced::{DataGridMessage, IcedDataGrid};

    #[test]
    fn iced_data_grid_drives_all_24_tools_offline() {
        let wiring = build_synthetic_suite_wiring();
        assert_eq!(wiring.providers.len(), 24);
        let tool_ids: Vec<String> = wiring.providers.iter().map(|p| p.tool_id().to_string()).collect();

        let tmp = tempfile::tempdir().unwrap();
        let mut grid = IcedDataGrid::new(wiring.providers)
            .with_export_dir(tmp.path().to_path_buf())
            .with_dark_mode(true)
            .with_page_size(200);

        for tid in &tool_ids {
            let _ = grid.update(DataGridMessage::SelectTool(tid.clone()));
            assert_eq!(grid.active_tool_id(), Some(tid.as_str()));
            assert!(!grid.columns().is_empty(), "tool {tid} has empty columns");
            assert!(
                grid.last_error().is_none(),
                "tool {tid} errored: {:?}",
                grid.last_error()
            );
        }

        let _ = grid.update(DataGridMessage::SelectTool("fs2rust.data.csv_file_view".to_string()));
        assert_eq!(grid.total_rows(), 2);
        let _ = grid.update(DataGridMessage::FilterChanged("alpha".to_string()));
        assert_eq!(grid.total_rows(), 1);
        let _ = grid.update(DataGridMessage::FilterChanged(String::new()));
        assert_eq!(grid.total_rows(), 2);
        let _ = grid.update(DataGridMessage::SortColumn(0));
        let _ = grid.update(DataGridMessage::SelectRow(0));
        let _ = grid.update(DataGridMessage::Export(ExportFormat::Json));
        assert!(grid.last_export_manifest().is_some());
    }
}
