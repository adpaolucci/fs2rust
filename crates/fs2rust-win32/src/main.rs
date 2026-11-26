use fs2rust_core::init_logging;
use fs2rust_mcp::build_suite_wiring;
use guap_gui_win32::{Win32TableHostConfig, run_win32_suite};

fn main() -> anyhow::Result<()> {
    init_logging(false);
    let offline = std::env::args().any(|a| a == "--offline");
    let wiring = build_suite_wiring(offline, Vec::new());
    let host_cfg = Win32TableHostConfig {
        app_title: "fs2rust — Filesystem, NTFS & Data Console".to_string(),
        dark_mode: true,
        show_hex_pane: true,
        default_export_dir: None,
    };
    run_win32_suite(host_cfg, wiring.providers, wiring.actions)
}

#[cfg(test)]
mod tests {
    use fs2rust_mcp::build_synthetic_suite_wiring;
    use guap_export::ExportFormat;
    use guap_gui_win32::{Win32GridState, Win32TableHostConfig, run_win32_suite};

    #[test]
    fn win32_grid_state_drives_all_24_tools_offline() {
        let _keep_symbol = run_win32_suite as *const ();

        let wiring = build_synthetic_suite_wiring();
        assert_eq!(wiring.providers.len(), 24);
        assert_eq!(wiring.actions.len(), 8);

        let host_cfg = Win32TableHostConfig {
            app_title: "fs2rust Test".to_string(),
            dark_mode: true,
            show_hex_pane: true,
            default_export_dir: None,
        };
        let mut grid = Win32GridState::new(host_cfg, wiring.providers, wiring.actions);

        for idx in 0..24 {
            assert!(grid.select_tool(idx), "failed to select tool index {idx}");
            assert!(!grid.columns().is_empty(), "tool index {idx} has empty columns");
            if grid.row_count() > 0 {
                let _ = grid.cell_text(0, 0);
                let _ = grid.format_inspector_crlf();
            }
        }

        // Verify filter, sort, and CSV export on search_files / fs2rust.data.csv_file_view
        assert!(grid.select_tool_by_id("fs2rust.data.csv_file_view"));
        assert_eq!(grid.row_count(), 2);
        grid.set_filter("alpha".to_string());
        assert_eq!(grid.row_count(), 1);
        grid.set_filter(String::new());
        assert_eq!(grid.row_count(), 2);
        assert!(grid.toggle_sort(0));
        let _ = grid.format_inspector_crlf();

        let tmp = tempfile::tempdir().unwrap();
        let exp_path = tmp.path().join("win32_export.csv");
        grid.export_to_path(&exp_path, ExportFormat::Csv).unwrap();
        assert!(exp_path.is_file());
    }
}
