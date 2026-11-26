#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use fs2rust_mcp::build_synthetic_suite_wiring;

const FORBIDDEN_PATTERNS: &[(&str, &str)] = &[
    // Excluded cred2rust & credential-dumping tools/APIs (R4 §8.1)
    ("cred2rust", "excluded cred2rust suite"),
    ("webbrowserpassview", "prohibited credential recovery tool"),
    ("chromepass", "prohibited credential recovery tool"),
    ("passwordfox", "prohibited credential recovery tool"),
    ("mail passview", "prohibited credential recovery tool"),
    ("mailpv", "prohibited credential recovery tool"),
    ("outlookpassview", "prohibited credential recovery tool"),
    ("wirelesskeyview", "prohibited Wi-Fi key recovery tool"),
    ("wifikeyview", "prohibited Wi-Fi key recovery tool"),
    ("credentialsfileview", "prohibited credential recovery tool"),
    ("vaultpasswordview", "prohibited credential recovery tool"),
    ("lsasecretsview", "prohibited LSA secret dumper"),
    ("lsasecretsdump", "prohibited LSA secret dumper"),
    ("securityquestionsview", "prohibited credential recovery tool"),
    ("dialupass", "prohibited credential recovery tool"),
    ("asterisk logger", "prohibited password logger"),
    ("bulletspassview", "prohibited password recovery tool"),
    ("protected storage passview", "prohibited password recovery tool"),
    ("vncpassview", "prohibited password recovery tool"),
    ("routerpassview", "prohibited password recovery tool"),
    ("produkey", "prohibited key extractor"),
    ("sniffpass", "prohibited network password sniffer"),
    ("credenumeratew", "prohibited Windows credential API"),
    ("vaultenumerateitems", "prohibited Windows Vault API"),
    ("vaultgetitem", "prohibited Windows Vault API"),
    ("lsaretrieveprivatedata", "prohibited LSA secret API"),
    ("cryptunprotectdata", "prohibited DPAPI decryption API"),
    ("wlan_profile_get_plaintext_key", "prohibited Wi-Fi plaintext key flag"),
    // Excluded DLL injection & API hooking tools/APIs (R4 §8.2)
    ("runasdate", "prohibited API hooking tool"),
    ("socketsniff", "prohibited DLL injection sniffer"),
    ("injecteddll", "prohibited DLL injection tool"),
    ("createremotethread", "prohibited DLL injection API"),
    ("ntcreatethreadex", "prohibited DLL injection API"),
    ("queueuserapc", "prohibited APC injection API"),
    ("setwindowshookexw", "prohibited global hook API"),
    ("writeprocessmemory", "prohibited remote memory write API"),
    // 39 retired legacy NirSoft tools (R4 §8.3)
    ("iecacheview", "retired legacy IE tool"),
    ("iehistoryview", "retired legacy IE tool"),
    ("iecookiesview", "retired legacy IE tool"),
    ("iesessionview", "retired legacy IE tool"),
    ("iedownloadview", "retired legacy IE tool"),
    ("iepassview", "retired legacy IE credential tool"),
    ("urlstringgrabber", "retired legacy IE/Opera tool"),
    ("favoritesview", "retired legacy IE tool"),
    ("webvideocap", "retired legacy Flash/IE tool"),
    ("flashcookiesview", "retired legacy Flash tool"),
    ("rtmpdumphelper", "retired legacy Flash/RTMP hook tool"),
    ("activexhelper", "retired legacy ActiveX tool"),
    ("win9xpv", "retired legacy Win9x tool"),
    ("9xprotect", "retired legacy Win9x tool"),
    ("msnpass", "retired legacy MSN tool"),
    ("messenpass", "retired legacy IM tool"),
    ("skypelogview", "retired legacy Skype tool"),
    ("skypecontactsview", "retired legacy Skype tool"),
    ("pcanywherecif", "retired legacy pcANYWHERE tool"),
    ("accesspassview", "retired legacy Access tool"),
    ("accesspv", "retired legacy Access tool"),
    ("oeview", "retired legacy Outlook Express tool"),
    ("dbxtract", "retired legacy Outlook Express tool"),
    ("wlmpv", "retired legacy Windows Live Mail tool"),
    ("netscapecacheview", "retired legacy Netscape tool"),
    ("nshistoryview", "retired legacy Netscape tool"),
    ("paltalkpass", "retired legacy IM tool"),
    ("mirandapass", "retired legacy IM tool"),
    ("trillianpass", "retired legacy IM tool"),
    ("pidginpass", "retired legacy IM tool"),
    ("googletalkpass", "retired legacy IM tool"),
    ("gizmopass", "retired legacy IM tool"),
    ("icqpass", "retired legacy IM tool"),
    ("aimpass", "retired legacy IM tool"),
    ("winupdateslist", "retired legacy WinXP updates tool"),
    ("drwatsonlogview", "retired legacy DrWatson tool"),
    ("livecontactsview", "retired legacy Windows Live tool"),
    ("winmailpass", "retired legacy Windows Mail tool"),
    ("silverlightcache", "retired legacy Silverlight tool"),
    ("javacacheview", "retired legacy Java plugin tool"),
    ("siteshoter", "retired legacy IE Trident tool"),
    ("htmldocedit", "retired legacy IE Trident tool"),
    ("systrayrefresh", "retired legacy Win9x/XP tray tool"),
    ("taskbarhide", "retired legacy Win9x/XP tray tool"),
    ("indexdatview", "retired legacy IE index.dat tool"),
    ("smartftp", "retired legacy FTP credential tool"),
    ("cuteftp", "retired legacy FTP credential tool"),
    ("flashfxp", "retired legacy FTP credential tool"),
];

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name == "target" || name == ".git" {
                continue;
            }
            collect_files(&path, out);
        } else if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
            if file_name == "r4_compliance.rs" {
                continue;
            }
            if file_name == "Cargo.toml" || path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
}

fn scan_text(label: &str, text: &str, violations: &mut Vec<String>) {
    let lower = text.to_ascii_lowercase();
    for (pattern, reason) in FORBIDDEN_PATTERNS {
        if lower.contains(pattern) {
            violations.push(format!("{label}: matched '{pattern}' ({reason})"));
        }
    }
}

#[test]
fn r4_workspace_manifests_sources_and_mcp_registry_are_compliant() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();

    let mut files = vec![workspace_root.join("Cargo.toml")];
    collect_files(&workspace_root.join("crates"), &mut files);
    assert!(
        files.len() >= 20,
        "expected >= 20 Cargo.toml/.rs files, got {}",
        files.len()
    );

    let mut violations = Vec::new();
    for path in &files {
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        scan_text(&path.display().to_string(), &content, &mut violations);
    }

    let wiring = build_synthetic_suite_wiring();
    assert_eq!(wiring.providers.len(), 24);
    assert_eq!(wiring.actions.len(), 8);

    for p in &wiring.providers {
        scan_text(&format!("provider:{}", p.tool_id()), p.tool_id(), &mut violations);
        scan_text(
            &format!("provider_desc:{}", p.tool_id()),
            p.description(),
            &mut violations,
        );
    }
    for a in &wiring.actions {
        scan_text(&format!("action:{}", a.command_id()), a.command_id(), &mut violations);
        scan_text(
            &format!("action_desc:{}", a.command_id()),
            a.description(),
            &mut violations,
        );
    }

    assert!(
        violations.is_empty(),
        "R4 compliance violations found:\n{}",
        violations.join("\n")
    );
}
