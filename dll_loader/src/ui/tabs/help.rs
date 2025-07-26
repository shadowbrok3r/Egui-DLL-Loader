use eframe::egui::*;

impl crate::PluginApp {
    pub fn help(&mut self, ui: &mut Ui) {
        // Help page content
        ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                ui.heading("🛠️ DLL Injection Techniques - Help Guide");
                ui.separator();
                ui.add_space(10.);

                // Classic Injection Help
                ui.colored_label(Color32::LIGHT_BLUE, "📘 Classic Injection");
                ui.label("Traditional DLL injection using CreateRemoteThread or thread hijacking.");
                ui.label("• What it does: Loads a DLL into a target process using the Windows loader");
                ui.label("• How to use: Select target process → Select DLL → Click arrow button");
                ui.label("• When to use: Standard injection, most compatible");
                ui.label("• Requirements: Target process must be running, DLL must be on disk");
                ui.add_space(10.);

                // Process Hollowing Help
                ui.colored_label(Color32::LIGHT_RED, "🔥 Process Hollowing");
                ui.label("Advanced technique that creates a suspended process and replaces its memory.");
                ui.label("• What it does: Creates a legitimate process, then replaces its code with your DLL");
                ui.label("• How to use: Enter executable path → Select DLL function → Click 'Hollow Process'");
                ui.label("• When to use: Stealth injection, bypassing some security measures");
                ui.label("• Requirements: Valid executable path, administrative privileges");
                ui.label("• Note: Creates a new process, not injecting into existing one");
                ui.add_space(10.);

                // Reflective Injection Help
                ui.colored_label(Color32::LIGHT_GREEN, "🌟 Reflective Injection");
                ui.label("Memory-only DLL loading without filesystem traces.");
                ui.label("• What it does: Manually loads DLL entirely in memory, bypassing Windows loader");
                ui.label("• How to use: Select target process → Select DLL → Navigate to Reflective tab → Click 'Inject Reflectively'");
                ui.label("• When to use: Avoid disk artifacts, advanced evasion");
                ui.label("• Requirements: Target process, properly crafted DLL");
                ui.label("• Note: DLL must be compatible with manual loading");
                ui.add_space(10.);

                // Manual Mapping Help
                ui.colored_label(Color32::YELLOW, "⚙️ Manual Mapping");
                ui.label("Complete PE mapping with comprehensive Import Address Table fixups.");
                ui.label("• What it does: Manually maps DLL sections, fixes relocations and imports");
                ui.label("• How to use: Select target process → Select DLL → Navigate to Manual Mapping → Click 'Manual Map'");
                ui.label("• When to use: Maximum control over injection process, bypass some hooks");
                ui.label("• Requirements: Target process, DLL with proper PE structure");
                ui.label("• Note: Most complex method, handles dependencies automatically");
                ui.add_space(15.);

                ui.separator();
                ui.heading("🔧 Additional Options");
                ui.add_space(10.);

                // AV Evasion Help
                ui.colored_label(Color32::GOLD, "🛡️ AV Evasion Mode");
                ui.label("Applies basic anti-analysis techniques before injection.");
                ui.label("• What it does: Random delays, VM detection, sandbox detection");
                ui.label("• When to use: Research environments, evasion testing");
                ui.label("• Note: Educational purposes only, may slow down injection");
                ui.add_space(10.);

                // Thread Hijacking Help
                ui.colored_label(Color32::LIGHT_GRAY, "🧵 Thread Hijacking");
                ui.label("Alternative to CreateRemoteThread using existing thread contexts.");
                ui.label("• What it does: Hijacks existing thread, modifies context to load DLL");
                ui.label("• When to use: Stealth injection, avoiding CreateRemoteThread detection");
                ui.label("• Note: More complex but potentially stealthier");
                ui.add_space(15.);

                ui.separator();
                ui.heading("📋 General Usage Instructions");
                ui.add_space(10.);

                ui.label("1. Set Plugin Path: Enter the directory containing your DLL files");
                ui.label("2. Scan: Click 'Scan' to load available DLL files");
                ui.label("3. Refresh Processes: Click to update the process list");
                ui.label("4. Select Target: Choose a target process from the left panel");
                ui.label("5. Select DLL: Choose a DLL from the right panel (this loads available functions)");
                ui.label("6. Select Function: Choose the exported function to call");
                ui.label("7. Choose Method: Select injection technique using the tabs");
                ui.label("8. Configure Options: Enable AV Evasion or Thread Hijacking if needed");
                ui.label("9. Execute: Use the appropriate button for your chosen method");
                ui.add_space(15.);

                ui.separator();
                ui.heading("⚠️ Important Notes");
                ui.add_space(10.);

                ui.colored_label(Color32::RED, "Security Requirements:");
                ui.label("• Administrator privileges required for most injection techniques");
                ui.label("• Target process must be accessible (same or lower privilege level)");
                ui.label("• Some antivirus software may flag this as malicious behavior");
                ui.add_space(10.);

                ui.colored_label(Color32::YELLOW, "Educational Purpose:");
                ui.label("• This tool is designed for educational and research purposes only");
                ui.label("• Use only on systems you own or have explicit permission to test");
                ui.label("• Respect all applicable laws and regulations");
                ui.add_space(10.);

                ui.colored_label(Color32::LIGHT_BLUE, "Troubleshooting:");
                ui.label("• If injection fails, check Messages panel for error details");
                ui.label("• Ensure DLL is compatible with target process architecture (x64/x86)");
                ui.label("• Try different injection methods if one fails");
                ui.label("• Verify target process is not protected by security software");
                ui.add_space(5.);
                
                ui.colored_label(Color32::from_rgb(255, 150, 150), "Common Error Solutions:");
                ui.label("• 'Access Denied': Run as Administrator, choose unprotected process");
                ui.label("• 'DLL not found': Verify file path, ensure DLL exists");
                ui.label("• 'Function not found': Check function is exported from DLL");
                ui.label("• 'VirtualAllocEx failed': Target process may be protected");
                ui.label("• Process Hollowing 'DLL not found': This is expected - function executed directly");
                ui.add_space(10.);

                ui.separator();
                ui.heading("🔍 Injection Method Comparison");
                ui.add_space(10.);

                ui.label("Stealth Level (Low to High):");
                ui.label("1. Classic Injection (Basic stealth)");
                ui.label("2. Manual Mapping (Medium stealth)");
                ui.label("3. Reflective Injection (High stealth)");
                ui.label("4. Process Hollowing (Highest stealth)");
                ui.add_space(10.);

                ui.label("Complexity Level (Low to High):");
                ui.label("1. Classic Injection (Easiest)");
                ui.label("2. Process Hollowing (Medium)");
                ui.label("3. Reflective Injection (Complex)");
                ui.label("4. Manual Mapping (Most Complex)");
                ui.add_space(20.);
            });
    }
}