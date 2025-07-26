pub mod pe_helpers;
pub mod reflective;
pub mod processes;
pub mod pe_types;
pub mod inject;
pub mod hollow;
pub mod ui;

pub use pe_types::*;

pub struct PluginApp {
    pub plugin_dir: String,
    pub plugins: Vec<String>,
    pub selected_plugin: Option<String>,
    pub processes: Vec<(String, sysinfo::Pid)>,
    pub target_pid: Option<sysinfo::Pid>,
    pub system: sysinfo::System,
    pub pid_tx: crossbeam::channel::Sender<sysinfo::Pid>,
    pub pid_rx: crossbeam::channel::Receiver<sysinfo::Pid>,
    pub exported_functions: Vec<pe_types::ExportInfo>,
    pub selected_function: Option<String>,
    pub process_to_hollow: String,
    process_to_hollow_file_dialog: egui_file_dialog::FileDialog,
    plugin_dir_file_dialog: egui_file_dialog::FileDialog,
    open_warning_modal: bool,
    first_run: bool,
    process_search_string: String,
    current_page: ui::tabs::InjectionPage,
    open_log_window: bool,
    evasion_mode: bool,
    thread_hijack_mode: bool,
}

impl PluginApp {
    fn new() -> Self {
        let default_dir = "../target/release".to_string();
        // let cwd = std::env::current_dir().unwrap_or_default();
        let mut system = sysinfo::System::new_all();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let mut processes = system
            .processes()
            .iter()
            .map(|(pid, proc_)| (proc_.name().to_string_lossy().into_owned(), *pid))
            .collect::<Vec<_>>();
        processes.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut plugins = vec![];
        if let Ok(entries) = std::fs::read_dir(&default_dir) {
            plugins = entries
                .filter_map(|e| {
                    let path = e.ok()?.path();
                    if path.extension().map(|e| e == "dll" || e == "exe").unwrap_or(false) {
                        path.file_name()?.to_str().map(String::from)
                    } else {
                        None
                    }
                })
                .collect();
        }

        let (pid_tx, pid_rx) = crossbeam::channel::unbounded();

        Self {
            plugin_dir: default_dir,
            selected_plugin: None,
            open_log_window: false,
            plugins,
            processes,
            system,
            target_pid: None,
            pid_tx, pid_rx,
            exported_functions: Vec::new(),
            selected_function: None,
            process_to_hollow: "C:\\Windows\\notepad.exe".to_string(),
            process_to_hollow_file_dialog: egui_file_dialog::FileDialog::new()
                .show_hidden_option(true)
                .initial_directory("C:\\".into())
                .add_file_filter_extensions("Targets", vec!["exe"])
                .default_file_filter("Targets")
                .show_search(true),
            plugin_dir_file_dialog: egui_file_dialog::FileDialog::new()
                .show_hidden_option(true)
                .initial_directory("C:\\".into())
                .add_file_filter_extensions("Plugins", vec!["exe", "dll"])
                .default_file_filter("Plugins")
                .show_search(true),
            open_warning_modal: false,
            first_run: true,
            process_search_string: String::new(),
            current_page: ui::tabs::InjectionPage::ClassicInjection,
            evasion_mode: false,
            thread_hijack_mode: false,
        }
    }

    fn scan_plugins(&mut self) {
        self.plugins.clear();
        if let Ok(entries) = std::fs::read_dir(&self.plugin_dir) {
            self.plugins = entries
                .filter_map(|e| {
                    let path = e.ok()?.path();
                    if path.extension().map(|e| e == "dll" || e == "exe").unwrap_or(false) {
                        path.file_name()?.to_str().map(String::from)
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    {
        use windows::Win32::System::Threading::GetCurrentProcess;
        use windows::Win32::System::Threading::SetPriorityClass;
        use windows::Win32::System::Threading::ABOVE_NORMAL_PRIORITY_CLASS;
        unsafe {
            let _ = SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
            let enable_dbg_privelege = crate::pe_helpers::enable_debug_privilege();
            log::info!("enable_dbg_privelege: {enable_dbg_privelege:?}");
        }
    }

    let _ = egui_logger::builder()
    .max_level(simplelog::LevelFilter::Info)
    .init();

    let app = PluginApp::new();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "DLL Injector",
        native_options,
        Box::new(|_| Ok(Box::new(app))),
    )
}
