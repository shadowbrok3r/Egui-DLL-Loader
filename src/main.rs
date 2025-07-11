use dll_syringe::{Syringe, process::OwnedProcess};
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::WindowsProgramming::*;
use windows::Win32::System::SystemInformation::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;
use eframe::egui::{self, Id, ScrollArea};
use sysinfo::{System, ProcessesToUpdate};
use windows::Win32::System::Memory::*;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::*;
use windows_strings::PCSTR;
use windows_strings::PSTR;
use windows::core::BOOL;
use std::fs::read_dir;
use tokio::sync::mpsc;

pub mod processes;
pub mod inject;

pub struct PluginApp {
    pub plugin_dir: String,
    pub plugins: Vec<String>,
    pub load_err: Vec<String>,
    pub selected_plugin: Option<String>,
    pub processes: Vec<(String, sysinfo::Pid)>,
    pub system: System,
    pub last_refresh: Instant,
    pub custom_path: String,
    pub tx: mpsc::Sender<String>,
    pub rx: mpsc::Receiver<String>,
}

impl PluginApp {
    fn new() -> Self {
        let default_dir = "C:\\Users\\shadowbroker\\Desktop\\injector\\target\\release".to_string();
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);
        let mut processes = system
            .processes()
            .iter()
            .map(|(pid, proc_)| (proc_.name().to_string_lossy().into_owned(), *pid))
            .collect::<Vec<_>>();
        processes.sort_by(|(a, _), (b, _)| a.cmp(b));
        let (tx, rx) = mpsc::channel(32);
        Self {
            plugin_dir: default_dir.clone(),
            plugins: Vec::new(),
            load_err: Vec::new(),
            selected_plugin: None,
            processes,
            system,
            last_refresh: Instant::now(),
            custom_path: default_dir,
            tx,
            rx,
        }
    }

    fn scan_plugins(&mut self) {
        self.plugins.clear();
        if let Ok(entries) = read_dir(&self.plugin_dir) {
            self.plugins = entries
                .filter_map(|e| {
                    let path = e.ok()?.path();
                    if path.extension().map(|e| e == "dll").unwrap_or(false) {
                        path.file_name()?.to_str().map(String::from)
                    } else {
                        None
                    }
                })
                .collect();
        }
    }

    fn get_export_rva(data: &[u8], function_name: &str) -> Result<u32, String> {
        // Similar parsing as get_exports
        // ...
        let e_lfanew = // ...
        // ...
        let export_rva = // ...
        // ...
        let number_of_names = // ...
        let address_of_names = // ...
        let address_of_name_ordinals = u32::from_le_bytes([data[export_rva + 36], data[export_rva + 37], data[export_rva + 38], data[export_rva + 39]]) as usize;
        let address_of_functions = u32::from_le_bytes([data[export_rva + 28], data[export_rva + 29], data[export_rva + 30], data[export_rva + 31]]) as usize;
        for i in 0..number_of_names {
            let name_rva = u32::from_le_bytes([data[address_of_names + i*4], // ...
            let name = // ...
            if name == function_name {
                let ordinal = u16::from_le_bytes([data[address_of_name_ordinals + i*2], data[address_of_name_ordinals + i*2 + 1]]) as usize;
                let rva = u32::from_le_bytes([data[address_of_functions + ordinal*4], // ...
                return Ok(rva);
            }
        }
        Err("Function not found".to_string())
    }


}

impl eframe::App for PluginApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed() >= Duration::from_secs(1) {
            self.scan_processes();
            self.last_refresh = Instant::now();
        }
        while let Ok(msg) = self.rx.try_recv() {
            self.load_err.push(msg);
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.columns(2, |ui| {
                ui[0].vertical_centered(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Custom Plugin Path:");
                        ui.text_edit_singleline(&mut self.custom_path);
                    });
                    if ui.button("Set Path").clicked() {
                        self.plugin_dir = if self.custom_path.is_empty() {
                            "C:\\Users\\shadowbroker\\Desktop\\injector\\target\\release".to_string()
                        } else {
                            self.custom_path.clone()
                        };
                        self.scan_plugins();
                    }
                    if ui.button("Scan Plugins").clicked() {
                        self.scan_plugins();
                    }
                    ui.label("Available Plugins:");
                    for plugin in &self.plugins {
                        if ui.radio_value(&mut self.selected_plugin, Some(plugin.clone()), plugin).clicked() {
                            self.selected_plugin = Some(plugin.clone());
                        }
                    }

                    if ui.button("Scan Processes").clicked() {
                        self.scan_processes();
                    }
                    ui.heading("Available Processes:");

                });

                ScrollArea::vertical()
                .auto_shrink(false)
                .id_salt(Id::new("Processes"))
                .show(&mut ui[0], |ui| {
                    let process = self.processes.clone();
                    for (name, pid) in &process {
                        if ui.button(format!("{} (PID: {})", name, pid)).clicked() {
                            let plugs = self.selected_plugin.clone();
                            let tx = self.tx.clone();
                            let plugin_dir = self.plugin_dir.clone();
                            let pid = *pid;
                            if let Some(plugin) = plugs {
                                tokio::spawn(async move {
                                    match unsafe { PluginApp::inject_dll(pid, plugin_dir, plugin) }.await {
                                        Ok(()) => {
                                            tx.send(format!("Injected into PID {}", pid)).await.ok();
                                        }
                                        Err(e) => {
                                            println!("Error: {e:?}");
                                            tx.send(e).await.ok();
                                        }
                                    }
                                    // match unsafe { PluginApp::hollow_and_inject(pid, plugin_dir, plugin) }.await {
                                    //     Ok(()) => {
                                    //         tx.send(format!("Injected into PID {}", pid)).await.ok();
                                    //     }
                                    //     Err(e) => {
                                    //         println!("Error: {e:?}");
                                    //         tx.send(e).await.ok();
                                    //     }
                                    // }
                                });
                            } else {
                                self.load_err.push("No plugin selected".to_string());
                            }
                        }
                    }
                });
                ui[1].vertical_centered(|ui| {
                    ui.heading("Messages:");
                });
                ScrollArea::vertical()
                .auto_shrink(false)
                .id_salt(Id::new("Error messages"))
                .show(&mut ui[1], |ui| {
                    for err in self.load_err.iter() {
                        ui.label(err.clone());
                        ui.separator();
                    }
                });
            });
        });
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
        }
    }

    let app = PluginApp::new();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Plugin App",
        native_options,
        Box::new(|_| Ok(Box::new(app))),
    )
}