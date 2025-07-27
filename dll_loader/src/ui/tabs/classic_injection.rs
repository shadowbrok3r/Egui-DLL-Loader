use crate::PluginApp;
use eframe::egui::*;

impl PluginApp {
    pub fn classic_injection(&mut self, ui: &mut Ui) {
        // Original layout for other pages
        ui.columns(2, |ui| {
            ui[0].vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.heading("Available Processes");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("Refresh").clicked() {
                            self.scan_processes();
                        }
                    });
                });
                ui.text_edit_singleline(&mut self.process_search_string);
                ui.separator();
            });
            ScrollArea::both()
            .auto_shrink(false)
            .id_salt(Id::new("Processes"))
            .show(&mut ui[0], |ui| {
                let process = self.processes.clone();
                
                let search = self.process_search_string.to_lowercase();
                for (name, pid) in process
                    .iter()
                    .filter(|(name, pid)| name.to_lowercase().contains(&search) || format!("{}", pid.as_u32()).contains(&search)) 
                {
                    ui.horizontal(|ui| {
                        ui.colored_label(ui.style().visuals.error_fg_color, format!("{}", pid.as_u32()));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button("⮫").clicked() {
                                let plugs = self.selected_plugin.clone();
                                let plugin_dir = self.plugin_dir.clone();
                                self.target_pid = Some(*pid);
                                let pid = *pid;
                                let current_page = self.current_page.clone();
                                let thread_hijack = self.thread_hijack_mode;
                                let evasion_mode = self.evasion_mode;
                                
                                if let (Some(plugin), Some(function)) = (plugs, self.selected_function.clone()) {
                                    tokio::spawn(async move {
                                        let result = match current_page {
                                            super::InjectionPage::ClassicInjection => {
                                                unsafe { PluginApp::inject_dll_with_options(pid, &plugin_dir, &plugin, &function, thread_hijack, evasion_mode) }.await
                                            }
                                            super::InjectionPage::ReflectiveInjection => {
                                                unsafe { PluginApp::inject_reflective_dll(pid, &plugin_dir, &plugin, &function) }.await
                                            }
                                            _ => { Err(anyhow::anyhow!("Try a different method")) }
                                        };
                                        
                                        match result {
                                            Ok(()) => log::info!("Injected into PID {pid}"),
                                            Err(e) => log::error!("Error: {e:?}")
                                        }
                                    });
                                } else {
                                    self.open_warning_modal = true;
                                }
                            }
                            ui.label(name);
                        });
                    });
                }
            });

            ui[1].vertical_centered(|ui| {
                ui.heading("Available Plugins");
                ui.separator();
                ScrollArea::vertical()
                .auto_shrink(true)
                .max_height(200.)
                .id_salt(Id::new("Available Plugins List"))
                .show(ui, |ui| {
                    let plugs = self.plugins.clone();
                    for plugin in plugs.iter() {
                        ui.horizontal(|ui| {
                            if ui.radio_value(&mut self.selected_plugin, Some(plugin.clone()), plugin).clicked() {
                                log::error!("Selected Plugin: {plugin}");
                                self.selected_plugin = Some(plugin.clone());
                                self.list_exports(); // <-- Parse and list exported functions
                            }
                        });
                    }
                });

                ui.heading("Available Functions");
                ui.separator();
                ScrollArea::both()
                .auto_shrink(true)
                .max_height(500.)
                .id_salt(Id::new("Available Functions List"))
                .show(ui, |ui| {
                    let exported = self.exported_functions.clone();
                    for export in exported.iter() {
                        ui.horizontal(|ui| {
                            if ui.button(RichText::new("Run").color(Color32::LIGHT_RED)).clicked() {
                                if let Some(pid) = self.target_pid {
                                    let plugin_name = self.selected_plugin.clone().unwrap();
                                    let path = format!("{}\\{}", self.plugin_dir, plugin_name);
                                    let function = export.name.clone();
                                    let pid = pid.as_u32();
                                    match unsafe { Self::call_exported_fn(plugin_name, path, function.clone(), pid) } {
                                        Ok(_) => log::info!("Called exported function: {function:?}"),
                                        Err(e) => log::error!("Error: {e:?}")
                                    }
                                } else {
                                    self.open_warning_modal = true;
                                }
                            }
                            if ui.radio_value(&mut self.selected_function, Some(export.name.clone()), RichText::new(&export.name).color(Color32::LIGHT_GREEN)).clicked() {
                                log::error!("Selected Function: {}", export.name);
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if export.virtual_address > 0 {
                                    ui.label(format!("{:#X}", export.virtual_address));
                                    ui.colored_label(Color32::LIGHT_GREEN, "Virtual Addr:");
                                }
                                
                                ui.label(format!("{:#X}", export.offset));
                                ui.colored_label(Color32::LIGHT_BLUE, "Offset:");

                                ui.label(format!("{:#X}", export.rva));
                                ui.colored_label(Color32::from_rgb(155, 10, 155), "RVA:");
                            });
                        });
                    }
                });
            });
        });
    }
}