use eframe::egui::*;
impl crate::PluginApp {
    pub fn process_hollowing_page_controls(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Process to hollow: ");
            ui.text_edit_singleline(&mut self.process_to_hollow);
            ui.add_space(10.);
            if ui.button("...").clicked() { self.process_to_hollow_file_dialog.pick_file(); }
            if let Some(path) = self.process_to_hollow_file_dialog.take_picked() {
                self.process_to_hollow = format!("{}", path.to_string_lossy());
            }

            ui.add_space(27.);

            if ui.button(RichText::new("Hollow Process 2").color(Color32::LIGHT_RED)).clicked() {
                if let Some(plugin) = &self.selected_plugin {
                    let exe_path = self.process_to_hollow.clone();
                    if exe_path.is_empty() { self.open_warning_modal = true; }
                    let plugin_dir = self.plugin_dir.clone();
                    let plugin = plugin.clone();
                    let pid_tx = self.pid_tx.clone();

                    if let Some(function) = &self.selected_function && plugin.ends_with("dll") {
                        let function = function.clone();
                        std::thread::spawn(move || {
                            // 1. Create suspended process
                            let process_info = unsafe { crate::PluginApp::get_process_info(&exe_path) };
                            match process_info {
                                Ok((proc_info, h_process_all)) => {
                                    let _ = pid_tx.send(sysinfo::Pid::from_u32(proc_info.dwProcessId));
                                    // 2. Read DLL data
                                    let dll_path = format!("{}\\{}", plugin_dir, plugin);
                                    let dll_data = match std::fs::read(&dll_path) {
                                        Ok(d) => d,
                                        Err(e) => {
                                            log::error!("Failed to read DLL: {e:?}");
                                            return;
                                        }
                                    };
                                    // 3. Inject DLL into hollowed process (calls export before resuming main thread)
                                    let inject_result = unsafe {
                                        crate::PluginApp::inject_hollowed_process_improved(
                                            &dll_data,
                                            h_process_all,
                                            &function,
                                            proc_info.hThread,
                                        )
                                    };
                                    match inject_result {
                                        Ok(()) => log::error!("Successfully injected and called export '{function}' in hollowed process"),
                                        Err(e) => log::error!("Process hollowing failed: {e}")
                                    }
                                },
                                Err(e) => log::error!("Failed to create suspended process: {e}")
                            }
                        });
                    } else if plugin.ends_with("exe") {
                        std::thread::spawn(move || {
                            use std::fs;
                            let exe_path = exe_path.clone();
                            let plugin_path = format!("{}\\{}", plugin_dir, plugin);
                            log::info!("Reading {plugin_path}");
                            let pe_data = match fs::read(&plugin_path) {
                                Ok(d) => d,
                                Err(e) => {
                                    log::error!("Failed to read EXE: {e}");
                                    return;
                                }
                            };

                            match unsafe { crate::PluginApp::hollow_process_with_exe2(&pe_data, &exe_path) } {
                                Ok(pid) => {
                                    let _ = pid_tx.send(sysinfo::Pid::from_u32(pid));
                                    log::info!("Successfully hollowed process with EXE '{plugin}' (PID: {pid})");
                                },
                                Err(e) => log::error!("Process hollowing with EXE failed: {e}")
                            }
                        });
                    }
                    
                } else { self.open_warning_modal = true; }
            }
            ui.add_space(5.);
            if ui.button(RichText::new("Hollow Process 3").color(Color32::LIGHT_BLUE)).clicked() {
                if let Some(plugin) = &self.selected_plugin {
                    let exe_path = self.process_to_hollow.clone();
                    if exe_path.is_empty() { self.open_warning_modal = true; }
                    let plugin_dir = self.plugin_dir.clone();
                    let plugin = plugin.clone();
                    let pid_tx = self.pid_tx.clone();

                    if plugin.ends_with("exe") {
                        std::thread::spawn(move || {
                            use std::fs;
                            let exe_path = exe_path.clone();
                            let plugin_path = format!("{}\\{}", plugin_dir, plugin);
                            log::info!("Reading {plugin_path}");
                            let pe_data = match fs::read(&plugin_path) {
                                Ok(d) => d,
                                Err(e) => {
                                    log::error!("Failed to read EXE: {e}");
                                    return;
                                }
                            };

                            match unsafe { crate::PluginApp::hollow_process_with_exe3(&pe_data, &exe_path) } {
                                Ok(pid) => {
                                    let _ = pid_tx.send(sysinfo::Pid::from_u32(pid));
                                    log::info!("Successfully hollowed process with EXE '{plugin}' (PID: {pid})");
                                },
                                Err(e) => log::error!("Process hollowing with EXE failed: {e}")
                            }
                        });
                    }
                    
                } else { self.open_warning_modal = true; }
            }

            if ui.button(RichText::new("Hollow Process Original").color(Color32::LIGHT_BLUE)).clicked() {
                if let Some(plugin) = &self.selected_plugin {
                    let exe_path = self.process_to_hollow.clone();
                    if exe_path.is_empty() { self.open_warning_modal = true; }
                    let plugin_dir = self.plugin_dir.clone();
                    let plugin = plugin.clone();
                    let pid_tx = self.pid_tx.clone();

                    if plugin.ends_with("exe") {
                        std::thread::spawn(move || {
                            use std::fs;
                            let exe_path = exe_path.clone();
                            let plugin_path = format!("{}\\{}", plugin_dir, plugin);
                            log::info!("Reading {plugin_path}");
                            let pe_data = match fs::read(&plugin_path) {
                                Ok(d) => d,
                                Err(e) => {
                                    log::error!("Failed to read EXE: {e}");
                                    return;
                                }
                            };

                            match unsafe { crate::PluginApp::hollow_process_with_exe_original(&pe_data, &exe_path) } {
                                Ok(pid) => {
                                    let _ = pid_tx.send(sysinfo::Pid::from_u32(pid));
                                    log::info!("Successfully hollowed process with EXE '{plugin}' (PID: {pid})");
                                },
                                Err(e) => log::error!("Process hollowing with EXE failed: {e}")
                            }
                        });
                    }
                    
                } else { self.open_warning_modal = true; }
            }
        });
    }

    pub fn process_hollowing(&mut self, ui: &mut Ui) {
        ui.columns(2, |ui| {
            ui[0].vertical_centered(|ui| {
                ui.heading("Available Plugins");
                ui.separator();
            });
            ui[0].vertical_centered(|ui| {
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
            });
            ui[1].vertical_centered(|ui| {
                ui.heading("Available Functions");
                ui.separator();
            });
            ui[1].vertical_centered(|ui| {
                ScrollArea::both()
                .auto_shrink(true)
                .max_height(200.)
                .id_salt(Id::new("Available Functions List"))
                .show(ui, |ui| {
                    let exported = self.exported_functions.clone();
                    for export in exported.iter() {
                        ui.horizontal(|ui| {
                            if ui.radio_value(&mut self.selected_function, Some(export.name.clone()), RichText::new(&export.name).color(Color32::LIGHT_GREEN)).clicked() {
                                log::error!("Selected Function: {}", export.name);
                            }
                        });
                    }
                });
            });
        });

        ui.columns(2, |ui| {
            if !self.process_to_hollow.is_empty() {
                ui[0].vertical_centered(|ui| {
                    ScrollArea::vertical()
                    .auto_shrink(true)
                    .max_width(ui.available_width()/1.1)
                    .id_salt(Id::new("Selected Victim scroll area"))
                    .show(ui, |ui| {
                        // Try to parse victim PE info and display
                        if let Ok(victim_exports) = crate::PluginApp::get_exports_x64(&self.process_to_hollow) {
                            if let Some(victim) = victim_exports.first() {
                                CollapsingHeader::new(RichText::new(format!("Victim PE: {}", self.process_to_hollow)).color(Color32::LIGHT_GREEN))
                                .show(ui, |ui| {
                                    let width = ui.available_width() / 4.5;
                                    ui.columns(2, |ui| {
                                        ui[0].group(|ui| {
                                            ScrollArea::vertical()
                                            .auto_shrink(true)
                                            .max_width(ui.available_width()/2.05)
                                            .max_height(500.)
                                            .id_salt(Id::new(format!("{} {} Victim Grid ScrollArea", victim.name, victim.virtual_address)))
                                            .show(ui, |ui| {
                                                Grid::new(format!("{} {} Victim Grid", victim.name, victim.virtual_address))
                                                .min_col_width(width)
                                                .show(ui, |ui| {
                                                    ui.colored_label(Color32::LIGHT_GREEN, "Virtual Addr:"); 
                                                    ui.label(format!("{:#X}", victim.virtual_address)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::LIGHT_BLUE, "Offset:"); 
                                                    ui.label(format!("{:#X}", victim.offset)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::from_rgb(155, 10, 155), "RVA:"); 
                                                    ui.label(format!("{:#X}", victim.rva)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Image Base:"); 
                                                    ui.label(format!("{:#X}", victim.image_base)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Size of Image:"); 
                                                    ui.label(format!("{:#X}", victim.size_of_image)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Size of Headers:"); 
                                                    ui.label(format!("{:#X}", victim.size_of_headers)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Entry Point RVA:"); 
                                                    ui.label(format!("{:#X}", victim.entry_point)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Machine:"); 
                                                    ui.label(format!("{:#X}", victim.machine)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Sections:"); 
                                                    ui.label(format!("{:#X}", victim.number_of_sections)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Subsystem:"); 
                                                    ui.label(format!("{:#X}", victim.subsystem)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "DLL Characteristics:"); 
                                                    ui.label(format!("{:#X}", victim.dll_characteristics)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::YELLOW, "Timestamp:"); 
                                                    ui.label(format!("{:#X}", victim.timestamp)); 
                                                    ui.end_row();
                                                });
                                            });
                                        });
                                        if !victim.export_info.is_empty() {
                                            ui[1].group(|ui| {
                                                ScrollArea::vertical()
                                                .auto_shrink(true)
                                                .max_width(ui.available_width()/2.05)
                                                .max_height(500.)
                                                .id_salt(Id::new(format!("{} {} Victim Export Grid ScrollArea", victim.name, victim.virtual_address)))
                                                .show(ui, |ui| {
                                                    Grid::new(format!("Victim Export Grid {}", victim.name))
                                                    .min_col_width(width)
                                                    .show(ui, |ui| {
                                                        ui.label("Exports"); 
                                                        ui.label("");
                                                        ui.end_row();
                                                        for expf in &victim.export_info {
                                                            ui.label(expf.name.clone().unwrap_or_default());
                                                            ui.colored_label(Color32::LIGHT_GREEN, format!("RVA: {:#X}", expf.rva));
                                                            ui.end_row();
                                                        }
                                                    });
                                                });
                                            });
                                        }
                                    });
                                    
                                    ui.columns(2, |ui| {
                                        if !victim.section_info.is_empty() {
                                            ui[0].group(|ui| {
                                                ScrollArea::vertical()
                                                .auto_shrink(true)
                                                .max_height(500.)
                                                .max_width(ui.available_width()/2.05)
                                                .id_salt(Id::new(format!("{} {} Victim Section Info Grid ScrollArea", victim.name, victim.virtual_address)))
                                                .show(ui, |ui| {
                                                    ui.heading("Sections"); 
                                                    Grid::new(format!("Export Section Info Grid"))
                                                    .min_col_width(ui.available_width()/5.1)
                                                    .show(ui, |ui| {
                                                        ui.colored_label(Color32::LIGHT_BLUE, "Name");
                                                        ui.colored_label(Color32::LIGHT_BLUE, "Virtual Addr");
                                                        ui.colored_label(Color32::LIGHT_BLUE, "Virtual Addr Size");
                                                        ui.colored_label(Color32::LIGHT_BLUE, "Raw Size");
                                                        ui.colored_label(Color32::LIGHT_BLUE, "Characteristics");
                                                        ui.end_row();
                                                        for sec in &victim.section_info {
                                                            ui.label(sec.name.clone());
                                                            ui.label(format!("{:#X}", sec.virtual_address));
                                                            ui.label(format!("{:#X}", sec.virtual_size));
                                                            ui.label(format!("{:#X}", sec.raw_size));
                                                            ui.label(format!("{:#X}", sec.characteristics));
                                                            ui.end_row();
                                                        }
                                                    });
                                                });
                                            });
                                        }
                                        if let Some(tls) = &victim.tls_info {
                                            ui[1].group(|ui| {
                                                Grid::new(format!("TLS victim info grid "))
                                                .min_col_width(width)
                                                .show(ui, |ui| {
                                                    ui.colored_label(Color32::BLUE, "TLS Info");
                                                    ui.label("");
                                                    ui.end_row();
                                                    ui.colored_label(Color32::LIGHT_BLUE, "TLS Start Raw");
                                                    ui.label(format!("{:#X}", tls.start_address_of_raw_data)); 
                                                    ui.end_row();
                                                    ui.colored_label(Color32::LIGHT_BLUE, "TLS End Raw");
                                                    ui.label(format!("{:#X}", tls.end_address_of_raw_data));
                                                    ui.end_row();
                                                    ui.colored_label(Color32::LIGHT_BLUE, "TLS Index");
                                                    ui.label(format!("{:#X}", tls.address_of_index));
                                                    ui.end_row();
                                                    ui.colored_label(Color32::LIGHT_BLUE, "TLS Callbacks");
                                                    ui.label(format!("{:#X}", tls.address_of_callbacks));
                                                    ui.end_row();
                                                });
                                            });
                                        }
                                    });
                                });
                            }
                        }
                    });
                });
            }
            if let Some(selected_fn) = &self.selected_function {
                ui[1].vertical_centered(|ui| {
                    ScrollArea::vertical()
                    .auto_shrink(true)
                    .max_width(ui.available_width()/1.1)
                    .id_salt(Id::new("Selected plugin scroll area"))
                    .show(ui, |ui| {
                        let export = self.exported_functions.iter().find(|f| f.name == *selected_fn);
                        if let Some(export) = export {
                            CollapsingHeader::new(RichText::new(format!("Selected Plugin: {}", selected_fn)).color(Color32::LIGHT_GREEN))
                            .show(ui, |ui| {
                                let width = ui.available_width() / 4.5;
                                ui.columns(2, |ui| {
                                    ui[0].group(|ui| {
                                        ScrollArea::vertical()
                                        .auto_shrink(true)
                                        .max_height(500.)
                                        .max_width(ui.available_width()/2.05)
                                        .id_salt(Id::new(format!("{} {} export Grid ScrollArea", export.name, export.virtual_address)))
                                        .show(ui, |ui| {
                                            Grid::new(format!("{} {} export Grid", export.name, export.virtual_address))
                                            .min_col_width(width)
                                            .show(ui, |ui| {
                                                ui.colored_label(Color32::LIGHT_GREEN, "Virtual Addr:"); 
                                                ui.label(format!("{:#X}", export.virtual_address)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::LIGHT_BLUE, "Offset:"); 
                                                ui.label(format!("{:#X}", export.offset)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::from_rgb(155, 10, 155), "RVA:"); 
                                                ui.label(format!("{:#X}", export.rva)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Image Base:"); 
                                                ui.label(format!("{:#X}", export.image_base)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Size of Image:"); 
                                                ui.label(format!("{:#X}", export.size_of_image)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Size of Headers:"); 
                                                ui.label(format!("{:#X}", export.size_of_headers)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Entry Point RVA:"); 
                                                ui.label(format!("{:#X}", export.entry_point)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Machine:"); 
                                                ui.label(format!("{:#X}", export.machine)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Sections:"); 
                                                ui.label(format!("{:#X}", export.number_of_sections)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Subsystem:"); 
                                                ui.label(format!("{:#X}", export.subsystem)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "DLL Characteristics:"); 
                                                ui.label(format!("{:#X}", export.dll_characteristics)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::YELLOW, "Timestamp:"); 
                                                ui.label(format!("{:#X}", export.timestamp)); 
                                                ui.end_row();
                                            });
                                        });
                                    });
                                    if !export.export_info.is_empty() {
                                        ui[1].group(|ui| {
                                            ScrollArea::vertical()
                                            .auto_shrink(true)
                                            .max_width(ui.available_width()/2.05)
                                            .max_height(500.)
                                            .id_salt(Id::new(format!("{} {} export Export Grid ScrollArea", export.name, export.virtual_address)))
                                            .show(ui, |ui| {
                                                Grid::new(format!("export Export Grid {}", export.name))
                                                .min_col_width(width)
                                                .show(ui, |ui| {
                                                    ui.label("Exports"); 
                                                    ui.label("");
                                                    ui.end_row();
                                                    for expf in &export.export_info {
                                                        ui.label(expf.name.clone().unwrap_or_default());
                                                        ui.colored_label(Color32::LIGHT_GREEN, format!("RVA: {:#X}", expf.rva));
                                                        ui.end_row();
                                                    }
                                                });
                                            });
                                        });
                                    }
                                });
                                
                                ui.columns(2, |ui| {
                                    if !export.section_info.is_empty() {
                                        ui[0].group(|ui| {
                                            ScrollArea::vertical()
                                            .auto_shrink(true)
                                            .max_height(500.)
                                            .max_width(ui.available_width()/2.05)
                                            .id_salt(Id::new(format!("{} {} export Section Info Grid ScrollArea", export.name, export.virtual_address)))
                                            .show(ui, |ui| {
                                                ui.heading("Sections"); 
                                                Grid::new(format!("Export Section Info Grid"))
                                                .min_col_width(ui.available_width()/5.1)
                                                .show(ui, |ui| {
                                                    ui.colored_label(Color32::LIGHT_BLUE, "Name");
                                                    ui.colored_label(Color32::LIGHT_BLUE, "Virtual Addr");
                                                    ui.colored_label(Color32::LIGHT_BLUE, "Virtual Addr Size");
                                                    ui.colored_label(Color32::LIGHT_BLUE, "Raw Size");
                                                    ui.colored_label(Color32::LIGHT_BLUE, "Characteristics");
                                                    ui.end_row();
                                                    for sec in &export.section_info {
                                                        ui.label(sec.name.clone());
                                                        ui.label(format!("{:#X}", sec.virtual_address));
                                                        ui.label(format!("{:#X}", sec.virtual_size));
                                                        ui.label(format!("{:#X}", sec.raw_size));
                                                        ui.label(format!("{:#X}", sec.characteristics));
                                                        ui.end_row();
                                                    }
                                                });
                                            });
                                        });
                                    }
                                    if let Some(tls) = &export.tls_info {
                                        ui[1].group(|ui| {
                                            Grid::new(format!("TLS export info grid "))
                                            .min_col_width(width)
                                            .show(ui, |ui| {
                                                ui.colored_label(Color32::BLUE, "TLS Info");
                                                ui.label("");
                                                ui.end_row();
                                                ui.colored_label(Color32::LIGHT_BLUE, "TLS Start Raw");
                                                ui.label(format!("{:#X}", tls.start_address_of_raw_data)); 
                                                ui.end_row();
                                                ui.colored_label(Color32::LIGHT_BLUE, "TLS End Raw");
                                                ui.label(format!("{:#X}", tls.end_address_of_raw_data));
                                                ui.end_row();
                                                ui.colored_label(Color32::LIGHT_BLUE, "TLS Index");
                                                ui.label(format!("{:#X}", tls.address_of_index));
                                                ui.end_row();
                                                ui.colored_label(Color32::LIGHT_BLUE, "TLS Callbacks");
                                                ui.label(format!("{:#X}", tls.address_of_callbacks));
                                                ui.end_row();
                                            });
                                        });
                                    }
                                });
                                
                                if !export.import_info.is_empty() {
                                    ScrollArea::vertical()
                                    .auto_shrink(true)
                                    .max_height(500.)
                                    .max_width(ui.available_width()/2.05)
                                    .id_salt(Id::new(format!("{} {} export Imports Grid ScrollArea", export.name, export.virtual_address)))
                                    .show(ui, |ui| {
                                        ui.heading("Imports");
                                        Grid::new("Export Imports Grid")
                                        .min_col_width(width)
                                        .show(ui, |ui| {
                                            ui.label("DLL");
                                            ui.label("Functions");
                                            ui.end_row();
                                            for imp in &export.import_info {
                                                let mut first = true;
                                                for function in &imp.functions {
                                                    if first {
                                                        ui.colored_label(Color32::PURPLE, imp.dll.clone());
                                                        first = false;
                                                    } else {
                                                        ui.label("");
                                                    }
                                                    ui.label(function);
                                                    ui.end_row();
                                                }
                                            }
                                        });
                                    });
                                }
                            });
                        }
                    });
                });
            }
        });
    }
}