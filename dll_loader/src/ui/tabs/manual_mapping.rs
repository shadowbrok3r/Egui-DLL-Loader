use eframe::egui::*;

impl crate::PluginApp {
    pub fn manual_mapping_page_controls(&mut self, ui: &mut eframe::egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Manual Mapping with IAT Fixups");
            ui.add_space(20.);
            if ui.button(RichText::new("Manual Map").color(Color32::LIGHT_GREEN)).clicked() {
                if let (Some(_function), Some(_plugin)) = (&self.selected_function, &self.selected_plugin) {
                    if let Some(_pid) = self.target_pid {
                        // let plugin_dir = self.plugin_dir.clone();
                        // let tx = self.tx.clone();
                        // let plugin = plugin.clone();
                        // let function = function.clone();
                        // tokio::spawn(async move {
                        //     match unsafe { PluginApp::inject_manual_map(pid, &plugin_dir, &plugin, &function) }.await {
                        //         Ok(()) => {
                        //             tx.send(format!("Manual mapped into PID {}", pid)).ok();
                        //         }
                        //         Err(e) => {
                        //             tx.send(e.to_string()).ok();
                        //         }
                        //     }
                        // });
                    } else {
                        self.open_warning_modal = true;
                    }
                } else {
                    self.open_warning_modal = true;
                }
            }
        });
    }
}
