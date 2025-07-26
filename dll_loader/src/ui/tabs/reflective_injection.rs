use crate::PluginApp;
use eframe::egui::*;
impl PluginApp {
    pub fn reflective_injection_page_controls(&mut self, ui: &mut eframe::egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Reflective DLL Injection");
            ui.add_space(20.);
            if ui.button(RichText::new("Inject Reflectively").color(Color32::LIGHT_BLUE)).clicked() {
                if let (Some(function), Some(plugin)) = (&self.selected_function, &self.selected_plugin) {
                    if let Some(pid) = self.target_pid {
                        let plugin_dir = self.plugin_dir.clone();
                        let plugin = plugin.clone();
                        let function = function.clone();
                        tokio::spawn(async move {
                            match unsafe { PluginApp::inject_reflective_dll(pid, &plugin_dir, &plugin, &function) }.await {
                                Ok(()) => log::info!("Reflectively injected into PID {pid}"),
                                Err(e) => log::error!("Error: {e:?}")
                            }
                        });
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