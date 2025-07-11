use crate::PluginApp;


impl PluginApp {
    pub fn scan_processes(&mut self) {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        let mut processes = self
            .system
            .processes()
            .iter()
            .map(|(pid, proc_)| (proc_.name().to_string_lossy().into_owned(), *pid))
            .collect::<Vec<_>>();
        processes.sort_by(|(a, _), (b, _)| a.cmp(b));
        self.processes = processes;
    }

    pub fn list_exports(&mut self) {
        self.exported_functions.clear();
        if let Some(plugin) = &self.selected_plugin {
            let path = format!("{}/{}", self.plugin_dir, plugin);
            if let Ok(exports) = Self::get_exports(&path) {
                self.exported_functions = exports;
            } else {
                self.load_err.push("Failed to list exports".to_string());
            }
        }
    }

    fn get_exports(file_path: &str) -> Result<Vec<String>, String> {
        unsafe {
            let data = std::fs::read(file_path).map_err(|e| e.to_string())?;
            if data.len() < 64 || u16::from_le_bytes([data[0], data[1]]) != 0x5A4D {
                return Err("Invalid DOS header".to_string());
            }
            let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
            if data.len() < e_lfanew + 24 || u32::from_le_bytes([data[e_lfanew], data[e_lfanew+1], data[e_lfanew+2], data[e_lfanew+3]]) != 0x4550 {
                return Err("Invalid NT header".to_string());
            }
            let optional_rva = e_lfanew + 24;
            let magic = u16::from_le_bytes([data[optional_rva], data[optional_rva+1]]);
            if magic != 0x10b {
                return Err("Not 32bit PE".to_string());
            }
            let export_rva = u32::from_le_bytes([data[optional_rva + 88], data[optional_rva + 89], data[optional_rva + 90], data[optional_rva + 91]]) as usize;
            let export_size = u32::from_le_bytes([data[optional_rva + 92], data[optional_rva + 93], data[optional_rva + 94], data[optional_rva + 95]]) as usize;
            if export_rva == 0 || export_size == 0 {
                return Err("No export table".to_string());
            }
            let number_of_names = u32::from_le_bytes([data[export_rva + 24], data[export_rva + 25], data[export_rva + 26], data[export_rva + 27]]) as usize;
            let address_of_names = u32::from_le_bytes([data[export_rva + 32], data[export_rva + 33], data[export_rva + 34], data[export_rva + 35]]) as usize;
            let mut exports = Vec::with_capacity(number_of_names);
            for i in 0..number_of_names {
                let name_rva = u32::from_le_bytes([data[address_of_names + i*4], data[address_of_names + i*4 + 1], data[address_of_names + i*4 + 2], data[address_of_names + i*4 + 3]]) as usize;
                let name = std::str::from_utf8(std::slice::from_raw_parts(&data[name_rva], data.len() - name_rva).iter().take_while(|&&b| b != 0).count()).map_err(|e| e.to_string())?.to_string();
                exports.push(name);
            }
            Ok(exports)
        }
    }
}