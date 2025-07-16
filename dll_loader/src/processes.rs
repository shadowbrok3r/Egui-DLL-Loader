use sysinfo::ProcessesToUpdate;

use crate::{ExportInfo, PluginApp};


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
            match Self::get_exports_x64(&path) {
                Ok(exports) => self.exported_functions = exports,
                Err(e) => self.load_err.push(format!("Failed to list exports: {e:?}")),
            }
        }
    }

    fn get_exports_x64(file_path: &str) -> anyhow::Result<Vec<ExportInfo>> {
        let data = std::fs::read(file_path)?;
        if data.len() < 64 || u16::from_le_bytes([data[0], data[1]]) != 0x5A4D {
            return Err(anyhow::anyhow!("Invalid DOS header"));
        }

        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into()?) as usize;
        if data.len() < e_lfanew + 4 || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(anyhow::anyhow!("Invalid NT header"));
        }

        let optional_header_offset = e_lfanew + 24;
        let magic = u16::from_le_bytes(data[optional_header_offset..optional_header_offset + 2].try_into()?);
        if magic != 0x20B {
            return Err(anyhow::anyhow!("Not 64bit PE"));
        }

        let export_rva = u32::from_le_bytes(
            data[optional_header_offset + 0x70..optional_header_offset + 0x74].try_into()?
        ) as usize;
        let export_size = u32::from_le_bytes(
            data[optional_header_offset + 0x74..optional_header_offset + 0x78].try_into()?
        ) as usize;
        if export_rva == 0 || export_size == 0 {
            return Err(anyhow::anyhow!("No export table"));
        }

        let export_offset = Self::rva_to_offset(&data, export_rva)?;

        let number_of_names = u32::from_le_bytes(data[export_offset + 24..export_offset + 28].try_into()?) as usize;
        let address_of_names = u32::from_le_bytes(data[export_offset + 32..export_offset + 36].try_into()?) as usize;

        let mut exports = Vec::with_capacity(number_of_names);

        for i in 0..number_of_names {
            let name_rva_offset = Self::rva_to_offset(&data, address_of_names + i * 4)?;
            let name_rva = u32::from_le_bytes(data[name_rva_offset..name_rva_offset + 4].try_into()?) as usize;

            if let Ok(name_offset) = Self::rva_to_offset(&data, name_rva) {
                let len = data[name_offset..].iter().position(|&b| b == 0).unwrap_or(data.len() - name_offset);
                let name = std::str::from_utf8(&data[name_offset..name_offset + len])?.to_string();
                exports.push(ExportInfo {
                    name,
                    virtual_address: 0, // will be filled later when injected
                    rva: name_rva,
                    offset: name_offset,
                });
            }
        }

        Ok(exports)
    }

    fn rva_to_offset(data: &[u8], rva: usize) -> anyhow::Result<usize> {
        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into()?) as usize;
        let number_of_sections = u16::from_le_bytes(data[e_lfanew + 6..e_lfanew + 8].try_into()?) as usize;
        let optional_header_size = u16::from_le_bytes(data[e_lfanew + 20..e_lfanew + 22].try_into()?) as usize;
        let section_table = e_lfanew + 24 + optional_header_size;

        for i in 0..number_of_sections {
            let offset = section_table + i * 40;
            let virtual_address = u32::from_le_bytes(data[offset + 12..offset + 16].try_into()?) as usize;
            let size_of_raw_data = u32::from_le_bytes(data[offset + 16..offset + 20].try_into()?) as usize;
            let pointer_to_raw_data = u32::from_le_bytes(data[offset + 20..offset + 24].try_into()?) as usize;

            if rva >= virtual_address && rva < virtual_address + size_of_raw_data {
                return Ok(rva - virtual_address + pointer_to_raw_data);
            }
        }

        Err(anyhow::anyhow!("Could not get Offset from RVA"))
    }

    pub fn get_export_rva(data: &[u8], function_name: &str) -> Result<u32, String> {
        if data.len() < 64 || &data[0..2] != b"MZ" {
            return Err("Invalid DOS header".to_string());
        }

        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err("Invalid NT header".to_string());
        }

        let optional_header = &data[e_lfanew + 0x18..];
        let magic = u16::from_le_bytes(optional_header[0..2].try_into().unwrap());

        let export_dir_rva = if magic == 0x10B {
            u32::from_le_bytes(optional_header[96..100].try_into().unwrap()) as usize // PE32
        } else if magic == 0x20B {
            u32::from_le_bytes(optional_header[112..116].try_into().unwrap()) as usize // PE32+
        } else {
            return Err("Unknown PE magic".to_string());
        };

        let export_offset = Self::rva_to_offset(data, export_dir_rva).map_err(|e| format!("Invalid export directory RVA: {e:?}"))?;

        let number_of_names = u32::from_le_bytes(data[export_offset + 24..export_offset + 28].try_into().unwrap()) as usize;

        let address_of_functions_rva = u32::from_le_bytes(data[export_offset + 28..export_offset + 32].try_into().unwrap()) as usize;
        let address_of_names_rva = u32::from_le_bytes(data[export_offset + 32..export_offset + 36].try_into().unwrap()) as usize;
        let address_of_name_ordinals_rva = u32::from_le_bytes(data[export_offset + 36..export_offset + 40].try_into().unwrap()) as usize;

        let address_of_functions = Self::rva_to_offset(data, address_of_functions_rva).map_err(|e| format!("Invalid AddressOfFunctions RVA: {e:?}"))?;
        let address_of_names = Self::rva_to_offset(data, address_of_names_rva).map_err(|e| format!("Invalid AddressOfNames RVA: {e:?}"))?;
        let address_of_name_ordinals = Self::rva_to_offset(data, address_of_name_ordinals_rva).map_err(|e| format!("Invalid AddressOfNameOrdinals RVA: {e:?}"))?;

        for i in 0..number_of_names {
            // This is correct: reading RVA of i-th name string
            let name_rva = u32::from_le_bytes(
                data[address_of_names + i * 4..address_of_names + i * 4 + 4].try_into().unwrap()
            ) as usize;

            // Convert name RVA -> file offset
            let name_offset = Self::rva_to_offset(data, name_rva)
                .map_err(|e| format!("Invalid name_offset RVA: {e:?}"))?;

            // Read the null-terminated name string
            let name_end = data[name_offset..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(data.len() - name_offset)
                + name_offset;

            let name = std::str::from_utf8(&data[name_offset..name_end])
                .map_err(|e| format!("Invalid name UTF-8: {e:?}"))?;

            if name == function_name {
                let ordinal = u16::from_le_bytes(
                    data[address_of_name_ordinals + i * 2..address_of_name_ordinals + i * 2 + 2]
                        .try_into()
                        .unwrap(),
                ) as usize;

                let rva = u32::from_le_bytes(
                    data[address_of_functions + ordinal * 4..address_of_functions + ordinal * 4 + 4]
                        .try_into()
                        .unwrap(),
                );

                return Ok(rva);
            }
        }

        Err("Function not found in export table".to_string())
    }


    fn _get_exports(file_path: &str) -> Result<Vec<String>, String> {
        let data = std::fs::read(file_path).map_err(|e| e.to_string())?;
        println!("Data: {}", data.len());
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
            let name_rva = u32::from_le_bytes(data[address_of_names + i*4..address_of_names + i*4 + 4].try_into().unwrap()) as usize;
            if let Ok(name_offset) = Self::rva_to_offset(&data, name_rva) {
                let len = data[name_offset..].iter().position(|&b| b == 0).unwrap_or(data.len() - name_offset);
                let name = std::str::from_utf8(&data[name_offset..name_offset + len]).map_err(|e| e.to_string())?.to_string();
                exports.push(name);
            }
        }
        Ok(exports)
    }

}