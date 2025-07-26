use std::ffi::c_void;

use sysinfo::ProcessesToUpdate;
use windows::{core::BOOL, Win32::{Foundation::{FALSE, HANDLE}, Security::{GetSidSubAuthority, GetSidSubAuthorityCount}, System::Threading::{CreateProcessA, OpenProcess, OpenProcessToken, CREATE_SUSPENDED, PROCESS_ALL_ACCESS, PROCESS_INFORMATION, STARTUPINFOA}}};
use windows_strings::PSTR;

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

        // Helper to get the integrity level of a process
    pub fn get_process_integrity_level(process_handle: HANDLE) -> anyhow::Result<String, anyhow::Error> {
        use windows::Win32::Security::{GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL, TOKEN_QUERY};
        use std::ptr;

        unsafe {
            let mut h_token = HANDLE(ptr::null_mut());
            OpenProcessToken(process_handle, TOKEN_QUERY, &mut h_token)
                .map_err(|e| anyhow::anyhow!("OpenProcessToken (for integrity level) failed: {e}"))?;

            // Query buffer size
            let mut size = 0u32;
            let _ = GetTokenInformation(
                h_token,
                TokenIntegrityLevel,
                None,
                0,
                &mut size,
            );
            if size == 0 {
                return Err(anyhow::anyhow!("GetTokenInformation (size query) failed"));
            }

            let mut buf = vec![0u8; size as usize];
            let ok = GetTokenInformation(
                h_token,
                TokenIntegrityLevel,
                Some(buf.as_mut_ptr() as *mut _),
                size,
                &mut size,
            );
            if !ok.is_ok() {
                return Err(anyhow::anyhow!("GetTokenInformation (data) failed"));
            }

            let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let p_sid = tml.Label.Sid;
            if p_sid.is_invalid() {
                return Err(anyhow::anyhow!("SID is invalid"));
            }

            let sub_auth_count = *GetSidSubAuthorityCount(p_sid);
            if sub_auth_count == 0 {
                return Err(anyhow::anyhow!("SID has no subauthorities"));
            }
            let rid = *GetSidSubAuthority(p_sid, (sub_auth_count - 1) as u32);

            let level = match rid {
                0x0000_0000 => "Untrusted",
                0x0000_1000 => "Low",
                0x0000_2000 => "Medium",
                0x0000_2100 => "Medium Plus",
                0x0000_3000 => "High",
                0x0000_4000 => "System",
                0x0000_5000 => "Protected Process",
                _ => "Other"
            };
            Ok(level.to_string())
        }
    }

    /// Get remote module base address (HANDLE) for a given DLL name in a process
    pub fn get_remote_module_base_handle(h_process: HANDLE, module_name: &str) -> anyhow::Result<*mut c_void, anyhow::Error> {
        use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE};
        use std::ffi::CStr;
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, windows::Win32::System::Threading::GetProcessId(h_process) ) };
        if !snapshot.is_ok() {
            return Err(anyhow::anyhow!("CreateToolhelp32Snapshot failed"));
        }
        let snapshot = snapshot.unwrap();
        let mut entry = MODULEENTRY32 { dwSize: std::mem::size_of::<MODULEENTRY32>() as u32, ..Default::default() };
        let mut found = None;
        if unsafe { Module32First(snapshot, &mut entry) }.is_ok() {
            loop {
                let name_ptr = entry.szModule.as_ptr();
                let name_cstr = unsafe { CStr::from_ptr(name_ptr) };
                let name_str = name_cstr.to_string_lossy().trim_end_matches(char::from(0)).to_lowercase();
                if name_str == module_name.to_lowercase() {
                    found = Some(entry.modBaseAddr as *mut c_void);
                    break;
                }
                if unsafe { Module32Next(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        unsafe { windows::Win32::Foundation::CloseHandle(snapshot)? };
        found.ok_or_else(|| anyhow::anyhow!("Module {} not found in remote process", module_name))
    }
    
    // Improved process hollowing with proper PE handling
    pub unsafe fn get_process_info(exe_path: &str) -> Result<(PROCESS_INFORMATION, HANDLE), String> {
        unsafe {
            let mut startup_info = STARTUPINFOA::default();
            let mut process_info = PROCESS_INFORMATION::default();
            let mut command_line = format!("{}\0", exe_path);

            CreateProcessA(
                None,
                Some(PSTR(command_line.as_mut_ptr())),
                None,
                None,
                BOOL(0).into(),
                CREATE_SUSPENDED,
                None,
                None,
                &mut startup_info,
                &mut process_info,
            )
            .map_err(|e| format!("CreateProcessA failed: {}", e))?;

            // Open process with PROCESS_ALL_ACCESS for injection
            let h_process = OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE.into(),
                process_info.dwProcessId
            ).map_err(|e| format!("OpenProcess(PROCESS_ALL_ACCESS) failed: {}", e))?;

            // Return both process_info and h_process so caller can resume main thread
            Ok((process_info, h_process))
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

    pub fn rva_to_offset(data: &[u8], rva: usize) -> anyhow::Result<usize, anyhow::Error> {
        use goblin::pe::PE;
        let pe = PE::parse(data)?;
        // Try to find the section containing the RVA
        for section in &pe.sections {
            let va = section.virtual_address as usize;
            let vsz = std::cmp::max(section.virtual_size, section.size_of_raw_data) as usize;
            let raw_ptr = section.pointer_to_raw_data as usize;
            if rva >= va && rva < va + vsz {
                return Ok(rva - va + raw_ptr);
            }
        }
        // If not found in any section, check if it's in headers
        if let Some(opt) = pe.header.optional_header {
            if rva < opt.windows_fields.size_of_headers as usize {
                return Ok(rva);
            }
        }
        Err(anyhow::anyhow!("Could not get Offset from RVA: 0x{:X}", rva))
    }

    pub fn get_export_rva(data: &[u8], function_name: &str) -> anyhow::Result<u32, anyhow::Error> {
        use goblin::pe::PE;
        let pe = PE::parse(data)?;
        for export in &pe.exports {
            if let Some(name) = &export.name {
                if *name == function_name {
                    return Ok(export.rva as u32);
                }
            }
        }
        Err(anyhow::anyhow!("Function not found in export table: {}", function_name))
    }
}