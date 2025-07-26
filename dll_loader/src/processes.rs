use windows::{core::BOOL, Win32::{Foundation::{FALSE, HANDLE}, Security::{GetSidSubAuthority, GetSidSubAuthorityCount}, System::Threading::{CreateProcessA, OpenProcess, OpenProcessToken, CREATE_SUSPENDED, PROCESS_ALL_ACCESS, PROCESS_INFORMATION, STARTUPINFOA}}};
use sysinfo::ProcessesToUpdate;
use windows_strings::PSTR;
use std::ffi::c_void;
use crate::*;

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
                Err(e) => log::error!("Failed to list exports: {e:?}"),
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

    pub fn get_exports_x64(file_path: &str) -> anyhow::Result<Vec<ExportInfo>> {
        use goblin::pe::PE;
        let data = std::fs::read(file_path)?;
        let pe = PE::parse(&data)?;
        let opt = pe.header.optional_header.ok_or_else(|| anyhow::anyhow!("Missing optional header"))?;

        // Sections
        let section_info: Vec<SectionInfo> = pe.sections.iter().map(|s| SectionInfo {
            name: String::from_utf8_lossy(s.name().unwrap_or_default().as_bytes()).to_string(),
            virtual_address: s.virtual_address as usize,
            virtual_size: s.virtual_size as usize,
            raw_size: s.size_of_raw_data as usize,
            characteristics: s.characteristics,
        }).collect();

        // Imports
        let import_info: Vec<ImportInfo> = pe.imports.iter().map(|imp| ImportInfo {
            dll: imp.dll.to_string(),
            functions: if !imp.name.is_empty() { vec![imp.name.to_string()] } else { vec![] },
        }).collect();

        // Exports
        let export_info: Vec<ExportFuncInfo> = pe.exports.iter().map(|exp| ExportFuncInfo {
            name: exp.name.as_ref().map(|s| s.to_string()),
            rva: exp.rva as usize,
        }).collect();

        // TLS: goblin does not parse TLS directly, so we check data directories
        let tls_info = opt.data_directories.get_tls_table().and_then(|tls_dir| {
            if tls_dir.virtual_address != 0 {
                let tls_offset = Self::rva_to_offset(&data, tls_dir.virtual_address as usize).ok()?;
                // Try to parse TLS structure (simplified)
                if data.len() >= tls_offset + 40 {
                    Some(TlsInfo {
                        start_address_of_raw_data: u64::from_le_bytes(data[tls_offset..tls_offset+8].try_into().ok()?) as usize,
                        end_address_of_raw_data: u64::from_le_bytes(data[tls_offset+8..tls_offset+16].try_into().ok()?) as usize,
                        address_of_index: u64::from_le_bytes(data[tls_offset+16..tls_offset+24].try_into().ok()?) as usize,
                        address_of_callbacks: u64::from_le_bytes(data[tls_offset+24..tls_offset+32].try_into().ok()?) as usize,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        });

        // Main PE metadata
        let machine = pe.header.coff_header.machine;
        let number_of_sections = pe.header.coff_header.number_of_sections as usize;
        let entry_point = opt.standard_fields.address_of_entry_point;
        let image_base = opt.windows_fields.image_base as usize;
        let size_of_image = opt.windows_fields.size_of_image as usize;
        let size_of_headers = opt.windows_fields.size_of_headers as usize;
        let subsystem = opt.windows_fields.subsystem;
        let dll_characteristics = opt.windows_fields.dll_characteristics;
        let timestamp = pe.header.coff_header.time_date_stamp;

        // For each export, create a full ExportInfo
        let mut exports = Vec::new();
        for exp in &pe.exports {
            exports.push(ExportInfo {
                name: exp.name.as_ref().map(|s| s.to_string()).unwrap_or_default(),
                virtual_address: image_base + exp.rva as usize,
                rva: exp.rva as usize,
                offset: Self::rva_to_offset(&data, exp.rva as usize).unwrap_or(0),
                machine,
                number_of_sections,
                entry_point,
                image_base,
                size_of_image,
                size_of_headers,
                subsystem,
                dll_characteristics,
                timestamp,
                section_info: section_info.clone(),
                import_info: import_info.clone(),
                export_info: export_info.clone(),
                tls_info: tls_info.clone(),
            });
        }
        // If no exports, still return one with just metadata
        if exports.is_empty() {
            exports.push(ExportInfo {
                name: String::new(),
                virtual_address: 0,
                rva: 0,
                offset: 0,
                machine,
                number_of_sections,
                entry_point,
                image_base,
                size_of_image,
                size_of_headers,
                subsystem,
                dll_characteristics,
                timestamp,
                section_info,
                import_info,
                export_info,
                tls_info,
            });
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