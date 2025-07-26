use windows::{Win32::{Foundation::*, System::{Threading::*, Memory::*}}};
use crate::PluginApp;

impl PluginApp {
        // Reflective DLL injection implementation
    pub async unsafe fn inject_reflective_dll(
        pid: sysinfo::Pid,
        plugin_dir: &str,
        plugin: &str,
        function: &str
    ) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
            let dll_path = format!("{}\\{}", plugin_dir, plugin);
            let dll_data = std::fs::read(&dll_path).map_err(|e| anyhow::anyhow!("Failed to read DLL file {}: {}", dll_path, e))?;

            let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE.into(), pid.as_u32())
                .map_err(|e| anyhow::anyhow!("OpenProcess failed for PID {} (access denied - try running as administrator): {}", pid.as_u32(), e))?;

            // Parse PE and get required info
            let (preferred_base, _entry_rva, size_of_image) = Self::parse_pe_headers(&dll_data)?;

            // Allocate memory for the DLL
            let alloc = VirtualAllocEx(
                h_process,
                None,
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if alloc.is_null() {
                CloseHandle(h_process).ok();
                return Err(anyhow::anyhow!("VirtualAllocEx failed for reflective injection in PID {} - insufficient privileges or protected process", pid.as_u32()));
            }

            let actual_base = alloc as usize;

            // Map PE sections
            if let Err(e) = Self::map_pe_sections(&dll_data, h_process, alloc) {
                VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE)?;
                CloseHandle(h_process).ok();
                return Err(anyhow::anyhow!("Failed to map PE sections: {}", e));
            }

            // Apply relocations
            if actual_base != preferred_base {
                if let Err(e) = Self::apply_relocations(&dll_data, h_process, actual_base, preferred_base) {
                    VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE)?;
                    CloseHandle(h_process).ok();
                    return Err(anyhow::anyhow!("Failed to apply relocations: {}", e));
                }
            }

            // Resolve imports
            if let Err(e) = Self::resolve_imports(&dll_data, h_process, alloc) {
                VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE)?;
                CloseHandle(h_process).ok();
                return Err(anyhow::anyhow!("Failed to resolve imports: {}", e));
            }

            // Call DllMain manually if needed
            let dll_main_rva = Self::get_dll_main_rva(&dll_data)?;
            if dll_main_rva > 0 {
                let dll_main_addr = actual_base + dll_main_rva as usize;
                let thread_handle = CreateRemoteThread(
                    h_process,
                    None,
                    0,
                    Some(std::mem::transmute(dll_main_addr)),
                    Some(1 as *mut _), // DLL_PROCESS_ATTACH
                    0,
                    None,
                ).map_err(|e| anyhow::anyhow!("Failed to call DllMain: {}", e))?;

                WaitForSingleObject(thread_handle, INFINITE);
                CloseHandle(thread_handle).ok();
            }

            // Now call the exported function
            let function_rva = Self::get_export_rva(&dll_data, function)?;
            let function_addr = actual_base + function_rva as usize;

            let thread_handle = CreateRemoteThread(
                h_process,
                None,
                0,
                Some(std::mem::transmute(function_addr)),
                None,
                0,
                None,
            ).map_err(|e| anyhow::anyhow!("Failed to create remote thread for function {}: {}", function, e))?;

            WaitForSingleObject(thread_handle, INFINITE);
            CloseHandle(thread_handle).ok();
            CloseHandle(h_process).ok();

            Ok(())
        }
    }

}