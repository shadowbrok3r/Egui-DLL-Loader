use windows::{Win32::{Foundation::*, System::{LibraryLoader::*, Threading::*, Memory::*, Diagnostics::{Debug::*, ToolHelp::*}}}};
use dll_syringe::{Syringe, process::OwnedProcess};
use crossbeam::channel::Sender;
use windows_strings::PCSTR;
use crate::PluginApp;
use rand;

impl PluginApp {
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
        _function: &str
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
            
            let base = Self::get_remote_module_base_from_pid(pid, &plugin_name).ok_or(anyhow::anyhow!("DLL not found in remote process"))?;
            
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
    