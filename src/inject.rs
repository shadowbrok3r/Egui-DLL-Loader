use dll_syringe::process::OwnedProcess;
use dll_syringe::process::ProcessModule;
use dll_syringe::Syringe;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Memory::*;
use windows::Win32::Foundation::*;
use windows_strings::PCSTR;
use windows_strings::PSTR;
use windows::core::BOOL;
use std::ffi::c_void;
use crate::PluginApp;


impl PluginApp {
    pub unsafe fn hollow_process(exe_path: &str) -> Result<PROCESS_INFORMATION, String> {
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
        
            Ok(process_info)
        }
    }

    pub unsafe fn inject_hollowed_process(    
        dll_data: &[u8],
        process_handle: HANDLE,
        function_name: &str,
        pid: u32
    ) -> Result<(), String> {
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
                return Err("VirtualAllocEx failed".to_string());
            }

            // Write DLL headers and sections
            WriteProcessMemory(process_handle, alloc, dll_data.as_ptr() as _, dll_data.len(), None)
                .map_err(|e| format!("WriteProcessMemory failed: {}", e))?;

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
            ).map_err(|e| e.to_string())?;

            if thread_handle.is_invalid() {
                return Err("CreateRemoteThread failed".to_string());
            }

            println!("Wrote {} bytes to remote process at {:p}", dll_data.len(), alloc);
            let mut verify = vec![0u8; dll_data.len()];
            ReadProcessMemory(process_handle, alloc, verify.as_mut_ptr() as _, dll_data.len(), None).map_err(|e| e.to_string())?;
            
            if verify == dll_data {
                println!("Remote memory matches injected DLL image");
            } else {
               return Err("WARNING: Remote memory does not match!".to_string());
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

            CloseHandle(thread_handle).map_err(|e| e.to_string())?;

            Ok(())
        }
    }

    pub unsafe fn call_exported_fn(
        plugin_name: String, 
        path: String, 
        function: String, 
        pid: u32,
        tx: tokio::sync::mpsc::Sender<String>
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
                tx.send(format!("Called '{}'", function)).await.ok();
            });
        }
        Ok(())
    }

    pub async unsafe fn inject_dll(pid: sysinfo::Pid, plugin_dir: &str, plugin: &str, function: &str) -> Result<(), String> {
        let path = format!("{}/{}", plugin_dir, plugin);
        println!("Injecting DLL: {} into PID: {}", path, pid);
        let process = OwnedProcess::from_pid(pid.as_u32()).map_err(|e| e.to_string())?;
        let syringe = Syringe::for_process(process);
        let injected = syringe.inject(&path).map_err(|e| e.to_string())?;
        println!("DLL injected");
        unsafe {
            let remote_proc = syringe
                .get_raw_procedure::<extern "system" fn() -> i32>(injected, function)
                .map_err(|e| e.to_string())?
                .ok_or("Procedure not found")?;
            let result = remote_proc.call().map_err(|e| e.to_string())?;
            println!("{function} returned: {}", result);
        }
        Ok(())
    }

    pub async unsafe fn inject_dll_alt(pid: sysinfo::Pid, plugin_dir: String, plugin: String) -> anyhow::Result<(), String> {
        unsafe {
            let dll_path = format!("{}/{}", plugin_dir, plugin);
            let dll_data = std::fs::read(&dll_path).map_err(|e| e.to_string())?;

            let exe_path = "C:\\Windows\\notepad.exe\0";
            let mut startup_info = STARTUPINFOA::default();
            let mut process_info = PROCESS_INFORMATION::default();
            let mut command_line = exe_path.to_string();

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
            ).map_err(|e| e.to_string())?;

            let mut context = CONTEXT { ContextFlags: CONTEXT_ALL_AMD64, ..Default::default() };
            GetThreadContext(process_info.hThread, &mut context).map_err(|e| e.to_string())?;

            let mut image_base: *mut c_void = std::ptr::null_mut();
            ReadProcessMemory(
                process_info.hProcess,
                (context.Rbx + 8) as *const _,
                &mut image_base as *mut _ as *mut _,
                size_of::<*mut c_void>(),
                None,
            ).map_err(|e| e.to_string())?;

            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())).map_err(|e| e.to_string())?;
            let nt_unmap_addr = GetProcAddress(ntdll, PCSTR(b"NtUnmapViewOfSection\0".as_ptr()))
                .ok_or("NtUnmapViewOfSection not found")?;
            let nt_unmap: extern "system" fn(HANDLE, *mut c_void) -> NTSTATUS = std::mem::transmute(nt_unmap_addr);
            let _ = nt_unmap(process_info.hProcess, image_base);

            if dll_data.len() < 64 || dll_data[0..2] != [0x4D, 0x5A] {
                return Err("Invalid DOS header".to_string());
            }
            let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
            if dll_data[e_lfanew..e_lfanew + 4] != [0x50, 0x45, 0x00, 0x00] {
                return Err("Invalid PE header".to_string());
            }

            let optional_rva = e_lfanew + 0x18;
            let magic = u16::from_le_bytes(dll_data[optional_rva..optional_rva + 2].try_into().unwrap());
            let (preferred_base, entry_rva, size_of_image, size_of_headers) = if magic == 0x10B {
                let base = u32::from_le_bytes(dll_data[optional_rva + 0x1C..optional_rva + 0x20].try_into().unwrap()) as usize;
                let entry = u32::from_le_bytes(dll_data[optional_rva + 0x10..optional_rva + 0x14].try_into().unwrap());
                let image_size = u32::from_le_bytes(dll_data[optional_rva + 0x38..optional_rva + 0x3C].try_into().unwrap()) as usize;
                let header_size = u32::from_le_bytes(dll_data[optional_rva + 0x3C..optional_rva + 0x40].try_into().unwrap()) as usize;
                (base, entry, image_size, header_size)
            } else if magic == 0x20B {
                let base = u64::from_le_bytes(dll_data[optional_rva + 0x18..optional_rva + 0x20].try_into().unwrap()) as usize;
                let entry = u32::from_le_bytes(dll_data[optional_rva + 0x10..optional_rva + 0x14].try_into().unwrap());
                let image_size = u32::from_le_bytes(dll_data[optional_rva + 0x38..optional_rva + 0x3C].try_into().unwrap()) as usize;
                let header_size = u32::from_le_bytes(dll_data[optional_rva + 0x3C..optional_rva + 0x40].try_into().unwrap()) as usize;
                (base, entry, image_size, header_size)
            } else {
                return Err("Unsupported PE format".to_string());
            };

            let alloc = VirtualAllocEx(
                process_info.hProcess,
                Some(preferred_base as *mut _),
                size_of_image,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            WriteProcessMemory(
                process_info.hProcess,
                alloc,
                dll_data.as_ptr() as _,
                size_of_headers,
                None,
            ).map_err(|e| e.to_string())?;

            let number_of_sections = u16::from_le_bytes(dll_data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
            let section_rva = optional_rva + if magic == 0x10B { 96 } else { 112 };
            for i in 0..number_of_sections {
                let sec = section_rva + i * 40;
                let va = u32::from_le_bytes(dll_data[sec + 12..sec + 16].try_into().unwrap()) as usize;
                let raw_ptr = u32::from_le_bytes(dll_data[sec + 20..sec + 24].try_into().unwrap()) as usize;
                let raw_size = u32::from_le_bytes(dll_data[sec + 16..sec + 20].try_into().unwrap()) as usize;
                WriteProcessMemory(
                    process_info.hProcess,
                    alloc.add(va),
                    dll_data.as_ptr().add(raw_ptr) as _,
                    raw_size,
                    None,
                ).map_err(|e| e.to_string())?;
            }

            let entry_point = alloc.add(entry_rva as usize);
            context.Rcx = entry_point as usize as u64;
            SetThreadContext(process_info.hThread, &context).map_err(|e| e.to_string())?;
            ResumeThread(process_info.hThread);
        }
        Ok(())
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
}