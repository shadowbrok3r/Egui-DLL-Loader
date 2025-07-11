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
    pub async unsafe fn hollow_and_inject(pid: sysinfo::Pid, plugin_dir: String, plugin: String) -> Result<(), String> {
        unsafe {
            let path = format!("{}\\{}", plugin_dir, plugin);
            println!("Hollowing and injecting DLL: {} into PID: {}", path, pid);

            // Open process
            let h_process = OpenProcess(
                PROCESS_ALL_ACCESS, 
                FALSE.into(), 
                pid.as_u32()
            ).map_err(|e| e.to_string())?;

            if h_process.is_invalid() {
                return Err("Failed to open process".to_string());
            }

            let dll_path = path.clone() + "\0";

            // Allocate memory for DLL path in remote process
            let remote_mem = VirtualAllocEx(
                h_process,
                None,
                dll_path.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );

            if remote_mem.is_null() {
                return Err("Failed to allocate memory in remote process".to_string());
            }

            WriteProcessMemory(
                h_process,
                remote_mem,
                dll_path.as_ptr() as _,
                dll_path.len(),
                None,
            ).map_err(|e| e.to_string())?;

            // LoadLibraryA address
            let kernel32 = GetModuleHandleA(
                PCSTR(b"kernel32.dll\0".as_ptr())
            ).map_err(|e| e.to_string())?;

            if kernel32.is_invalid() {
                return Err("Failed to get handle to kernel32.dll".to_string());
            }

            let load_library = GetProcAddress(kernel32, PCSTR(b"LoadLibraryA\0".as_ptr()));
            if load_library.is_none() {
                return Err("Failed to get address of LoadLibraryA".to_string());
            }

            // Create remote thread to load DLL
            let remote_thread = CreateRemoteThread(
                h_process,
                None,
                0,
                Some(std::mem::transmute(load_library)),
                Some(remote_mem),
                0,
                None,
            ).map_err(|e| e.to_string())?;
                
            if remote_thread.is_invalid() {
                return Err("Failed to create remote thread".to_string());
            }
            CloseHandle(remote_thread).map_err(|e| e.to_string())?;
            CloseHandle(h_process).map_err(|e| e.to_string())?;
        };
        Ok(())
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

    pub async unsafe fn inject_dll(pid: sysinfo::Pid, plugin_dir: String, plugin: String) -> Result<(), String> {
        unsafe {
            let dll_path = format!("{}/{}", plugin_dir, plugin);
            let dll_data = std::fs::read(&dll_path).map_err(|e| e.to_string())?;
            let exe_path = "C:\\Windows\\notepad.exe".to_owned(); // Example legit exe
            let mut startup_info = STARTUPINFOA::default();
            let mut process_info = PROCESS_INFORMATION::default();
            let mut command_line = exe_path.clone() + "\0";
            
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
                &mut process_info
            ).map_err(|e| e.to_string())?;

            let mut context = CONTEXT { ContextFlags: CONTEXT_ALL_AMD64, ..Default::default() };
            GetThreadContext(process_info.hThread, &mut context).map_err(|e| e.to_string())?;
            let mut image_base: *mut c_void = std::ptr::null_mut();
            ReadProcessMemory(process_info.hProcess, (context.Rbx + 8) as *const _, &mut image_base as *mut _ as *mut _, size_of::<*mut c_void>(), None).map_err(|e| e.to_string())?;
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())).map_err(|e| e.to_string())?;
            let nt_unmap_addr = GetProcAddress(ntdll, PCSTR(b"NtUnmapViewOfSection\0".as_ptr())).ok_or("NtUnmapViewOfSection not found")?;
            type NtUnmap = extern "system" fn(HANDLE, *mut c_void) -> NTSTATUS;
            let nt_unmap: NtUnmap = std::mem::transmute(nt_unmap_addr);
            let nt_status = nt_unmap(process_info.hProcess, image_base);
            println!("NT STATUS: {:?}", nt_status.to_hresult());

            if dll_data.len() < 64 || dll_data[0..2] != [0x4D, 0x5A] {
                return Err("Invalid DOS header".to_string());
            }
            let e_lfanew = u32::from_le_bytes(dll_data[0x3C..0x40].try_into().unwrap()) as usize;
            if dll_data.len() < e_lfanew + 4 || dll_data[e_lfanew..e_lfanew+4] != [0x50, 0x45, 0x00, 0x00] {
                return Err("Invalid NT header".to_string());
            }
            let optional_rva = e_lfanew + 0x18;
            let magic = u16::from_le_bytes(dll_data[optional_rva..optional_rva+2].try_into().unwrap());
            if magic != 0x10B {
                return Err("Not PE32".to_string());
            }
            let preferred_base = u32::from_le_bytes(dll_data[optional_rva + 0x1C..optional_rva + 0x20].try_into().unwrap()) as *mut c_void;
            let size_of_image = u32::from_le_bytes(dll_data[optional_rva + 0x38..optional_rva + 0x3C].try_into().unwrap()) as usize;
            let entry_rva = u32::from_le_bytes(dll_data[optional_rva + 0x10..optional_rva + 0x14].try_into().unwrap());
            let alloc = VirtualAllocEx(process_info.hProcess, Some(preferred_base), size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            let delta = (alloc as isize) - (preferred_base as isize);
            let size_of_headers = u32::from_le_bytes(dll_data[optional_rva + 0x3C..optional_rva + 0x40].try_into().unwrap()) as usize;
            WriteProcessMemory(process_info.hProcess, alloc, dll_data.as_ptr() as _, size_of_headers, None).map_err(|e| e.to_string())?;
            let number_of_sections = u16::from_le_bytes(dll_data[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) as usize;
            let section_rva = optional_rva + 96; // for PE32 optional size 96
            for i in 0..number_of_sections {
                let sec = section_rva + i * 40;
                let va = u32::from_le_bytes(dll_data[sec + 12..sec + 16].try_into().unwrap()) as usize;
                let vs = u32::from_le_bytes(dll_data[sec + 8..sec + 12].try_into().unwrap()) as usize;
                let raw_ptr = u32::from_le_bytes(dll_data[sec + 20..sec + 24].try_into().unwrap()) as usize;
                let raw_size = u32::from_le_bytes(dll_data[sec + 16..sec + 20].try_into().unwrap()) as usize;
                WriteProcessMemory(process_info.hProcess, alloc.add(va), dll_data.as_ptr().add(raw_ptr) as _, raw_size, None).map_err(|e| e.to_string())?;
            }
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