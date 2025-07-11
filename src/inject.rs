use windows::core::BOOL;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::WindowsProgramming::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::SystemInformation::*;
use dll_syringe::{Syringe, process::OwnedProcess};
use eframe::egui::{self, Id, ScrollArea};
use windows_strings::PCSTR;
use windows_strings::PSTR;
use std::fs::read_dir;
use std::time::{Duration, Instant};
use sysinfo::{System, ProcessesToUpdate};
use tokio::sync::mpsc;

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

    pub async unsafe fn inject_dll(pid: sysinfo::Pid, plugin_dir: String, plugin: String) -> Result<(), String> {
        unsafe {
            let path = format!("{}/{}", plugin_dir, plugin);
            println!("Injecting DLL: {} into PID: {}", path, pid);
            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, BOOL(0).into(), pid.as_u32()).map_err(|e| e.to_string())?;
            let dll_path_bytes = path.as_bytes();
            let alloc = VirtualAllocEx(process_handle, None, dll_path_bytes.len() + 1, MEM_COMMIT, PAGE_READWRITE);
            if alloc.is_null() {
                return Err("VirtualAllocEx failed".to_string());
            }
            
            WriteProcessMemory(
                process_handle, 
                alloc, 
                dll_path_bytes.as_ptr() as _, 
                dll_path_bytes.len(), 
                None
            ).map_err(|e| e.to_string())?;

            let kernel32 = GetModuleHandleA(
                PCSTR(b"kernel32.dll\0".as_ptr())
            ).map_err(|e| e.to_string())?;

            if kernel32.is_invalid() {
                return Err("Failed to get handle to kernel32.dll".to_string());
            }

            let load_library_addr = GetProcAddress(kernel32, PCSTR(b"LoadLibraryA\0".as_ptr()));
            if load_library_addr.is_none() {
                return Err("Failed to get address of LoadLibraryA".to_string());
            }
            
            let thread_handle = CreateRemoteThread(
                process_handle, 
                None, 
                0, 
                Some(std::mem::transmute(load_library_addr)), 
                Some(alloc), 
                0, 
                None
            ).map_err(|e| e.to_string())?;
            // Wait for thread to finish, etc.
            // For hollowing, add suspension and unmapping
            // First, suspend threads
            // But for running process, enumerate threads, suspend
            // This is complex, omit for brevity, focus on injection
            // To explore hollowing, note: Create suspended process from exe path
            let mut exe_path = "C:\\Windows\\notepad.exe".to_owned(); // Example legit exe
            let mut startup_info = STARTUPINFOA::default();
            let mut process_info = PROCESS_INFORMATION::default();
            CreateProcessA(
                None, 
                Some(PSTR(exe_path.as_mut_ptr())), 
                None, 
                None, 
                BOOL(0).into(), 
                CREATE_SUSPENDED, 
                None, 
                None, 
                &mut startup_info,
                &mut process_info
            ).map_err(|e| e.to_string())?;
            // Get context
            let mut context = CONTEXT::default();
            GetThreadContext(process_info.hThread, &mut context).map_err(|e| e.to_string())?;
            // Read PEB, image base, unmap, allocate, write DLL sections (adapt for DLL), set entry, resume
            // But DLL not PE for process, so load DLL after
            ResumeThread(process_info.hThread);
        }
        Ok(())
    }

}