
# 🧪 Egui DLL Loader (WIP)
A modern GUI tool built with Rust and [`egui`](https://github.com/emilk/egui) to inject or manually map DLLs into running processes using classic injection or process hollowing techniques.

## ✨ Features

- 🚀 DLL injection via `CreateRemoteThread + LoadLibraryW`
- 🧠 Manual process hollowing with custom image mapping
- 🧬 Exported function resolution via PE parsing
- 📜 Export viewer for inspecting DLL symbols
- 🪟 Windows native API integration via `windows` crate
- 🎨 UI built with `eframe` and `egui`

## 🛠️ Usage

1. **Run the application:**

```bash
   cargo run --release
````
2. **Choose a DLL** from your plugin directory.
3. **Select an exported function** (like `DllMain` or `test_function`).
4. **Inject it** into a running process or launch a **hollowed process**.
5. Confirm behavior via popups, file logs, or custom payload logic.

## ⚠️ Notes

* **Manual mapping requires PE32/PE32+ compliant DLLs.**
* Ensure your exported function is a proper entrypoint (e.g., no reliance on loader IAT unless mapped).
* Hollowed processes must be suspended and launched from trusted binaries (`notepad.exe`, `rundll32.exe`, etc.).

## 🔒 Disclaimer

This tool is for **educational and development** purposes only. Unauthorized process injection may be considered malicious by antivirus software and violates the terms of use on most systems.

## 🧩 Example Rust DLL

```rust
#[no_mangle]
pub extern "system" fn test_function() {
    let msg = widestring::U16CString::from_str("Test Function Called!").unwrap();
    let title = widestring::U16CString::from_str("Test DLL").unwrap();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK,
        );
    }
}
```

## 📁 Project Structure

```
egui_dll_loader/
├── src/
│   ├── main.rs         # GUI entrypoint
│   ├── processes.rs    # Hollowing + injection logic
│   └── pe.rs           # PE parsing (export RVA, sections)
├── plugins/            # Your DLLs
├── Cargo.toml
└── README.md
```

## 🧠 Future Ideas

* Reflective DLL injection
* IAT fixups for full manual mapping
* Thread hijacking instead of `CreateRemoteThread`
* Basic AV evasion research modes


```
