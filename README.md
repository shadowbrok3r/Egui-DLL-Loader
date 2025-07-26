# 🧪 Egui DLL Loader (Enhanced)
A modern GUI tool built with Rust and [`egui`](https://github.com/emilk/egui) for advanced DLL injection techniques including classic injection, process hollowing, reflective injection, and manual mapping with comprehensive IAT fixups.

## ✨ Features

### Injection Techniques
- 🚀 **Classic DLL Injection** via `CreateRemoteThread + LoadLibraryW`
- 🎯 **Thread Hijacking** as alternative to CreateRemoteThread
- 🧠 **Improved Process Hollowing** with proper PE handling and IAT resolution
- 🔄 **Reflective DLL Injection** for memory-only loading
- 🛠️ **Manual Mapping** with comprehensive IAT fixups
- 🛡️ **Basic AV Evasion** research modes with environment detection

### Advanced Features
- 🧬 Exported function resolution via PE parsing
- 📜 Export viewer for inspecting DLL symbols
- 🔧 Proper PE32/PE32+ support with relocations
- 🎛️ Multi-page UI for different injection techniques
- 🪟 Windows native API integration via `windows` crate
- 🎨 Modern UI built with `eframe` and `egui`

## 🛠️ Usage

1. **Run the application:**
```bash
   cargo run --release
```

2. **Select injection technique** from the available tabs:
   - **Classic Injection**: Traditional DLL injection
   - **Process Hollowing**: Advanced process replacement
   - **Reflective Injection**: Memory-only DLL loading
   - **Manual Mapping**: Full PE mapping with IAT fixups

3. **Configure options:**
   - Toggle **AV Evasion Mode** for basic anti-detection
   - Enable **Thread Hijacking** for alternative injection method

4. **Choose a DLL** from your plugin directory
5. **Select an exported function** (like `test_injection`, `test_reflective`, etc.)
6. **Select target process** and inject using the appropriate method

## 🔧 Technical Details

### Process Hollowing Improvements
- Fixed broken PE section mapping
- Added proper relocation table processing
- Implemented comprehensive IAT resolution
- Enhanced memory protection management

### Reflective Injection
- Manual PE loading without filesystem traces
- In-memory DLL mapping with custom relocations
- Direct function execution bypass

### Thread Hijacking
- Thread enumeration and context manipulation
- LoadLibraryA execution via hijacked thread
- Proper execution flow restoration

### AV Evasion Features
- Analysis environment detection (VM/sandbox)
- Random execution delays
- Security tool process detection

## ⚠️ Notes

* **Requires x86_64-pc-windows-msvc toolchain** - will not run on other platforms
* **Manual mapping requires PE32/PE32+ compliant DLLs**
* **Administrator privileges required** for process injection operations
* Hollowed processes must be suspended and launched from trusted binaries

## 🔒 Disclaimer

This tool is for **educational and development** purposes only. Unauthorized process injection may be considered malicious by antivirus software and violates the terms of use on most systems.

## 🧩 Enhanced Test DLL Functions

The included `rusty_dll` now provides multiple test functions:

```rust
// Classic injection test
pub extern "system" fn test_injection() -> i32

// Reflective injection test  
pub extern "system" fn test_reflective() -> i32

// Manual mapping test
pub extern "system" fn test_manual_map() -> i32

// Thread hijacking test
pub extern "system" fn test_thread_hijack() -> i32
```

## 📁 Project Structure

```
egui_dll_loader/
├── Cargo.toml
├── dll_loader/
│   ├── build.rs
│   └── src/      
│       ├── inject.rs      # Advanced injection implementations
│       ├── main.rs        # Multi-page GUI
│       └── processes.rs   # PE parsing and process management
├── rusty_dll/
│   └── src/
│       └── lib.rs         # Enhanced test DLL
└── FEATURE_SUMMARY.md     # Detailed implementation guide
```

## 🚀 New Features Implemented

- ✅ Fixed and improved process hollowing technique
- ✅ Implemented reflective DLL injection
- ✅ Added IAT fixups for full manual mapping
- ✅ Implemented thread hijacking alternative
- ✅ Added basic AV evasion research modes
- ✅ Created separate UI pages for different techniques