extern crate winapi;

use winapi::um::winuser::{MessageBoxW, MB_OK};
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;

#[unsafe(no_mangle)]
pub extern "system" fn test_injection() -> i32 {
    let msg: Vec<u16> = OsStr::new("DLL Injected Successfully!").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Test DLL").encode_wide().chain(Some(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK,
        );
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_hinst: *mut (), _reason: u32, _reserved: *mut ()) -> i32 {
    let msg: Vec<u16> = OsStr::new("DLL Injected Successfully!").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Test DLL").encode_wide().chain(Some(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK,
        );
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    println!("Plugin initialized!");
}