extern crate winapi;

use winapi::um::winuser::{MessageBoxW, MB_OK};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

fn main() {
    let msg: Vec<u16> = OsStr::new("EXE Injected Successfully!\nHello, World").encode_wide().chain(Some(0)).collect();
    let title: Vec<u16> = OsStr::new("Test EXE").encode_wide().chain(Some(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK,
        );
    }
}