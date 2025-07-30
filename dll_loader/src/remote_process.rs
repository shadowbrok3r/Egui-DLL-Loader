use goblin::pe::{PE, utils::find_offset};
use scroll::{Pread, LE};

/// Parse PE buffer using goblin and extract import DLLs
pub fn goblin_imports(pe_buf: &[u8]) -> Option<Vec<String>> {
    // Manual PE parsing for import DLLs
    // DOS header: e_lfanew at 0x3C
    if pe_buf.len() < 0x100 { return None; }
    let e_lfanew = u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;
    if pe_buf.len() < e_lfanew + 0x108 { return None; }
    let nt_headers = &pe_buf[e_lfanew..e_lfanew+0x108];
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset+1]]);
    let import_dir_offset = if magic == 0x10b { optional_header_offset + 0x60 } else if magic == 0x20b { optional_header_offset + 0x70 } else { return None; };
    let import_rva = u32::from_le_bytes([
        nt_headers[import_dir_offset],
        nt_headers[import_dir_offset+1],
        nt_headers[import_dir_offset+2],
        nt_headers[import_dir_offset+3],
    ]) as usize;
    if import_rva == 0 { return None; }
    // Find section containing import_rva
    let num_sections = u16::from_le_bytes([nt_headers[6], nt_headers[7]]) as usize;
    let section_table_offset = e_lfanew + 0x108;
    let mut import_offset = 0;
    for i in 0..num_sections {
        let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
        let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
        let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
        if import_rva >= va && import_rva < va + raw_size {
            import_offset = raw_ptr + (import_rva - va);
            break;
        }
    }
    if import_offset == 0 || pe_buf.len() < import_offset + 20 { return None; }
    let mut imports = Vec::new();
    let mut offset = 0;
    loop {
        if pe_buf.len() < import_offset + offset + 20 { break; }
        let desc = &pe_buf[import_offset + offset .. import_offset + offset + 20];
        let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]) as usize;
        if name_rva == 0 { break; }
        // Find section for name_rva
        let mut name_offset = 0;
        for i in 0..num_sections {
            let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
            let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
            let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
            let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
            if name_rva >= va && name_rva < va + raw_size {
                name_offset = raw_ptr + (name_rva - va);
                break;
            }
        }
        if name_offset == 0 || name_offset >= pe_buf.len() { break; }
        let mut dll_name_bytes = Vec::new();
        let mut name_idx = 0;
        loop {
            if name_offset + name_idx >= pe_buf.len() { break; }
            let b = pe_buf[name_offset + name_idx];
            if b == 0 { break; }
            dll_name_bytes.push(b);
            name_idx += 1;
        }
        let dll_name = String::from_utf8_lossy(&dll_name_bytes).to_string();
        imports.push(dll_name);
        offset += 20;
    }
    if imports.is_empty() { None } else { Some(imports) }
}

/// Parse PE buffer using goblin and extract export names
pub fn goblin_exports(pe_buf: &[u8]) -> Option<Vec<String>> {
    // Manual PE parsing for export names
    if pe_buf.len() < 0x100 { return None; }
    let e_lfanew = u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;
    if pe_buf.len() < e_lfanew + 0x108 { return None; }
    let nt_headers = &pe_buf[e_lfanew..e_lfanew+0x108];
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset+1]]);
    let export_dir_offset = if magic == 0x10b { optional_header_offset + 0x58 } else if magic == 0x20b { optional_header_offset + 0x68 } else { return None; };
    let export_rva = u32::from_le_bytes([
        nt_headers[export_dir_offset],
        nt_headers[export_dir_offset+1],
        nt_headers[export_dir_offset+2],
        nt_headers[export_dir_offset+3],
    ]) as usize;
    if export_rva == 0 { return None; }
    let num_sections = u16::from_le_bytes([nt_headers[6], nt_headers[7]]) as usize;
    let section_table_offset = e_lfanew + 0x108;
    let mut export_offset = 0;
    for i in 0..num_sections {
        let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
        let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
        let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
        if export_rva >= va && export_rva < va + raw_size {
            export_offset = raw_ptr + (export_rva - va);
            break;
        }
    }
    if export_offset == 0 || pe_buf.len() < export_offset + 40 { return None; }
    let export_dir = &pe_buf[export_offset..export_offset+40];
    let num_names = u32::from_le_bytes([export_dir[24], export_dir[25], export_dir[26], export_dir[27]]) as usize;
    let names_rva = u32::from_le_bytes([export_dir[32], export_dir[33], export_dir[34], export_dir[35]]) as usize;
    if num_names == 0 || names_rva == 0 { return None; }
    let mut names_offset = 0;
    for i in 0..num_sections {
        let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
        let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
        let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
        if names_rva >= va && names_rva < va + raw_size {
            names_offset = raw_ptr + (names_rva - va);
            break;
        }
    }
    if names_offset == 0 || pe_buf.len() < names_offset + num_names * 4 { return None; }
    let mut exports = Vec::new();
    for i in 0..num_names {
        let name_rva = u32::from_le_bytes([
            pe_buf[names_offset + i*4],
            pe_buf[names_offset + i*4 + 1],
            pe_buf[names_offset + i*4 + 2],
            pe_buf[names_offset + i*4 + 3],
        ]) as usize;
        let mut name_offset = 0;
        for j in 0..num_sections {
            let sec = &pe_buf[section_table_offset + j*40 .. section_table_offset + (j+1)*40];
            let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
            let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
            let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
            if name_rva >= va && name_rva < va + raw_size {
                name_offset = raw_ptr + (name_rva - va);
                break;
            }
        }
        if name_offset == 0 || name_offset >= pe_buf.len() { continue; }
        let mut name_bytes = Vec::new();
        let mut name_idx = 0;
        loop {
            if name_offset + name_idx >= pe_buf.len() { break; }
            let b = pe_buf[name_offset + name_idx];
            if b == 0 { break; }
            name_bytes.push(b);
            name_idx += 1;
        }
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        exports.push(name);
    }
    if exports.is_empty() { None } else { Some(exports) }
}

/// Parse PE buffer using goblin and extract section names
pub fn goblin_sections(pe_buf: &[u8]) -> Option<Vec<String>> {
    // Manual PE parsing for section names
    if pe_buf.len() < 0x100 { return None; }
    let e_lfanew = u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;
    if pe_buf.len() < e_lfanew + 0x108 { return None; }
    let nt_headers = &pe_buf[e_lfanew..e_lfanew+0x108];
    let num_sections = u16::from_le_bytes([nt_headers[6], nt_headers[7]]) as usize;
    let section_table_offset = e_lfanew + 0x108;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
        let name_bytes = &sec[0..8];
        let name = name_bytes.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect::<String>();
        sections.push(name);
    }
    if sections.is_empty() { None } else { Some(sections) }
}

/// Parse PE buffer using goblin and extract TLS callback addresses
pub fn goblin_tls_callbacks(pe_buf: &[u8]) -> Option<Vec<usize>> {
    // Manual PE parsing for TLS callbacks
    if pe_buf.len() < 0x100 { return None; }
    let e_lfanew = u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;
    if pe_buf.len() < e_lfanew + 0x108 { return None; }
    let nt_headers = &pe_buf[e_lfanew..e_lfanew+0x108];
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset+1]]);
    let tls_dir_offset = if magic == 0x10b { optional_header_offset + 0xC8 } else if magic == 0x20b { optional_header_offset + 0xD8 } else { return None; };
    let tls_rva = u32::from_le_bytes([
        nt_headers[tls_dir_offset],
        nt_headers[tls_dir_offset+1],
        nt_headers[tls_dir_offset+2],
        nt_headers[tls_dir_offset+3],
    ]) as usize;
    if tls_rva == 0 { return None; }
    let num_sections = u16::from_le_bytes([nt_headers[6], nt_headers[7]]) as usize;
    let section_table_offset = e_lfanew + 0x108;
    let mut tls_offset = 0;
    for i in 0..num_sections {
        let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
        let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
        let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
        if tls_rva >= va && tls_rva < va + raw_size {
            tls_offset = raw_ptr + (tls_rva - va);
            break;
        }
    }
    if tls_offset == 0 { return None; }
    let dir_size = if magic == 0x20b { 40 } else { 24 };
    if pe_buf.len() < tls_offset + dir_size { return None; }
    let ptr_size = if magic == 0x20b { 8 } else { 4 };
    let callbacks_va = if magic == 0x20b {
        u64::from_le_bytes([
            pe_buf[tls_offset+24], pe_buf[tls_offset+25], pe_buf[tls_offset+26], pe_buf[tls_offset+27],
            pe_buf[tls_offset+28], pe_buf[tls_offset+29], pe_buf[tls_offset+30], pe_buf[tls_offset+31],
        ]) as usize
    } else {
        u32::from_le_bytes([
            pe_buf[tls_offset+16], pe_buf[tls_offset+17], pe_buf[tls_offset+18], pe_buf[tls_offset+19],
        ]) as usize
    };
    if callbacks_va == 0 { return None; }
    // Find file offset for AddressOfCallbacks
    let mut callbacks_offset = 0;
    for i in 0..num_sections {
        let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
        let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
        let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
        if callbacks_va >= va && callbacks_va < va + raw_size {
            callbacks_offset = raw_ptr + (callbacks_va - va);
            break;
        }
    }
    if callbacks_offset == 0 { return None; }
    let mut callbacks = Vec::new();
    let mut offset = 0;
    loop {
        if pe_buf.len() < callbacks_offset + offset + ptr_size { break; }
        let callback = if ptr_size == 8 {
            u64::from_le_bytes([
                pe_buf[callbacks_offset+offset], pe_buf[callbacks_offset+offset+1], pe_buf[callbacks_offset+offset+2], pe_buf[callbacks_offset+offset+3],
                pe_buf[callbacks_offset+offset+4], pe_buf[callbacks_offset+offset+5], pe_buf[callbacks_offset+offset+6], pe_buf[callbacks_offset+offset+7],
            ]) as usize
        } else {
            u32::from_le_bytes([
                pe_buf[callbacks_offset+offset], pe_buf[callbacks_offset+offset+1], pe_buf[callbacks_offset+offset+2], pe_buf[callbacks_offset+offset+3],
            ]) as usize
        };
        if callback == 0 { break; }
        callbacks.push(callback);
        offset += ptr_size;
    }
    if callbacks.is_empty() { None } else { Some(callbacks) }
}

/// Parse PE buffer using goblin and extract relocation block RVAs
pub fn goblin_reloc_blocks(pe_buf: &[u8]) -> Option<Vec<usize>> {
    // Manual PE parsing for relocation block RVAs
    if pe_buf.len() < 0x100 { return None; }
    let e_lfanew = u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;
    if pe_buf.len() < e_lfanew + 0x108 { return None; }
    let nt_headers = &pe_buf[e_lfanew..e_lfanew+0x108];
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset+1]]);
    let reloc_dir_offset = if magic == 0x10b { optional_header_offset + 0xA0 } else if magic == 0x20b { optional_header_offset + 0xB0 } else { return None; };
    let reloc_rva = u32::from_le_bytes([
        nt_headers[reloc_dir_offset],
        nt_headers[reloc_dir_offset+1],
        nt_headers[reloc_dir_offset+2],
        nt_headers[reloc_dir_offset+3],
    ]) as usize;
    let reloc_size = u32::from_le_bytes([
        nt_headers[reloc_dir_offset+4],
        nt_headers[reloc_dir_offset+5],
        nt_headers[reloc_dir_offset+6],
        nt_headers[reloc_dir_offset+7],
    ]) as usize;
    if reloc_rva == 0 || reloc_size == 0 { return None; }
    let num_sections = u16::from_le_bytes([nt_headers[6], nt_headers[7]]) as usize;
    let section_table_offset = e_lfanew + 0x108;
    let mut reloc_offset = 0;
    for i in 0..num_sections {
        let sec = &pe_buf[section_table_offset + i*40 .. section_table_offset + (i+1)*40];
        let va = u32::from_le_bytes([sec[12], sec[13], sec[14], sec[15]]) as usize;
        let raw_ptr = u32::from_le_bytes([sec[20], sec[21], sec[22], sec[23]]) as usize;
        let raw_size = u32::from_le_bytes([sec[16], sec[17], sec[18], sec[19]]) as usize;
        if reloc_rva >= va && reloc_rva < va + raw_size {
            reloc_offset = raw_ptr + (reloc_rva - va);
            break;
        }
    }
    if reloc_offset == 0 { return None; }
    let mut blocks = Vec::new();
    let mut offset = 0;
    while offset < reloc_size {
        if pe_buf.len() < reloc_offset + offset + 8 { break; }
        let page_rva = u32::from_le_bytes([
            pe_buf[reloc_offset+offset],
            pe_buf[reloc_offset+offset+1],
            pe_buf[reloc_offset+offset+2],
            pe_buf[reloc_offset+offset+3],
        ]) as usize;
        let block_size = u32::from_le_bytes([
            pe_buf[reloc_offset+offset+4],
            pe_buf[reloc_offset+offset+5],
            pe_buf[reloc_offset+offset+6],
            pe_buf[reloc_offset+offset+7],
        ]) as usize;
        if page_rva == 0 || block_size < 8 { break; }
        blocks.push(page_rva);
        offset += block_size;
    }
    if blocks.is_empty() { None } else { Some(blocks) }
}
use windows::Win32::{Foundation::{HANDLE}, System::Diagnostics::{Debug::ReadProcessMemory, ToolHelp::*}};
use anyhow::{Result, anyhow};
use std::ffi::c_void;

/// Reads memory from a remote process
pub fn read_remote_memory(process: HANDLE, address: usize, size: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut read = 0;
    unsafe {
        let success = ReadProcessMemory(
            process,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            Some(&mut read),
        );
        if let Err(e) = success {
            if read == 0 {
                return Err(anyhow!("Failed to read remote memory: {e:?}"));
            } else {
                return Err(anyhow!("Read memory but encountered an error: {e:?}"));
            }
        }
    }
    Ok(buffer)
}

/// Finds the base address of the main module in the remote process
pub fn get_remote_base_address(process_id: u32) -> Result<usize> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id)?;
        let mut module_entry = MODULEENTRY32W { dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32, ..Default::default() };
        if Module32FirstW(snapshot, &mut module_entry).is_ok() {
            log::warn!("get_remote_base_address: {:?}", module_entry.modBaseAddr);
            Ok(module_entry.modBaseAddr as usize)
        } else {
            Err(anyhow!("Failed to get module base address"))
        }
    }
}

/// Scans the remote process for PE headers and returns raw header data
pub fn get_remote_pe_headers(process: HANDLE, base_address: usize) -> Result<Vec<u8>> {
    // Read DOS header first
    let dos_header = read_remote_memory(process, base_address, 0x100)?;
    // Parse e_lfanew
    let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]) as usize;
    // Read NT headers
    let nt_headers = read_remote_memory(process, base_address + e_lfanew, 0x108)?;
    // Combine for full header
    let mut full_header = dos_header;
    full_header.extend_from_slice(&nt_headers);
    log::warn!("Got PE Headers: {:?}", full_header.len());
    Ok(full_header)
}

/// Extracts import table info from remote process
pub fn get_remote_imports(process: HANDLE, base_address: usize) -> Result<Option<Vec<String>>> {
    // Read DOS header
    let dos_header = read_remote_memory(process, base_address, 0x100)?;
    let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]) as usize;
    // Read NT headers
    let nt_headers = read_remote_memory(process, base_address + e_lfanew, 0x108)?;
    // Get Optional Header offset
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset + 1]]);
    let import_dir_offset = if magic == 0x10b {
        // PE32
        optional_header_offset + 0x60
    } else if magic == 0x20b {
        // PE32+
        optional_header_offset + 0x70
    } else {
        return Ok(None);
    };

    let import_rva = u32::from_le_bytes([
        nt_headers[import_dir_offset],
        nt_headers[import_dir_offset + 1],
        nt_headers[import_dir_offset + 2],
        nt_headers[import_dir_offset + 3],
    ]) as usize;

    let _import_size = u32::from_le_bytes([
        nt_headers[import_dir_offset + 4],
        nt_headers[import_dir_offset + 5],
        nt_headers[import_dir_offset + 6],
        nt_headers[import_dir_offset + 7],
    ]) as usize;

    if import_rva == 0 {
        return Ok(None);
    }

    // Read first few IMAGE_IMPORT_DESCRIPTORs
    let mut imports = Vec::new();
    let mut offset = 0;
    loop {
        let desc = read_remote_memory(process, base_address + import_rva + offset, 20)?;
        let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]) as usize;
        if name_rva == 0 {
            break;
        }
        // Read DLL name
        let mut dll_name_bytes = Vec::new();
        let mut name_offset = 0;
        loop {
            let b = read_remote_memory(process, base_address + name_rva + name_offset, 1)?[0];
            if b == 0 { break; }
            dll_name_bytes.push(b);
            name_offset += 1;
        }
        let dll_name = String::from_utf8_lossy(&dll_name_bytes).to_string();
        imports.push(dll_name);
        offset += 20;
    }
    if imports.is_empty() {
        Ok(None)
    } else {
        log::warn!("Got some Imports: {imports:?}");
        Ok(Some(imports))
    }
}

/// Extracts export table info from remote process
pub fn get_remote_exports(process: HANDLE, base_address: usize) -> Result<Option<Vec<String>>> {
    // Read DOS header
    let dos_header = read_remote_memory(process, base_address, 0x100)?;
    let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]) as usize;
    // Read NT headers
    let nt_headers = read_remote_memory(process, base_address + e_lfanew, 0x108)?;
    // Get Optional Header offset
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset + 1]]);
    let export_dir_offset = if magic == 0x10b {
        // PE32
        optional_header_offset + 0x58
    } else if magic == 0x20b {
        // PE32+
        optional_header_offset + 0x68
    } else {
        return Ok(None);
    };
    let export_rva = u32::from_le_bytes([
        nt_headers[export_dir_offset],
        nt_headers[export_dir_offset + 1],
        nt_headers[export_dir_offset + 2],
        nt_headers[export_dir_offset + 3],
    ]) as usize;
    if export_rva == 0 {
        return Ok(None);
    }
    // Read IMAGE_EXPORT_DIRECTORY (40 bytes)
    let export_dir = read_remote_memory(process, base_address + export_rva, 40)?;
    let num_names = u32::from_le_bytes([export_dir[24], export_dir[25], export_dir[26], export_dir[27]]) as usize;
    let names_rva = u32::from_le_bytes([export_dir[32], export_dir[33], export_dir[34], export_dir[35]]) as usize;
    if num_names == 0 || names_rva == 0 {
        return Ok(None);
    }
    let mut exports = Vec::new();
    for i in 0..num_names {
        let name_rva_bytes = read_remote_memory(process, base_address + names_rva + i * 4, 4)?;
        let name_rva = u32::from_le_bytes([name_rva_bytes[0], name_rva_bytes[1], name_rva_bytes[2], name_rva_bytes[3]]) as usize;
        // Read export name string
        let mut name_bytes = Vec::new();
        let mut name_offset = 0;
        loop {
            let b = read_remote_memory(process, base_address + name_rva + name_offset, 1)?[0];
            if b == 0 { break; }
            name_bytes.push(b);
            name_offset += 1;
        }
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        exports.push(name);
    }
    if exports.is_empty() {
        Ok(None)
    } else {
        log::warn!("Got some Exports: {exports:?}");
        Ok(Some(exports))
    }
}

/// Extracts TLS callback addresses from remote process
pub fn get_remote_tls_callbacks(process: HANDLE, base_address: usize) -> Result<Option<Vec<usize>>> {
    // Read DOS header
    let dos_header = read_remote_memory(process, base_address, 0x100)?;
    let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]) as usize;
    // Read NT headers
    let nt_headers = read_remote_memory(process, base_address + e_lfanew, 0x108)?;
    // Get Optional Header offset
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset + 1]]);
    let tls_dir_offset = if magic == 0x10b {
        // PE32
        optional_header_offset + 0xC8
    } else if magic == 0x20b {
        // PE32+
        optional_header_offset + 0xD8
    } else {
        return Ok(None);
    };
    let tls_rva = u32::from_le_bytes([
        nt_headers[tls_dir_offset],
        nt_headers[tls_dir_offset + 1],
        nt_headers[tls_dir_offset + 2],
        nt_headers[tls_dir_offset + 3],
    ]) as usize;
    if tls_rva == 0 {
        return Ok(None);
    }
    // Read IMAGE_TLS_DIRECTORY (size: 24 for PE32, 40 for PE32+)
    let tls_dir_size = if magic == 0x10b { 24 } else { 40 };
    let tls_dir = read_remote_memory(process, base_address + tls_rva, tls_dir_size)?;
    // AddressOfCallbacks is at offset 16 (PE32) or 24 (PE32+)
    let callbacks_va = if magic == 0x10b {
        u32::from_le_bytes([tls_dir[16], tls_dir[17], tls_dir[18], tls_dir[19]]) as usize
    } else {
        u64::from_le_bytes([
            tls_dir[24], tls_dir[25], tls_dir[26], tls_dir[27],
            tls_dir[28], tls_dir[29], tls_dir[30], tls_dir[31],
        ]) as usize
    };
    if callbacks_va == 0 {
        return Ok(None);
    }
    // Read callback addresses until a NULL pointer is found
    let mut callbacks = Vec::new();
    let ptr_size = if magic == 0x10b { 4 } else { 8 };
    let mut offset = 0;
    loop {
        let callback_bytes = read_remote_memory(process, callbacks_va + offset, ptr_size)?;
        let callback = if ptr_size == 4 {
            u32::from_le_bytes([callback_bytes[0], callback_bytes[1], callback_bytes[2], callback_bytes[3]]) as usize
        } else {
            u64::from_le_bytes([
                callback_bytes[0], callback_bytes[1], callback_bytes[2], callback_bytes[3],
                callback_bytes[4], callback_bytes[5], callback_bytes[6], callback_bytes[7],
            ]) as usize
        };
        if callback == 0 {
            break;
        }
        callbacks.push(callback);
        offset += ptr_size;
    }
    if callbacks.is_empty() {
        Ok(None)
    } else {
        log::warn!("Got some Callbacks: {callbacks:?}");
        Ok(Some(callbacks))
    }
}

/// Extracts relocation table info from remote process
pub fn get_remote_relocations(process: HANDLE, base_address: usize) -> Result<Option<Vec<usize>>> {
    // Read DOS header
    let dos_header = read_remote_memory(process, base_address, 0x100)?;
    let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]) as usize;
    // Read NT headers
    let nt_headers = read_remote_memory(process, base_address + e_lfanew, 0x108)?;
    // Get Optional Header offset
    let optional_header_offset = 0x18;
    let magic = u16::from_le_bytes([nt_headers[optional_header_offset], nt_headers[optional_header_offset + 1]]);
    let reloc_dir_offset = if magic == 0x10b {
        // PE32
        optional_header_offset + 0xA0
    } else if magic == 0x20b {
        // PE32+
        optional_header_offset + 0xB0
    } else {
        return Ok(None);
    };
    let reloc_rva = u32::from_le_bytes([
        nt_headers[reloc_dir_offset],
        nt_headers[reloc_dir_offset + 1],
        nt_headers[reloc_dir_offset + 2],
        nt_headers[reloc_dir_offset + 3],
    ]) as usize;
    let reloc_size = u32::from_le_bytes([
        nt_headers[reloc_dir_offset + 4],
        nt_headers[reloc_dir_offset + 5],
        nt_headers[reloc_dir_offset + 6],
        nt_headers[reloc_dir_offset + 7],
    ]) as usize;
    if reloc_rva == 0 || reloc_size == 0 {
        return Ok(None);
    }
    // Parse relocation blocks
    let mut relocs = Vec::new();
    let mut offset = 0;
    while offset < reloc_size {
        let block = read_remote_memory(process, base_address + reloc_rva + offset, 8)?;
        let page_rva = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
        let block_size = u32::from_le_bytes([block[4], block[5], block[6], block[7]]) as usize;
        if page_rva == 0 || block_size < 8 {
            break;
        }
        relocs.push(page_rva);
        offset += block_size;
    }
    if relocs.is_empty() {
        Ok(None)
    } else {
        log::warn!("Got some Relocs: {relocs:?}");
        Ok(Some(relocs))
    }
}

/// Extracts section info from remote process
pub fn get_remote_sections(process: HANDLE, base_address: usize) -> Result<Option<Vec<String>>> {
    // Read DOS header
    let dos_header = read_remote_memory(process, base_address, 0x100)?;
    let e_lfanew = u32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]) as usize;
    // Read NT headers
    let nt_headers = read_remote_memory(process, base_address + e_lfanew, 0x108)?;
    // Number of sections is at offset 6 in NT headers
    let num_sections = u16::from_le_bytes([nt_headers[6], nt_headers[7]]) as usize;
    // Section headers start after NT headers (0x108 from e_lfanew)
    let section_table_offset = base_address + e_lfanew + 0x108;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let section_header = read_remote_memory(process, section_table_offset + i * 40, 40)?;
        // Name is first 8 bytes
        let name_bytes = &section_header[0..8];
        let name = name_bytes.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect::<String>();
        sections.push(name);
    }
    if sections.is_empty() {
        Ok(None)
    } else {
        log::warn!("Got some Sections: {sections:?}");
        Ok(Some(sections))
    }
}
