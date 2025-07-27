#[derive(Debug, Clone, Default)]
pub struct ExportInfo {
    pub name: String,
    pub virtual_address: usize,
    pub rva: usize,
    pub offset: usize,
    // PE Metadata
    pub machine: u16,
    pub number_of_sections: usize,
    pub entry_point: u32,
    pub image_base: usize,
    pub size_of_image: usize,
    pub size_of_headers: usize,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub timestamp: u32,
    pub section_info: Vec<SectionInfo>,
    pub import_info: Vec<ImportInfo>,
    pub export_info: Vec<ExportFuncInfo>,
    pub tls_info: Option<TlsInfo>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_size: usize,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExportFuncInfo {
    pub name: Option<String>,
    pub rva: usize,
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub start_address_of_raw_data: usize,
    pub end_address_of_raw_data: usize,
    pub address_of_index: usize,
    pub address_of_callbacks: usize,
}