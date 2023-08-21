//! C type definitions from the kernel module translated to Rust

#[repr(C)]
pub struct DataReadOrWrite {
    pub caller_mem_len: u64,
    pub procmem_ptr: u64,
    
    pub caller_mem: *mut u8,
    pub direction: u8,
}

#[repr(C)]
pub struct InspectorRequest {
    pub reads_and_writes: *const DataReadOrWrite,
    pub reads_and_writes_len: u64,
    pub target_process_id: i32,
}

#[repr(C)]
pub struct SearchOperation {
    pub max_search_results: u64,
    pub results_found: u64,

    pub results: *mut u64,
    pub contiguous_page_data: *const u8,
    pub search_term_len: u64,

    pub search_term: *const u8,
    pub process_id: i32,
}