#![allow(nonstandard_style, missing_docs)]

use std::ffi::c_void;

use winapi::shared::{
    ntdef::NTSTATUS,
    minwindef::ULONG,
    basetsd::ULONG_PTR
};

/// PF structures
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PF_PHYSICAL_MEMORY_RANGE {
    pub BasePfn: ULONG_PTR,
    pub PageCount: ULONG_PTR,
}

/// PF Memory range strucvture
/// 
/// On x86_64 that means 8-byte alignment; use repr(align(8)) to
/// match the C compiler behaviour for the flexible-array-member case.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct PF_MEMORY_RANGE_INFO_V1 {
    pub Version: ULONG,
    pub RangeCount: ULONG,
    // followed by PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY]
    pub Ranges: [PF_PHYSICAL_MEMORY_RANGE; 1],
}

/// PF Memory range strucvture
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct PF_MEMORY_RANGE_INFO_V2 {
    pub Version: ULONG,
    pub Flags: ULONG,
    pub RangeCount: ULONG,
    // followed by PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY]
    pub Ranges: [PF_PHYSICAL_MEMORY_RANGE; 1],
}

/// STATUS_BUFFER_TOO_SMALL (0xC0000023) as NTSTATUS
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = -1073741789i32;

/// MMPFN_IDENTITY structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MMPFN_IDENTITY {
    pub u1: u64,  // Union of various frame information types
    pub PageFrameIndex: ULONG_PTR,
    pub u2_VirtualAddress: *mut c_void,  // Union field - using VirtualAddress variant
}

/// SYSTEM_MEMORY_LIST_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SYSTEM_MEMORY_LIST_INFORMATION {
    pub ZeroPageCount: usize,
    pub FreePageCount: usize,
    pub ModifiedPageCount: usize,
    pub ModifiedNoWritePageCount: usize,
    pub BadPageCount: usize,
    pub PageCountByPriority: [usize; 8],
    pub RepurposedPagesByPriority: [usize; 8],
    pub ModifiedPageCountPageFile: ULONG_PTR,
}

/// PF_PFN_PRIO_REQUEST structure
#[repr(C)]
#[derive(Debug)]
pub struct PF_PFN_PRIO_REQUEST {
    pub Version: ULONG,
    pub RequestFlags: ULONG,
    pub PfnCount: usize,
    pub MemInfo: SYSTEM_MEMORY_LIST_INFORMATION,
    // followed by MMPFN_IDENTITY PageData[PfnCount]
}
