#![allow(nonstandard_style)]

use std::ffi::c_void;

use ntapi::ntexapi::NtQuerySystemInformation;
use winapi::shared::{
    minwindef::ULONG,
    ntdef::{NTSTATUS, PVOID}
};

#[repr(C)]
#[allow(missing_docs)]
#[allow(unused)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SUPERFETCH_INFORMATION_CLASS {
    SuperfetchRetrieveTrace = 1,
    SuperfetchSystemParameters = 2,
    SuperfetchLogEvent = 3,
    SuperfetchGenerateTrace = 4,
    SuperfetchPrefetch = 5,
    SuperfetchPfnQuery = 6,
    SuperfetchPfnSetPriority = 7,
    SuperfetchPrivSourceQuery = 8,
    SuperfetchSequenceNumberQuery = 9,
    SuperfetchScenarioPhase = 10,
    SuperfetchWorkerPriority = 11,
    SuperfetchScenarioQuery = 12,
    SuperfetchScenarioPrefetch = 13,
    SuperfetchRobustnessControl = 14,
    SuperfetchTimeControl = 15,
    SuperfetchMemoryListQuery = 16,
    SuperfetchMemoryRangesQuery = 17,
    SuperfetchTracingControl = 18,
    SuperfetchTrimWhileAgingControl = 19,
    SuperfetchInformationMax = 20,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SUPERFETCH_INFORMATION {
    pub Version: u32,
    pub Magic: u32,
    pub InfoClass: SUPERFETCH_INFORMATION_CLASS,
    pub Data: *mut c_void,
    pub Length: u32,
}

/// Query Superfetch info
/// 
/// If you don't know how to use it, just don't use it then
/// 
/// If you willing to know how to use it, read articles from doc front-page
/// 
#[allow(nonstandard_style)]
pub unsafe fn superfetch(
    info_class: SUPERFETCH_INFORMATION_CLASS,
    buffer: *mut c_void,
    length: ULONG,
    return_length: *mut ULONG,
) -> NTSTATUS {
    let mut sf_info = SUPERFETCH_INFORMATION {
        Version: 45,
        Magic: u32::from_be_bytes(*b"kuhC"),
        InfoClass: info_class,
        Data: buffer,
        Length: length,
    };

    const SystemSuperfetchInformation: i32 = 0x4F;

    unsafe {
        NtQuerySystemInformation(
            SystemSuperfetchInformation as u32,
            &mut sf_info as *mut _ as PVOID,
            size_of::<SUPERFETCH_INFORMATION>() as ULONG,
            return_length,
        )
    }
}