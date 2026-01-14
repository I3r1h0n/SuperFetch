use std::fmt;

use winapi::shared::ntdef::NTSTATUS;

/// Custom error type
pub enum SpfError {
    /// Can't raise needed privileges for current process
    /// 
    /// SuperFetch requires SE_PROF_SINGLE_PROCESS_PRIVILEGE and SE_DEBUG_PRIVILEGE
    /// 
    /// Returns [`NTSTATUS`] from windows call
    RaisePrivilege(NTSTATUS),
    /// Can't query memory ranges
    /// 
    /// Returns [`NTSTATUS`] from windows call
    QueryRanges(NTSTATUS),
    /// Can't translate page frame numbers
    /// 
    /// Returns [`NTSTATUS`] from windows call
    QueryPfn(NTSTATUS),
    /// Can't setup correct structure layout
    Layout,
    /// Can't translate virtual memory to physical
    /// 
    /// Actially means that we can't find needed element in memory translation HashMap
    Translate,
    /// Can't allocate memory
    Allocation
}

impl fmt::Display for SpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpfError::RaisePrivilege(s) => write!(f, "Can't raise privilege: {:#x}", s),
            SpfError::QueryPfn(s) => write!(f, "Can't query page frame numbers: {:#x}", s),
            SpfError::QueryRanges(s) => write!(f, "Can't query memory ranges: {:#x}", s),
            SpfError::Translate => write!(f, "Unable to translate VA to PA"),
            SpfError::Allocation => write!(f, "Unable allocate memory"),
            SpfError::Layout => write!(f, "Unable to form a correct layout")
        }
    }
}
