//! # `SuperFetch`
//! 
//! A lib allowing to utilize the Windows superfetch magic to translate 
//! virtual addresses to physical.
//! 
//! ## Overview
//! 
//! `SuperFetch` is a library designed to speed up the memory tool and exploit development on Windows systems. 
//! This crate will help you to quickly turn the virtual address to physical, using one simple function. Small example below:
//! ```rust
//! let va: LPVOID = get_base_addr("ntoskrnl.exe")?;
//! let mm: MemoryMap = unsafe { MemoryMap::snapshot()? };
//! let pa: u64 = mm.translate(va)?;
//! ```
//! You can find full example in example [folder of project github](https://github.com/I3r1h0n/SuperFetch).
//! 
//! ## Details
//! 
//! This crate utilizes the [Superfetch](https://learn.microsoft.com/en-us/windows-hardware/test/assessments/superfetch-prepare-memory-duration). 
//! This is a Windows service that can speed up data access by preloading it. If you are wondering how it works, I strongly recommend you to read these articles:
//! - [Inside windows page frame numbers](https://rayanfam.com/topics/inside-windows-page-frame-number-part1/) by [Sina Karvandi](https://github.com/SinaKarvandi)
//! - [Windows address translation deep dive](Ihttps://bsodtutorials.wordpress.com/2024/04/05/windows-address-translation-deep-dive-part-2/) by 0x14c
//! - [The SuperFetch Query superpower](https://v1k1ngfr.github.io/superfetchquery-superpower/) by [Viking](https://github.com/v1k1ngfr)
//! 
//! Later, I will write a small note explaining his technique on the high level, and leave it on project github.
//! 
//! This crate is based on the C++ library [superfetch](https://github.com/jonomango/superfetch) created by [jonomango](https://github.com/jonomango).
//! 

#![warn(missing_docs)]
use std::{
    ffi::c_void,
    ptr::null_mut,
    collections::HashMap, 
    mem::{size_of, zeroed},
    alloc::{alloc_zeroed, dealloc, Layout}
};

use winapi::shared::{
    ntdef::NT_SUCCESS,
    minwindef::{LPVOID, ULONG}
};

use crate::{
    error::SpfError,
    superfetch::{superfetch, SUPERFETCH_INFORMATION_CLASS},
    types::{
        PF_MEMORY_RANGE_INFO_V1, 
        PF_MEMORY_RANGE_INFO_V2, 
        PF_PHYSICAL_MEMORY_RANGE, 
        PF_PFN_PRIO_REQUEST, 
        MMPFN_IDENTITY,
        STATUS_BUFFER_TOO_SMALL
    }
};

/// The `error` module contains the crate error type
pub mod error;
/// The `type` module contains the windows types, nessesery for crate work
pub mod types;
/// The `superfetch` module provides the wrapper around the NtQuerySystemInformation
pub mod superfetch;

/// Physical memory range information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRange {
    /// Page frame number
    pub pfn: u64,
    /// Number of pages
    pub page_count: usize,
}

/// Memory map object
pub struct MemoryMap {
    /// Physical memory ranges
    memory_ranges: Vec<MemoryRange>,
    /// VA to PA translation map
    translations: HashMap<LPVOID, u64>,
}

impl MemoryMap {
    /// Returns a snapshot of a current system memory map.
    /// 
    /// # Details
    /// 
    /// Gets a physical memory ranges for current system, and builds a translation map. 
    /// 
    /// Translation map usually consist of around 1 million entries (this depents on amount of phyiscal memory available on your system), 
    /// so the building may take some time and consume a significant amount of memory, consider it when using. 
    /// 
    /// Also if you perform a lot of snapshot, make shure to drop the memory map right after you done with it.
    /// 
    /// # Note
    /// 
    /// Memory maps may become invalid after some time, so I recommend you to take a snapshot right before the VA to PA translation.
    /// 
    pub unsafe fn snapshot() -> Result<Self, SpfError> {
        // Privilege raise
        privilege::raise()?;

        // Get memory ranges
        let memory_ranges = unsafe { Self::query_ranges()? };

        let mut translations = HashMap::new();

        // Query PFN information to build translations
        for range in &memory_ranges {
            let base_pfn = range.pfn as usize;
            let page_count = range.page_count;

            // Allocate buffer for PF_PFN_PRIO_REQUEST + array of MMPFN_IDENTITY
            let buffer_length = size_of::<PF_PFN_PRIO_REQUEST>() + size_of::<MMPFN_IDENTITY>() * page_count;

            let layout = Layout::from_size_align(buffer_length, std::mem::align_of::<PF_PFN_PRIO_REQUEST>())
                .map_err(|_| SpfError::Layout)?;
            let buf_ptr = unsafe { alloc_zeroed(layout) };
            if buf_ptr.is_null() {
                return Err(SpfError::Allocation);
            }

            let request = buf_ptr as *mut PF_PFN_PRIO_REQUEST;
            unsafe {
                (*request).Version = 1;
                (*request).RequestFlags = 1;
                (*request).PfnCount = page_count;

                // Fill in the PageFrameIndex for each page in this range
                let page_data_ptr = (buf_ptr as *mut u8)
                    .add(size_of::<PF_PFN_PRIO_REQUEST>()) as *mut MMPFN_IDENTITY;
                for i in 0..page_count {
                    (*page_data_ptr.add(i)).PageFrameIndex = (base_pfn + i) as usize;
                }
            }

            // Query superfetch info for PFN data
            let status = unsafe {
                superfetch(
                    SUPERFETCH_INFORMATION_CLASS::SuperfetchPfnQuery,
                    request as *mut c_void,
                    buffer_length as ULONG,
                    null_mut(),
                )
            };

            if NT_SUCCESS(status) {
                // Cache the translations for each page
                let page_data_ptr = unsafe {
                    (buf_ptr as *mut u8)
                        .add(size_of::<PF_PFN_PRIO_REQUEST>()) as *mut MMPFN_IDENTITY
                };

                for i in 0..page_count {
                    unsafe {
                        let page_data = &(*page_data_ptr.add(i));
                        if !page_data.u2_VirtualAddress.is_null() {
                            let virt_addr = page_data.u2_VirtualAddress as LPVOID;
                            let phys_addr = ((base_pfn + i) << 12) as u64;
                            translations.insert(virt_addr, phys_addr);
                        } 
                    }
                }
            }

            unsafe { dealloc(buf_ptr, layout); }
        }

        Ok(Self {
            memory_ranges,
            translations
        })
    }

    /// Return memory ranges [`Vec<MemoryRange>`]
    pub fn ranges(&self) -> Vec<MemoryRange> {
        return self.memory_ranges.clone();
    }

    /// Return translations [`HashMap<LPVOID, u64>`]
    pub fn translations(&self) -> HashMap<LPVOID, u64> {
        return self.translations.clone();
    }

    /// Translate a virtual address to a physical address
    /// 
    /// # Description
    /// 
    /// Translates memory vitrual address to physical one, using the tranlsation map from the snapshot made.
    /// 
    /// # Example usage
    /// ```rust
    /// let some_va: LPVOID = //...some virtual address
    /// let some_pa = match mm.translate(some_va) {
    ///     Ok(p) => p,
    ///     Err(e: SpfError) => {
    ///         //...do something about the error  
    ///     }
    /// };
    /// ```
    /// 
    pub fn translate(&self, address: LPVOID) -> Result<u64, SpfError> {
        // Align to the lowest page boundary (page size = 4096 = 0x1000)
        let aligned = (address as u64) & !0xFFFu64;
        let aligned_ptr = aligned as LPVOID;

        // Look up in translations map
        match self.translations.get(&aligned_ptr) {
            Some(&phys_base) => {
                // Add offset within the page
                let offset = (address as u64) & 0xFFFu64;
                Ok(phys_base + offset)
            }
            None => Err(SpfError::Translate),
        }
    }

    /// Query memory ranges
    unsafe fn query_ranges() -> Result<Vec<MemoryRange>, SpfError> {
        let mut buffer_length: ULONG = 0;

        // Probe V1: expect STATUS_BUFFER_TOO_SMALL and required buffer length
        let mut probe_v1: PF_MEMORY_RANGE_INFO_V1 = unsafe { zeroed() };
        probe_v1.Version = 1;
        let status = unsafe {
            superfetch(
                SUPERFETCH_INFORMATION_CLASS::SuperfetchMemoryRangesQuery,
                &mut probe_v1 as *mut _ as *mut c_void,
                size_of::<PF_MEMORY_RANGE_INFO_V1>() as ULONG,
                &mut buffer_length as *mut ULONG,
            )
        };

        if status == STATUS_BUFFER_TOO_SMALL {
            if buffer_length == 0 {
                return Err(SpfError::Layout);
            }

            let size = buffer_length as usize;
            let align = std::mem::align_of::<PF_PHYSICAL_MEMORY_RANGE>();
            let layout = Layout::from_size_align(size, align).map_err(|_| SpfError::Layout)?;
            let buf_ptr = unsafe { alloc_zeroed(layout) };
            if buf_ptr.is_null() {
                return Err(SpfError::Allocation);
            }

            let info_ptr = buf_ptr as *mut PF_MEMORY_RANGE_INFO_V1;
            unsafe { (*info_ptr).Version = 1; }

            let call_status = unsafe {
                superfetch(
                    SUPERFETCH_INFORMATION_CLASS::SuperfetchMemoryRangesQuery,
                    info_ptr as *mut c_void,
                    buffer_length,
                    null_mut(),
                )
            };

            if call_status >= 0 {
                let range_count = unsafe { (*info_ptr).RangeCount as usize };
                let header_size = size_of::<PF_MEMORY_RANGE_INFO_V1>();
                let ranges_ptr = unsafe { buf_ptr.add(header_size - size_of::<PF_PHYSICAL_MEMORY_RANGE>()) as *const PF_PHYSICAL_MEMORY_RANGE };
                let mut ranges = Vec::with_capacity(range_count);
                for i in 0..range_count {
                    let r = unsafe { *ranges_ptr.add(i) };
                    ranges.push(MemoryRange { pfn: r.BasePfn as u64, page_count: r.PageCount as usize });
                }
                unsafe { dealloc(buf_ptr, layout) };
                return Ok(ranges);
            }

            unsafe { dealloc(buf_ptr, layout) };
        }

        // Probe V2
        buffer_length = 0;
        let mut probe_v2: PF_MEMORY_RANGE_INFO_V2 = unsafe { zeroed() };
        probe_v2.Version = 2;
        let status2 = unsafe {
            superfetch(
                SUPERFETCH_INFORMATION_CLASS::SuperfetchMemoryRangesQuery,
                &mut probe_v2 as *mut _ as *mut c_void,
                size_of::<PF_MEMORY_RANGE_INFO_V2>() as ULONG,
                &mut buffer_length as *mut ULONG,
            )
        };

        if status2 == STATUS_BUFFER_TOO_SMALL { 
            if buffer_length == 0 {
                return Err(SpfError::Layout);
            }

            let size = buffer_length as usize;
            let align = std::mem::align_of::<PF_PHYSICAL_MEMORY_RANGE>();
            let layout = Layout::from_size_align(size, align).map_err(|_| SpfError::Layout)?;
            let buf_ptr = unsafe { alloc_zeroed(layout) };
            if buf_ptr.is_null() {
                return Err(SpfError::Allocation);
            }

            let info_ptr = buf_ptr as *mut PF_MEMORY_RANGE_INFO_V2;
            unsafe { (*info_ptr).Version = 2; }

            let call_status = unsafe {
                superfetch(
                    SUPERFETCH_INFORMATION_CLASS::SuperfetchMemoryRangesQuery,
                    info_ptr as *mut c_void,
                    buffer_length,
                    null_mut(),
                )
            };

            if call_status >= 0 {
                let range_count = unsafe { (*info_ptr).RangeCount as usize };
                let header_size = size_of::<PF_MEMORY_RANGE_INFO_V2>();

                let ranges_ptr = unsafe { 
                    buf_ptr.add(header_size - size_of::<PF_PHYSICAL_MEMORY_RANGE>()) as *const PF_PHYSICAL_MEMORY_RANGE 
                };

                let mut ranges = Vec::with_capacity(range_count);
                for i in 0..range_count {
                    let r = unsafe { *ranges_ptr.add(i) };
                    ranges.push(MemoryRange { pfn: r.BasePfn as u64, page_count: r.PageCount as usize });
                }
                unsafe { dealloc(buf_ptr, layout) };
                return Ok(ranges);
            }

            unsafe { dealloc(buf_ptr, layout) };
            return Err(SpfError::QueryRanges(call_status));
        } else {
            return Err(SpfError::QueryRanges(status2));
        }
    }
}

mod privilege {
    use ntapi::{ntrtl::RtlAdjustPrivilege, ntseapi::{SE_DEBUG_PRIVILEGE, SE_PROF_SINGLE_PROCESS_PRIVILEGE}};
    use winapi::shared::ntdef::{BOOLEAN, NT_SUCCESS};

    use crate::error::SpfError;

    pub fn raise() -> Result<(), SpfError> {
        unsafe {
            let mut old: BOOLEAN = 0;
            let status1 = RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE as u32, 1, 0, &mut old);
            if !NT_SUCCESS(status1) {
                return Err(SpfError::RaisePrivilege(status1));
            }

            let mut old2: BOOLEAN = 0;
            let status2 = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE as u32, 1, 0, &mut old2);
            if !NT_SUCCESS(status2) {
                return Err(SpfError::RaisePrivilege(status2));
            }

            return Ok(());
        }
    }
}
