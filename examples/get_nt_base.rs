use std::ptr;

use superfetch::MemoryMap;
use widestring::U16CString;
use winapi::ctypes::c_void;
use winapi::um::psapi::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};
use winapi::shared::minwindef::{DWORD, LPVOID};

fn get_base_addr(drv_name: &str) -> Option<LPVOID> {
    // Allocate a buffer for device drivers
    let mut drivers: [LPVOID; 1024] = [ptr::null_mut(); 1024];
    let mut cb_needed: DWORD = 0;

    // Enumerate device drivers
    unsafe {
        if EnumDeviceDrivers(
            drivers.as_mut_ptr(), 
            (std::mem::size_of::<LPVOID>() * drivers.len()) as DWORD, 
            &mut cb_needed
        ) != 0 && cb_needed < (std::mem::size_of::<LPVOID>() * drivers.len()) as DWORD 
        {
            // Calculate number of drivers
            let n_drivers = (cb_needed / std::mem::size_of::<LPVOID>() as DWORD) as usize;
            
            // Buffer for driver base name
            let mut sz_drivers: [u16; 1024] = [0; 1024];

            // Iterate through drivers
            for i in 0..n_drivers {
                if GetDeviceDriverBaseNameW(
                    drivers[i], 
                    sz_drivers.as_mut_ptr(), 
                    (sz_drivers.len()) as u32
                ) > 0 
                {
                    // Convert driver name to string
                    let current_driver_name = U16CString::from_vec_truncate(
                        sz_drivers.iter()
                            .take_while(|&&x| x != 0)
                            .cloned()
                            .collect::<Vec<u16>>()
                    ).to_string_lossy();
                    
                    // Compare driver names
                    if current_driver_name == drv_name {
                        return Some(drivers[i]);
                    }
                }
            }
        }
    }
    
    // Return None if no matching driver found
    None
}

fn main() {
    let nt_base: LPVOID = match get_base_addr("ntoskrnl.exe") {
        Some(base_addr) => {
            if base_addr == 0 as *mut c_void {
                println!("[!] Unable to obtain base address");
                return;
            } else {
                base_addr
            }
        },
        None => {
            println!("[!] Driver not found");
            return;
        },
    };

    let mm = unsafe { 
        match MemoryMap::snapshot() {
            Ok(m) => m,
            Err(e) => {
                println!("[!] {}", e);
                return;
            }
        }
    };

    match mm.translate(nt_base){
        Ok(nt_base_pa) => {
            println!("\n[*] ntoskrnl.exe VA: {:p}", nt_base);
            println!("[*] ntosktrl.exe PA: {:#x}", nt_base_pa);
        }
        Err(e) => {
            println!("[!] {}", e);
        }
    }
}
