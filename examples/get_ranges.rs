use superfetch::MemoryMap;

fn main() {
    let mm = unsafe { 
        match MemoryMap::snapshot() {
            Ok(m) => m,
            Err(e) => {
                println!("[!] {}", e);
                return;
            }
        }
    };

    let m_ranges = mm.ranges();

    println!("[*] Memory ranges ({}): ", m_ranges.len());
    for range in m_ranges {
        println!("     memory_range[pfn={}, page_count={} ]", range.pfn, range.page_count); 
    }
}
