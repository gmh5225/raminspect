//! This example changes the current text in Firefox's browser search bar from 
//! "Old search text" to "New search text". To run this example, open an instance
//! of Firefox and type "Old search text" in the search bar. If all goes well, when
//! you run this example as root, it should be replaced with "New search text",
//! although you may have to click on the search bar again in order for it to
//! render the new text.

fn main() {
    use raminspect::RamInspector;
    // Iterate over all running Firefox instances
    for pid in raminspect::find_processes("/usr/lib/firefox/firefox") {
        if let Ok(mut inspector) = RamInspector::new(pid) {
            for proc_addr in inspector.search_for_term(b"Old search text").unwrap() {
                unsafe {
                    // This is safe because modifying the text in the Firefox search bar will not crash
                    // the browser or negatively impact system stability in any way.

                    println!("Writing to process virtual address: 0x{:X}", proc_addr);
                    inspector.write_to_address(proc_addr, b"New search text").unwrap();
                }
            }
        }
    }
}