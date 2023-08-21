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
        let mut inspector = RamInspector::new(pid).unwrap();
        for proc_addr in inspector.search_for_term(b"Old search text").unwrap().to_vec() {
            unsafe {
                // This is safe because modifying the text in the Firefox search bar will not crash
                // the browser or negatively impact system stability in any way.
                inspector.queue_write(proc_addr, b"New search text");
            }
        }

        inspector.flush().unwrap();
    }
}