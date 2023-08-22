//! A library used to find and replace arbitrary data in an arbitrary
//! processes memory on Linux systems. You must run your program as
//! root in order for this crate to function.

use std::fs::File;
use std::fs::OpenOptions;

use std::io::SeekFrom;
use std::io::prelude::*;

use nix::unistd::Pid;
use nix::sys::signal::kill;
use nix::sys::signal::SIGSTOP;
use nix::sys::signal::SIGCONT;

/// Finds a list of all processes containing a given search term in
/// their executable file name using a shell command. This makes
/// figuring out process IDs for the process you want to hijack
/// easier. The command used is present on basically every Linux
/// installations so this shouldn't ever not work (if it doesn't
/// file an issue on the GitHub repository).

pub fn find_processes(name_contains: &str) -> Vec<i32> {
    use std::process::Command;
    let mut results = Vec::new();
    let out = Command::new("ps").arg("-ax").output().unwrap();
    for line in String::from_utf8(out.stdout).unwrap().lines().filter(|line| line.contains(name_contains)) {
        let pid_string = line.trim().chars().take_while(|c| c.is_ascii_digit()).collect::<String>();
        results.push(pid_string.parse().unwrap());
    }

    results
}

/// This is the primary interface used by the crate to search through, read, and modify an
/// arbitrary processes' memory. 
/// 
/// Note that when an inspector is created for a process, the process will be paused until
/// the inspector is dropped, in order to ensure that we have exclusive access to the
/// processes' memory.
/// 
/// # Example Usage
/// 
/// ```rust
/// //! This example changes the current text in Firefox's browser search bar from 
/// //! "Old search text" to "New search text". To run this example, open an instance
/// //! of Firefox and type "Old search text" in the search bar. If all goes well, when
/// //! you run this example as root, it should be replaced with "New search text",
/// //! although you may have to click on the search bar again in order for it to
/// //! render the new text.
/// 
/// fn main() {
///     use raminspect::RamInspector;
///     // Iterate over all running Firefox instances
///     for pid in raminspect::find_processes("/usr/lib/firefox/firefox") {
///         if let Ok(mut inspector) = RamInspector::new(pid) {
///             for proc_addr in inspector.search_for_term(b"Old search text").unwrap() {
///                 unsafe {
///                     // This is safe because modifying the text in the Firefox search bar will not crash
///                    // the browser or negatively impact system stability in any way.
///                     inspector.write_to_address(proc_addr, b"New search text").unwrap();
///                 }
///             }
///         }
///     }
/// }
/// ```

pub struct RamInspector {
    pid: i32,
    proc_mem_file: File,
    proc_maps_file: File,
}

#[non_exhaustive]
/// The error type for this library. The variants have self-explanatory names.

pub enum RamInspectError {
    FailedToOpenProcMem,
    FailedToOpenProcMaps,
    FailedToPauseProcess,

    FailedToReadMem,
    FailedToWriteMem,
    FailedToReadProcMaps,
}

use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
impl Debug for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            RamInspectError::FailedToOpenProcMaps => "Failed to access the target processes' memory maps! Are you sure you're running as root? If you are, is the target process running?",
            RamInspectError::FailedToOpenProcMem => "Failed to open the target processes' memory file! Are you sure you're running as root? If you are, is the target process running?",
            RamInspectError::FailedToWriteMem => "Failed to write to the specified memory address! Are you sure you used an address derived from a search result?",
            RamInspectError::FailedToReadMem => "Failed to read from the specified memory address! Are you sure you used an address derived from a search result?",
            RamInspectError::FailedToReadProcMaps => "Failed to read the process memory maps file! This most likely means that the target process terminated.",
            RamInspectError::FailedToPauseProcess => "Failed to pause the target process! Are you sure it is currently running?",
        })
    }
}

impl RamInspector {
    /// Creates a new inspector attached to the specified process ID. This will pause the target process until
    /// the inspector is dropped.
    
    pub fn new(pid: i32) -> Result<Self, RamInspectError> {
        let proc_mem_file = OpenOptions::new().read(true).write(true).open(&format!("/proc/{}/mem", pid)).map_err(|_| {
            RamInspectError::FailedToOpenProcMem
        })?;

        let proc_maps_file = OpenOptions::new().read(true).write(true).open(&format!("/proc/{}/maps", pid)).map_err(|_| {
            RamInspectError::FailedToOpenProcMaps
        })?;

        // Pause the target process with a SIGSTOP signal
        kill(Pid::from_raw(pid), SIGSTOP).map_err(|_| RamInspectError::FailedToPauseProcess)?;

        Ok(RamInspector {
            pid,
            proc_mem_file,
            proc_maps_file,
        })
    }

    /// Fills the output buffer with memory read starting from the target address. This can fail
    /// if the target process was suddenly terminated or if the address used was not obtained
    /// from one of the searching functions called on this inspector.
    
    pub fn read_address(&mut self, addr: u64, out_buf: &mut [u8]) -> Result<(), RamInspectError> {
        self.proc_mem_file.seek(SeekFrom::Start(addr)).map_err(|_| RamInspectError::FailedToReadMem)?;
        self.proc_mem_file.read_exact(out_buf).map_err(|_| RamInspectError::FailedToReadMem)?;
        Ok(())
    }

    /// A convenience function that reads the specified amount of bytes from the target address
    /// and stores the output in a vector. This is shorthand for:
    /// 
    /// ```rust
    /// let mut out = vec![0; count];
    /// self.read_address(addr, &mut out);
    /// out
    /// ```
    
    pub fn read_vec(&mut self, addr: u64, count: usize) -> Result<Vec<u8>, RamInspectError> {
        let mut out = vec![0; count];
        self.read_address(addr, &mut out)?;
        Ok(out)
    }

    /// Writes tbe specified data to the specified memory address of the target process. This has
    /// the same failure conditions as [RamInspector::read_address].
    /// 
    /// For safety reasons the caller must ensure that writing the specified data to the specified memory
    /// will not negatively affect system stability in any way. This is especially important to consider
    /// in the case where the user is modifying the memory of a system process.
    
    pub unsafe fn write_to_address(&mut self, addr: u64, buf: &[u8]) -> Result<(), RamInspectError> {
        self.proc_mem_file.seek(SeekFrom::Start(addr)).map_err(|_| RamInspectError::FailedToWriteMem)?;
        self.proc_mem_file.write_all(buf).map_err(|_| RamInspectError::FailedToWriteMem)?;
        Ok(())
    }

    /// A function used internally to iterate over and process the target processes' memory regions. The first argument
    /// to the callback is the data contained within the memory region, and the second argument is the starting address
    /// of the memory region. This is exposed publicly to allow for more complicated, custom analysis of an applications' 
    /// memory than the built-in search function would allow on its own.
    /// 
    /// The reason why this is implemented as a function that takes a closure instead of an iterator is simply because
    /// I find this interface more elegant, it takes less LOC to implement, and there aren't any cases I can think 
    /// of where a regular iterator would provide any additional functionality that this wouldn't provide already.
    
    pub fn iter_memory_regions<F: FnMut(Vec<u8>, u64)>(&mut self, mut callback: F) -> Result<(), RamInspectError> {
        let mut memareas = String::new();
        self.proc_maps_file.read_to_string(&mut memareas).map_err(|_| RamInspectError::FailedToReadProcMaps)?;

        for line in memareas.lines() {
            let mut chars = line.chars();
            // The lines read from /proc/PID/maps should conform to the following format:
            //
            // HEX_START_ADDR-HEX_END_ADDR rw... etc
            //
            // Where rw describes whether or not the described memory region can be read from and
            // written to. If not the corresponding character will be dashed out. For example read-only 
            // memory areas would show an r- in the string and write-only ones would show a -w. Read-write
            // memory areas would contain both characters.

            let start_addr_string = (&mut chars).take_while(char::is_ascii_hexdigit).collect::<String>();
            let end_addr_string = (&mut chars).take_while(char::is_ascii_hexdigit).collect::<String>();

            // Only consider read / write memory areas
            if chars.next() == Some('r') && chars.next() == Some('w') {
                let start_addr = u64::from_str_radix(&start_addr_string, 16).unwrap();
                let end_addr = u64::from_str_radix(&end_addr_string, 16).unwrap();
                let mut region = vec![0; (end_addr - start_addr) as usize];

                self.proc_mem_file.seek(SeekFrom::Start(start_addr)).map_err(|_| RamInspectError::FailedToReadMem)?;
                self.proc_mem_file.read_exact(&mut region).map_err(|_| RamInspectError::FailedToReadMem)?;
                callback(region, start_addr);
            }
        }

        Ok(())
    }

    /// Searches the target processes' memory for the specified data. This will fail if the process 
    /// terminated unexpectedly, but should succeed in basically any other case.
    
    pub fn search_for_term(&mut self, search_term: &[u8]) -> Result<Vec<u64>, RamInspectError> {
        if search_term.is_empty() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        self.iter_memory_regions(|region, start_addr| {
            if region.len() < search_term.len() {
                return;
            }
                
            for i in 0..region.len() - search_term.len() {
                if region[i..].starts_with(search_term) {
                    out.push(start_addr + i as u64);
                }
            }
        })?;

        Ok(out)
    }
}

impl Drop for RamInspector {
    fn drop(&mut self) {
        // Resume the target process on drop with a SIGCONT. We ignore errors here
        // since there's no guarantee that the process is still running, so trying
        // to send a signal to it might fail.

        let _ = kill(Pid::from_raw(self.pid), SIGCONT);
    }
}