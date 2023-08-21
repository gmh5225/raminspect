//! A library used to find and replace arbitrary data in an arbitrary
//! processes memory on Linux systems. Root privileges are required, for 
//! obvious reasons, and the core kernel module has to be built and installed
//! by following the instructions detailed on the GitHub page before this can be used.
//! 
//! # Note
//! 
//! As of right now this only works on x86-64 Linux, although I might add support for 
//! more CPU architectures in the future (for example ARM), and contributions are welcome.

mod ffi;
use ffi::DataReadOrWrite;
use ffi::InspectorRequest;

use ffi::SearchOperation;
use core::marker::PhantomData;

mod ioctl;
use nix::unistd::Pid;
use nix::errno::Errno;
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

use std::fs::File;
/// This is the primary interface used by this library to communicate with
/// the backend kernel module. You can queue arbitrary reads and writes to
/// an arbitrary processes' memory using this structure, and execute them
/// all in a batch by using the flush method.
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
///         let mut inspector = RamInspector::new(pid).unwrap();
///         for proc_addr in inspector.search_for_term(b"Old search text").unwrap().to_vec() {
///             unsafe {
///                 // This is safe because modifying the text in the Firefox search bar will not crash
///                 // the browser or negatively impact system stability in any way.
///                 inspector.queue_write(proc_addr, b"New search text");
///             }
///         }
/// 
///         inspector.flush().unwrap();
///     }
/// }
/// ```

pub struct RamInspector<'a> {
    pid: i32,
    device_fd: i32,
    _device_file: File,
    phdata: PhantomData<&'a ()>,

    process_paused: bool,
    max_search_results: usize,
    search_results_buffer: Vec<u64>,
    queued_reads_and_writes: Vec<DataReadOrWrite>,
}

impl<'a> RamInspector<'a> {
    /// Creates a new [RamInspector] attached to the specified process ID with a default value
    /// of 100 maximum search results returnable by [RamInspector::search_for_term]. The maximum
    /// can be changed through the [RamInspector::set_max_search_results] method.
    
    pub fn new(pid: i32) -> Result<Self, String> {
        use std::fs::OpenOptions;
        use std::os::fd::AsRawFd;
        let max_search_results = 100;

        let device_file = OpenOptions::new()
            .read(true)
            .open("/dev/raminspect")
            .map_err(|_| "Failed to open raminspect device file! Are you sure you're running with root privileges? If you are, is the kernel module loaded?")?;

        let device_fd = device_file.as_raw_fd();

        Ok(RamInspector {
            pid,
            device_fd,
            max_search_results,
            phdata: PhantomData,
            process_paused: false,
            _device_file: device_file,
            queued_reads_and_writes: Vec::new(),
            search_results_buffer: vec![0; max_search_results],
        })
    }

    /// Searches the target applications' memory for the given search term.
    /// The maximum number of results returned can be controlled using the
    /// [RamInspector::max_search_results] and [RamInspector::set_max_search_results] methods.
    /// 
    /// This fails if the ioctl call sent to the kernel module fails, and the error code
    /// is returned if it fails.
    
    pub fn search_for_term(&mut self, search_term: &[u8]) -> Result<&[u64], Errno> {
        unsafe {
            let mut search_operation = SearchOperation {
                results_found: 0,
                process_id: self.pid,
                search_term: search_term.as_ptr(),
                contiguous_page_data: core::ptr::null(),
                search_term_len: search_term.len() as u64,
                results: self.search_results_buffer.as_mut_ptr(),
                max_search_results: self.max_search_results as u64,
            };

            ioctl::conduct_search(self.device_fd, &mut search_operation)?;
            Ok(&self.search_results_buffer[..search_operation.results_found as usize])
        }
    }

    /// Gets the current max search results that can be returned from
    /// a call to [RamInspector::search_for_term].
    
    pub fn max_search_results(&self) -> usize {
        self.max_search_results
    }

    /// Changes the maximum search results that can be returned from a 
    /// call to [RamInspector::search_for_term].
    
    pub fn set_max_search_results(&mut self, max_results: usize) {
        self.max_search_results = max_results;
        self.search_results_buffer = vec![0; max_results];
    }

    /// Queues a data read of the application's memory. This is unsafe because 
    /// reading from a memory-mapped I/O area could cause unexpected behavior,
    /// and the caller must therefore ensure that the memory being read does
    /// not belong to such an area or that if it does the effects of doing
    /// so are well-defined and not dangerous for the system. Note that
    /// this has no effect until [RamInspector::flush] is called.
    
    pub unsafe fn queue_read(&mut self, proc_addr: u64, out_buf: &'a mut [u8]) {
        self.queued_reads_and_writes.push(DataReadOrWrite {
            direction: 0,
            procmem_ptr: proc_addr,
            caller_mem: out_buf.as_mut_ptr(),
            caller_mem_len: out_buf.len() as u64,
        });
    }

    /// Queues a data write to an arbitrary location in the applications'
    /// memory. This is unsafe since it could cause the target process to
    /// crash or otherwise corrupt it's state. 
    /// 
    /// The caller must either ensure that writing to the specified memory 
    /// location will not result in a corruption of the target applications'
    /// state or accept the risk of crashing the target application. The 
    /// caller should also ensure that the target memory area does not
    /// belong to some MMIO area, or that if it does the effects of
    /// writing the specified data to it are well-defined and not
    /// dangerous for the stability of the system.
    /// 
    /// Like [RamInspector::queue_read], this does not have any effect
    /// until [RamInspector::flush] is called. See the documentation of
    /// that function for more information.
    
    pub unsafe fn queue_write(&mut self, proc_addr: u64, data: &'a [u8]) {
        self.queued_reads_and_writes.push(DataReadOrWrite {
            direction: 1,
            procmem_ptr: proc_addr,
            caller_mem_len: data.len() as u64,
            caller_mem: data.as_ptr() as *mut u8,
        });
    }

    /// Executes all of the queued reads and writes and clears the queues
    /// after it finishes. Providing that the safety requirements for the 
    /// queue read and queue write functions were upheld for each call
    /// calling this should be safe.
    
    pub fn flush(&mut self) -> Result<(), Errno> {
        unsafe {
            ioctl::send_inspector_request(self.device_fd, &InspectorRequest {
                target_process_id: self.pid,
                reads_and_writes: self.queued_reads_and_writes.as_ptr(),
                reads_and_writes_len: self.queued_reads_and_writes.len() as u64,
            })?;
        }

        self.queued_reads_and_writes.clear();
        Ok(())
    }

    /// Sometimes it may be desirable to pause a process manually before a search
    /// is conducted, in which case this function may prove to be useful. Do note
    /// that this may cause issues with processes that perform network I/O if the
    /// process isn't resumed for an extended period of time.

    pub fn pause_process(&mut self) -> nix::Result<()> {
        self.process_paused = true;
        kill(Pid::from_raw(self.pid), SIGSTOP)
    }

    /// Resumes a process paused using [RamInspector::pause_process]. This should ideally be called
    /// soon after the process is paused to reduce the chances of network timeouts and such.

    pub fn resume_process(&mut self) -> nix::Result<()> {
        self.process_paused = false;
        kill(Pid::from_raw(self.pid), SIGCONT)
    }
}

impl<'a> Drop for RamInspector<'a> {
    fn drop(&mut self) {
        if self.process_paused {
            // We don't want a process to freeze if there's a panic or another error
            // after it was previously paused.
            let _ = self.resume_process();
        }
    }
}