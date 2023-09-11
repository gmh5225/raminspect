//! raminspect is a crate that allows for the inspection and manipulation of the memory and code of 
//! a running process on a Linux system. It provides functions for finding and replacing search terms 
//! in a processes' memory, as well as an interface that allows for the injection of arbitrary shellcode 
//! running in the processes' context. All of this requires root privileges, for obvious reasons.

// Starting from v0.3.0, we use libc and alloc instead of std and nix to support 
// architectures like 32-bit RISCV which don't have standard library support. This 
// complicates the code quite a bit but it's a price I'm willing to pay for cross-
// platform support.

#![no_std]
extern crate alloc;
use libc_alloc::LibcAlloc;

#[global_allocator]
static ALLOCATOR: LibcAlloc = LibcAlloc;

use libc::*;
use alloc::vec;
use alloc::format;
use alloc::vec::Vec;
use alloc::string::String;

trait IntoResult: Sized {
    // Used for cleaner handling of errors from calling libc functions
    fn into_result(self, error: RamInspectError) -> Result<Self, RamInspectError>;
}

macro_rules! impl_into_result_for_num {
    ($num_ty:ty) => {
        impl IntoResult for $num_ty {
            fn into_result(self, error: RamInspectError) -> Result<Self, RamInspectError> {
                if self < 0 {
                    Err(error)
                } else {
                    Ok(self)
                }
            }
        }
    }
}

impl_into_result_for_num!(i32);
impl_into_result_for_num!(i64);
impl_into_result_for_num!(isize);

impl<T> IntoResult for *mut T {
    fn into_result(self, error: RamInspectError) -> Result<Self, RamInspectError> {
        if self == core::ptr::null_mut() {
            Err(error)
        } else {
            Ok(self)
        }
    }
}

// A wrapper around a raw file descriptor that closes itself when
// dropped. This exists to prevent leaks.

struct FileWrapper {
    descriptor: i32
}

impl FileWrapper {
    fn open(path: &str, mode: i32, on_err: RamInspectError) -> Result<Self, RamInspectError> {
        Ok(Self {
            descriptor: unsafe {
                open(path.as_ptr() as _, mode).into_result(on_err)?
            }
        })
    }
}

impl Drop for FileWrapper {
    fn drop(&mut self) {
        unsafe {
            close(self.descriptor);
        }
    }
}

// A packet sent to the backend kernel module through an 'ioctl' call 
// that requests the current instruction pointer of an application.

#[repr(C)]
struct InstructionPointerRequest {
    pid: i32,
    instruction_pointer: u64,
}

// ioctl command definitions
const RESTORE_REGS: c_ulong = 0x40047B03;
const GET_INST_PTR: c_ulong = 0xC0107B02;
const WAIT_FOR_FINISH: c_ulong = 0x40047B00;
const TOGGLE_EXEC_WRITE: c_ulong = 0x40047B01;

/// Finds a list of all processes containing a given search term in
/// their executable file name using a shell command. This makes
/// figuring out process IDs for the process you want to hijack
/// easier. The command used is present on basically every Linux
/// installations so this shouldn't ever not work (if it doesn't
/// file an issue on the GitHub repository).

pub fn find_processes(name_contains: &str) -> Vec<i32> {
    // This is safe because theres nothing actually unsafe about calling
    // popen or fgets. They're only marked unsafe because they're C bindings.

    unsafe {
        let mut results = Vec::new();
        let fp = popen(b"ps -ax\0".as_ptr() as _, b"r\0".as_ptr() as _);

        let mut line: [u8; 4096] = [0; 4096];
        while fgets(line.as_mut_ptr() as _, line.len() as i32, fp) != core::ptr::null_mut() {
            let line_str = core::str::from_utf8(
                &line[..line.iter().position(|byte| *byte == 0).unwrap_or(line.len())]
            ).unwrap();

            if !line_str.contains(name_contains) {
                line = [0; 4096];
                continue;
            }

            let pid_string = line_str.trim().chars().take_while(|c| c.is_ascii_digit()).collect::<String>();
            results.push(pid_string.parse().unwrap());
            line = [0; 4096];
        }
    
        fclose(fp);
        results
    }
}

/// This is the primary interface used by the crate to search through, read, and modify an
/// arbitrary processes' memory and code.
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
///                     // the browser or negatively impact system stability in any way.
///                     inspector.write_to_address(proc_addr, b"New search text").unwrap();
///                 }
///             }
///         }
///     }
/// }
/// ```

pub struct RamInspector {
    pid: i32,
    proc_mem_fd: FileWrapper,
    proc_maps_file: *mut FILE,
}

#[non_exhaustive]
/// The error type for this library. The variants have self-explanatory names.

pub enum RamInspectError {
    ProcessTerminated,
    FailedToOpenProcMem,
    FailedToOpenProcMaps,
    FailedToPauseProcess,

    FailedToReadMem,
    FailedToWriteMem,
    FailedToOpenDeviceFile,
    FailedToAllocateBuffer,
}

use core::fmt;
use core::fmt::Debug;
use core::fmt::Formatter;
impl Debug for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            RamInspectError::FailedToOpenDeviceFile => "Failed to open the raminspect device file! Are you sure the kernel module is currently inserted? If it is, are you running as root?",
            RamInspectError::FailedToOpenProcMaps => "Failed to access the target processes' memory maps! Are you sure you're running as root? If you are, is the target process running?",
            RamInspectError::FailedToOpenProcMem => "Failed to open the target processes' memory file! Are you sure you're running as root? If you are, is the target process running?",
            RamInspectError::FailedToWriteMem => "Failed to write to the specified memory address! Are you sure you used an address derived from a search result?",
            RamInspectError::FailedToReadMem => "Failed to read from the specified memory address! Are you sure you used an address derived from a search result?",
            RamInspectError::FailedToPauseProcess => "Failed to pause the target process! Are you sure it is currently running?",
            RamInspectError::FailedToAllocateBuffer => "Failed to allocate the specified buffer.",
            RamInspectError::ProcessTerminated => "The target process unexpectedly terminated.",
        })
    }
}

use core::fmt::Display;
impl Display for RamInspectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}

impl RamInspector {
    /// Creates a new inspector attached to the specified process ID. This will pause the target process until
    /// the inspector is dropped.
    
    pub fn new(pid: i32) -> Result<Self, RamInspectError> {
        unsafe {
            let mem_path = format!("/proc/{}/mem\0", pid);
            let proc_mem_fd = FileWrapper::open(&mem_path, O_RDWR, RamInspectError::FailedToOpenProcMem)?;

            let maps_path = format!("/proc/{}/maps\0", pid);
            let proc_maps_file = fopen(maps_path.as_ptr() as _, "r\0".as_ptr() as _).into_result(
                RamInspectError::FailedToOpenProcMaps
            )?;
    
            // Pause the target process with a SIGSTOP signal
            if let Err(error) = kill(pid, SIGSTOP).into_result(RamInspectError::FailedToPauseProcess) {
                fclose(proc_maps_file);
                return Err(error);
            }
    
            Ok(RamInspector {
                pid,
                proc_mem_fd,
                proc_maps_file,
            })
        }
    }

    /// Allows for the execution of arbitrary code in the context of the process. This is unsafe
    /// because there are no checks in place to ensure the provided code is safe. The provided
    /// code should also be completely position independent, since it could be loaded anywhere.
    /// 
    /// This function waits for a signal from the shellcode that it is finished executing, given
    /// by reading exactly one byte from the raminspect device file. It does not time out, so if
    /// you forget to send the signal you'll have to terminate the hijacked process for this 
    /// function to resume and the shellcode to finish executing.
    /// 
    /// The second argument is a callback that is called once the shellcode is finished executing
    /// that takes in the inspector and a pointer to the starting address of the loaded shellcode 
    /// as arguments, before the old instructions are restored in memory. This can be useful if 
    /// you want to retrieve information from the shellcode after it's done executing.
    /// 
    /// Note that this restores the previous register state automatically, so you don't have to 
    /// save and restore registers in your shellcode manually if you're writing it in assembly.
    
    pub unsafe fn execute_shellcode<F: FnMut(&mut RamInspector, u64) -> Result<(), RamInspectError>>(
        &mut self,
        shellcode: &[u8],
        mut callback: F
    ) -> Result<(), RamInspectError> {
        let device_fd_wrapper = FileWrapper::open("/dev/raminspect\0", O_RDWR, RamInspectError::FailedToOpenDeviceFile)?;
        let device_fd = device_fd_wrapper.descriptor;

        ioctl(device_fd, TOGGLE_EXEC_WRITE, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;
        // Get process instruction pointer. ptrace and /proc/stat don't work here, at least on my machine, so we
        // rely on the kernel module to do it for us instead.

        let mut inst_ptr_request = InstructionPointerRequest {
            pid: self.pid,
            instruction_pointer: 0,
        };

        ioctl(device_fd, GET_INST_PTR, &mut inst_ptr_request).into_result(RamInspectError::ProcessTerminated)?;
        let instruction_pointer = inst_ptr_request.instruction_pointer;
        
        // Save the old code and load the new code
        let old_code = self.read_vec(instruction_pointer, shellcode.len())?;
        self.write_to_address(instruction_pointer, shellcode)?;

        // Resume the process and wait for the code to finish executing
        kill(self.pid, SIGCONT).into_result(RamInspectError::ProcessTerminated)?;
        ioctl(device_fd, WAIT_FOR_FINISH, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;

        // Then pause the process again and call the callback
        kill(self.pid, SIGSTOP).into_result(RamInspectError::ProcessTerminated)?;
        callback(self, instruction_pointer)?;

        // Restore the old code and registers
        self.write_to_address(instruction_pointer, &old_code)?;
        ioctl(device_fd, RESTORE_REGS, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;

        // Leaving the target code as writable when it was originally read-only would present 
        // a fairly big security issue, so we make the modified regions read-only again after 
        // we're done by performing another write.
        
        ioctl(device_fd, TOGGLE_EXEC_WRITE, self.pid as c_ulong).into_result(RamInspectError::ProcessTerminated)?;
        Ok(())
    }

    /// Allocates a new buffer with the given size for the current process and returns the address
    /// of it. Currently this only works on x86-64, but PRs to expand it to work on other CPU
    /// architectures are welcome.
    /// 
    /// Note that due to the way this is implemented this function is fairly expensive. Don't use this many 
    /// times in a hot loop; try to make a few big allocations instead of many small ones for better performance.
    
    pub fn allocate_buffer(&mut self, size: usize) -> Result<u64, RamInspectError> {
        unsafe {
            let mut shellcode: Vec<u8> = include_bytes!("../alloc-blob.bin").to_vec();
            let alloc_size_identifier = &[1, 1, 1, 1, 1, 1, 1, 1];
            let out_ptr_identifier = &[2, 2, 2, 2, 2, 2, 2, 2];

            let alloc_size_offset = (0..shellcode.len()).find(|i| shellcode[*i..].starts_with(alloc_size_identifier)).unwrap();
            let out_ptr_offset = (0..shellcode.len()).find(|i| shellcode[*i..].starts_with(out_ptr_identifier)).unwrap();
            shellcode[alloc_size_offset..alloc_size_offset + 8].copy_from_slice(&(size as u64).to_le_bytes());

            let mut addr_bytes = [0; 8];
            self.execute_shellcode(&shellcode, |this, inst_ptr| {
                this.read_address(inst_ptr + out_ptr_offset as u64, &mut addr_bytes)
            })?;

            Ok(u64::from_le_bytes(addr_bytes))
        }
    }

    /// Fills the output buffer with memory read starting from the target address. This can fail
    /// if the target process was suddenly terminated or if the address used was not obtained
    /// from one of the searching functions called on this inspector.
    
    pub fn read_address(&mut self, addr: u64, out_buf: &mut [u8]) -> Result<(), RamInspectError> {
        unsafe {
            let mut total_count = 0;
            lseek(self.proc_mem_fd.descriptor, addr as _, SEEK_SET).into_result(RamInspectError::FailedToReadMem)?;

            loop {
                let count = read(self.proc_mem_fd.descriptor, out_buf.as_mut_ptr() as _, out_buf.len() - total_count).into_result(RamInspectError::FailedToReadMem)?;
                total_count += count as usize;

                if count == 0 && total_count < out_buf.len() {
                    return Err(RamInspectError::FailedToReadMem);
                }

                if total_count >= out_buf.len() {
                    break;
                }
            }

            Ok(())
        }
    }

    /// A convenience function that reads the specified amount of bytes from the target address
    /// and stores the output in a vector. This is shorthand for:
    /// 
    /// ```rust
    /// let mut out = vec![0; count];
    /// self.read_address(addr, &mut out);
    /// ```
    
    pub fn read_vec(&mut self, addr: u64, count: usize) -> Result<Vec<u8>, RamInspectError> {
        let mut out = vec![0; count];
        self.read_address(addr, &mut out)?;
        Ok(out)
    }

    /// Writes the specified data to the specified memory address of the target process. This has
    /// the same failure conditions as [RamInspector::read_address]. This is unsafe since directly
    /// writing to an arbitrary address in an arbitrary processes' memory is not memory safe at 
    /// all; it is assumed that the caller knows what they're doing.
    
    pub unsafe fn write_to_address(&mut self, addr: u64, buf: &[u8]) -> Result<(), RamInspectError> {
        if pwrite(self.proc_mem_fd.descriptor, buf.as_ptr() as _, buf.len(), addr as _) == buf.len() as isize {
            Ok(())
        } else {
            Err(RamInspectError::FailedToWriteMem)
        }
    }

    /// A function used internally to iterate over and process the target processes' memory regions. The first argument
    /// to the callback is the data contained within the memory region, and the second argument is the starting address
    /// of the memory region. This is exposed publicly to allow for more complicated, custom analysis of an applications' 
    /// memory than the built-in search function would allow on its own.
    
    // The reason why this is implemented as a function that takes a closure instead of an iterator is simply because
    // I find this interface more elegant, it takes less LOC to implement, and there aren't any cases I can think 
    // of where a regular iterator would provide additional functionality that this wouldn't provide already.
    
    pub fn iter_memory_regions<F: FnMut(Vec<u8>, u64)>(&mut self, mut callback: F) -> Result<(), RamInspectError> {
        unsafe {
            fseek(self.proc_maps_file, 0, SEEK_SET);
        }

        let mut line: [u8; 4096] = [0; 4096];
        while unsafe { fgets(line.as_mut_ptr() as _, line.len() as i32, self.proc_maps_file) } != core::ptr::null_mut() {
            let line_str = core::str::from_utf8(
                &line[..line.iter().position(|byte| *byte == 0).unwrap_or(line.len())]
            ).unwrap();

            let mut chars = line_str.trim().chars();
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
                assert!(end_addr > start_addr);

                if let Ok(region) = self.read_vec(start_addr, (end_addr - start_addr) as usize) {
                    callback(region, start_addr);
                }
            }

            line = [0; 4096];
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

        unsafe {
            fclose(self.proc_maps_file);
            kill(self.pid, SIGCONT);
        }
    }
}