//! # Purpose
//! 
//! This example is a CLI application that can find and replace arbitrary
//! data in an arbitrary process, using the raminspect library as a backend.
//! 
//! # Usage
//! 
//! `sudo cargo run --example replacemem --release -- <pid> <search term> <replacement>`
//!
//! Or if you want to install this as a command line application, you may build it using this command:
//! 
//! `cargo build --release --example replacemem`
//!
//! And then copy the output to /usr/bin like so:
//! 
//! `cp target/release/examples/replacemem /usr/bin/replacemem`
//! 
//! And then use the resulting executable like this after you refresh your shell:
//! 
//! `replacemem <pid> <string search term> <string replacement>`

fn exit_err(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    eprintln!("Program usage: replacemem pidnumber \"searchterm\" \"replacement\"");
    std::process::exit(1);
}

fn main() {
    use raminspect::RamInspector;
    let mut args = std::env::args();

    // Skip the first argument which is the program name on Unix systems
    args.next();

    let pid_parse_err = "Expected a number as the first argument";
    
    let pid = args.next().unwrap_or_else(|| {
        exit_err(pid_parse_err)
    }).parse::<i32>().unwrap_or_else(|_| exit_err(pid_parse_err));

    let search_term = args.next().unwrap_or_else(|| exit_err("Expected three arguments."));
    let replacement_term = args.next().unwrap_or_else(|| exit_err("Expected three arguments."));

    if args.next().is_some() {
        exit_err("Expected no more than three arguments.");
    }

    fn inspect_process(pid: i32, search_term: &str, replacement_term: &str) -> Result<(), String> {
        let mut inspector = RamInspector::new(pid)?;
        inspector.set_max_search_results(5000);
        inspector.pause_process().map_err(|err| {
            format!("Pausing process failed with error: {}", err)
        })?;

        unsafe {
            for result_addr in inspector.search_for_term(search_term.as_bytes()).map_err(|err| {
                format!("ioctl failed with error: {}", err)
            })?.to_vec() {
                inspector.queue_write(result_addr, replacement_term.as_bytes());
            }
        
            inspector.flush().map_err(|err| format!("ioctl failed with error: {}", err))?;
        }

        // This isn't actually necessary since the process is resumed upon the drop of
        // the inspector but I prefer to be explicit here.
        
        inspector.resume_process().map_err(|err| {
            format!("Resuming process failed with error: {}", err)
        })?;

        Ok(())
    }

    if let Err(error) = inspect_process(pid, &search_term, &replacement_term) {
        exit_err(&error);
    }
}