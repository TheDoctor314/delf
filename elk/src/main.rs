use std::error::Error;

use mmap::{MapOption, MemoryMap};
use region::Protection;

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = std::env::args().nth(1).expect("usage: elk FILE");
    let input = std::fs::read(&input_path)?;

    println!("Analyzing {:?}...", input_path);

    let file = match delf::File::parse_or_print_err(&input) {
        Some(f) => f,
        None => std::process::exit(1),
    };
    println!("{file:#?}");

    println!("Dynamic Entries:");
    if let Some(ds) = file
        .program_headers
        .iter()
        .find(|ph| ph.typ == delf::SegmentType::Dynamic)
    {
        if let delf::SegmentContents::Dynamic(ref table) = ds.contents {
            for entry in table {
                println!(" - {:?}", entry);
            }
        }
    }

    println!("Rela entries:");
    let rela_entries = file.read_rela_entries()?;
    for e in &rela_entries {
        println!("{:#?}", e);
        if let Some(seg) = file.segment_at(e.offset) {
            println!("... for {:#?}", seg);
        }
    }

    println!("Mapping {:?} in memory...", input_path);

    let base = 0x400000_usize;
    let mut mappings = Vec::new();

    // interested only in "Load" segments
    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.typ == delf::SegmentType::Load)
        // filter zero length sections
        .filter(|ph| ph.mem_range().end > ph.mem_range().start)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);

        // NOTE: mmap-ing would fail if the segments were not aligned on
        // pages, here that's not a problem.
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start = mem_range.start.0 as usize + base;
        let aligned_start = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr: *mut u8 = aligned_start as _;
        println!("Addr: {addr:p}, Padding: {padding:08x}");

        // first, we want the map to be writable to copy the required data.
        // we can set the correct permissions later.
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("Copying segment data...");
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(addr.add(padding), ph.data.len()) };

            dst.copy_from_slice(&ph.data[..]);
        }

        println!("Adjusting permissions...");
        // mapping from `delf` crate bitflags to `region`s.
        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Execute => Protection::EXECUTE,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Read => Protection::READ,
            };
        }

        unsafe {
            region::protect(addr, len, protection)?;
        }

        mappings.push(map);
    }

    let entry_point = file.entry_point;
    println!("Jumping to entry point @ {:?}", entry_point);
    pause("jmp")?;
    unsafe {
        // no pointer arithmetic since the entry point is mapped at
        // the right locations.
        jmp((entry_point.0 as usize + base) as _);
    }

    Ok(())
}

/// Truncates a usize to the left-adjacent 4KiB boundary.
const fn align_lo(addr: usize) -> usize {
    addr & !0xfff
}

fn pause(label: &str) -> Result<(), Box<dyn Error>> {
    println!("Press Enter to {}", label);
    let mut s = String::new();

    std::io::stdin().read_line(&mut s)?;
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", origin.0))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(code)?;
    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}
