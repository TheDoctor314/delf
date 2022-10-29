use std::{error::Error, ptr::copy_nonoverlapping};

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

    let rela_entries = file.read_rela_entries().unwrap_or_else(|e| {
        println!("Could not read relocations: {:?}", e);
        Default::default()
    });
    let base = 0x400000_usize;
    println!("Loading with base address @ 0x{:x}", base);
    let non_empty_load_segments = file
        .program_headers
        .iter()
        .filter(|ph| ph.typ == delf::SegmentType::Load)
        // filter zero length sections
        .filter(|ph| ph.mem_range().end > ph.mem_range().start);

    let mut mappings = Vec::new();
    for ph in non_empty_load_segments {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start = mem_range.start.0 as usize + base;
        let aligned_start = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr: *mut u8 = aligned_start as _;
        if padding > 0 {
            println!("(With 0x{:x} bytes of padding at the start)", padding);
        }

        // first, we want the map to be writable to copy the required data.
        // we can set the correct permissions later.
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        unsafe {
            copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
        }

        let mut num_relocs = 0;
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                num_relocs += 1;
                unsafe {
                    let real_segment_start = addr.add(padding);
                    let offset_into_segment = reloc.offset - mem_range.start;
                    let reloc_addr = real_segment_start.add(offset_into_segment.into());

                    match reloc.typ {
                        delf::RelType::Relative => {
                            // this assumes `reloc_addr` is 8-byte aligned.
                            // if this isn't the case, we would crash.
                            let reloc_addr: *mut u64 = std::mem::transmute(reloc_addr);
                            let reloc_value = reloc.addend + delf::Addr(base as u64);
                            *reloc_addr = reloc_value.0;
                        }
                        typ => panic!("Unsupported relocation type {:?}", typ),
                    }
                }
            }
        }

        if num_relocs > 0 {
            println!("(Applied {num_relocs} relocations)");
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
