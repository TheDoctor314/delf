use std::error::Error;

mod process;

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = std::env::args().nth(1).expect("usage: elk FILE");

    let mut proc = process::Process::new();
    proc.load_object(input_path)?;
    println!("{:#?}", proc);
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
