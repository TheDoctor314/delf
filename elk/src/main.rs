use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = std::env::args().nth(1).expect("usage: elk FILE");
    let input = std::fs::read(input_path)?;

    let file = match delf::File::parse_or_print_err(&input) {
        Some(f) => f,
        None => std::process::exit(1),
    };

    println!("{file:#?}");

    Ok(())
}
