use std::{
    env, fs,
    io::{self, Write},
    process,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("bininspect error: {err}");
        process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let mut pretty = true;
    let mut path: Option<String> = None;

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--compact" => pretty = false,
            "--pretty" => pretty = true,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            value if value.starts_with('-') => {
                anyhow::bail!("unknown flag: {value}");
            }
            value => path = Some(value.to_string()),
        }
    }

    let Some(path) = path else {
        print_help();
        anyhow::bail!("missing input path");
    };

    let bytes = fs::read(&path)?;
    let json = bininspect::analyze_to_json(&bytes, pretty)?;
    let mut stdout = io::stdout().lock();
    if let Err(err) = stdout.write_all(json.as_bytes()) {
        if err.kind() != io::ErrorKind::BrokenPipe {
            return Err(err.into());
        }
        return Ok(());
    }
    if let Err(err) = stdout.write_all(b"\n")
        && err.kind() != io::ErrorKind::BrokenPipe
    {
        return Err(err.into());
    }
    Ok(())
}

fn print_help() {
    println!("bininspect <path> [--pretty|--compact]");
    println!("Inspect Mach-O/ELF/PE/WASM binaries and output normalized JSON.");
}
