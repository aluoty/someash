use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, IsTerminal};
use std::path::Path;
use std::process;

use clap::Parser;

mod hash;

#[derive(Parser)]
#[command(
    name = "someash",
    version,
    about = "Universal hash tool — multiple algorithms, strings, files, and stdin"
)]
struct Cli {
    /// Hash algorithm to use
    #[arg(short, long, default_value = "sha256")]
    algorithm: hash::Algorithm,

    /// Strings to hash (positional)
    strings: Vec<String>,

    /// File(s) to hash
    #[arg(short, long)]
    file: Vec<String>,

    /// Read data from stdin
    #[arg(long)]
    stdin: bool,

    /// Output format: hex or base64
    #[arg(long, default_value = "hex")]
    format: OutputFormat,

    /// List all available hash algorithms and exit
    #[arg(short, long)]
    list: bool,

    /// Verify checksums against a sums-file (format: <hash>  <filename>)
    #[arg(long, value_name = "FILE")]
    check: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputFormat {
    Hex,
    Base64,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "hex" => Ok(OutputFormat::Hex),
            "base64" => Ok(OutputFormat::Base64),
            _ => Err(format!("unknown output format: {s} (use hex or base64)")),
        }
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.list {
        println!("Available algorithms:");
        for algo in hash::Algorithm::all() {
            println!("  {:20}  {} bytes", algo.name(), algo.output_size());
        }
        return;
    }

    if let Some(check_path) = &cli.check {
        verify_checksums(check_path, &cli.algorithm);
        return;
    }

    if !cli.strings.is_empty() {
        for s in &cli.strings {
            let h = cli.algorithm.hash(s.as_bytes());
            println!("{}  \"{}\"", format_hash(&h, cli.format), s);
        }
        return;
    }

    if !cli.file.is_empty() {
        for path in &cli.file {
            match read_file(path) {
                Ok(data) => {
                    let h = cli.algorithm.hash(&data);
                    println!("{}  {}", format_hash(&h, cli.format), path);
                }
                Err(e) => {
                    eprintln!("{}: {e}", path);
                    process::exit(1);
                }
            }
        }
        return;
    }

    if cli.stdin || !std::io::stdin().is_terminal() {
        let mut data = Vec::new();
        if let Err(e) = io::stdin().lock().read_to_end(&mut data) {
            eprintln!("stdin: {e}");
            process::exit(1);
        }
        if data.is_empty() && cli.stdin {
            return;
        }
        let h = cli.algorithm.hash(&data);
        println!("{}", format_hash(&h, cli.format));
    } else {
        eprintln!("No input provided. Pipe data, pass strings/files, or use --help.");
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

fn read_file(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let mut f = File::open(path.as_ref())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Checksum verification  (<hash>  <filename> format)
// ---------------------------------------------------------------------------

fn verify_checksums(path: &str, algorithm: &hash::Algorithm) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{path}: {e}");
            process::exit(1);
        }
    };
    let reader = BufReader::new(file);
    let mut ok = 0u64;
    let mut failed = 0u64;

    for (lineno, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{}:{}: {e}", path, lineno + 1);
                continue;
            }
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let Some((expected_hex, filename)) = line.split_once(char::is_whitespace) else {
            eprintln!("{}:{}: malformed line", path, lineno + 1);
            continue;
        };
        let filename = filename.trim();

        let actual = match read_file(filename) {
            Ok(d) => algorithm.hash(&d),
            Err(e) => {
                println!("{}: FAILED ({})", filename, e);
                failed += 1;
                continue;
            }
        };
        let actual_hex = hex::encode(&actual);
        if actual_hex == expected_hex {
            println!("{}: OK", filename);
            ok += 1;
        } else {
            println!("{}: FAILED", filename);
            failed += 1;
        }
    }

    eprintln!("\n{} OK, {} FAILED", ok, failed);
    if failed > 0 {
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

fn format_hash(hash: &[u8], fmt: OutputFormat) -> String {
    match fmt {
        OutputFormat::Hex => hex::encode(hash),
        OutputFormat::Base64 => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(hash)
        }
    }
}
