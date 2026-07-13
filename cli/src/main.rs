use clap::{Parser, Subcommand};
use std::path::PathBuf;

use stx_core::{ScanRequest, VERSION, scan};

#[derive(Parser)]
#[command(name = "stx")]
#[command(about = "Pre-execution threat analysis CLI.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Scan { path: PathBuf },

    Url,

    Hash,

    Version,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan { path }) => {
            let request = ScanRequest { path };

            let result = scan(request);

            println!("{:#?}", result);
        }

        Some(Commands::Url) => {
            println!("URL analysis is not implemented yet.");
        }

        Some(Commands::Hash) => {
            println!("Hash analysis is not implemented yet.");
        }

        Some(Commands::Version) => {
            println!("SentinelX {VERSION}");
        }

        None => {
            println!("SentinelX {VERSION}");
            println!();
            println!("Pre-execution threat analysis CLI.");
            println!();
            println!("Run 'stx --help' for usage.");
        }
    }
}
