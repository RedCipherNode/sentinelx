use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "stx")]
#[command(about = "Pre-execution threat analysis CLI.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Scan,
    Url,
    Hash,
    Version,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Version) => {
            println!("SentinelX {}", stx_core::version::VERSION);
        }

        Some(Commands::Scan) => {
            println!("Scan is not implemented yet.");
        }

        Some(Commands::Url) => {
            println!("URL analysis is not implemented yet.");
        }

        Some(Commands::Hash) => {
            println!("Hash analysis is not implemented yet.");
        }

        None => {
            println!("SentinelX {}", stx_core::version::VERSION);
            println!();
            println!("Pre-execution threat analysis CLI.");
            println!();
            println!("Run 'stx --help' for usage.");
        }
    }
}
