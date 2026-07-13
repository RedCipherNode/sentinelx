use std::env;

use stx_core::{Target, inspect};

fn main() {
    let mut args = env::args().skip(1);

    let Some(command) = args.next() else {
        print_help();
        return;
    };

    match command.as_str() {
        "inspect" => {
            let Some(input) = args.next() else {
                eprintln!("error: missing target\n");
                print_help();
                std::process::exit(1);
            };

            let target = Target::resolve(&input);

            let assessment = inspect(target);

            println!("SentinelX");
            println!("==========");
            println!();
            println!("{}", assessment.summary);

            if !assessment.observations.is_empty() {
                println!();

                println!("Observations");

                for observation in &assessment.observations {
                    println!("- {}: {}", observation.title, observation.value,);
                }
            }
        }

        "-h" | "--help" | "help" => {
            print_help();
        }

        "-V" | "--version" | "version" => {
            println!("SentinelX v0.1.0");
        }

        _ => {
            eprintln!("error: unknown command '{}'\n", command);
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!(
        r#"SentinelX

USAGE:
    stx <COMMAND> <TARGET>

COMMANDS:
    inspect     Inspect a target
    version     Show version
    help        Show this help

EXAMPLES:
    stx inspect malware.exe
    stx inspect archive.zip
    stx inspect https://example.com
    stx inspect ./project
"#
    );
}
