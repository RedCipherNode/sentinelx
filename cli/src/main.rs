use std::env;

use stx_core::{Assessment, Target, inspect};

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

            print_assessment(&assessment);
        }

        "help" | "-h" | "--help" => {
            print_help();
        }

        "version" | "-V" | "--version" => {
            print_version();
        }

        _ => {
            eprintln!("error: unknown command '{}'\n", command);
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_assessment(assessment: &Assessment) {
    println!();
    println!("Summary");
    println!("-------");
    println!("{}", assessment.summary);

    println!();
    println!("Observations");
    println!("------------");

    for observation in &assessment.observations {
        println!(
            "[{:<8}] {:<24} {}",
            observation.severity.display(),
            observation.title,
            observation.value,
        );

        if let Some(description) = &observation.description {
            println!("           {}", description);
        }
    }
}

fn print_help() {
    println!(
        r#"SentinelX

USAGE:
    stx <COMMAND> <TARGET>

COMMANDS:
    inspect     Inspect a file, directory, URL, or command
    version     Show version information
    help        Show this help message

EXAMPLES:
    stx inspect malware.exe
    stx inspect archive.zip
    stx inspect https://example.com
    stx inspect ./project
"#
    );
}

fn print_version() {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"),);
}
