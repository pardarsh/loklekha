use std::process::ExitCode;

use clap::Parser;
use loklekha::cli::{Cli, run};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command, &mut std::io::stdout()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
