use std::process::ExitCode;

mod cli;
mod crypto;
mod format;

fn main() -> ExitCode {
    cli::run()
}
