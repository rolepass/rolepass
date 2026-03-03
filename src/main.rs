mod aws;
mod commands;
mod config;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use owo_colors::{OwoColorize, Stream, Style};

use config::ConfigPaths;

#[derive(Parser)]
#[command(
    name = "rolepass",
    version,
    about = "Manage AWS IAM roles for CI/CD pipelines"
)]
struct Cli {
    /// Config directory (default: current directory)
    #[arg(long, default_value = ".", env = "ROLEPASS_CONFIG_DIR")]
    config_dir: PathBuf,

    /// Override accounts file path
    #[arg(long, env = "ROLEPASS_ACCOUNTS")]
    accounts: Option<PathBuf>,

    /// Override role file paths
    #[arg(long, env = "ROLEPASS_ROLES", value_delimiter = ',')]
    roles: Option<Vec<PathBuf>>,

    /// Enable debug output
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new rolepass project with sample config files
    Init,
    /// Validate config files without making AWS calls
    Validate,
    /// Preview the generated IAM role JSON without making AWS calls
    Preview,
    /// Show what changes would be made (requires AWS credentials)
    Plan,
    /// Deploy roles to AWS accounts (requires AWS credentials)
    Apply {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init => commands::init::run(&cli.config_dir),
        _ => {
            let paths = ConfigPaths {
                config_dir: cli.config_dir,
                accounts_path: cli.accounts,
                role_paths: cli.roles,
            };
            match cli.command {
                Command::Validate => commands::validate::run(&paths),
                Command::Preview => commands::preview::run(&paths),
                Command::Plan => commands::plan::run(&paths, cli.debug).await,
                Command::Apply { yes } => commands::apply::run(&paths, yes, cli.debug).await,
                Command::Init => unreachable!(),
            }
        }
    };

    if let Err(e) = result {
        eprintln!(
            "{} {e:#}",
            "Error:".if_supports_color(Stream::Stderr, |t| t.style(Style::new().red().bold()))
        );
        process::exit(1);
    }
}
