use anyhow::Result;
use owo_colors::{OwoColorize, Stream};

use crate::config::{ConfigPaths, load_config};

pub fn run(paths: &ConfigPaths) -> Result<()> {
    let config = load_config(paths)?;

    println!(
        "{} {} account(s), {} role(s)",
        "Configuration is valid:".if_supports_color(Stream::Stdout, |t| t.green()),
        config.accounts.accounts.len(),
        config.roles.len()
    );

    for role in &config.roles {
        let line = format!(
            "  - role '{}' -> accounts: {}",
            role.name,
            role.accounts.join(", ")
        );
        println!("{}", line.if_supports_color(Stream::Stdout, |t| t.dimmed()));
    }

    Ok(())
}
