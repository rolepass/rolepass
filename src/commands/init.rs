use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use owo_colors::{OwoColorize, Stream};

const SAMPLE_ACCOUNTS: &str = "\
accounts:
  - name: production
    id: \"123456789012\"
  - name: staging
    id: \"123456789013\"
";

const SAMPLE_ROLE: &str = "\
name: deploy
description: CI/CD deployment role
accounts:
  - production
trust:
  provider: github
  repo: my-org/my-repo
  refs:
    - refs/heads/main
permissions:
  - effect: Allow
    actions:
      - sts:GetCallerIdentity
    resources:
      - \"*\"
";

pub fn run(config_dir: &Path) -> Result<()> {
    let accounts_path = config_dir.join("accounts.yaml");
    let roles_dir = config_dir.join("roles");
    let role_path = roles_dir.join("deploy.yaml");

    if accounts_path.exists() {
        bail!(
            "{} already exists, refusing to overwrite",
            accounts_path.display()
        );
    }
    if role_path.exists() {
        bail!(
            "{} already exists, refusing to overwrite",
            role_path.display()
        );
    }

    fs::create_dir_all(&roles_dir)?;
    fs::write(&accounts_path, SAMPLE_ACCOUNTS)?;
    fs::write(&role_path, SAMPLE_ROLE)?;

    println!(
        "{} {}",
        "Created".if_supports_color(Stream::Stdout, |t| t.green()),
        accounts_path.display()
    );
    println!(
        "{} {}",
        "Created".if_supports_color(Stream::Stdout, |t| t.green()),
        role_path.display()
    );
    let hint = "\nEdit these files, then run `rolepass validate` to check your config.";
    println!("{}", hint.if_supports_color(Stream::Stdout, |t| t.dimmed()));

    Ok(())
}
