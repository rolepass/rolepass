pub mod accounts;
pub mod role;
pub mod validation;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use accounts::{AccountsFile, load_accounts_file};
use role::{RoleFile, load_role_file};
use validation::{validate_accounts, validate_role};

#[derive(Debug)]
pub struct Config {
    pub accounts: AccountsFile,
    pub roles: Vec<RoleFile>,
}

pub struct ConfigPaths {
    pub config_dir: PathBuf,
    pub accounts_path: Option<PathBuf>,
    pub role_paths: Option<Vec<PathBuf>>,
}

pub fn load_config(paths: &ConfigPaths) -> Result<Config> {
    let accounts_path = match &paths.accounts_path {
        Some(p) => p.clone(),
        None => paths.config_dir.join("accounts.yaml"),
    };

    if !accounts_path.exists() {
        bail!("accounts file not found: {}", accounts_path.display());
    }

    let accounts_yaml = std::fs::read_to_string(&accounts_path)
        .with_context(|| format!("reading {}", accounts_path.display()))?;
    validate_accounts(&accounts_yaml, &accounts_path)?;
    let accounts = load_accounts_file(&accounts_path)?;

    let role_files = match &paths.role_paths {
        Some(explicit) => explicit.clone(),
        None => discover_role_files(&paths.config_dir)?,
    };

    let mut roles = Vec::new();
    for role_path in &role_files {
        let role_yaml = std::fs::read_to_string(role_path)
            .with_context(|| format!("reading {}", role_path.display()))?;
        validate_role(&role_yaml, role_path)?;
        let role = load_role_file(role_path)?;
        roles.push(role);
    }

    let config = Config { accounts, roles };
    cross_validate(&config)?;
    Ok(config)
}

fn discover_role_files(config_dir: &Path) -> Result<Vec<PathBuf>> {
    let roles_dir = config_dir.join("roles");
    if !roles_dir.exists() {
        return Ok(Vec::new());
    }

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&roles_dir)
        .with_context(|| format!("reading directory {}", roles_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
        })
        .collect();

    paths.sort();
    Ok(paths)
}

fn cross_validate(config: &Config) -> Result<()> {
    let account_names: Vec<&str> = config
        .accounts
        .accounts
        .iter()
        .map(|a| a.name.as_str())
        .collect();

    let mut errors = Vec::new();
    for role in &config.roles {
        for account_ref in &role.accounts {
            if !account_names.contains(&account_ref.as_str()) {
                errors.push(format!(
                    "role '{}' references unknown account '{account_ref}'",
                    role.name
                ));
            }
        }
    }

    if !errors.is_empty() {
        bail!(
            "cross-validation errors:\n{}",
            errors
                .iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_config_dir(dir: &Path) {
        fs::create_dir_all(dir.join("roles")).unwrap();

        fs::write(
            dir.join("accounts.yaml"),
            r#"
accounts:
  - name: prod
    id: "111111111111"
  - name: staging
    id: "222222222222"
"#,
        )
        .unwrap();

        fs::write(
            dir.join("roles/deploy.yaml"),
            r#"
name: deploy-role
accounts:
  - prod
trust:
  provider: github
  repo: my-org/my-repo
permissions:
  - effect: Allow
    actions:
      - s3:GetObject
    resources:
      - "*"
"#,
        )
        .unwrap();
    }

    #[test]
    fn load_config_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        setup_config_dir(dir.path());

        let config = load_config(&ConfigPaths {
            config_dir: dir.path().to_path_buf(),
            accounts_path: None,
            role_paths: None,
        })
        .unwrap();

        assert_eq!(config.accounts.accounts.len(), 2);
        assert_eq!(config.roles.len(), 1);
        assert_eq!(config.roles[0].name, "deploy-role");
    }

    #[test]
    fn cross_validation_catches_unknown_account() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("roles")).unwrap();

        fs::write(
            dir.path().join("accounts.yaml"),
            r#"
accounts:
  - name: prod
    id: "111111111111"
"#,
        )
        .unwrap();

        fs::write(
            dir.path().join("roles/deploy.yaml"),
            r#"
name: deploy-role
accounts:
  - nonexistent
trust:
  provider: github
  repo: my-org/my-repo
permissions:
  - effect: Allow
    actions:
      - s3:GetObject
    resources:
      - "*"
"#,
        )
        .unwrap();

        let err = load_config(&ConfigPaths {
            config_dir: dir.path().to_path_buf(),
            accounts_path: None,
            role_paths: None,
        })
        .unwrap_err();

        assert!(err.to_string().contains("unknown account 'nonexistent'"));
    }

    #[test]
    fn missing_accounts_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_config(&ConfigPaths {
            config_dir: dir.path().to_path_buf(),
            accounts_path: None,
            role_paths: None,
        })
        .unwrap_err();

        assert!(err.to_string().contains("accounts file not found"));
    }
}
