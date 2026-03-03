pub mod accounts;
pub mod role;
pub mod validation;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use accounts::{AccountsFile, parse_accounts};
use role::{RoleFile, parse_role};
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
        bail!(
            "accounts file not found: {}. Run `rolepass init` to create a new project.",
            accounts_path.display()
        );
    }

    let accounts_yaml = std::fs::read_to_string(&accounts_path)
        .with_context(|| format!("reading {}", accounts_path.display()))?;
    validate_accounts(&accounts_yaml, &accounts_path)?;
    let accounts = parse_accounts(&accounts_yaml, &accounts_path)?;

    let explicit_roles = paths.role_paths.is_some();
    let role_files = match &paths.role_paths {
        Some(explicit) => explicit.clone(),
        None => discover_role_files(&paths.config_dir)?,
    };

    if role_files.is_empty() && !explicit_roles {
        eprintln!(
            "warning: no role files found in {}/roles/",
            paths.config_dir.display()
        );
    }

    let mut roles = Vec::new();
    for role_path in &role_files {
        let role_yaml = std::fs::read_to_string(role_path)
            .with_context(|| format!("reading {}", role_path.display()))?;
        validate_role(&role_yaml, role_path)?;
        let role = parse_role(&role_yaml, role_path)?;
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

    let mut paths = Vec::new();
    collect_role_files(&roles_dir, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_role_files(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_role_files(&path, paths)?;
        } else if path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn cross_validate(config: &Config) -> Result<()> {
    let account_names: HashSet<&str> = config
        .accounts
        .accounts
        .iter()
        .map(|a| a.name.as_str())
        .collect();

    let mut errors = Vec::new();

    // Check duplicate account names
    let mut seen_names = HashSet::new();
    for account in &config.accounts.accounts {
        if !seen_names.insert(&account.name) {
            errors.push(format!("duplicate account name '{}'", account.name));
        }
    }

    // Check duplicate role-per-account
    let mut seen_role_accounts = HashSet::new();
    for role in &config.roles {
        for acct in &role.accounts {
            if !seen_role_accounts.insert((&role.name, acct)) {
                errors.push(format!(
                    "role '{}' targets account '{}' more than once",
                    role.name, acct
                ));
            }
        }
    }

    for role in &config.roles {
        for account_ref in &role.accounts {
            if !account_names.contains(account_ref.as_str()) {
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
    fn discover_role_files_recursively() {
        let dir = tempfile::tempdir().unwrap();
        setup_config_dir(dir.path());

        // Add a nested role file
        fs::create_dir_all(dir.path().join("roles/sub")).unwrap();
        fs::write(
            dir.path().join("roles/sub/worker.yaml"),
            r#"
name: worker-role
accounts:
  - staging
trust:
  provider: github
  repo: my-org/my-repo
permissions:
  - effect: Allow
    actions:
      - sqs:ReceiveMessage
    resources:
      - "*"
"#,
        )
        .unwrap();

        let config = load_config(&ConfigPaths {
            config_dir: dir.path().to_path_buf(),
            accounts_path: None,
            role_paths: None,
        })
        .unwrap();

        assert_eq!(config.roles.len(), 2);
        let names: Vec<&str> = config.roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"deploy-role"));
        assert!(names.contains(&"worker-role"));
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

    #[test]
    fn cross_validation_catches_duplicate_account_names() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("roles")).unwrap();

        fs::write(
            dir.path().join("accounts.yaml"),
            r#"
accounts:
  - name: prod
    id: "111111111111"
  - name: prod
    id: "222222222222"
"#,
        )
        .unwrap();

        fs::write(
            dir.path().join("roles/deploy.yaml"),
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

        let err = load_config(&ConfigPaths {
            config_dir: dir.path().to_path_buf(),
            accounts_path: None,
            role_paths: None,
        })
        .unwrap_err();

        assert!(err.to_string().contains("duplicate account name 'prod'"));
    }

    #[test]
    fn cross_validation_catches_duplicate_role_account() {
        use crate::config::accounts::AccountsFile;
        use crate::config::role::{Effect, PolicyStatement, Provider, RoleFile, Trust};

        // Build config directly to bypass schema validation (which has uniqueItems: true)
        let config = Config {
            accounts: AccountsFile {
                accounts: vec![crate::config::accounts::Account {
                    name: "prod".to_string(),
                    id: "111111111111".to_string(),
                    partition: None,
                    deployer_role_name: None,
                }],
            },
            roles: vec![RoleFile {
                name: "deploy-role".to_string(),
                description: None,
                accounts: vec!["prod".to_string(), "prod".to_string()],
                trust: Trust {
                    provider: Provider::GitHub,
                    issuer: None,
                    repo: "my-org/my-repo".to_string(),
                    refs: None,
                },
                permissions: vec![PolicyStatement {
                    effect: Effect::Allow,
                    actions: vec!["s3:GetObject".to_string()],
                    resources: vec!["*".to_string()],
                    conditions: None,
                }],
                max_session_duration: None,
            }],
        };

        let err = cross_validate(&config).unwrap_err();
        assert!(
            err.to_string()
                .contains("role 'deploy-role' targets account 'prod' more than once")
        );
    }
}
