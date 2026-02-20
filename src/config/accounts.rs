use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsFile {
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub id: String,
    #[serde(default = "default_partition")]
    pub partition: Option<String>,
    #[serde(default)]
    pub deployer_role_name: Option<String>,
}

fn default_partition() -> Option<String> {
    Some("aws".to_string())
}

impl Account {
    pub fn partition(&self) -> &str {
        self.partition.as_deref().unwrap_or("aws")
    }

    pub fn deployer_role_name(&self) -> &str {
        self.deployer_role_name
            .as_deref()
            .unwrap_or("rolepass-deployer")
    }
}

pub fn load_accounts_file(path: &Path) -> Result<AccountsFile> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let accounts_file: AccountsFile =
        serde_yaml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;
    Ok(accounts_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_account() {
        let yaml = r#"
accounts:
  - name: prod
    id: "111111111111"
"#;
        let file: AccountsFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.accounts.len(), 1);
        assert_eq!(file.accounts[0].name, "prod");
        assert_eq!(file.accounts[0].id, "111111111111");
        assert_eq!(file.accounts[0].partition(), "aws");
        assert_eq!(file.accounts[0].deployer_role_name(), "rolepass-deployer");
    }

    #[test]
    fn parse_full_account() {
        let yaml = r#"
accounts:
  - name: staging
    id: "222222222222"
    partition: aws-cn
    deployer_role_name: my-deployer
"#;
        let file: AccountsFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.accounts[0].partition(), "aws-cn");
        assert_eq!(file.accounts[0].deployer_role_name(), "my-deployer");
    }
}
