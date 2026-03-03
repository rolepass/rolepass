use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

pub const DEFAULT_DEPLOYER_ROLE_NAME: &str = "rolepass-deployer";

#[derive(Debug, Clone, Deserialize)]
pub struct AccountsFile {
    pub accounts: Vec<Account>,
}

impl AccountsFile {
    pub fn account_map(&self) -> HashMap<&str, &Account> {
        self.accounts.iter().map(|a| (a.name.as_str(), a)).collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
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
            .unwrap_or(DEFAULT_DEPLOYER_ROLE_NAME)
    }
}

pub fn parse_accounts(contents: &str, path: &Path) -> Result<AccountsFile> {
    let accounts_file: AccountsFile =
        serde_yml::from_str(contents).with_context(|| format!("parsing {}", path.display()))?;
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
        let file: AccountsFile = serde_yml::from_str(yaml).unwrap();
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
        let file: AccountsFile = serde_yml::from_str(yaml).unwrap();
        assert_eq!(file.accounts[0].partition(), "aws-cn");
        assert_eq!(file.accounts[0].deployer_role_name(), "my-deployer");
    }

    #[test]
    fn account_map_works() {
        let yaml = r#"
accounts:
  - name: prod
    id: "111111111111"
  - name: staging
    id: "222222222222"
"#;
        let file: AccountsFile = serde_yml::from_str(yaml).unwrap();
        let map = file.account_map();
        assert_eq!(map.len(), 2);
        assert_eq!(map["prod"].id, "111111111111");
        assert_eq!(map["staging"].id, "222222222222");
    }
}
