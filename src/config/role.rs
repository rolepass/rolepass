use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleFile {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub accounts: Vec<String>,
    pub trust: Trust,
    pub permissions: Vec<PolicyStatement>,
    #[serde(default = "default_max_session_duration")]
    pub max_session_duration: Option<u32>,
}

fn default_max_session_duration() -> Option<u32> {
    Some(3600)
}

impl RoleFile {
    pub fn max_session_duration(&self) -> u32 {
        self.max_session_duration.unwrap_or(3600)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    GitHub,
    GitLab,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trust {
    pub provider: Provider,
    #[serde(default)]
    pub issuer: Option<String>,
    pub repo: String,
    #[serde(default)]
    pub refs: Option<Vec<String>>,
}

impl Trust {
    pub fn issuer(&self) -> &str {
        self.issuer.as_deref().unwrap_or(match self.provider {
            Provider::GitHub => "token.actions.githubusercontent.com",
            Provider::GitLab => "gitlab.com",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStatement {
    pub effect: Effect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default)]
    pub conditions: Option<HashMap<String, HashMap<String, ConditionValue>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    Single(String),
    Multiple(Vec<String>),
}

pub fn load_role_file(path: &Path) -> Result<RoleFile> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let role_file: RoleFile =
        serde_yaml::from_str(&contents).with_context(|| format!("parsing {}", path.display()))?;
    Ok(role_file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_role() {
        let yaml = r#"
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
"#;
        let file: RoleFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.name, "deploy-role");
        assert_eq!(file.accounts, vec!["prod"]);
        assert_eq!(file.trust.repo, "my-org/my-repo");
        assert!(file.trust.refs.is_none());
        assert_eq!(file.permissions.len(), 1);
        assert_eq!(file.max_session_duration(), 3600);
    }

    #[test]
    fn parse_full_role() {
        let yaml = r#"
name: deploy-role
description: Deploys things
accounts:
  - prod
  - staging
trust:
  provider: github
  repo: my-org/my-repo
  refs:
    - refs/heads/main
    - refs/tags/*
permissions:
  - effect: Allow
    actions:
      - s3:*
    resources:
      - arn:aws:s3:::my-bucket
      - arn:aws:s3:::my-bucket/*
    conditions:
      StringEquals:
        aws:RequestedRegion:
          - eu-west-1
          - eu-central-1
  - effect: Deny
    actions:
      - s3:DeleteBucket
    resources:
      - "*"
max_session_duration: 7200
"#;
        let file: RoleFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.description.as_deref(), Some("Deploys things"));
        assert_eq!(file.accounts.len(), 2);
        assert_eq!(file.trust.refs.as_ref().unwrap().len(), 2);
        assert_eq!(file.permissions.len(), 2);
        assert_eq!(file.max_session_duration(), 7200);

        let conditions = file.permissions[0].conditions.as_ref().unwrap();
        let region_condition = &conditions["StringEquals"]["aws:RequestedRegion"];
        match region_condition {
            ConditionValue::Multiple(vals) => assert_eq!(vals.len(), 2),
            _ => panic!("expected multiple values"),
        }
    }

    #[test]
    fn parse_condition_single_value() {
        let yaml = r#"
name: test
accounts: [prod]
trust:
  provider: github
  repo: org/repo
permissions:
  - effect: Allow
    actions: ["s3:GetObject"]
    resources: ["*"]
    conditions:
      StringEquals:
        aws:PrincipalTag/env: production
"#;
        let file: RoleFile = serde_yaml::from_str(yaml).unwrap();
        let conditions = file.permissions[0].conditions.as_ref().unwrap();
        let val = &conditions["StringEquals"]["aws:PrincipalTag/env"];
        match val {
            ConditionValue::Single(s) => assert_eq!(s, "production"),
            _ => panic!("expected single value"),
        }
    }
}
