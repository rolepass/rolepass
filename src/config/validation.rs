use std::path::Path;

use anyhow::{Result, bail};
use jsonschema::Validator;
use serde_json::Value;

static ACCOUNTS_SCHEMA: &str = include_str!("../../schemas/accounts.schema.json");
static ROLE_SCHEMA: &str = include_str!("../../schemas/role.schema.json");

pub fn validate_accounts(yaml_str: &str, file_path: &Path) -> Result<()> {
    let schema: Value = serde_json::from_str(ACCOUNTS_SCHEMA)?;
    let value: Value = serde_yml::from_str(yaml_str)?;
    validate_value(&schema, &value, file_path)
}

pub fn validate_role(yaml_str: &str, file_path: &Path) -> Result<()> {
    let schema: Value = serde_json::from_str(ROLE_SCHEMA)?;
    let value: Value = serde_yml::from_str(yaml_str)?;
    validate_value(&schema, &value, file_path)
}

fn validate_value(schema: &Value, value: &Value, file_path: &Path) -> Result<()> {
    let validator = Validator::new(schema)?;
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| {
            let path = e.instance_path().to_string();
            if path.is_empty() {
                format!("  - {e}")
            } else {
                format!("  - {path}: {e}")
            }
        })
        .collect();
    if !errors.is_empty() {
        bail!(
            "schema validation failed for {}:\n{}",
            file_path.display(),
            errors.join("\n")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn valid_accounts_yaml() {
        let yaml = r#"
accounts:
  - name: prod
    id: "111111111111"
"#;
        validate_accounts(yaml, &PathBuf::from("test.yaml")).unwrap();
    }

    #[test]
    fn valid_accounts_eusc_partition() {
        let yaml = r#"
accounts:
  - name: prod
    id: "111111111111"
    partition: aws-eusc
"#;
        validate_accounts(yaml, &PathBuf::from("test.yaml")).unwrap();
    }

    #[test]
    fn invalid_accounts_unknown_partition() {
        let yaml = r#"
accounts:
  - name: prod
    id: "111111111111"
    partition: aws-iso
"#;
        let err = validate_accounts(yaml, &PathBuf::from("test.yaml")).unwrap_err();
        assert!(err.to_string().contains("schema validation failed"));
    }

    #[test]
    fn invalid_accounts_missing_id() {
        let yaml = r#"
accounts:
  - name: prod
"#;
        let err = validate_accounts(yaml, &PathBuf::from("test.yaml")).unwrap_err();
        assert!(err.to_string().contains("schema validation failed"));
    }

    #[test]
    fn invalid_accounts_bad_id_format() {
        let yaml = r#"
accounts:
  - name: prod
    id: "123"
"#;
        let err = validate_accounts(yaml, &PathBuf::from("test.yaml")).unwrap_err();
        assert!(err.to_string().contains("schema validation failed"));
    }

    #[test]
    fn valid_role_yaml() {
        let yaml = r#"
name: deploy
accounts: [prod]
trust:
  provider: github
  repo: org/repo
permissions:
  - effect: Allow
    actions: ["s3:GetObject"]
    resources: ["*"]
"#;
        validate_role(yaml, &PathBuf::from("test.yaml")).unwrap();
    }

    #[test]
    fn invalid_role_missing_trust() {
        let yaml = r#"
name: deploy
accounts: [prod]
permissions:
  - effect: Allow
    actions: ["s3:GetObject"]
    resources: ["*"]
"#;
        // trust is missing entirely, so schema validation should fail
        let err = validate_role(yaml, &PathBuf::from("test.yaml")).unwrap_err();
        assert!(err.to_string().contains("schema validation failed"));
    }
}
