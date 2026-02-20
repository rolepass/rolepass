use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::config::accounts::Account;
use crate::config::role::{ConditionValue, Effect, PolicyStatement, Provider, Trust};

pub const ROLEPASS_POLICY_NAME: &str = "rolepass-policy";

pub fn oidc_provider_arn(trust: &Trust, account: &Account) -> String {
    format!(
        "arn:{}:iam::{}:oidc-provider/{}",
        account.partition(),
        account.id,
        trust.issuer()
    )
}

pub fn generate_trust_policy(trust: &Trust, account: &Account) -> Result<Value> {
    let issuer = trust.issuer();
    let provider_arn = oidc_provider_arn(trust, account);

    let sub_values = build_sub_claims(trust)?;

    let sub_condition = if sub_values.len() == 1 {
        json!(sub_values[0])
    } else {
        json!(sub_values)
    };

    Ok(json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Federated": provider_arn
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    format!("{issuer}:aud"): "sts.amazonaws.com"
                },
                "StringLike": {
                    format!("{issuer}:sub"): sub_condition
                }
            }
        }]
    }))
}

fn build_sub_claims(trust: &Trust) -> Result<Vec<String>> {
    match &trust.refs {
        None => {
            let pattern = match trust.provider {
                Provider::GitHub => format!("repo:{}:*", trust.repo),
                Provider::GitLab => format!("project_path:{}:*", trust.repo),
            };
            Ok(vec![pattern])
        }
        Some(refs) => {
            let mut claims = Vec::with_capacity(refs.len());
            for r in refs {
                let claim = match trust.provider {
                    Provider::GitHub => format!("repo:{}:ref:{}", trust.repo, r),
                    Provider::GitLab => {
                        let (ref_type, short_name) = parse_gitlab_ref(r)?;
                        format!(
                            "project_path:{}:ref_type:{}:ref:{}",
                            trust.repo, ref_type, short_name
                        )
                    }
                };
                claims.push(claim);
            }
            Ok(claims)
        }
    }
}

fn parse_gitlab_ref(full_ref: &str) -> Result<(&str, &str)> {
    if let Some(name) = full_ref.strip_prefix("refs/heads/") {
        Ok(("branch", name))
    } else if let Some(name) = full_ref.strip_prefix("refs/tags/") {
        Ok(("tag", name))
    } else {
        bail!(
            "unsupported ref format for GitLab: '{full_ref}'. Expected refs/heads/<name> or refs/tags/<name>"
        )
    }
}

pub fn generate_permission_policy(permissions: &[PolicyStatement]) -> Value {
    let statements: Vec<Value> = permissions
        .iter()
        .map(|stmt| {
            let effect = match stmt.effect {
                Effect::Allow => "Allow",
                Effect::Deny => "Deny",
            };

            let mut s = json!({
                "Effect": effect,
                "Action": stmt.actions,
                "Resource": stmt.resources,
            });

            if let Some(conditions) = &stmt.conditions {
                let mut cond_obj = serde_json::Map::new();
                for (operator, keys) in conditions {
                    let mut op_obj = serde_json::Map::new();
                    for (key, value) in keys {
                        let v = match value {
                            ConditionValue::Single(s) => json!(s),
                            ConditionValue::Multiple(m) => json!(m),
                        };
                        op_obj.insert(key.clone(), v);
                    }
                    cond_obj.insert(operator.clone(), Value::Object(op_obj));
                }
                s["Condition"] = Value::Object(cond_obj);
            }

            s
        })
        .collect();

    json!({
        "Version": "2012-10-17",
        "Statement": statements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::accounts::Account;
    use crate::config::role::{ConditionValue, Effect, PolicyStatement, Provider, Trust};
    use std::collections::HashMap;

    fn make_account(id: &str, partition: Option<&str>) -> Account {
        Account {
            name: "test".to_string(),
            id: id.to_string(),
            partition: partition.map(String::from),
            deployer_role_name: None,
        }
    }

    fn make_trust(provider: Provider, repo: &str, refs: Option<Vec<&str>>) -> Trust {
        Trust {
            provider,
            issuer: None,
            repo: repo.to_string(),
            refs: refs.map(|r| r.into_iter().map(String::from).collect()),
        }
    }

    // --- OIDC ARN tests ---

    #[test]
    fn oidc_arn_github() {
        let trust = make_trust(Provider::GitHub, "org/repo", None);
        let account = make_account("111111111111", None);
        assert_eq!(
            oidc_provider_arn(&trust, &account),
            "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn oidc_arn_gitlab() {
        let trust = make_trust(Provider::GitLab, "group/project", None);
        let account = make_account("222222222222", None);
        assert_eq!(
            oidc_provider_arn(&trust, &account),
            "arn:aws:iam::222222222222:oidc-provider/gitlab.com"
        );
    }

    #[test]
    fn oidc_arn_custom_issuer() {
        let trust = Trust {
            provider: Provider::GitLab,
            issuer: Some("gitlab.mycompany.com".to_string()),
            repo: "group/project".to_string(),
            refs: None,
        };
        let account = make_account("333333333333", None);
        assert_eq!(
            oidc_provider_arn(&trust, &account),
            "arn:aws:iam::333333333333:oidc-provider/gitlab.mycompany.com"
        );
    }

    #[test]
    fn oidc_arn_china_partition() {
        let trust = make_trust(Provider::GitHub, "org/repo", None);
        let account = make_account("444444444444", Some("aws-cn"));
        assert_eq!(
            oidc_provider_arn(&trust, &account),
            "arn:aws-cn:iam::444444444444:oidc-provider/token.actions.githubusercontent.com"
        );
    }

    // --- GitHub trust policy tests ---

    #[test]
    fn trust_policy_github_no_refs() {
        let trust = make_trust(Provider::GitHub, "my-org/my-repo", None);
        let account = make_account("111111111111", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let stmt = &policy["Statement"][0];
        assert_eq!(stmt["Effect"], "Allow");
        assert_eq!(stmt["Action"], "sts:AssumeRoleWithWebIdentity");
        assert_eq!(
            stmt["Principal"]["Federated"],
            "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
        );
        assert_eq!(
            stmt["Condition"]["StringEquals"]["token.actions.githubusercontent.com:aud"],
            "sts.amazonaws.com"
        );
        assert_eq!(
            stmt["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"],
            "repo:my-org/my-repo:*"
        );
    }

    #[test]
    fn trust_policy_github_with_refs() {
        let trust = make_trust(
            Provider::GitHub,
            "my-org/my-repo",
            Some(vec!["refs/heads/main", "refs/tags/*"]),
        );
        let account = make_account("111111111111", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let sub = &policy["Statement"][0]["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"];
        let subs: Vec<&str> = sub
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            subs,
            vec![
                "repo:my-org/my-repo:ref:refs/heads/main",
                "repo:my-org/my-repo:ref:refs/tags/*"
            ]
        );
    }

    #[test]
    fn trust_policy_github_single_ref() {
        let trust = make_trust(
            Provider::GitHub,
            "my-org/my-repo",
            Some(vec!["refs/heads/main"]),
        );
        let account = make_account("111111111111", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let sub = &policy["Statement"][0]["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"];
        assert_eq!(sub, "repo:my-org/my-repo:ref:refs/heads/main");
    }

    // --- GitLab trust policy tests ---

    #[test]
    fn trust_policy_gitlab_no_refs() {
        let trust = make_trust(Provider::GitLab, "my-group/my-project", None);
        let account = make_account("222222222222", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let stmt = &policy["Statement"][0];
        assert_eq!(
            stmt["Condition"]["StringLike"]["gitlab.com:sub"],
            "project_path:my-group/my-project:*"
        );
        assert_eq!(
            stmt["Condition"]["StringEquals"]["gitlab.com:aud"],
            "sts.amazonaws.com"
        );
    }

    #[test]
    fn trust_policy_gitlab_branch_ref() {
        let trust = make_trust(
            Provider::GitLab,
            "my-group/my-project",
            Some(vec!["refs/heads/main"]),
        );
        let account = make_account("222222222222", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let sub = &policy["Statement"][0]["Condition"]["StringLike"]["gitlab.com:sub"];
        assert_eq!(
            sub,
            "project_path:my-group/my-project:ref_type:branch:ref:main"
        );
    }

    #[test]
    fn trust_policy_gitlab_tag_ref() {
        let trust = make_trust(
            Provider::GitLab,
            "my-group/my-project",
            Some(vec!["refs/tags/v1.0"]),
        );
        let account = make_account("222222222222", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let sub = &policy["Statement"][0]["Condition"]["StringLike"]["gitlab.com:sub"];
        assert_eq!(
            sub,
            "project_path:my-group/my-project:ref_type:tag:ref:v1.0"
        );
    }

    #[test]
    fn trust_policy_gitlab_wildcard_ref() {
        let trust = make_trust(
            Provider::GitLab,
            "my-group/my-project",
            Some(vec!["refs/heads/*"]),
        );
        let account = make_account("222222222222", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let sub = &policy["Statement"][0]["Condition"]["StringLike"]["gitlab.com:sub"];
        assert_eq!(
            sub,
            "project_path:my-group/my-project:ref_type:branch:ref:*"
        );
    }

    #[test]
    fn trust_policy_gitlab_multiple_refs() {
        let trust = make_trust(
            Provider::GitLab,
            "my-group/my-project",
            Some(vec!["refs/heads/main", "refs/tags/v*"]),
        );
        let account = make_account("222222222222", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let sub = &policy["Statement"][0]["Condition"]["StringLike"]["gitlab.com:sub"];
        let subs: Vec<&str> = sub
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            subs,
            vec![
                "project_path:my-group/my-project:ref_type:branch:ref:main",
                "project_path:my-group/my-project:ref_type:tag:ref:v*",
            ]
        );
    }

    #[test]
    fn trust_policy_custom_issuer() {
        let trust = Trust {
            provider: Provider::GitLab,
            issuer: Some("gitlab.mycompany.com".to_string()),
            repo: "team/project".to_string(),
            refs: None,
        };
        let account = make_account("555555555555", None);
        let policy = generate_trust_policy(&trust, &account).unwrap();

        let stmt = &policy["Statement"][0];
        assert_eq!(
            stmt["Condition"]["StringEquals"]["gitlab.mycompany.com:aud"],
            "sts.amazonaws.com"
        );
        assert_eq!(
            stmt["Condition"]["StringLike"]["gitlab.mycompany.com:sub"],
            "project_path:team/project:*"
        );
    }

    #[test]
    fn gitlab_ref_parse_invalid() {
        let result = parse_gitlab_ref("main");
        assert!(result.is_err());
    }

    // --- Permission policy tests ---

    #[test]
    fn permission_policy_allow() {
        let stmts = vec![PolicyStatement {
            effect: Effect::Allow,
            actions: vec!["s3:GetObject".to_string()],
            resources: vec!["*".to_string()],
            conditions: None,
        }];
        let policy = generate_permission_policy(&stmts);
        assert_eq!(policy["Version"], "2012-10-17");
        assert_eq!(policy["Statement"][0]["Effect"], "Allow");
        assert_eq!(policy["Statement"][0]["Action"][0], "s3:GetObject");
        assert_eq!(policy["Statement"][0]["Resource"][0], "*");
    }

    #[test]
    fn permission_policy_deny() {
        let stmts = vec![PolicyStatement {
            effect: Effect::Deny,
            actions: vec!["s3:DeleteBucket".to_string()],
            resources: vec!["*".to_string()],
            conditions: None,
        }];
        let policy = generate_permission_policy(&stmts);
        assert_eq!(policy["Statement"][0]["Effect"], "Deny");
    }

    #[test]
    fn permission_policy_with_conditions() {
        let mut cond_keys = HashMap::new();
        cond_keys.insert(
            "aws:RequestedRegion".to_string(),
            ConditionValue::Multiple(vec!["eu-west-1".to_string(), "eu-central-1".to_string()]),
        );
        let mut conditions = HashMap::new();
        conditions.insert("StringEquals".to_string(), cond_keys);

        let stmts = vec![PolicyStatement {
            effect: Effect::Allow,
            actions: vec!["s3:*".to_string()],
            resources: vec!["arn:aws:s3:::my-bucket".to_string()],
            conditions: Some(conditions),
        }];
        let policy = generate_permission_policy(&stmts);
        let cond = &policy["Statement"][0]["Condition"]["StringEquals"]["aws:RequestedRegion"];
        assert_eq!(cond.as_array().unwrap().len(), 2);
    }

    #[test]
    fn permission_policy_multiple_statements() {
        let stmts = vec![
            PolicyStatement {
                effect: Effect::Allow,
                actions: vec!["s3:GetObject".to_string()],
                resources: vec!["*".to_string()],
                conditions: None,
            },
            PolicyStatement {
                effect: Effect::Deny,
                actions: vec!["s3:DeleteBucket".to_string()],
                resources: vec!["*".to_string()],
                conditions: None,
            },
        ];
        let policy = generate_permission_policy(&stmts);
        assert_eq!(policy["Statement"].as_array().unwrap().len(), 2);
    }
}
