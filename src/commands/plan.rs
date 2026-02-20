use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail};
use owo_colors::{OwoColorize, Stream};
use serde_json::Value;

use crate::aws::iam::{FetchedRoleState, fetch_role_state, iam_client_from_credentials};
use crate::aws::tagging::{list_managed_role_names, tagging_client_from_credentials};
use crate::aws::policy::{generate_permission_policy, generate_trust_policy};
use crate::aws::sts::assume_all_deployer_roles;
use crate::config::accounts::Account;
use crate::config::role::RoleFile;
use crate::config::{ConfigPaths, load_config};

#[derive(Debug)]
pub struct PlanEntry {
    pub role_name: String,
    pub account_name: String,
    pub account_id: String,
    pub action: PlannedAction,
}

#[derive(Debug)]
pub enum PlannedAction {
    Create,
    NoChange,
    Update { changes: Vec<ChangeDetail> },
    Delete,
}

#[derive(Debug)]
pub enum ChangeDetail {
    TrustPolicy {
        current: Value,
        desired: Value,
    },
    PermissionPolicy {
        current: Option<Value>,
        desired: Value,
    },
    MaxSessionDuration {
        current: i32,
        desired: i32,
    },
    Description {
        current: Option<String>,
        desired: Option<String>,
    },
}

impl std::fmt::Display for ChangeDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeDetail::TrustPolicy { .. } => write!(f, "trust policy changed"),
            ChangeDetail::PermissionPolicy { .. } => write!(f, "permission policy changed"),
            ChangeDetail::MaxSessionDuration { current, desired } => {
                write!(f, "max session duration: {current}s -> {desired}s")
            }
            ChangeDetail::Description { current, desired } => {
                let cur = current.as_deref().unwrap_or("<none>");
                let des = desired.as_deref().unwrap_or("<none>");
                write!(f, "description: \"{cur}\" -> \"{des}\"")
            }
        }
    }
}

pub fn compute_action(
    current: Option<&FetchedRoleState>,
    desired_trust: &Value,
    desired_permissions: &Value,
    desired_max_session_duration: i32,
    desired_description: &Option<String>,
) -> PlannedAction {
    let Some(current) = current else {
        return PlannedAction::Create;
    };

    let mut changes = Vec::new();

    if normalize_json(&current.trust_policy) != normalize_json(desired_trust) {
        changes.push(ChangeDetail::TrustPolicy {
            current: current.trust_policy.clone(),
            desired: desired_trust.clone(),
        });
    }

    if current.inline_policy.as_ref().map(normalize_json)
        != Some(normalize_json(desired_permissions))
    {
        changes.push(ChangeDetail::PermissionPolicy {
            current: current.inline_policy.clone(),
            desired: desired_permissions.clone(),
        });
    }

    if current.max_session_duration != desired_max_session_duration {
        changes.push(ChangeDetail::MaxSessionDuration {
            current: current.max_session_duration,
            desired: desired_max_session_duration,
        });
    }

    if current.description != *desired_description {
        changes.push(ChangeDetail::Description {
            current: current.description.clone(),
            desired: desired_description.clone(),
        });
    }

    if changes.is_empty() {
        PlannedAction::NoChange
    } else {
        PlannedAction::Update { changes }
    }
}

/// Normalize JSON for comparison: sort object keys recursively.
fn normalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), normalize_json(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(normalize_json).collect()),
        other => other.clone(),
    }
}

pub async fn run(paths: &ConfigPaths, debug: bool) -> Result<()> {
    let config = load_config(paths)?;

    let account_map: HashMap<&str, &Account> = config
        .accounts
        .accounts
        .iter()
        .map(|a| (a.name.as_str(), a))
        .collect();

    // Use ALL accounts from accounts file (not just role-referenced ones)
    // so we can detect orphaned roles in accounts where roles were removed from config
    let unique_accounts: Vec<&Account> = config.accounts.accounts.iter().collect();

    println!(
        "{}",
        format!(
            "Assuming deployer roles in {} account(s)...",
            unique_accounts.len()
        )
        .if_supports_color(Stream::Stdout, |t| t.bold())
    );

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let sts_client = aws_sdk_sts::Client::new(&aws_config);

    let (successes, failures) = assume_all_deployer_roles(&sts_client, &unique_accounts).await;

    if !failures.is_empty() {
        eprintln!(
            "\n{}",
            format!("Failed to assume roles in {} account(s):", failures.len())
                .if_supports_color(Stream::Stderr, |t| t.red())
        );
        for (name, err) in &failures {
            eprintln!("  {}: {:#}", name, err);
        }
        bail!(
            "Failed to assume deployer roles in {} account(s). Cannot proceed.",
            failures.len()
        );
    }

    // Build IAM client per account
    let iam_clients: HashMap<&str, aws_sdk_iam::Client> = successes
        .iter()
        .map(|(id, assumed)| {
            let client = iam_client_from_credentials(&assumed.credentials);
            (id.as_str(), client)
        })
        .collect();

    // Build tagging client per account
    let tagging_clients: HashMap<&str, aws_sdk_resourcegroupstagging::Client> = successes
        .iter()
        .map(|(id, assumed)| {
            let client = tagging_client_from_credentials(&assumed.credentials);
            (id.as_str(), client)
        })
        .collect();

    // Compute plan entries for config-defined roles
    let mut entries = Vec::new();
    for role in &config.roles {
        for account_name in &role.accounts {
            let account = account_map[account_name.as_str()];
            let iam_client = &iam_clients[account.id.as_str()];

            let entry = compute_plan_entry(role, account, iam_client).await?;
            entries.push(entry);
        }
    }

    // Build desired set of (role_name, account_id) from config
    let mut desired: HashSet<(&str, &str)> = HashSet::new();
    for role in &config.roles {
        for acct_name in &role.accounts {
            let account = account_map[acct_name.as_str()];
            desired.insert((role.name.as_str(), account.id.as_str()));
        }
    }

    // Discover orphaned roles in each account
    for account in &unique_accounts {
        let tagging_client = &tagging_clients[account.id.as_str()];
        let iam_client = &iam_clients[account.id.as_str()];
        let managed_names = list_managed_role_names(tagging_client, iam_client, debug).await?;

        for role_name in managed_names {
            if !desired.contains(&(role_name.as_str(), account.id.as_str())) {
                entries.push(PlanEntry {
                    role_name,
                    account_name: account.name.clone(),
                    account_id: account.id.clone(),
                    action: PlannedAction::Delete,
                });
            }
        }
    }

    // Print plan
    print_plan(&entries);
    Ok(())
}

pub async fn compute_plan_entry(
    role: &RoleFile,
    account: &Account,
    iam_client: &aws_sdk_iam::Client,
) -> Result<PlanEntry> {
    let desired_trust = generate_trust_policy(&role.trust, account)?;
    let desired_permissions = generate_permission_policy(&role.permissions);
    let desired_max_session_duration = role.max_session_duration() as i32;

    let current = fetch_role_state(iam_client, &role.name).await?;

    let action = compute_action(
        current.as_ref(),
        &desired_trust,
        &desired_permissions,
        desired_max_session_duration,
        &role.description,
    );

    Ok(PlanEntry {
        role_name: role.name.clone(),
        account_name: account.name.clone(),
        account_id: account.id.clone(),
        action,
    })
}

pub fn print_plan(entries: &[PlanEntry]) {
    println!(
        "\n{}\n",
        "Plan:".if_supports_color(Stream::Stdout, |t| t.bold())
    );

    let mut create_count = 0;
    let mut update_count = 0;
    let mut delete_count = 0;
    let mut no_change_count = 0;

    for entry in entries {
        match &entry.action {
            PlannedAction::Create => {
                create_count += 1;
                println!(
                    "  {} {} in {} ({}): {}",
                    "+".if_supports_color(Stream::Stdout, |t| t.green()),
                    entry.role_name,
                    entry.account_name,
                    entry.account_id,
                    "CREATE".if_supports_color(Stream::Stdout, |t| t.green()),
                );
            }
            PlannedAction::Update { changes } => {
                update_count += 1;
                println!(
                    "  {} {} in {} ({}): {}",
                    "~".if_supports_color(Stream::Stdout, |t| t.yellow()),
                    entry.role_name,
                    entry.account_name,
                    entry.account_id,
                    "UPDATE".if_supports_color(Stream::Stdout, |t| t.yellow()),
                );
                for change in changes {
                    let detail = format!("      - {change}");
                    println!(
                        "{}",
                        detail.if_supports_color(Stream::Stdout, |t| t.yellow())
                    );
                }
            }
            PlannedAction::Delete => {
                delete_count += 1;
                println!(
                    "  {} {} in {} ({}): {}",
                    "-".if_supports_color(Stream::Stdout, |t| t.red()),
                    entry.role_name,
                    entry.account_name,
                    entry.account_id,
                    "DELETE".if_supports_color(Stream::Stdout, |t| t.red()),
                );
            }
            PlannedAction::NoChange => {
                no_change_count += 1;
                let line = format!(
                    "    {} in {} ({}): no change",
                    entry.role_name, entry.account_name, entry.account_id
                );
                println!("{}", line.if_supports_color(Stream::Stdout, |t| t.dimmed()));
            }
        }
    }

    println!(
        "\n{} {} to create, {} to update, {} to delete, {} unchanged",
        "Summary:".if_supports_color(Stream::Stdout, |t| t.bold()),
        create_count
            .to_string()
            .if_supports_color(Stream::Stdout, |t| t.green()),
        update_count
            .to_string()
            .if_supports_color(Stream::Stdout, |t| t.yellow()),
        delete_count
            .to_string()
            .if_supports_color(Stream::Stdout, |t| t.red()),
        no_change_count
            .to_string()
            .if_supports_color(Stream::Stdout, |t| t.dimmed()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_trust_policy() -> Value {
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com" },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
                    "StringLike": { "token.actions.githubusercontent.com:sub": "repo:org/repo:*" }
                }
            }]
        })
    }

    fn make_permission_policy() -> Value {
        json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["*"]
            }]
        })
    }

    #[test]
    fn compute_action_create_when_no_current() {
        let trust = make_trust_policy();
        let perms = make_permission_policy();
        let action = compute_action(None, &trust, &perms, 3600, &None);
        assert!(matches!(action, PlannedAction::Create));
    }

    #[test]
    fn compute_action_no_change() {
        let trust = make_trust_policy();
        let perms = make_permission_policy();
        let current = FetchedRoleState {
            trust_policy: trust.clone(),
            inline_policy: Some(perms.clone()),
            max_session_duration: 3600,
            description: None,
        };
        let action = compute_action(Some(&current), &trust, &perms, 3600, &None);
        assert!(matches!(action, PlannedAction::NoChange));
    }

    #[test]
    fn compute_action_update_trust() {
        let trust = make_trust_policy();
        let perms = make_permission_policy();
        let mut old_trust = trust.clone();
        old_trust["Statement"][0]["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"] =
            json!("repo:org/old-repo:*");

        let current = FetchedRoleState {
            trust_policy: old_trust,
            inline_policy: Some(perms.clone()),
            max_session_duration: 3600,
            description: None,
        };
        let action = compute_action(Some(&current), &trust, &perms, 3600, &None);
        match action {
            PlannedAction::Update { changes } => {
                assert_eq!(changes.len(), 1);
                assert!(matches!(changes[0], ChangeDetail::TrustPolicy { .. }));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn compute_action_update_permissions() {
        let trust = make_trust_policy();
        let perms = make_permission_policy();
        let current = FetchedRoleState {
            trust_policy: trust.clone(),
            inline_policy: None,
            max_session_duration: 3600,
            description: None,
        };
        let action = compute_action(Some(&current), &trust, &perms, 3600, &None);
        match action {
            PlannedAction::Update { changes } => {
                assert_eq!(changes.len(), 1);
                assert!(matches!(changes[0], ChangeDetail::PermissionPolicy { .. }));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn compute_action_update_duration() {
        let trust = make_trust_policy();
        let perms = make_permission_policy();
        let current = FetchedRoleState {
            trust_policy: trust.clone(),
            inline_policy: Some(perms.clone()),
            max_session_duration: 3600,
            description: None,
        };
        let action = compute_action(Some(&current), &trust, &perms, 7200, &None);
        match action {
            PlannedAction::Update { changes } => {
                assert_eq!(changes.len(), 1);
                assert!(matches!(
                    changes[0],
                    ChangeDetail::MaxSessionDuration {
                        current: 3600,
                        desired: 7200
                    }
                ));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn compute_action_update_description() {
        let trust = make_trust_policy();
        let perms = make_permission_policy();
        let current = FetchedRoleState {
            trust_policy: trust.clone(),
            inline_policy: Some(perms.clone()),
            max_session_duration: 3600,
            description: None,
        };
        let desired_desc = Some("new description".to_string());
        let action = compute_action(Some(&current), &trust, &perms, 3600, &desired_desc);
        match action {
            PlannedAction::Update { changes } => {
                assert_eq!(changes.len(), 1);
                assert!(matches!(changes[0], ChangeDetail::Description { .. }));
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn compute_action_multiple_changes() {
        let trust = make_trust_policy();
        let perms = make_permission_policy();
        let current = FetchedRoleState {
            trust_policy: json!({"Version": "2012-10-17", "Statement": []}),
            inline_policy: None,
            max_session_duration: 1800,
            description: Some("old".to_string()),
        };
        let action = compute_action(
            Some(&current),
            &trust,
            &perms,
            7200,
            &Some("new".to_string()),
        );
        match action {
            PlannedAction::Update { changes } => {
                assert_eq!(changes.len(), 4);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn print_plan_with_delete_entries() {
        let entries = vec![
            PlanEntry {
                role_name: "ci-deploy".to_string(),
                account_name: "prod".to_string(),
                account_id: "111111111111".to_string(),
                action: PlannedAction::Create,
            },
            PlanEntry {
                role_name: "ci-read".to_string(),
                account_name: "prod".to_string(),
                account_id: "111111111111".to_string(),
                action: PlannedAction::NoChange,
            },
            PlanEntry {
                role_name: "orphaned-role".to_string(),
                account_name: "prod".to_string(),
                account_id: "111111111111".to_string(),
                action: PlannedAction::Delete,
            },
            PlanEntry {
                role_name: "old-role".to_string(),
                account_name: "staging".to_string(),
                account_id: "222222222222".to_string(),
                action: PlannedAction::Delete,
            },
        ];

        // Should not panic — exercises the Delete branch in print_plan
        print_plan(&entries);
    }
}
