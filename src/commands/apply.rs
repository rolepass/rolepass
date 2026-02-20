use std::collections::{HashMap, HashSet};

use std::io::IsTerminal;

use anyhow::{Result, bail};
use owo_colors::{OwoColorize, Stream, Style};

use crate::aws::iam::{
    create_role, delete_role, delete_role_policy, iam_client_from_credentials, put_role_policy,
    tag_role, update_role, update_trust_policy,
};
use crate::aws::tagging::{list_managed_role_names, tagging_client_from_credentials};
use crate::aws::policy::{ROLEPASS_POLICY_NAME, generate_permission_policy, generate_trust_policy};
use crate::aws::sts::assume_all_deployer_roles;
use crate::commands::plan::{
    ChangeDetail, PlanEntry, PlannedAction, compute_plan_entry, print_plan,
};
use crate::config::accounts::Account;
use crate::config::role::RoleFile;
use crate::config::{ConfigPaths, load_config};

pub async fn run(paths: &ConfigPaths, auto_approve: bool, debug: bool) -> Result<()> {
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

    // Early return if nothing to do
    if entries
        .iter()
        .all(|e| matches!(e.action, PlannedAction::NoChange))
    {
        println!(
            "\n{}",
            "No changes to apply.".if_supports_color(Stream::Stdout, |t| t.dimmed())
        );
        return Ok(());
    }

    // Confirm before applying
    if !auto_approve {
        if !std::io::stdin().is_terminal() {
            bail!(
                "Cannot prompt for confirmation: stdin is not a terminal. Pass --yes to skip confirmation."
            );
        }

        use std::io::Write;
        print!("\nDo you want to apply these changes? (yes/no): ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("yes") {
            println!("Apply cancelled.");
            return Ok(());
        }
    }

    // Apply changes
    println!(
        "\n{}\n",
        "Applying changes...".if_supports_color(Stream::Stdout, |t| t.bold())
    );

    let mut succeeded = 0u32;
    let mut failed = 0u32;

    for entry in &entries {
        let account = account_map[entry.account_name.as_str()];
        let iam_client = &iam_clients[account.id.as_str()];

        match &entry.action {
            PlannedAction::NoChange => continue,
            PlannedAction::Create => {
                let role = config.roles.iter().find(|r| {
                    r.name == entry.role_name && r.accounts.contains(&entry.account_name)
                });
                let role = match role {
                    Some(r) => r,
                    None => continue,
                };
                eprint!(
                    "  {} {} in {} ({})...",
                    "Creating".if_supports_color(Stream::Stderr, |t| t.green()),
                    entry.role_name,
                    entry.account_name,
                    entry.account_id
                );
                match apply_create(role, account, iam_client).await {
                    Ok(()) => {
                        eprintln!(
                            " {}",
                            "done".if_supports_color(Stream::Stderr, |t| t
                                .style(Style::new().green().bold()))
                        );
                        succeeded += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            " {}",
                            "FAILED".if_supports_color(Stream::Stderr, |t| t
                                .style(Style::new().red().bold()))
                        );
                        eprintln!(
                            "    {}: {:#}",
                            "Error".if_supports_color(Stream::Stderr, |t| t.red()),
                            e
                        );
                        failed += 1;
                    }
                }
            }
            PlannedAction::Update { changes } => {
                let role = config.roles.iter().find(|r| {
                    r.name == entry.role_name && r.accounts.contains(&entry.account_name)
                });
                let role = match role {
                    Some(r) => r,
                    None => continue,
                };
                eprint!(
                    "  {} {} in {} ({})...",
                    "Updating".if_supports_color(Stream::Stderr, |t| t.yellow()),
                    entry.role_name,
                    entry.account_name,
                    entry.account_id
                );
                match apply_update(role, iam_client, changes).await {
                    Ok(()) => {
                        eprintln!(
                            " {}",
                            "done".if_supports_color(Stream::Stderr, |t| t
                                .style(Style::new().green().bold()))
                        );
                        succeeded += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            " {}",
                            "FAILED".if_supports_color(Stream::Stderr, |t| t
                                .style(Style::new().red().bold()))
                        );
                        eprintln!(
                            "    {}: {:#}",
                            "Error".if_supports_color(Stream::Stderr, |t| t.red()),
                            e
                        );
                        failed += 1;
                    }
                }
            }
            PlannedAction::Delete => {
                eprint!(
                    "  {} {} in {} ({})...",
                    "Deleting".if_supports_color(Stream::Stderr, |t| t.red()),
                    entry.role_name,
                    entry.account_name,
                    entry.account_id
                );
                match apply_delete(&entry.role_name, iam_client).await {
                    Ok(()) => {
                        eprintln!(
                            " {}",
                            "done".if_supports_color(Stream::Stderr, |t| t
                                .style(Style::new().green().bold()))
                        );
                        succeeded += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            " {}",
                            "FAILED".if_supports_color(Stream::Stderr, |t| t
                                .style(Style::new().red().bold()))
                        );
                        eprintln!(
                            "    {}: {:#}",
                            "Error".if_supports_color(Stream::Stderr, |t| t.red()),
                            e
                        );
                        failed += 1;
                    }
                }
            }
        }
    }

    let failed_str = if failed > 0 {
        format!(
            "{}",
            failed
                .to_string()
                .if_supports_color(Stream::Stdout, |t| t.red())
        )
    } else {
        failed.to_string()
    };
    println!(
        "\n{} {} succeeded, {} failed",
        "Apply complete:".if_supports_color(Stream::Stdout, |t| t.bold()),
        succeeded
            .to_string()
            .if_supports_color(Stream::Stdout, |t| t.green()),
        failed_str,
    );

    if failed > 0 {
        bail!("{} operation(s) failed. Re-run to retry.", failed);
    }

    Ok(())
}

async fn apply_create(
    role: &RoleFile,
    account: &Account,
    iam_client: &aws_sdk_iam::Client,
) -> Result<()> {
    let trust_policy = generate_trust_policy(&role.trust, account)?;
    let permission_policy = generate_permission_policy(&role.permissions);
    let max_session_duration = role.max_session_duration() as i32;

    create_role(
        iam_client,
        &role.name,
        &trust_policy,
        role.description.as_deref(),
        max_session_duration,
    )
    .await?;

    put_role_policy(
        iam_client,
        &role.name,
        ROLEPASS_POLICY_NAME,
        &permission_policy,
    )
    .await?;

    Ok(())
}

async fn apply_update(
    role: &RoleFile,
    iam_client: &aws_sdk_iam::Client,
    changes: &[ChangeDetail],
) -> Result<()> {
    // Retrofit managed-by tag on existing roles during update
    tag_role(iam_client, &role.name).await?;

    for change in changes {
        match change {
            ChangeDetail::TrustPolicy { desired, .. } => {
                update_trust_policy(iam_client, &role.name, desired).await?;
            }
            ChangeDetail::PermissionPolicy { desired, .. } => {
                put_role_policy(iam_client, &role.name, ROLEPASS_POLICY_NAME, desired).await?;
            }
            ChangeDetail::MaxSessionDuration { desired, .. } => {
                update_role(iam_client, &role.name, Some(*desired), None).await?;
            }
            ChangeDetail::Description { desired, .. } => {
                update_role(iam_client, &role.name, None, desired.as_deref()).await?;
            }
        }
    }
    Ok(())
}

async fn apply_delete(role_name: &str, iam_client: &aws_sdk_iam::Client) -> Result<()> {
    // Remove inline policy first (ignore NoSuchEntity — policy may not exist)
    match delete_role_policy(iam_client, role_name, ROLEPASS_POLICY_NAME).await {
        Ok(()) => {}
        Err(e) => {
            let err_str = format!("{e:#}");
            if !err_str.contains("NoSuchEntity") {
                return Err(e);
            }
        }
    }

    delete_role(iam_client, role_name).await?;
    Ok(())
}
