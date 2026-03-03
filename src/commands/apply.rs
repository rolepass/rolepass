use std::io::IsTerminal;

use anyhow::{Result, bail};
use owo_colors::{OwoColorize, Stream, Style};

use crate::aws::iam::{
    create_role, delete_role, delete_role_policy, put_role_policy, tag_role, update_role,
    update_trust_policy,
};
use crate::aws::policy::{ROLEPASS_POLICY_NAME, generate_permission_policy, generate_trust_policy};
use crate::commands::plan::{ChangeDetail, PlannedAction, build_plan, print_plan};
use crate::config::ConfigPaths;
use crate::config::accounts::Account;
use crate::config::role::RoleFile;

pub async fn run(paths: &ConfigPaths, auto_approve: bool, debug: bool) -> Result<()> {
    let (config, entries, iam_clients) = build_plan(paths, debug).await?;

    // Print plan
    print_plan(&entries);

    // Early return if nothing to do
    if entries
        .iter()
        .all(|e| matches!(e.action, PlannedAction::NoChange))
    {
        eprintln!(
            "\n{}",
            "No changes to apply.".if_supports_color(Stream::Stderr, |t| t.dimmed())
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
        eprint!("\nDo you want to apply these changes? (yes/no): ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("yes") {
            eprintln!("Apply cancelled.");
            return Ok(());
        }
    }

    // Apply changes
    eprintln!(
        "\n{}\n",
        "Applying changes...".if_supports_color(Stream::Stderr, |t| t.bold())
    );

    let account_map = config.accounts.account_map();
    let mut succeeded = 0u32;
    let mut failed = 0u32;

    for entry in &entries {
        let account = account_map
            .get(entry.account_name.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("unknown account '{}' during apply", entry.account_name)
            })?;
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
                .if_supports_color(Stream::Stderr, |t| t.red())
        )
    } else {
        failed.to_string()
    };
    eprintln!(
        "\n{} {} succeeded, {} failed",
        "Apply complete:".if_supports_color(Stream::Stderr, |t| t.bold()),
        succeeded
            .to_string()
            .if_supports_color(Stream::Stderr, |t| t.green()),
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
    // Remove inline policy first (NoSuchEntity is handled internally by delete_role_policy)
    delete_role_policy(iam_client, role_name, ROLEPASS_POLICY_NAME).await?;
    delete_role(iam_client, role_name).await?;
    Ok(())
}
