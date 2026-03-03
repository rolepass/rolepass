use anyhow::Result;
use serde_json::{Value, json};

use crate::aws::policy::{generate_permission_policy, generate_trust_policy};
use crate::config::{ConfigPaths, load_config};

pub fn run(paths: &ConfigPaths) -> Result<()> {
    let config = load_config(paths)?;
    let account_map = config.accounts.account_map();

    let mut entries: Vec<Value> = Vec::new();

    for role in &config.roles {
        for account_name in &role.accounts {
            let account = account_map.get(account_name.as_str()).ok_or_else(|| {
                anyhow::anyhow!("unknown account '{account_name}' in role '{}'", role.name)
            })?;

            let trust_policy = generate_trust_policy(&role.trust, account)?;
            let permission_policy = generate_permission_policy(&role.permissions);

            let mut entry = json!({
                "role_name": role.name,
                "account_name": account.name,
                "account_id": account.id,
                "trust_policy": trust_policy,
                "permission_policy": permission_policy,
                "max_session_duration": role.max_session_duration(),
            });

            if let Some(desc) = &role.description {
                entry["description"] = json!(desc);
            }

            entries.push(entry);
        }
    }

    println!("{}", serde_json::to_string_pretty(&entries)?);

    Ok(())
}
