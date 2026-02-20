use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use aws_sdk_sts::types::Credentials;

use crate::config::accounts::Account;

#[derive(Debug)]
pub struct AssumedRole {
    pub role_arn: String,
    pub credentials: Credentials,
    pub account_id: String,
}

pub fn deployer_role_arn(account: &Account) -> String {
    format!(
        "arn:{}:iam::{}:role/{}",
        account.partition(),
        account.id,
        account.deployer_role_name()
    )
}

pub async fn assume_deployer_role(
    sts_client: &aws_sdk_sts::Client,
    account: &Account,
) -> Result<AssumedRole> {
    let role_arn = deployer_role_arn(account);
    let session_name = format!("rolepass-{}", account.name);

    let resp = sts_client
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name(&session_name)
        .send()
        .await
        .with_context(|| format!("assuming role {} in account {}", role_arn, account.name))?;

    let credentials = resp
        .credentials()
        .ok_or_else(|| anyhow!("no credentials in AssumeRole response for {}", account.name))?
        .clone();

    Ok(AssumedRole {
        role_arn,
        credentials,
        account_id: account.id.clone(),
    })
}

pub async fn assume_all_deployer_roles(
    sts_client: &aws_sdk_sts::Client,
    accounts: &[&Account],
) -> (HashMap<String, AssumedRole>, Vec<(String, anyhow::Error)>) {
    let mut successes = HashMap::new();
    let mut failures = Vec::new();

    for account in accounts {
        match assume_deployer_role(sts_client, account).await {
            Ok(assumed) => {
                successes.insert(account.id.clone(), assumed);
            }
            Err(e) => {
                failures.push((account.name.clone(), e));
            }
        }
    }

    (successes, failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(
        name: &str,
        id: &str,
        partition: Option<&str>,
        deployer_role_name: Option<&str>,
    ) -> Account {
        Account {
            name: name.to_string(),
            id: id.to_string(),
            partition: partition.map(String::from),
            deployer_role_name: deployer_role_name.map(String::from),
        }
    }

    #[test]
    fn deployer_role_arn_default_partition() {
        let account = make_account("prod", "111111111111", None, None);
        assert_eq!(
            deployer_role_arn(&account),
            "arn:aws:iam::111111111111:role/rolepass-deployer"
        );
    }

    #[test]
    fn deployer_role_arn_explicit_aws_partition() {
        let account = make_account("prod", "111111111111", Some("aws"), None);
        assert_eq!(
            deployer_role_arn(&account),
            "arn:aws:iam::111111111111:role/rolepass-deployer"
        );
    }

    #[test]
    fn deployer_role_arn_china_partition() {
        let account = make_account("china", "222222222222", Some("aws-cn"), None);
        assert_eq!(
            deployer_role_arn(&account),
            "arn:aws-cn:iam::222222222222:role/rolepass-deployer"
        );
    }

    #[test]
    fn deployer_role_arn_govcloud_partition() {
        let account = make_account("gov", "333333333333", Some("aws-us-gov"), None);
        assert_eq!(
            deployer_role_arn(&account),
            "arn:aws-us-gov:iam::333333333333:role/rolepass-deployer"
        );
    }

    #[test]
    fn deployer_role_arn_custom_deployer_role() {
        let account = make_account("prod", "444444444444", None, Some("my-custom-deployer"));
        assert_eq!(
            deployer_role_arn(&account),
            "arn:aws:iam::444444444444:role/my-custom-deployer"
        );
    }

    #[test]
    fn deployer_role_arn_custom_partition_and_role() {
        let account = make_account(
            "staging",
            "555555555555",
            Some("aws-cn"),
            Some("cn-deployer"),
        );
        assert_eq!(
            deployer_role_arn(&account),
            "arn:aws-cn:iam::555555555555:role/cn-deployer"
        );
    }
}
