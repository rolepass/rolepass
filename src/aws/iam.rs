use anyhow::{Context, Result};
use aws_sdk_iam::Client as IamClient;
use aws_sdk_iam::operation::get_role::GetRoleError;
use aws_sdk_iam::operation::get_role_policy::GetRolePolicyError;
use aws_sdk_iam::types::Tag;
use aws_sdk_sts::types::Credentials;
use serde_json::Value;

use super::policy::ROLEPASS_POLICY_NAME;

pub const ROLEPASS_TAG_KEY: &str = "managed-by";
pub const ROLEPASS_TAG_VALUE: &str = "rolepass";

#[derive(Debug)]
pub struct FetchedRoleState {
    pub trust_policy: Value,
    pub inline_policy: Option<Value>,
    pub max_session_duration: i32,
    pub description: Option<String>,
}

pub fn iam_client_from_credentials(credentials: &Credentials) -> IamClient {
    let creds = aws_sdk_iam::config::Credentials::new(
        credentials.access_key_id(),
        credentials.secret_access_key(),
        Some(credentials.session_token().to_string()),
        None,
        "rolepass-sts",
    );
    let config = aws_sdk_iam::Config::builder()
        .credentials_provider(creds)
        .region(aws_sdk_iam::config::Region::new("us-east-1"))
        .behavior_version_latest()
        .build();
    IamClient::from_conf(config)
}

pub async fn fetch_role_state(
    iam_client: &IamClient,
    role_name: &str,
) -> Result<Option<FetchedRoleState>> {
    let role_result = iam_client.get_role().role_name(role_name).send().await;

    let role_output = match role_result {
        Ok(output) => output,
        Err(sdk_err) => {
            if matches!(
                sdk_err.as_service_error(),
                Some(GetRoleError::NoSuchEntityException(_))
            ) {
                return Ok(None);
            }
            return Err(sdk_err).context(format!("fetching role '{role_name}'"));
        }
    };

    let role = role_output
        .role()
        .ok_or_else(|| anyhow::anyhow!("no role in GetRole response for '{role_name}'"))?;

    let trust_policy_doc = role
        .assume_role_policy_document()
        .ok_or_else(|| anyhow::anyhow!("no trust policy on role '{role_name}'"))?;
    let trust_policy_decoded = urlencoding::decode(trust_policy_doc)
        .with_context(|| format!("URL-decoding trust policy for '{role_name}'"))?;
    let trust_policy: Value = serde_json::from_str(&trust_policy_decoded)
        .with_context(|| format!("parsing trust policy JSON for '{role_name}'"))?;

    let max_session_duration = role.max_session_duration().unwrap_or(3600);
    let description = role.description().map(String::from);

    let inline_policy = fetch_inline_policy(iam_client, role_name).await?;

    Ok(Some(FetchedRoleState {
        trust_policy,
        inline_policy,
        max_session_duration,
        description,
    }))
}

pub async fn create_role(
    client: &IamClient,
    role_name: &str,
    trust_policy: &Value,
    description: Option<&str>,
    max_session_duration: i32,
) -> Result<()> {
    let trust_json =
        serde_json::to_string(trust_policy).context("serializing trust policy to JSON")?;

    let tag = Tag::builder()
        .key(ROLEPASS_TAG_KEY)
        .value(ROLEPASS_TAG_VALUE)
        .build()
        .context("building managed-by tag")?;

    let mut req = client
        .create_role()
        .role_name(role_name)
        .assume_role_policy_document(trust_json)
        .max_session_duration(max_session_duration)
        .tags(tag);

    if let Some(desc) = description {
        req = req.description(desc);
    }

    req.send()
        .await
        .with_context(|| format!("creating role '{role_name}'"))?;
    Ok(())
}

pub async fn put_role_policy(
    client: &IamClient,
    role_name: &str,
    policy_name: &str,
    policy_document: &Value,
) -> Result<()> {
    let policy_json =
        serde_json::to_string(policy_document).context("serializing policy document to JSON")?;

    client
        .put_role_policy()
        .role_name(role_name)
        .policy_name(policy_name)
        .policy_document(policy_json)
        .send()
        .await
        .with_context(|| format!("putting inline policy '{policy_name}' on role '{role_name}'"))?;
    Ok(())
}

pub async fn update_trust_policy(
    client: &IamClient,
    role_name: &str,
    trust_policy: &Value,
) -> Result<()> {
    let trust_json =
        serde_json::to_string(trust_policy).context("serializing trust policy to JSON")?;

    client
        .update_assume_role_policy()
        .role_name(role_name)
        .policy_document(trust_json)
        .send()
        .await
        .with_context(|| format!("updating trust policy on role '{role_name}'"))?;
    Ok(())
}

pub async fn update_role(
    client: &IamClient,
    role_name: &str,
    max_session_duration: Option<i32>,
    description: Option<&str>,
) -> Result<()> {
    let mut req = client.update_role().role_name(role_name);

    if let Some(duration) = max_session_duration {
        req = req.max_session_duration(duration);
    }

    if let Some(desc) = description {
        req = req.description(desc);
    }

    req.send()
        .await
        .with_context(|| format!("updating role '{role_name}'"))?;
    Ok(())
}

pub async fn tag_role(client: &IamClient, role_name: &str) -> Result<()> {
    let tag = Tag::builder()
        .key(ROLEPASS_TAG_KEY)
        .value(ROLEPASS_TAG_VALUE)
        .build()
        .context("building managed-by tag")?;

    client
        .tag_role()
        .role_name(role_name)
        .tags(tag)
        .send()
        .await
        .with_context(|| format!("tagging role '{role_name}'"))?;
    Ok(())
}

pub async fn delete_role_policy(
    client: &IamClient,
    role_name: &str,
    policy_name: &str,
) -> Result<()> {
    client
        .delete_role_policy()
        .role_name(role_name)
        .policy_name(policy_name)
        .send()
        .await
        .with_context(|| {
            format!("deleting inline policy '{policy_name}' from role '{role_name}'")
        })?;
    Ok(())
}

pub async fn delete_role(client: &IamClient, role_name: &str) -> Result<()> {
    client
        .delete_role()
        .role_name(role_name)
        .send()
        .await
        .with_context(|| format!("deleting role '{role_name}'"))?;
    Ok(())
}

async fn fetch_inline_policy(iam_client: &IamClient, role_name: &str) -> Result<Option<Value>> {
    let result = iam_client
        .get_role_policy()
        .role_name(role_name)
        .policy_name(ROLEPASS_POLICY_NAME)
        .send()
        .await;

    match result {
        Ok(output) => {
            let doc = output.policy_document();
            let decoded = urlencoding::decode(doc)
                .with_context(|| format!("URL-decoding inline policy for '{role_name}'"))?;
            let policy: Value = serde_json::from_str(&decoded)
                .with_context(|| format!("parsing inline policy JSON for '{role_name}'"))?;
            Ok(Some(policy))
        }
        Err(sdk_err) => {
            if matches!(
                sdk_err.as_service_error(),
                Some(GetRolePolicyError::NoSuchEntityException(_))
            ) {
                return Ok(None);
            }
            Err(sdk_err).context(format!(
                "fetching inline policy '{ROLEPASS_POLICY_NAME}' for role '{role_name}'"
            ))
        }
    }
}
