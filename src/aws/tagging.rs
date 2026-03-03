use anyhow::{Context, Result};
use aws_sdk_iam::Client as IamClient;
use aws_sdk_resourcegroupstagging::Client as TaggingClient;
use aws_sdk_resourcegroupstagging::types::TagFilter;
use aws_sdk_sts::types::Credentials;

use super::iam::{ROLEPASS_TAG_KEY, ROLEPASS_TAG_VALUE};
use super::{CREDENTIAL_PROVIDER_NAME, IAM_REGION};

/// Build a Resource Groups Tagging API client from STS assumed-role credentials.
///
/// IAM is a global service, but the Tagging API indexes IAM resources in us-east-1.
pub fn tagging_client_from_credentials(credentials: &Credentials) -> TaggingClient {
    let creds = aws_sdk_resourcegroupstagging::config::Credentials::new(
        credentials.access_key_id(),
        credentials.secret_access_key(),
        Some(credentials.session_token().to_string()),
        None,
        CREDENTIAL_PROVIDER_NAME,
    );
    let config = aws_sdk_resourcegroupstagging::Config::builder()
        .credentials_provider(creds)
        .region(aws_sdk_resourcegroupstagging::config::Region::new(
            IAM_REGION,
        ))
        .behavior_version_latest()
        .build();
    TaggingClient::from_conf(config)
}

/// List the names of all IAM roles tagged `managed-by:rolepass` in the account
/// associated with the given client.
///
/// Uses the Resource Groups Tagging API `GetResources` with tag and resource type filters,
/// replacing the previous N+1 approach of listing all roles then checking tags individually.
pub async fn list_managed_role_names(
    client: &TaggingClient,
    iam_client: &IamClient,
    debug: bool,
) -> Result<Vec<String>> {
    let tag_filter = TagFilter::builder()
        .key(ROLEPASS_TAG_KEY)
        .values(ROLEPASS_TAG_VALUE)
        .build();

    if debug {
        eprintln!(
            "[debug] GetResources: tag_filter={}:{}, resource_type_filters=iam:role",
            ROLEPASS_TAG_KEY, ROLEPASS_TAG_VALUE
        );
    }

    let mut role_names = Vec::new();
    let mut page_num = 0u32;
    let mut paginator = client
        .get_resources()
        .tag_filters(tag_filter)
        .resource_type_filters("iam:role")
        .into_paginator()
        .send();

    while let Some(page) = paginator.next().await {
        let output = page.context("fetching tagged IAM roles via Resource Groups Tagging API")?;
        page_num += 1;
        let mappings = output.resource_tag_mapping_list();
        if debug {
            eprintln!(
                "[debug] GetResources page {}: {} resource(s)",
                page_num,
                mappings.len()
            );
        }
        for mapping in mappings {
            if debug {
                eprintln!(
                    "[debug]   arn={:?} tags={:?}",
                    mapping.resource_arn(),
                    mapping
                        .tags()
                        .iter()
                        .map(|t| format!("{}={}", t.key(), t.value()))
                        .collect::<Vec<_>>()
                );
            }
            if let Some(arn) = mapping.resource_arn()
                && let Some(name) = extract_role_name_from_arn(arn)
            {
                role_names.push(name.to_string());
            }
        }
    }

    if debug {
        eprintln!(
            "[debug] GetResources total: {} managed role(s) found: {:?}",
            role_names.len(),
            role_names
        );
    }

    // Fall back to IAM-based detection when the Tagging API returns empty.
    // The Tagging API index can lag behind actual IAM tags, so we use the
    // slower but reliable list_roles + list_role_tags approach as a safety net.
    if role_names.is_empty() {
        if debug {
            eprintln!(
                "[debug] Tagging API returned 0 results, falling back to IAM list_roles + list_role_tags"
            );
        }
        return list_managed_role_names_iam_fallback(iam_client, debug).await;
    }

    Ok(role_names)
}

/// List rolepass-managed role names by paginating `list_roles` and checking tags on each role.
///
/// This is slower than the Tagging API (N+1 calls) but queries IAM directly and is
/// guaranteed to find roles tagged `managed-by:rolepass`.
async fn list_managed_role_names_iam_fallback(
    iam_client: &IamClient,
    debug: bool,
) -> Result<Vec<String>> {
    let mut role_names = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = iam_client.list_roles();
        if let Some(m) = &marker {
            req = req.marker(m);
        }
        let output = req
            .send()
            .await
            .context("listing IAM roles for fallback orphan detection")?;

        for role in output.roles() {
            let role_name = role.role_name();
            let tags_output = iam_client
                .list_role_tags()
                .role_name(role_name)
                .send()
                .await
                .with_context(|| format!("listing tags for role '{role_name}'"))?;

            let is_managed = tags_output
                .tags()
                .iter()
                .any(|t| t.key() == ROLEPASS_TAG_KEY && t.value() == ROLEPASS_TAG_VALUE);

            if is_managed {
                if debug {
                    eprintln!("[debug] IAM fallback: found managed role '{role_name}'");
                }
                role_names.push(role_name.to_string());
            }
        }

        if output.is_truncated() {
            marker = output.marker().map(String::from);
        } else {
            break;
        }
    }

    if debug {
        eprintln!(
            "[debug] IAM fallback total: {} managed role(s) found: {:?}",
            role_names.len(),
            role_names
        );
    }

    Ok(role_names)
}

/// Extract the role name from an IAM role ARN.
///
/// ARN format: `arn:{partition}:iam::{account_id}:role/{role_name}`
/// Also handles path-based ARNs: `arn:{partition}:iam::{account_id}:role/{path}/{role_name}`
fn extract_role_name_from_arn(arn: &str) -> Option<&str> {
    let role_marker = ":role/";
    let idx = arn.find(role_marker)?;
    let after_role = &arn[idx + role_marker.len()..];
    // For path-based roles, the name is the last segment after the final '/'.
    // For simple roles there's no slash, so rsplit gives the whole string.
    after_role.rsplit('/').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_simple_role_name() {
        assert_eq!(
            extract_role_name_from_arn("arn:aws:iam::123456789012:role/my-role"),
            Some("my-role")
        );
    }

    #[test]
    fn extract_path_based_role_name() {
        assert_eq!(
            extract_role_name_from_arn("arn:aws:iam::123456789012:role/service-roles/my-role"),
            Some("my-role")
        );
    }

    #[test]
    fn extract_china_partition_role() {
        assert_eq!(
            extract_role_name_from_arn("arn:aws-cn:iam::123456789012:role/my-role"),
            Some("my-role")
        );
    }

    #[test]
    fn extract_govcloud_partition_role() {
        assert_eq!(
            extract_role_name_from_arn("arn:aws-us-gov:iam::123456789012:role/my-role"),
            Some("my-role")
        );
    }

    #[test]
    fn extract_returns_none_for_non_role_arn() {
        assert_eq!(extract_role_name_from_arn("arn:aws:s3:::my-bucket"), None);
    }

    #[test]
    fn extract_returns_none_for_empty_string() {
        assert_eq!(extract_role_name_from_arn(""), None);
    }
}
