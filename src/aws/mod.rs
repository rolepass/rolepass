pub mod iam;
pub mod policy;
pub mod sts;
pub mod tagging;

pub const CREDENTIAL_PROVIDER_NAME: &str = "rolepass-sts";

/// The region IAM and the Tagging API are served from in each partition.
/// The SDK derives the partition (endpoints, signing) from the client region.
pub fn partition_home_region(partition: &str) -> &'static str {
    match partition {
        "aws-cn" => "cn-north-1",
        "aws-us-gov" => "us-gov-west-1",
        "aws-eusc" => "eusc-de-east-1",
        _ => "us-east-1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_region_per_partition() {
        assert_eq!(partition_home_region("aws"), "us-east-1");
        assert_eq!(partition_home_region("aws-cn"), "cn-north-1");
        assert_eq!(partition_home_region("aws-us-gov"), "us-gov-west-1");
        assert_eq!(partition_home_region("aws-eusc"), "eusc-de-east-1");
    }

    #[test]
    fn home_region_defaults_to_us_east_1() {
        assert_eq!(partition_home_region("something-else"), "us-east-1");
    }
}
