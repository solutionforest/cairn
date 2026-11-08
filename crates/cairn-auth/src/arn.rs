//! ARN helpers. Cairn uses the `aws` partition so SDKs and tools accept its ARNs.

use crate::types::ACCOUNT_ID;

/// `arn:aws:s3:::<bucket>`.
pub fn bucket(bucket: &str) -> String {
    format!("arn:aws:s3:::{bucket}")
}

/// `arn:aws:s3:::<bucket>/<key>`.
pub fn object(bucket: &str, key: &str) -> String {
    format!("arn:aws:s3:::{bucket}/{key}")
}

/// `arn:aws:iam::<acct>:user/<name>`.
pub fn user(name: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT_ID}:user/{name}")
}

/// `arn:aws:iam::<acct>:group/<name>`.
pub fn group(name: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT_ID}:group/{name}")
}

/// `arn:aws:iam::<acct>:role/<name>`.
pub fn role(name: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT_ID}:role/{name}")
}

/// `arn:aws:iam::<acct>:policy/<name>`.
pub fn policy(name: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT_ID}:policy/{name}")
}

/// `arn:aws:sts::<acct>:assumed-role/<role>/<session>`.
pub fn assumed_role(role: &str, session: &str) -> String {
    format!("arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role}/{session}")
}

/// `arn:aws:iam::<acct>:root` (the account / root principal).
pub fn root() -> String {
    format!("arn:aws:iam::{ACCOUNT_ID}:root")
}

/// `arn:cairn:admin:::server` — resource for server-wide `cairn:*` admin actions.
pub fn server() -> String {
    "arn:cairn:admin:::server".to_string()
}

/// The six components of an ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arn<'a> {
    /// Partition (`aws`, `cairn`).
    pub partition: &'a str,
    /// Service (`s3`, `iam`, `sts`, `admin`).
    pub service: &'a str,
    /// Region (empty for s3/iam).
    pub region: &'a str,
    /// Account id.
    pub account: &'a str,
    /// Resource part.
    pub resource: &'a str,
}

/// Split an ARN into its components. Returns `None` if not 6 colon-delimited parts.
pub fn parse(s: &str) -> Option<Arn<'_>> {
    let mut it = s.splitn(6, ':');
    if it.next()? != "arn" {
        return None;
    }
    Some(Arn {
        partition: it.next()?,
        service: it.next()?,
        region: it.next()?,
        account: it.next()?,
        resource: it.next()?,
    })
}

/// Validate a policy `Resource` value (wildcards allowed). Returns a reason on failure.
pub fn validate_resource_pattern(s: &str) -> Result<(), String> {
    if s == "*" {
        return Ok(());
    }
    let a = parse(s).ok_or_else(|| format!("{s}: not an ARN (expected arn:partition:service:region:account:resource)"))?;
    if a.partition.is_empty() || a.service.is_empty() || a.resource.is_empty() {
        return Err(format!("{s}: empty partition, service or resource"));
    }
    if a.service == "s3" {
        if !(a.region.is_empty() || a.region == "*") || !(a.account.is_empty() || a.account == "*") {
            return Err(format!("{s}: s3 ARNs have empty region and account"));
        }
        let bucket = a.resource.split('/').next().unwrap_or("");
        if bucket.is_empty() {
            return Err(format!("{s}: missing bucket"));
        }
        if !bucket
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '*' | '?' | '$' | '{' | '}' | ':'))
        {
            return Err(format!("{s}: invalid bucket name"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_validate() {
        assert_eq!(parse("arn:aws:s3:::b/k/x").unwrap().resource, "b/k/x");
        assert_eq!(parse("arn:aws:iam::0:user/a:b").unwrap().resource, "user/a:b");
        assert!(parse("arn:aws:s3").is_none());
        for ok in ["*", "arn:aws:s3:::b", "arn:aws:s3:::b/*", "arn:aws:s3:::b/p/*", "arn:aws:s3:::*",
            "arn:aws:s3:::b?x/*", "arn:aws:s3:::home/${aws:username}/*", "arn:aws:iam::000000000000:user/*",
            "arn:cairn:admin:::server"] {
            validate_resource_pattern(ok).unwrap();
        }
        for bad in ["bucket", "arn:aws:s3::", "arn:aws:s3:::", "arn:aws:s3:us-east-1::b",
            "arn:aws:s3::123:b", "arn::s3:::b", "arn:aws:s3:::/k", "arn:aws:s3:::B A/k"] {
            assert!(validate_resource_pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn constructors() {
        assert_eq!(object("b", "a b"), "arn:aws:s3:::b/a b");
        assert_eq!(assumed_role("r", "s"), "arn:aws:sts::000000000000:assumed-role/r/s");
        assert_eq!(root(), "arn:aws:iam::000000000000:root");
    }
}
