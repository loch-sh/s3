use serde::{Deserialize, Serialize};

use crate::error::S3Error;

/// A bucket policy document (AWS S3 format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketPolicy {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Statement")]
    pub statement: Vec<Statement>,
}

/// A single policy statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "Sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "Effect")]
    pub effect: Effect,
    #[serde(rename = "Principal")]
    pub principal: Principal,
    #[serde(rename = "Action")]
    pub action: ActionSet,
    #[serde(rename = "Resource")]
    pub resource: ResourceSet,
}

/// Allow or Deny.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Effect {
    Allow,
    Deny,
}

/// Principal: "*" for anonymous/public, or {"AWS": "arn:..."} for specific users.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Principal {
    Wildcard(String),
    Specific {
        #[serde(rename = "AWS")]
        aws: StringOrVec,
    },
}

/// A value that can be a single string or a list of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
}

/// Actions can be a single string or a list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionSet {
    Single(String),
    Multiple(Vec<String>),
}

/// Resources can be a single string or a list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceSet {
    Single(String),
    Multiple(Vec<String>),
}

/// The S3 actions we support for policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum S3Action {
    GetObject,
    PutObject,
    DeleteObject,
    ListBucket,
    GetBucketLocation,
}

impl S3Action {
    /// Return the S3 action string (e.g. "s3:GetObject").
    pub fn as_str(&self) -> &'static str {
        match self {
            S3Action::GetObject => "s3:GetObject",
            S3Action::PutObject => "s3:PutObject",
            S3Action::DeleteObject => "s3:DeleteObject",
            S3Action::ListBucket => "s3:ListBucket",
            S3Action::GetBucketLocation => "s3:GetBucketLocation",
        }
    }
}

impl BucketPolicy {
    /// Check if a given action on a given resource is allowed for anonymous access.
    /// Returns true if at least one statement explicitly allows AND no statement denies.
    pub fn is_allowed_for_anonymous(&self, action: S3Action, resource: &str) -> bool {
        let mut allowed = false;

        for statement in &self.statement {
            if !statement.is_principal_wildcard() {
                continue;
            }

            if !statement.matches_action(action) {
                continue;
            }

            if !statement.matches_resource(resource) {
                continue;
            }

            match statement.effect {
                Effect::Deny => return false,
                Effect::Allow => allowed = true,
            }
        }

        allowed
    }

    /// Check if a given action on a given resource is allowed for a specific user ARN.
    /// Matches statements where the principal is "*" or contains the user's ARN.
    pub fn is_allowed_for_user(
        &self,
        user_arn: &str,
        action: S3Action,
        resource: &str,
    ) -> bool {
        let mut allowed = false;

        for statement in &self.statement {
            if !statement.matches_principal(user_arn) {
                continue;
            }

            if !statement.matches_action(action) {
                continue;
            }

            if !statement.matches_resource(resource) {
                continue;
            }

            match statement.effect {
                Effect::Deny => return false,
                Effect::Allow => allowed = true,
            }
        }

        allowed
    }
}

impl Statement {
    fn is_principal_wildcard(&self) -> bool {
        match &self.principal {
            Principal::Wildcard(s) => s == "*",
            Principal::Specific { aws } => {
                let arns = match aws {
                    StringOrVec::Single(s) => vec![s.as_str()],
                    StringOrVec::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
                };
                arns.iter().any(|a| *a == "*")
            }
        }
    }

    fn matches_principal(&self, user_arn: &str) -> bool {
        match &self.principal {
            Principal::Wildcard(s) => s == "*",
            Principal::Specific { aws } => {
                let arns = match aws {
                    StringOrVec::Single(s) => vec![s.as_str()],
                    StringOrVec::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
                };
                arns.iter().any(|a| *a == "*" || *a == user_arn)
            }
        }
    }

    fn matches_action(&self, action: S3Action) -> bool {
        let action_str = action.as_str();
        let actions: Vec<&str> = match &self.action {
            ActionSet::Single(s) => vec![s.as_str()],
            ActionSet::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        };
        actions.iter().any(|a| *a == "s3:*" || *a == action_str)
    }

    fn matches_resource(&self, resource: &str) -> bool {
        let resources: Vec<&str> = match &self.resource {
            ResourceSet::Single(s) => vec![s.as_str()],
            ResourceSet::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        };
        resources.iter().any(|r| resource_matches(r, resource))
    }
}

/// Check if an ARN pattern matches a resource.
/// Supports trailing "*" wildcard.
/// Accepts `arn:aws:s3:::` as an alias for `arn:loch:s3:::` for AWS tool compatibility.
fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern = pattern.replace("arn:aws:s3:::", "arn:loch:s3:::");
    let resource = resource.replace("arn:aws:s3:::", "arn:loch:s3:::");
    if let Some(prefix) = pattern.strip_suffix('*') {
        resource.starts_with(prefix)
    } else {
        pattern == resource
    }
}

/// Parse and validate a bucket policy JSON string.
pub fn parse_policy(json_bytes: &[u8]) -> Result<BucketPolicy, S3Error> {
    let policy: BucketPolicy =
        serde_json::from_slice(json_bytes).map_err(|_| S3Error::MalformedPolicy)?;

    if policy.version != "2012-10-17" && policy.version != "2008-10-17" {
        return Err(S3Error::MalformedPolicy);
    }

    if policy.statement.is_empty() {
        return Err(S3Error::MalformedPolicy);
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_policy() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:loch:s3:::my-bucket/*"
            }]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert_eq!(policy.statement.len(), 1);
        assert_eq!(policy.statement[0].effect, Effect::Allow);
    }

    #[test]
    fn test_parse_invalid_version() {
        let json = r#"{
            "Version": "invalid",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]
        }"#;
        assert!(parse_policy(json.as_bytes()).is_err());
    }

    #[test]
    fn test_parse_empty_statements() {
        let json = r#"{"Version": "2012-10-17", "Statement": []}"#;
        assert!(parse_policy(json.as_bytes()).is_err());
    }

    #[test]
    fn test_anonymous_allow() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:loch:s3:::bucket", "arn:loch:s3:::bucket/*"]
            }]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert!(
            policy.is_allowed_for_anonymous(S3Action::GetObject, "arn:loch:s3:::bucket/file.txt")
        );
        assert!(policy.is_allowed_for_anonymous(S3Action::ListBucket, "arn:loch:s3:::bucket"));
        assert!(
            !policy.is_allowed_for_anonymous(S3Action::PutObject, "arn:loch:s3:::bucket/file.txt")
        );
        assert!(
            !policy
                .is_allowed_for_anonymous(S3Action::DeleteObject, "arn:loch:s3:::bucket/file.txt")
        );
    }

    #[test]
    fn test_explicit_deny_overrides_allow() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "arn:loch:s3:::bucket/*"},
                {"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteObject", "Resource": "arn:loch:s3:::bucket/*"}
            ]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert!(
            policy.is_allowed_for_anonymous(S3Action::GetObject, "arn:loch:s3:::bucket/file.txt")
        );
        assert!(
            !policy
                .is_allowed_for_anonymous(S3Action::DeleteObject, "arn:loch:s3:::bucket/file.txt")
        );
    }

    #[test]
    fn test_wildcard_action() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert!(policy.is_allowed_for_anonymous(S3Action::GetObject, "arn:loch:s3:::anything/key"));
        assert!(policy.is_allowed_for_anonymous(S3Action::PutObject, "arn:loch:s3:::anything/key"));
    }

    #[test]
    fn test_resource_prefix_match() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:loch:s3:::bucket/public/*"
            }]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert!(
            policy.is_allowed_for_anonymous(
                S3Action::GetObject,
                "arn:loch:s3:::bucket/public/file.txt"
            )
        );
        assert!(
            !policy.is_allowed_for_anonymous(
                S3Action::GetObject,
                "arn:loch:s3:::bucket/private/file.txt"
            )
        );
    }

    #[test]
    fn test_user_principal_allow() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:loch:iam:::user/alice"},
                "Action": "s3:GetObject",
                "Resource": "arn:loch:s3:::bucket/*"
            }]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert!(policy.is_allowed_for_user(
            "arn:loch:iam:::user/alice",
            S3Action::GetObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
        assert!(!policy.is_allowed_for_user(
            "arn:loch:iam:::user/bob",
            S3Action::GetObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
        // Anonymous should not match specific principal
        assert!(!policy.is_allowed_for_anonymous(
            S3Action::GetObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
    }

    #[test]
    fn test_user_principal_multiple() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:loch:iam:::user/alice", "arn:loch:iam:::user/bob"]},
                "Action": "s3:GetObject",
                "Resource": "arn:loch:s3:::bucket/*"
            }]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert!(policy.is_allowed_for_user(
            "arn:loch:iam:::user/alice",
            S3Action::GetObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
        assert!(policy.is_allowed_for_user(
            "arn:loch:iam:::user/bob",
            S3Action::GetObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
        assert!(!policy.is_allowed_for_user(
            "arn:loch:iam:::user/charlie",
            S3Action::GetObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
    }

    #[test]
    fn test_user_deny_overrides() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:loch:iam:::user/alice"}, "Action": "s3:*", "Resource": "arn:loch:s3:::bucket/*"},
                {"Effect": "Deny", "Principal": {"AWS": "arn:loch:iam:::user/alice"}, "Action": "s3:DeleteObject", "Resource": "arn:loch:s3:::bucket/*"}
            ]
        }"#;
        let policy = parse_policy(json.as_bytes()).unwrap();
        assert!(policy.is_allowed_for_user(
            "arn:loch:iam:::user/alice",
            S3Action::GetObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
        assert!(!policy.is_allowed_for_user(
            "arn:loch:iam:::user/alice",
            S3Action::DeleteObject,
            "arn:loch:s3:::bucket/file.txt"
        ));
    }
}
