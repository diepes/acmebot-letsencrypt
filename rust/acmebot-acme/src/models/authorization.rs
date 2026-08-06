use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

use super::identifier::AcmeIdentifier;
use super::problem::AcmeProblemDetails;

/// Mirrors `Acmebot.Acme.Models.AcmeAuthorizationStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcmeAuthorizationStatus(pub String);

impl AcmeAuthorizationStatus {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub mod authorization_statuses {
    use super::AcmeAuthorizationStatus;

    macro_rules! status {
        ($fn_name:ident, $value:literal) => {
            pub fn $fn_name() -> AcmeAuthorizationStatus {
                AcmeAuthorizationStatus($value.to_owned())
            }
        };
    }

    status!(pending, "pending");
    status!(valid, "valid");
    status!(invalid, "invalid");
    status!(deactivated, "deactivated");
    status!(expired, "expired");
    status!(revoked, "revoked");
}

/// Mirrors `Acmebot.Acme.Models.AcmeChallengeType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcmeChallengeType(pub String);

impl AcmeChallengeType {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub mod challenge_types {
    use super::AcmeChallengeType;

    pub fn http01() -> AcmeChallengeType {
        AcmeChallengeType("http-01".to_owned())
    }
    pub fn dns01() -> AcmeChallengeType {
        AcmeChallengeType("dns-01".to_owned())
    }
}

/// Mirrors `Acmebot.Acme.Models.AcmeChallengeStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcmeChallengeStatus(pub String);

impl AcmeChallengeStatus {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub mod challenge_statuses {
    use super::AcmeChallengeStatus;

    macro_rules! status {
        ($fn_name:ident, $value:literal) => {
            pub fn $fn_name() -> AcmeChallengeStatus {
                AcmeChallengeStatus($value.to_owned())
            }
        };
    }

    status!(pending, "pending");
    status!(processing, "processing");
    status!(valid, "valid");
    status!(invalid, "invalid");
}

/// Mirrors `Acmebot.Acme.Models.AcmeChallengeResource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChallengeResource {
    #[serde(rename = "type")]
    pub r#type: AcmeChallengeType,
    pub url: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AcmeChallengeStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AcmeProblemDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeAuthorizationResource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAuthorizationResource {
    pub identifier: AcmeIdentifier,
    pub status: AcmeAuthorizationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub challenges: Vec<AcmeChallengeResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<bool>,
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeNewAuthorizationRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeNewAuthorizationRequest {
    pub identifier: AcmeIdentifier,
}
