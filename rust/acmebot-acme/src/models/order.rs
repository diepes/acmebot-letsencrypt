use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

use super::identifier::AcmeIdentifier;
use super::problem::AcmeProblemDetails;

/// Mirrors `Acmebot.Acme.Models.AcmeOrderStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcmeOrderStatus(pub String);

impl AcmeOrderStatus {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub mod order_statuses {
    use super::AcmeOrderStatus;

    macro_rules! status {
        ($fn_name:ident, $value:literal) => {
            pub fn $fn_name() -> AcmeOrderStatus {
                AcmeOrderStatus($value.to_owned())
            }
        };
    }

    status!(pending, "pending");
    status!(ready, "ready");
    status!(processing, "processing");
    status!(valid, "valid");
    status!(invalid, "invalid");
}

/// Mirrors `Acmebot.Acme.Models.AcmeOrderResource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeOrderResource {
    pub status: AcmeOrderStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub identifiers: Vec<AcmeIdentifier>,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AcmeProblemDetails>,
    #[serde(default)]
    pub authorizations: Vec<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalize: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeOrderListResource`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcmeOrderListResource {
    #[serde(default)]
    pub orders: Vec<Url>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeNewOrderRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeNewOrderRequest {
    pub identifiers: Vec<AcmeIdentifier>,
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    pub not_after: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl AcmeNewOrderRequest {
    pub fn new(identifiers: Vec<AcmeIdentifier>) -> Self {
        Self {
            identifiers,
            not_before: None,
            not_after: None,
            replaces: None,
            profile: None,
        }
    }
}

/// Mirrors `Acmebot.Acme.Models.AcmeFinalizeOrderRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeFinalizeOrderRequest {
    pub csr: String,
}

/// Mirrors `Acmebot.Acme.Models.AcmeRevocationRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeRevocationRequest {
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<i32>,
}
