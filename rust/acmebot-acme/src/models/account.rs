use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

use super::signed_message::AcmeSignedMessage;

/// Mirrors `Acmebot.Acme.Models.AcmeAccountStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcmeAccountStatus(pub String);

impl AcmeAccountStatus {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub mod account_statuses {
    use super::AcmeAccountStatus;

    pub fn valid() -> AcmeAccountStatus {
        AcmeAccountStatus("valid".to_owned())
    }
    pub fn deactivated() -> AcmeAccountStatus {
        AcmeAccountStatus("deactivated".to_owned())
    }
    pub fn revoked() -> AcmeAccountStatus {
        AcmeAccountStatus("revoked".to_owned())
    }
}

/// Mirrors `Acmebot.Acme.Models.AcmeAccountResource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccountResource {
    pub status: AcmeAccountStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(
        rename = "termsOfServiceAgreed",
        skip_serializing_if = "Option::is_none"
    )]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(
        rename = "externalAccountBinding",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_account_binding: Option<AcmeSignedMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orders: Option<Url>,
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeNewAccountRequest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcmeNewAccountRequest {
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(
        rename = "termsOfServiceAgreed",
        skip_serializing_if = "Option::is_none"
    )]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(rename = "onlyReturnExisting", skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeUpdateAccountRequest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcmeUpdateAccountRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeExternalAccountBindingOptions`.
#[derive(Debug, Clone)]
pub struct AcmeExternalAccountBindingOptions {
    pub key_identifier: String,
    pub hmac_key: Vec<u8>,
    pub algorithm: String,
}

impl AcmeExternalAccountBindingOptions {
    pub fn from_base64url(
        key_identifier: impl Into<String>,
        hmac_key: &str,
        algorithm: impl Into<String>,
    ) -> Result<Self, base64::DecodeError> {
        use base64::Engine;

        let hmac_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(hmac_key)?;

        Ok(Self {
            key_identifier: key_identifier.into(),
            hmac_key,
            algorithm: algorithm.into(),
        })
    }
}
