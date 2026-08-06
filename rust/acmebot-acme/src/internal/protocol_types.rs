use serde::{Deserialize, Serialize};
use url::Url;

/// Mirrors `Acmebot.Acme.Internal.AcmeJsonWebKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeJsonWebKey {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl AcmeJsonWebKey {
    /// Mirrors `AcmeJsonWebKey.ToThumbprintJson()`: RFC 7638 requires JWK members in
    /// lexicographic order with no whitespace.
    pub fn to_thumbprint_json(&self) -> String {
        match self.kty.as_str() {
            "EC" => format!(
                r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                self.crv.as_deref().unwrap_or_default(),
                self.x.as_deref().unwrap_or_default(),
                self.y.as_deref().unwrap_or_default(),
            ),
            "RSA" => format!(
                r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                self.e.as_deref().unwrap_or_default(),
                self.n.as_deref().unwrap_or_default(),
            ),
            other => panic!("Unsupported JWK type: {other}"),
        }
    }
}

/// Mirrors `Acmebot.Acme.Internal.AcmeProtectedHeader` (the JWS protected header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeProtectedHeader {
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<AcmeJsonWebKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Mirrors `Acmebot.Acme.Internal.AcmeExternalAccountProtectedHeader`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeExternalAccountProtectedHeader {
    pub alg: String,
    pub kid: String,
    pub url: String,
}

/// Mirrors `Acmebot.Acme.Internal.AcmeAccountStatusUpdateRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccountStatusUpdateRequest {
    pub status: crate::models::AcmeAccountStatus,
}

/// Mirrors `Acmebot.Acme.Internal.AcmeAuthorizationStatusUpdateRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAuthorizationStatusUpdateRequest {
    pub status: crate::models::AcmeAuthorizationStatus,
}

/// Mirrors `Acmebot.Acme.Internal.AcmeKeyChangeRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeKeyChangeRequest {
    pub account: Url,
    #[serde(rename = "oldKey")]
    pub old_key: AcmeJsonWebKey,
}

/// Mirrors `Acmebot.Acme.Internal.AcmeEmptyObject` (an empty JSON payload, `{}`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcmeEmptyObject {}

/// Mirrors `Acmebot.Acme.Internal.JsonObjectAccountRequest`, used only when an external
/// account binding needs to be attached to a `newAccount` payload after the fact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonObjectAccountRequest {
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(
        rename = "termsOfServiceAgreed",
        skip_serializing_if = "Option::is_none"
    )]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(rename = "onlyReturnExisting", skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,
    #[serde(
        rename = "externalAccountBinding",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_account_binding: Option<crate::models::AcmeSignedMessage>,
}
