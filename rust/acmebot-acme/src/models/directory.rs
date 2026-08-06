use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Mirrors `Acmebot.Acme.Models.AcmeDirectoryResource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeDirectoryResource {
    #[serde(rename = "newNonce")]
    pub new_nonce: Url,
    #[serde(rename = "newAccount")]
    pub new_account: Url,
    #[serde(rename = "newOrder")]
    pub new_order: Url,
    #[serde(rename = "newAuthz", skip_serializing_if = "Option::is_none")]
    pub new_authorization: Option<Url>,
    #[serde(rename = "revokeCert", skip_serializing_if = "Option::is_none")]
    pub revoke_certificate: Option<Url>,
    #[serde(rename = "keyChange", skip_serializing_if = "Option::is_none")]
    pub key_change: Option<Url>,
    #[serde(rename = "renewalInfo", skip_serializing_if = "Option::is_none")]
    pub renewal_info: Option<Url>,
    #[serde(rename = "meta", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AcmeDirectoryMetadata>,
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeDirectoryMetadata`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcmeDirectoryMetadata {
    #[serde(rename = "termsOfService", skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<Url>,
    #[serde(rename = "caaIdentities", default)]
    pub caa_identities: Vec<String>,
    #[serde(
        rename = "externalAccountRequired",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_account_required: Option<bool>,
    #[serde(default)]
    pub profiles: HashMap<String, String>,
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}
