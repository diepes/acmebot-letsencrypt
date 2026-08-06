use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Mirrors `Acmebot.Acme.Models.AcmeRenewalWindow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeRenewalWindow {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

/// Mirrors `Acmebot.Acme.Models.AcmeRenewalInfoResource`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeRenewalInfoResource {
    #[serde(rename = "suggestedWindow")]
    pub suggested_window: AcmeRenewalWindow,
    #[serde(rename = "explanationURL", skip_serializing_if = "Option::is_none")]
    pub explanation_url: Option<Url>,
    #[serde(flatten)]
    pub additional_data: HashMap<String, serde_json::Value>,
}
