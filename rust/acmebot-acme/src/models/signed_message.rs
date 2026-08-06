use serde::{Deserialize, Serialize};
use url::Url;

/// Mirrors `Acmebot.Acme.Models.AcmeSignedMessage` (a JWS flattened-JSON serialization).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeSignedMessage {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// Mirrors `Acmebot.Acme.Models.AcmeLinkHeader`.
#[derive(Debug, Clone)]
pub struct AcmeLinkHeader {
    pub uri: Url,
    pub relation: Option<String>,
    pub media_type: Option<String>,
    pub title: Option<String>,
}
