use serde::{Deserialize, Serialize};

/// Mirrors `Acmebot.Acme.Models.AcmeIdentifierType`: a lightweight newtype wrapper
/// around a JSON string so unknown identifier types round-trip losslessly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcmeIdentifierType(pub String);

impl AcmeIdentifierType {
    pub fn dns() -> Self {
        Self("dns".to_owned())
    }

    pub fn ip() -> Self {
        Self("ip".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AcmeIdentifierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for AcmeIdentifierType {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Mirrors `Acmebot.Acme.Models.AcmeIdentifier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub r#type: AcmeIdentifierType,
    pub value: String,
}

impl AcmeIdentifier {
    pub fn dns(value: impl Into<String>) -> Self {
        Self {
            r#type: AcmeIdentifierType::dns(),
            value: value.into(),
        }
    }
}
