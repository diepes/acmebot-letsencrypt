use std::time::Duration;

use crate::models::{problem_types, AcmeLinkHeader, AcmeProblemDetails};

/// Mirrors `Acmebot.Acme.AcmeProtocolException`.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// The ACME server returned a non-success HTTP status. Mirrors the primary
    /// (problem-details) constructor path of `AcmeProtocolException`.
    #[error("{message}")]
    Protocol {
        status_code: u16,
        message: String,
        request_url: Option<url::Url>,
        problem: Option<AcmeProblemDetails>,
        replay_nonce: Option<String>,
        retry_after: Option<Duration>,
        links: Vec<AcmeLinkHeader>,
    },

    /// The underlying HTTP transport failed (DNS, TLS, connection reset, etc).
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    /// A response body could not be parsed as the expected JSON shape.
    #[error("Failed to deserialize ACME response as {type_name}: {source}")]
    Json {
        type_name: &'static str,
        #[source]
        source: serde_json::Error,
    },

    /// A precondition or invariant the C# client also enforces (e.g. a missing
    /// `Location` header, or calling an operation the directory doesn't advertise).
    #[error("{0}")]
    InvalidOperation(String),
}

impl AcmeError {
    /// Mirrors `AcmeProtocolException.IsBadNonce`.
    pub fn is_bad_nonce(&self) -> bool {
        matches!(
            self,
            AcmeError::Protocol { problem: Some(p), .. }
                if p.r#type.as_ref() == Some(&problem_types::bad_nonce())
        )
    }

    /// Mirrors `AcmeProtocolException.IsAlreadyReplaced`.
    pub fn is_already_replaced(&self) -> bool {
        matches!(
            self,
            AcmeError::Protocol { problem: Some(p), .. }
                if p.r#type.as_ref() == Some(&problem_types::already_replaced())
        )
    }
}
