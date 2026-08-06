use std::time::Duration;

use crate::models::AcmeLinkHeader;

/// Mirrors `Acmebot.Acme.AcmeResult<T>`.
#[derive(Debug, Clone)]
pub struct AcmeResult<T> {
    pub resource: T,
    pub location: Option<url::Url>,
    pub retry_after: Option<Duration>,
    pub links: Vec<AcmeLinkHeader>,
}
