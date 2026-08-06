/// Mirrors `Acmebot.Acme.AcmeClientOptions`.
#[derive(Debug, Clone)]
pub struct AcmeClientOptions {
    pub user_agent: String,
    pub accept_language: Option<String>,
    pub bad_nonce_retry_count: u32,
}

impl Default for AcmeClientOptions {
    fn default() -> Self {
        Self {
            user_agent: "acmebot-acme/0.1".to_owned(),
            accept_language: None,
            bad_nonce_retry_count: 1,
        }
    }
}
