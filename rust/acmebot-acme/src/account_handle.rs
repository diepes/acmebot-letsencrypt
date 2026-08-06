use crate::models::AcmeAccountResource;
use crate::signer::AcmeSigner;

/// Mirrors `Acmebot.Acme.AcmeAccountHandle`: an account URL bound to the signer that
/// authenticates as it, plus the last-known server-side account resource.
#[derive(Debug)]
pub struct AcmeAccountHandle {
    pub account_url: url::Url,
    pub signer: AcmeSigner,
    pub account: AcmeAccountResource,
}
