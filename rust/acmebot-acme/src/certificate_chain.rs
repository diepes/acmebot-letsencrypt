use url::Url;

/// Mirrors `Acmebot.Acme.AcmeCertificateChain`.
///
/// The C# type exposes parsed `X509Certificate2` instances; this port exposes the raw
/// DER bytes of each certificate in the chain instead, since parsing full X.509
/// certificate objects is outside the scope of the core ACME protocol client (callers
/// needing rich X.509 inspection can parse `certificates_der` with a crate such as
/// `x509-parser`).
#[derive(Debug, Clone)]
pub struct AcmeCertificateChain {
    pub pem_chain: String,
    pub certificates_der: Vec<Vec<u8>>,
    pub alternate_certificate_urls: Vec<Url>,
    pub issuer_certificate_urls: Vec<Url>,
}
