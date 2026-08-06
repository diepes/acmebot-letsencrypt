//! A Rust port of the core ACME v2 protocol client from `Acmebot.Acme` (C#).
//!
//! This crate implements the client-side ACME (RFC 8555) protocol flow:
//! directory discovery, account creation/lookup, order creation, authorization
//! and dns-01/http-01 challenge handling, order finalization with a CSR, and
//! certificate chain download. DNS provider integrations, Key Vault, Durable
//! Functions orchestration, the HTTP API, and the CLI from the original
//! Acmebot project are intentionally out of scope for this crate.
//!
//! Only the ES256 (NIST P-256 ECDSA) JWS algorithm is implemented for
//! [`AcmeSigner`]; the upstream C# `AcmeSigner` additionally supports
//! ES384/ES512/RS256/RS384/RS512.
//!
//! [`AcmeClient::create_certificate_identifier`] only implements the byte-span overload
//! of the C# `AcmeClient.CreateCertificateIdentifier` (deriving an ARI certificate
//! identifier from an already-extracted authority-key-identifier/serial-number pair).
//! The `X509Certificate2`-based overload, which additionally parses a DER certificate's
//! Authority Key Identifier extension via ASN.1, is intentionally not ported — this
//! crate has no X.509/ASN.1 dependency, and callers are expected to supply the raw
//! bytes themselves (e.g. extracted via the `x509-parser`/`rustls` crates in the
//! application layer, if/when needed).

pub mod account_handle;
pub mod certificate_chain;
pub mod challenges;
pub mod client;
pub mod client_options;
pub mod error;
pub mod internal;
pub mod models;
pub mod profile_validation;
pub mod result;
pub mod signer;

pub use account_handle::AcmeAccountHandle;
pub use certificate_chain::AcmeCertificateChain;
pub use challenges::{
    AcmeChallengeInstructions, AcmeDns01ChallengeInstruction, AcmeHttp01ChallengeInstruction,
};
pub use client::AcmeClient;
pub use client_options::AcmeClientOptions;
pub use error::AcmeError;
pub use result::AcmeResult;
pub use signer::AcmeSigner;
