use base64::Engine;
use ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::internal::AcmeJsonWebKey;

const BASE64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Mirrors `Acmebot.Acme.AcmeSigner`.
///
/// Only ES256 (NIST P-256 ECDSA) is implemented, matching the scope requested for this
/// port. The upstream C# type additionally supports ES384/ES512/RS256/RS384/RS512; those
/// are intentionally out of scope here (see crate-level docs).
pub struct AcmeSigner {
    signing_key: SigningKey,
}

impl std::fmt::Debug for AcmeSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeSigner")
            .field("algorithm", &Self::ALGORITHM)
            .finish_non_exhaustive()
    }
}

impl AcmeSigner {
    /// The JWS `alg` value for this signer. Only "ES256" is currently supported.
    pub const ALGORITHM: &'static str = "ES256";

    /// Mirrors `AcmeSigner.CreateP256()`: generates a new random P-256 key pair.
    pub fn generate_p256() -> Self {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        Self { signing_key }
    }

    /// Mirrors `AcmeSigner.Create(ECDsa, bool)` for the P-256 case: wraps an existing
    /// signing key instead of generating a new one.
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// The JWS signing algorithm identifier, e.g. `"ES256"`.
    pub fn algorithm(&self) -> &'static str {
        Self::ALGORITHM
    }

    /// Mirrors `AcmeSigner.SignData(ReadOnlySpan<byte>)`.
    ///
    /// Produces a fixed-size 64-byte `r || s` signature (IEEE P1363 / "raw" ECDSA
    /// format), matching `DSASignatureFormat.IeeeP1363FixedFieldConcatenation` used by
    /// the C# implementation. This is the encoding JWS ES256 requires (RFC 7518 §3.4).
    pub fn sign_data(&self, data: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Mirrors `AcmeSigner.ExportJsonWebKey()`.
    pub fn export_json_web_key(&self) -> AcmeJsonWebKey {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = point.x().expect("uncompressed point always has x");
        let y = point.y().expect("uncompressed point always has y");

        AcmeJsonWebKey {
            kty: "EC".to_owned(),
            crv: Some("P-256".to_owned()),
            x: Some(BASE64URL.encode(x)),
            y: Some(BASE64URL.encode(y)),
            n: None,
            e: None,
        }
    }

    /// Mirrors `AcmeSigner.GetThumbprint()`: the RFC 7638 JWK thumbprint, base64url
    /// (no padding) encoded.
    pub fn get_thumbprint(&self) -> String {
        let jwk = self.export_json_web_key();
        let json = jwk.to_thumbprint_json();
        let hash = Sha256::digest(json.as_bytes());

        BASE64URL.encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_p256_exports_expected_ec_jwk() {
        let signer = AcmeSigner::generate_p256();
        let jwk = signer.export_json_web_key();

        assert_eq!(signer.algorithm(), "ES256");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert!(BASE64URL.decode(jwk.x.as_ref().unwrap()).is_ok());
        assert!(BASE64URL.decode(jwk.y.as_ref().unwrap()).is_ok());
        assert!(jwk
            .to_thumbprint_json()
            .starts_with(r#"{"crv":"P-256","kty":"EC""#));
        assert!(!signer.get_thumbprint().is_empty());
    }

    #[test]
    fn thumbprint_is_deterministic_for_the_same_key() {
        let signer = AcmeSigner::generate_p256();
        let thumbprint_a = signer.get_thumbprint();
        let thumbprint_b = signer.get_thumbprint();

        assert_eq!(thumbprint_a, thumbprint_b);
    }

    #[test]
    fn different_keys_produce_different_thumbprints() {
        let signer_a = AcmeSigner::generate_p256();
        let signer_b = AcmeSigner::generate_p256();

        assert_ne!(signer_a.get_thumbprint(), signer_b.get_thumbprint());
    }

    #[test]
    fn sign_data_round_trips_through_verification() {
        use ecdsa::signature::Verifier;

        let signer = AcmeSigner::generate_p256();
        let data = b"protected.payload";
        let signature_bytes = signer.sign_data(data);

        assert_eq!(signature_bytes.len(), 64, "IEEE P1363 r||s is 64 bytes for P-256");

        let signature = Signature::from_slice(&signature_bytes).expect("valid signature bytes");
        let verifying_key = signer.signing_key.verifying_key();

        verifying_key
            .verify(data, &signature)
            .expect("signature should verify against the signer's own public key");
    }
}
