use base64::Engine;
use sha2::{Digest, Sha256};

use crate::account_handle::AcmeAccountHandle;
use crate::models::{challenge_types, AcmeAuthorizationResource, AcmeChallengeResource, AcmeChallengeType};

const BASE64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Mirrors `Acmebot.Acme.Challenges.AcmeHttp01ChallengeInstruction`.
#[derive(Debug, Clone)]
pub struct AcmeHttp01ChallengeInstruction {
    pub path: String,
    pub content: String,
}

/// Mirrors `Acmebot.Acme.Challenges.AcmeDns01ChallengeInstruction`.
#[derive(Debug, Clone)]
pub struct AcmeDns01ChallengeInstruction {
    pub record_name: String,
    pub record_value: String,
}

/// Mirrors `Acmebot.Acme.Challenges.AcmeChallengeInstructions`.
pub struct AcmeChallengeInstructions;

impl AcmeChallengeInstructions {
    /// Mirrors `AcmeChallengeInstructions.CreateKeyAuthorization`.
    pub fn create_key_authorization(
        account: &AcmeAccountHandle,
        challenge: &AcmeChallengeResource,
    ) -> Result<String, String> {
        let token = validate_token(challenge)?;
        Ok(format!("{token}.{}", account.signer.get_thumbprint()))
    }

    /// Mirrors `AcmeChallengeInstructions.CreateHttp01`.
    pub fn create_http01(
        account: &AcmeAccountHandle,
        challenge: &AcmeChallengeResource,
    ) -> Result<AcmeHttp01ChallengeInstruction, String> {
        ensure_challenge_type(challenge, &challenge_types::http01())?;
        let token = validate_token(challenge)?;
        let content = Self::create_key_authorization(account, challenge)?;

        Ok(AcmeHttp01ChallengeInstruction {
            path: format!("/.well-known/acme-challenge/{token}"),
            content,
        })
    }

    /// Mirrors `AcmeChallengeInstructions.CreateDns01`.
    pub fn create_dns01(
        account: &AcmeAccountHandle,
        authorization: &AcmeAuthorizationResource,
        challenge: &AcmeChallengeResource,
    ) -> Result<AcmeDns01ChallengeInstruction, String> {
        ensure_challenge_type(challenge, &challenge_types::dns01())?;
        let key_authorization = Self::create_key_authorization(account, challenge)?;
        let digest = Sha256::digest(key_authorization.as_bytes());

        Ok(AcmeDns01ChallengeInstruction {
            record_name: format!(
                "_acme-challenge.{}.",
                authorization.identifier.value.trim_end_matches('.')
            ),
            record_value: BASE64URL.encode(digest),
        })
    }
}

fn ensure_challenge_type(
    challenge: &AcmeChallengeResource,
    expected_type: &AcmeChallengeType,
) -> Result<(), String> {
    if &challenge.r#type != expected_type {
        Err(format!(
            "Expected an ACME {expected_type:?} challenge, got {:?}.",
            challenge.r#type
        ))
    } else {
        Ok(())
    }
}

fn validate_token(challenge: &AcmeChallengeResource) -> Result<&str, String> {
    let token = challenge
        .token
        .as_deref()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| "The ACME challenge token is missing or invalid.".to_owned())?;

    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "The ACME challenge token is missing or invalid.".to_owned())?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AcmeIdentifier, AcmeProblemDetails};
    use crate::signer::AcmeSigner;
    use std::collections::HashMap;
    use url::Url;

    fn account_with_signer() -> AcmeAccountHandle {
        AcmeAccountHandle {
            account_url: Url::parse("https://example.com/acme/acct/1").unwrap(),
            signer: AcmeSigner::generate_p256(),
            account: crate::models::AcmeAccountResource {
                status: crate::models::account_statuses::valid(),
                contact: None,
                terms_of_service_agreed: None,
                external_account_binding: None,
                orders: None,
                additional_data: HashMap::new(),
            },
        }
    }

    fn challenge(r#type: AcmeChallengeType, token: &str) -> AcmeChallengeResource {
        AcmeChallengeResource {
            r#type,
            url: Url::parse("https://example.com/acme/chall/1").unwrap(),
            status: None,
            validated: None,
            error: None::<AcmeProblemDetails>,
            token: Some(token.to_owned()),
            additional_data: HashMap::new(),
        }
    }

    #[test]
    fn create_key_authorization_combines_token_and_thumbprint() {
        let account = account_with_signer();
        let challenge = challenge(challenge_types::http01(), "YWJjMTIz");

        let key_auth = AcmeChallengeInstructions::create_key_authorization(&account, &challenge)
            .expect("valid challenge");

        assert_eq!(
            key_auth,
            format!("YWJjMTIz.{}", account.signer.get_thumbprint())
        );
    }

    #[test]
    fn create_http01_builds_well_known_path() {
        let account = account_with_signer();
        let challenge = challenge(challenge_types::http01(), "YWJjMTIz");

        let instruction =
            AcmeChallengeInstructions::create_http01(&account, &challenge).expect("valid");

        assert_eq!(instruction.path, "/.well-known/acme-challenge/YWJjMTIz");
    }

    #[test]
    fn create_dns01_builds_record_name_and_base64url_digest() {
        let account = account_with_signer();
        let challenge = challenge(challenge_types::dns01(), "YWJjMTIz");
        let authorization = AcmeAuthorizationResource {
            identifier: AcmeIdentifier::dns("example.com"),
            status: crate::models::authorization_statuses::pending(),
            expires: None,
            challenges: vec![],
            wildcard: None,
            additional_data: HashMap::new(),
        };

        let instruction =
            AcmeChallengeInstructions::create_dns01(&account, &authorization, &challenge)
                .expect("valid");

        assert_eq!(instruction.record_name, "_acme-challenge.example.com.");
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&instruction.record_value)
            .is_ok());
    }

    #[test]
    fn create_dns01_rejects_wrong_challenge_type() {
        let account = account_with_signer();
        let challenge = challenge(challenge_types::http01(), "YWJjMTIz");
        let authorization = AcmeAuthorizationResource {
            identifier: AcmeIdentifier::dns("example.com"),
            status: crate::models::authorization_statuses::pending(),
            expires: None,
            challenges: vec![],
            wildcard: None,
            additional_data: HashMap::new(),
        };

        let result = AcmeChallengeInstructions::create_dns01(&account, &authorization, &challenge);

        assert!(result.is_err());
    }

    #[test]
    fn create_http01_rejects_invalid_token() {
        // Mirrors AcmeChallengeInstructionsTests.CreateHttp01_ThrowsWhenTokenIsInvalid:
        // "+" is not part of the URL-safe base64 alphabet, so the token fails validation.
        let account = account_with_signer();
        let challenge = challenge(challenge_types::http01(), "not+valid");

        let result = AcmeChallengeInstructions::create_http01(&account, &challenge);

        assert_eq!(
            result.unwrap_err(),
            "The ACME challenge token is missing or invalid."
        );
    }
}
