use serde::{Deserialize, Serialize};

use super::identifier::AcmeIdentifier;

/// Mirrors `Acmebot.Acme.Models.AcmeProblemType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AcmeProblemType(pub String);

impl AcmeProblemType {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! problem_type_const {
    ($fn_name:ident, $value:literal) => {
        pub fn $fn_name() -> AcmeProblemType {
            AcmeProblemType(concat!("urn:ietf:params:acme:error:", $value).to_owned())
        }
    };
}

pub mod problem_types {
    use super::AcmeProblemType;

    problem_type_const!(account_does_not_exist, "accountDoesNotExist");
    problem_type_const!(already_replaced, "alreadyReplaced");
    problem_type_const!(already_revoked, "alreadyRevoked");
    problem_type_const!(bad_certificate_signing_request, "badCSR");
    problem_type_const!(bad_nonce, "badNonce");
    problem_type_const!(bad_public_key, "badPublicKey");
    problem_type_const!(bad_revocation_reason, "badRevocationReason");
    problem_type_const!(bad_signature_algorithm, "badSignatureAlgorithm");
    problem_type_const!(caa, "caa");
    problem_type_const!(compound, "compound");
    problem_type_const!(connection, "connection");
    problem_type_const!(dns, "dns");
    problem_type_const!(external_account_required, "externalAccountRequired");
    problem_type_const!(incorrect_response, "incorrectResponse");
    problem_type_const!(invalid_contact, "invalidContact");
    problem_type_const!(invalid_profile, "invalidProfile");
    problem_type_const!(malformed, "malformed");
    problem_type_const!(order_not_ready, "orderNotReady");
    problem_type_const!(rate_limited, "rateLimited");
    problem_type_const!(rejected_identifier, "rejectedIdentifier");
    problem_type_const!(server_internal, "serverInternal");
    problem_type_const!(tls, "tls");
    problem_type_const!(unauthorized, "unauthorized");
    problem_type_const!(unsupported_contact, "unsupportedContact");
    problem_type_const!(unsupported_identifier, "unsupportedIdentifier");
    problem_type_const!(user_action_required, "userActionRequired");
}

/// Mirrors `Acmebot.Acme.Models.AcmeProblemDetails`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AcmeProblemDetails {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<AcmeProblemType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<AcmeIdentifier>,
    #[serde(default)]
    pub subproblems: Vec<AcmeProblemDetails>,
    #[serde(default)]
    pub algorithms: Vec<String>,
    #[serde(flatten)]
    pub additional_data: std::collections::HashMap<String, serde_json::Value>,
}
