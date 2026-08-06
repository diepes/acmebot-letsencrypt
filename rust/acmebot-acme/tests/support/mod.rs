//! Shared wiremock test helpers mirroring `AcmeTestSupport.cs` / `RecordingHandler` /
//! `RecordedRequest` from the C# test suite: default directory URLs, JSON response
//! builders, and JWS-decoding helpers so integration tests can assert on the
//! protected-header/payload contents of signed ACME requests without repeating the
//! base64url-decoding boilerplate.
#![allow(dead_code)]

use std::collections::HashMap;

use acmebot_acme::models::{account_statuses, AcmeAccountResource};
use acmebot_acme::{AcmeAccountHandle, AcmeSigner};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use wiremock::{Request, Respond, ResponseTemplate};

/// The three nonce values used throughout the C# tests: `bm9uY2Ux`/`Uy`/`Uz` decode to
/// the ASCII strings `nonce1`/`nonce2`/`nonce3`, chosen in the original suite so a
/// human can eyeball which nonce is in play. Kept identical here for parity.
pub const NONCE_1: &str = "bm9uY2Ux";
pub const NONCE_2: &str = "bm9uY2Uy";
pub const NONCE_3: &str = "bm9uY2Uz";

/// Builds a `ResponseTemplate` with a JSON body and a `Replay-Nonce` header, mirroring
/// `AcmeTestSupport.CreateJsonResponse`.
pub fn json_response(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(body)
        .insert_header("Replay-Nonce", NONCE_1)
}

/// Builds a `ResponseTemplate` with a JSON body, a specific `Replay-Nonce`, and no
/// other headers.
pub fn json_response_with_nonce(status: u16, body: Value, nonce: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body).insert_header("Replay-Nonce", nonce)
}

/// Mirrors `AcmeTestSupport.CreateDirectoryResponse`: builds a directory JSON body from
/// optional overrides, defaulting `newNonce`/`newAccount`/`newOrder` the same way the C#
/// helper does.
pub struct DirectoryOptions<'a> {
    pub base_url: &'a str,
    pub new_authorization: Option<String>,
    pub revoke_cert: Option<String>,
    pub key_change: Option<String>,
    pub renewal_info: Option<String>,
    pub profiles: Option<HashMap<String, String>>,
}

impl<'a> DirectoryOptions<'a> {
    pub fn new(base_url: &'a str) -> Self {
        Self {
            base_url,
            new_authorization: None,
            revoke_cert: None,
            key_change: None,
            renewal_info: None,
            profiles: None,
        }
    }
}

pub fn directory_body(options: &DirectoryOptions<'_>) -> Value {
    let base = options.base_url;
    let mut body = serde_json::json!({
        "newNonce": format!("{base}/acme/new-nonce"),
        "newAccount": format!("{base}/acme/new-account"),
        "newOrder": format!("{base}/acme/new-order"),
    });

    if let Some(v) = &options.new_authorization {
        body["newAuthz"] = Value::String(v.clone());
    }
    if let Some(v) = &options.revoke_cert {
        body["revokeCert"] = Value::String(v.clone());
    }
    if let Some(v) = &options.key_change {
        body["keyChange"] = Value::String(v.clone());
    }
    if let Some(v) = &options.renewal_info {
        body["renewalInfo"] = Value::String(v.clone());
    }
    if let Some(profiles) = &options.profiles {
        body["meta"] = serde_json::json!({ "profiles": profiles });
    }

    body
}

/// Builds an `AcmeAccountHandle` pointing at `{base}/acme/account/1`, mirroring
/// `AcmeTestSupport.CreateAccountHandle`.
pub fn account_handle(base: &str, signer: AcmeSigner) -> AcmeAccountHandle {
    account_handle_at(&format!("{base}/acme/account/1"), signer)
}

pub fn account_handle_at(account_url: &str, signer: AcmeSigner) -> AcmeAccountHandle {
    AcmeAccountHandle {
        account_url: url::Url::parse(account_url).unwrap(),
        signer,
        account: AcmeAccountResource {
            status: account_statuses::valid(),
            contact: None,
            terms_of_service_agreed: None,
            external_account_binding: None,
            orders: None,
            additional_data: HashMap::new(),
        },
    }
}

/// Mirrors `RecordedRequest.GetSignedMessage/GetPayloadJson/GetProtectedHeaderJson`:
/// parses a request body as an ACME flattened-JWS JSON object and base64url-decodes the
/// `protected` and `payload` members into `serde_json::Value`s.
#[derive(Deserialize)]
struct RawSignedMessage {
    protected: String,
    payload: String,
    #[allow(dead_code)]
    signature: String,
}

pub struct DecodedSignedMessage {
    pub protected: Value,
    pub payload: Value,
}

pub fn decode_signed_message(body: &[u8]) -> DecodedSignedMessage {
    let raw: RawSignedMessage = serde_json::from_slice(body).expect("request body is a signed ACME message");
    let protected_bytes = URL_SAFE_NO_PAD.decode(&raw.protected).expect("protected header is valid base64url");
    let protected: Value = if protected_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&protected_bytes).expect("protected header is valid JSON")
    };

    let payload: Value = if raw.payload.is_empty() {
        Value::Null
    } else {
        let payload_bytes = URL_SAFE_NO_PAD.decode(&raw.payload).expect("payload is valid base64url");
        if payload_bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&payload_bytes).expect("payload is valid JSON")
        }
    };

    DecodedSignedMessage { protected, payload }
}

pub fn decode_signed_message_from_request(request: &Request) -> DecodedSignedMessage {
    decode_signed_message(&request.body)
}

/// A `Respond` implementation that returns a fixed sequence of responses, one per call,
/// and panics if called more times than there are responses configured. This mirrors
/// the FIFO-queue semantics of the C# `RecordingHandler`.
pub struct Sequence {
    responses: std::sync::Mutex<std::collections::VecDeque<ResponseTemplate>>,
}

impl Sequence {
    pub fn new(responses: Vec<ResponseTemplate>) -> Self {
        Self { responses: std::sync::Mutex::new(responses.into()) }
    }
}

impl Respond for Sequence {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("no response was configured for this HTTP request")
    }
}
