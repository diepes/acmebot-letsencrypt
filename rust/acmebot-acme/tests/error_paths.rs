//! Mirrors the intent of the C# `AcmeClientErrorTests`: missing-directory-resource
//! error paths, plus bad-nonce retry and problem-details error surfacing which aren't
//! covered by `happy_path.rs`.

use acmebot_acme::models::AcmeIdentifier;
use acmebot_acme::{AcmeClient, AcmeError, AcmeSigner};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REPLAY_NONCE: &str = "AAECAwQFBgcICQ";

async fn start_server_with_minimal_directory() -> (MockServer, String) {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "newNonce": format!("{base}/acme/new-nonce"),
                    "newAccount": format!("{base}/acme/new-account"),
                    "newOrder": format!("{base}/acme/new-order"),
                }))
                .insert_header("Replay-Nonce", REPLAY_NONCE),
        )
        .mount(&server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", REPLAY_NONCE))
        .mount(&server)
        .await;

    (server, base)
}

fn account_handle(base: &str, signer: AcmeSigner) -> acmebot_acme::AcmeAccountHandle {
    use acmebot_acme::models::{account_statuses, AcmeAccountResource};
    use std::collections::HashMap;

    acmebot_acme::AcmeAccountHandle {
        account_url: url::Url::parse(&format!("{base}/acme/account/1")).unwrap(),
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

#[tokio::test]
async fn get_orders_fails_when_account_has_no_orders_url_and_none_is_given() {
    let (_server, base) = start_server_with_minimal_directory().await;
    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client.get_orders(&account, None).await;

    match result {
        Err(AcmeError::InvalidOperation(msg)) => {
            assert_eq!(msg, "The account resource does not include an orders URL.");
        }
        other => panic!("expected InvalidOperation, got {other:?}"),
    }
}

#[tokio::test]
async fn change_account_key_fails_when_directory_lacks_key_change() {
    let (_server, base) = start_server_with_minimal_directory().await;
    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let new_signer = AcmeSigner::generate_p256();

    let result = client.change_account_key(account, new_signer).await;

    match result {
        Err(AcmeError::InvalidOperation(msg)) => {
            assert_eq!(msg, "The ACME server does not advertise the keyChange resource.");
        }
        other => panic!("expected InvalidOperation, got {other:?}"),
    }
}

#[tokio::test]
async fn create_authorization_fails_when_directory_lacks_new_authz() {
    let (_server, base) = start_server_with_minimal_directory().await;
    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client
        .create_authorization(&account, AcmeIdentifier::dns("example.org"))
        .await;

    match result {
        Err(AcmeError::InvalidOperation(msg)) => {
            assert_eq!(msg, "The ACME server does not advertise the newAuthz resource.");
        }
        other => panic!("expected InvalidOperation, got {other:?}"),
    }
}

#[tokio::test]
async fn get_renewal_info_fails_when_directory_lacks_renewal_info() {
    let (_server, base) = start_server_with_minimal_directory().await;
    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);

    let result = client.get_renewal_info("AQID.f4CB").await;

    match result {
        Err(AcmeError::InvalidOperation(msg)) => {
            assert_eq!(msg, "The ACME server does not advertise the renewalInfo resource.");
        }
        other => panic!("expected InvalidOperation, got {other:?}"),
    }
}

#[tokio::test]
async fn revoke_certificate_fails_when_directory_lacks_revoke_cert() {
    let (_server, base) = start_server_with_minimal_directory().await;
    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client.revoke_certificate(&account, &[1, 2, 3, 4], None).await;

    match result {
        Err(AcmeError::InvalidOperation(msg)) => {
            assert_eq!(msg, "The ACME server does not advertise the revokeCert resource.");
        }
        other => panic!("expected InvalidOperation, got {other:?}"),
    }
}

#[tokio::test]
async fn protocol_error_surfaces_problem_details_and_is_bad_nonce() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "newNonce": format!("{base}/acme/new-nonce"),
                    "newAccount": format!("{base}/acme/new-account"),
                    "newOrder": format!("{base}/acme/new-order"),
                }))
                .insert_header("Replay-Nonce", REPLAY_NONCE),
        )
        .mount(&server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", REPLAY_NONCE))
        .mount(&server)
        .await;

    // Every POST to new-account fails with badNonce, exhausting the client's retry budget
    // (default: 1 retry, i.e. 2 attempts total) and surfacing the problem details.
    Mock::given(method("POST"))
        .and(path("/acme/new-account"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({
                    "type": "urn:ietf:params:acme:error:badNonce",
                    "detail": "JWS has an invalid anti-replay nonce",
                }))
                .insert_header("Replay-Nonce", REPLAY_NONCE)
                .insert_header("Content-Type", "application/problem+json"),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let signer = AcmeSigner::generate_p256();

    let result = client
        .create_account(signer, Default::default(), None)
        .await;

    match result {
        Err(AcmeError::Protocol { status_code, problem, .. }) => {
            assert_eq!(status_code, 400);
            let problem = problem.expect("problem details should be parsed");
            assert_eq!(
                problem.detail.as_deref(),
                Some("JWS has an invalid anti-replay nonce")
            );
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }

    // Confirm the client actually retried once on badNonce (2 POSTs to new-account: the
    // original attempt plus the single configured retry).
    let requests = server.received_requests().await.unwrap();
    let new_account_posts = requests
        .iter()
        .filter(|r| r.url.path() == "/acme/new-account")
        .count();
    assert_eq!(new_account_posts, 2);
}
