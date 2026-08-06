//! Mirrors `AcmeClientProtocolTests.cs`: configured header propagation (User-Agent /
//! Accept-Language), a missing `Replay-Nonce` header on the new-nonce bootstrap
//! request, a missing `Location` header on account creation, and a PEM response whose
//! blocks have the wrong label.

mod support;

use acmebot_acme::models::AcmeNewAccountRequest;
use acmebot_acme::{AcmeClient, AcmeClientOptions, AcmeError, AcmeSigner};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use support::{account_handle, json_response_with_nonce, NONCE_1, NONCE_2};

#[tokio::test]
async fn get_directory_applies_configured_headers() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(
            200,
            json!({
                "newNonce": format!("{base}/acme/new-nonce"),
                "newAccount": format!("{base}/acme/new-account"),
                "newOrder": format!("{base}/acme/new-order"),
            }),
            NONCE_1,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let options = AcmeClientOptions {
        user_agent: "Acmebot.Acme.Tests/1.0".to_owned(),
        accept_language: Some("ja-JP".to_owned()),
        ..Default::default()
    };
    let client = AcmeClient::new(directory_url, Some(options));

    let _ = client.get_directory().await.expect("directory");

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request.headers.get("user-agent").map(|v| v.to_str().unwrap()),
        Some("Acmebot.Acme.Tests/1.0")
    );
    assert_eq!(
        request.headers.get("accept-language").map(|v| v.to_str().unwrap()),
        Some("ja-JP")
    );
}

#[tokio::test]
async fn get_order_throws_protocol_exception_when_replay_nonce_header_is_missing() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(
            200,
            json!({
                "newNonce": format!("{base}/acme/new-nonce"),
                "newAccount": format!("{base}/acme/new-account"),
                "newOrder": format!("{base}/acme/new-order"),
            }),
            NONCE_1,
        ))
        .mount(&server)
        .await;

    // No Replay-Nonce header on the HEAD response.
    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let order_url = url::Url::parse(&format!("{base}/acme/order/1")).unwrap();

    let result = client.get_order(&account, &order_url).await;

    match result {
        Err(AcmeError::Protocol { status_code, request_url, message, .. }) => {
            assert_eq!(status_code, 200);
            assert_eq!(
                request_url.as_ref().map(|u| u.as_str()),
                Some(format!("{base}/acme/new-nonce").as_str())
            );
            assert_eq!(message, "The ACME server did not provide a Replay-Nonce header.");
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }
}

#[tokio::test]
async fn create_account_throws_protocol_exception_when_location_header_is_missing() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(
            200,
            json!({
                "newNonce": format!("{base}/acme/new-nonce"),
                "newAccount": format!("{base}/acme/new-account"),
                "newOrder": format!("{base}/acme/new-order"),
            }),
            NONCE_1,
        ))
        .mount(&server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", NONCE_1))
        .mount(&server)
        .await;

    // 201 response with no Location header.
    Mock::given(method("POST"))
        .and(path("/acme/new-account"))
        .respond_with(json_response_with_nonce(201, json!({ "status": "valid" }), NONCE_2))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let signer = AcmeSigner::generate_p256();

    let result = client
        .create_account(
            signer,
            AcmeNewAccountRequest {
                contact: vec!["mailto:admin@example.com".to_owned()],
                terms_of_service_agreed: Some(true),
                only_return_existing: None,
            },
            None,
        )
        .await;

    match result {
        Err(AcmeError::Protocol { status_code, request_url, message, .. }) => {
            assert_eq!(status_code, 201);
            assert_eq!(
                request_url.as_ref().map(|u| u.as_str()),
                Some(format!("{base}/acme/new-account").as_str())
            );
            assert_eq!(message, "The ACME server did not return an account URL.");
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }
}

#[tokio::test]
async fn download_certificate_throws_when_pem_contains_unexpected_label() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(
            200,
            json!({
                "newNonce": format!("{base}/acme/new-nonce"),
                "newAccount": format!("{base}/acme/new-account"),
                "newOrder": format!("{base}/acme/new-order"),
            }),
            NONCE_1,
        ))
        .mount(&server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", NONCE_1))
        .mount(&server)
        .await;

    let non_certificate_pem = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----";
    Mock::given(method("POST"))
        .and(path("/acme/certificate/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(non_certificate_pem, "application/pem-certificate-chain")
                .insert_header("Replay-Nonce", NONCE_2),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let certificate_url = url::Url::parse(&format!("{base}/acme/certificate/1")).unwrap();

    let result = client.download_certificate(&account, &certificate_url).await;

    match result {
        Err(AcmeError::InvalidOperation(message)) => {
            assert_eq!(message, "The PEM response contains data other than certificates.");
        }
        other => panic!("expected InvalidOperation error, got {other:?}"),
    }
}
