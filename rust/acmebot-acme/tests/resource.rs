//! Mirrors the portable subset of `AcmeClientResourceTests.cs`: GetOrders using the
//! account's `orders` URL, CreateOrder request-overload payload serialization,
//! CreateAuthorization identifier payload, GetAuthorization/GetChallenge post-as-get
//! semantics, DeactivateAuthorization payload, cached profile metadata, and the
//! missing-profile error.
//!
//! The two X509Certificate2-dependent cases
//! (`GetRenewalInfoAsync_CertificateOverload_UsesDerivedIdentifier` and
//! `CreateCertificateIdentifier_CertificateOverload_ReturnsBase64UrlEncodedSegments`)
//! are intentionally skipped, per the crate's deviation notes in `src/lib.rs`: this
//! port does not depend on `X509Certificate2`/ASN.1 parsing to derive an authority-key-
//! identifier/serial-number pair from a certificate. The underlying byte-span overload
//! they both ultimately call (`AcmeClient.CreateCertificateIdentifier(ReadOnlySpan<byte>,
//! ReadOnlySpan<byte>)`) *is* portable and is covered below instead.

mod support;

use std::collections::HashMap;

use acmebot_acme::models::{
    authorization_statuses, challenge_statuses, AcmeAccountResource, AcmeIdentifier,
    AcmeNewOrderRequest,
};
use acmebot_acme::{AcmeAccountHandle, AcmeClient, AcmeError, AcmeSigner};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use support::{account_handle, decode_signed_message_from_request, json_response_with_nonce, DirectoryOptions, NONCE_1, NONCE_2};

async fn mount_new_nonce(server: &MockServer) {
    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", NONCE_1))
        .mount(server)
        .await;
}

#[tokio::test]
async fn get_orders_uses_orders_url_from_account_resource() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(200, support::directory_body(&DirectoryOptions::new(&base)), NONCE_1))
        .mount(&server)
        .await;
    mount_new_nonce(&server).await;

    let orders_url = format!("{base}/acme/account/1/orders");
    Mock::given(method("POST"))
        .and(path("/acme/account/1/orders"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "orders": [format!("{base}/acme/order/1")] }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = AcmeAccountHandle {
        account_url: url::Url::parse(&format!("{base}/acme/account/1")).unwrap(),
        signer: AcmeSigner::generate_p256(),
        account: AcmeAccountResource {
            status: acmebot_acme::models::account_statuses::valid(),
            contact: None,
            terms_of_service_agreed: None,
            external_account_binding: None,
            orders: Some(url::Url::parse(&orders_url).unwrap()),
            additional_data: HashMap::new(),
        },
    };

    let result = client.get_orders(&account, None).await.expect("get orders");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    assert_eq!(post.url.path(), "/acme/account/1/orders");
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload, serde_json::Value::Null);

    assert_eq!(result.resource.orders.len(), 1);
    assert_eq!(result.resource.orders[0].as_str(), format!("{base}/acme/order/1"));
}

#[tokio::test]
async fn create_order_request_overload_serializes_payload() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(200, support::directory_body(&DirectoryOptions::new(&base)), NONCE_1))
        .mount(&server)
        .await;
    mount_new_nonce(&server).await;

    let order_url = format!("{base}/acme/order/2");
    Mock::given(method("POST"))
        .and(path("/acme/new-order"))
        .respond_with(
            json_response_with_nonce(201, json!({ "status": "pending" }), NONCE_2)
                .insert_header("Location", order_url.as_str()),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let mut request = AcmeNewOrderRequest::new(vec![AcmeIdentifier::dns("example.net")]);
    request.profile = Some("mailserver".to_owned());

    let result = client.create_order(&account, request).await.expect("create order");

    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == "/acme/new-order")
        .expect("new-order POST");
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload["identifiers"][0]["value"], json!("example.net"));
    assert_eq!(decoded.payload["profile"], json!("mailserver"));
    assert_eq!(result.location.as_ref().map(|u| u.as_str()), Some(order_url.as_str()));
}

#[tokio::test]
async fn create_authorization_sends_identifier_payload() {
    let server = MockServer::start().await;
    let base = server.uri();
    let new_authorization_url = format!("{base}/acme/new-authz");

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(
            200,
            support::directory_body(&DirectoryOptions {
                new_authorization: Some(new_authorization_url.clone()),
                ..DirectoryOptions::new(&base)
            }),
            NONCE_1,
        ))
        .mount(&server)
        .await;
    mount_new_nonce(&server).await;

    let authorization_url = format!("{base}/acme/authz/1");
    Mock::given(method("POST"))
        .and(path("/acme/new-authz"))
        .respond_with(
            json_response_with_nonce(
                201,
                json!({
                    "identifier": { "type": "dns", "value": "example.org" },
                    "status": "pending",
                    "challenges": [],
                }),
                NONCE_2,
            )
            .insert_header("Location", authorization_url.as_str()),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client
        .create_authorization(
            &account,
            AcmeIdentifier::dns("example.org"),
        )
        .await
        .expect("create authorization");

    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == "/acme/new-authz")
        .expect("new-authz POST");
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload["identifier"]["type"], json!("dns"));
    assert_eq!(decoded.payload["identifier"]["value"], json!("example.org"));
    assert_eq!(result.location.as_ref().map(|u| u.as_str()), Some(authorization_url.as_str()));
}

#[tokio::test]
async fn get_authorization_uses_post_as_get() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(200, support::directory_body(&DirectoryOptions::new(&base)), NONCE_1))
        .mount(&server)
        .await;
    mount_new_nonce(&server).await;

    let authorization_url = format!("{base}/acme/authz/1");
    Mock::given(method("POST"))
        .and(path("/acme/authz/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({
                "identifier": { "type": "dns", "value": "example.org" },
                "status": "valid",
                "challenges": [],
            }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let authorization_url_parsed = url::Url::parse(&authorization_url).unwrap();

    let result = client
        .get_authorization(&account, &authorization_url_parsed)
        .await
        .expect("get authorization");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    assert_eq!(post.url.path(), "/acme/authz/1");
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload, serde_json::Value::Null);
    assert_eq!(result.resource.status, authorization_statuses::valid());
}

#[tokio::test]
async fn deactivate_authorization_sends_deactivated_status() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(200, support::directory_body(&DirectoryOptions::new(&base)), NONCE_1))
        .mount(&server)
        .await;
    mount_new_nonce(&server).await;

    let authorization_url = format!("{base}/acme/authz/2");
    Mock::given(method("POST"))
        .and(path("/acme/authz/2"))
        .respond_with(json_response_with_nonce(
            200,
            json!({
                "identifier": { "type": "dns", "value": "example.org" },
                "status": "deactivated",
                "challenges": [],
            }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let authorization_url_parsed = url::Url::parse(&authorization_url).unwrap();

    let result = client
        .deactivate_authorization(&account, &authorization_url_parsed)
        .await
        .expect("deactivate authorization");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload["status"], json!("deactivated"));
    assert_eq!(result.resource.status, authorization_statuses::deactivated());
}

#[tokio::test]
async fn get_challenge_uses_post_as_get() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(200, support::directory_body(&DirectoryOptions::new(&base)), NONCE_1))
        .mount(&server)
        .await;
    mount_new_nonce(&server).await;

    let challenge_url = format!("{base}/acme/challenge/2");
    Mock::given(method("POST"))
        .and(path("/acme/challenge/2"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "type": "dns-01", "url": challenge_url, "status": "valid" }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let challenge_url_parsed = url::Url::parse(&challenge_url).unwrap();

    let result = client
        .get_challenge(&account, &challenge_url_parsed)
        .await
        .expect("get challenge");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    assert_eq!(post.url.path(), "/acme/challenge/2");
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload, serde_json::Value::Null);
    assert_eq!(result.resource.status, Some(challenge_statuses::valid()));
}

#[tokio::test]
async fn profile_operations_use_cached_directory_metadata() {
    let server = MockServer::start().await;
    let base = server.uri();

    let mut profiles = HashMap::new();
    profiles.insert("tlsserver".to_owned(), "TLS Server".to_owned());

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(
            200,
            support::directory_body(&DirectoryOptions {
                profiles: Some(profiles),
                ..DirectoryOptions::new(&base)
            }),
            NONCE_1,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);

    let advertised_profiles = client.get_advertised_profiles().await.expect("profiles");
    let advertised = client.is_profile_advertised("tlsserver").await.expect("is advertised");
    client.ensure_profile_is_advertised("tlsserver").await.expect("ensure advertised");

    assert_eq!(advertised_profiles.get("tlsserver").map(String::as_str), Some("TLS Server"));
    assert!(advertised);

    let requests = server.received_requests().await.unwrap();
    let get_count = requests.iter().filter(|r| r.method.as_str() == "GET").count();
    assert_eq!(get_count, 1);
}

#[tokio::test]
async fn ensure_profile_is_advertised_throws_for_missing_profile() {
    let server = MockServer::start().await;
    let base = server.uri();

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(
            200,
            support::directory_body(&DirectoryOptions {
                profiles: Some(HashMap::new()),
                ..DirectoryOptions::new(&base)
            }),
            NONCE_1,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);

    let result = client.ensure_profile_is_advertised("missing").await;

    match result {
        Err(AcmeError::InvalidOperation(message)) => {
            assert_eq!(message, "The ACME server does not advertise the 'missing' profile.");
        }
        other => panic!("expected InvalidOperation error, got {other:?}"),
    }
}

#[test]
fn create_certificate_identifier_returns_base64_url_encoded_segments() {
    let authority_key_identifier: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
    let serial_number: &[u8] = &[0x01, 0x23, 0x45, 0x67];

    let identifier = AcmeClient::create_certificate_identifier(authority_key_identifier, serial_number);

    use base64::Engine;
    let expected = format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(authority_key_identifier),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serial_number)
    );
    assert_eq!(identifier, expected);
}
