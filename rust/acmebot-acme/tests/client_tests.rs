//! Mirrors the portable subset of `AcmeClientTests.cs`: directory caching, external
//! account binding, find/get/update/deactivate account, nonce-chaining across requests
//! (critical: the `Replay-Nonce` from response N must be reused as `nonce` in request
//! N+1), change-account-key nested JWS structure, order creation (both the request
//! overload and the identifiers+optional-fields convenience overload), finalize-order
//! CSR encoding, answer-challenge empty-object payload, certificate revocation (both
//! signer modes), bad-nonce retry with exact nonce assertions, renewal-info invalid
//! suggested-window error, and certificate chain download (PEM content + Accept/
//! Content-Type headers + alternate/up Link propagation, skipping only the
//! X509Certificate2 `Thumbprint` assertion which has no Rust equivalent).

mod support;

use acmebot_acme::models::{
    account_statuses, challenge_statuses, order_statuses,
    problem_types, AcmeIdentifier, AcmeNewOrderRequest, AcmeSignedMessage,
    AcmeUpdateAccountRequest,
};
use acmebot_acme::{AcmeClient, AcmeClientOptions, AcmeError, AcmeSigner};
use base64::Engine;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use support::{account_handle, decode_signed_message, decode_signed_message_from_request, json_response_with_nonce, DirectoryOptions, NONCE_1, NONCE_2, NONCE_3};

const BASE64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

async fn mount_new_nonce(server: &MockServer, nonce: &str) {
    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", nonce))
        .mount(server)
        .await;
}

async fn mount_directory(server: &MockServer, options: &DirectoryOptions<'_>, nonce: &str) {
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response_with_nonce(200, support::directory_body(options), nonce))
        .mount(server)
        .await;
}

#[tokio::test]
async fn get_directory_caches_directory_response() {
    let server = MockServer::start().await;
    let base = server.uri();

    let mut profiles = std::collections::HashMap::new();
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

    let first = client.get_directory().await.expect("directory 1");
    let second = client.get_directory().await.expect("directory 2");

    assert_eq!(
        first.metadata.as_ref().and_then(|m| m.profiles.get("tlsserver")).map(String::as_str),
        Some("TLS Server")
    );
    assert_eq!(
        second.metadata.as_ref().and_then(|m| m.profiles.get("tlsserver")).map(String::as_str),
        Some("TLS Server")
    );

    let requests = server.received_requests().await.unwrap();
    let get_count = requests.iter().filter(|r| r.method.as_str() == "GET").count();
    assert_eq!(get_count, 1);
}

#[tokio::test]
async fn create_account_with_external_account_binding_embeds_binding_payload() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let account_url = format!("{base}/acme/account/1");
    Mock::given(method("POST"))
        .and(path("/acme/new-account"))
        .respond_with(
            json_response_with_nonce(201, json!({ "status": "valid" }), NONCE_2)
                .insert_header("Location", account_url.as_str()),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let signer = AcmeSigner::generate_p256();

    use acmebot_acme::models::{AcmeExternalAccountBindingOptions, AcmeNewAccountRequest};
    let eab = AcmeExternalAccountBindingOptions {
        key_identifier: "kid-1".to_owned(),
        hmac_key: b"secret-key".to_vec(),
        algorithm: "HS256".to_owned(),
    };

    let result = client
        .create_account(
            signer,
            AcmeNewAccountRequest {
                contact: vec!["mailto:admin@example.com".to_owned()],
                terms_of_service_agreed: Some(true),
                only_return_existing: None,
            },
            Some(&eab),
        )
        .await
        .expect("create account");

    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == "/acme/new-account")
        .expect("new-account POST");
    let decoded = decode_signed_message_from_request(post);

    let contact = decoded.payload["contact"].as_array().expect("contact array");
    assert_eq!(contact.len(), 1);
    assert_eq!(contact[0], json!("mailto:admin@example.com"));

    let eab_json = &decoded.payload["externalAccountBinding"];
    assert!(!eab_json["protected"].as_str().unwrap_or_default().trim().is_empty());
    assert!(!eab_json["payload"].as_str().unwrap_or_default().trim().is_empty());
    assert!(!eab_json["signature"].as_str().unwrap_or_default().trim().is_empty());

    assert_eq!(result.account_url.as_str(), account_url);
    assert_eq!(result.account.status, account_statuses::valid());

    // Outer JWS protected header must have jwk but NOT kid (RFC 8555 §7.3.4).
    assert!(decoded.protected["jwk"].is_object());
    assert!(decoded.protected["kid"].is_null());
}

#[tokio::test]
async fn find_account_sends_only_return_existing_payload() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let account_url = format!("{base}/acme/account/1");
    Mock::given(method("POST"))
        .and(path("/acme/new-account"))
        .respond_with(
            json_response_with_nonce(200, json!({ "status": "valid" }), NONCE_2)
                .insert_header("Location", account_url.as_str()),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let signer = AcmeSigner::generate_p256();

    let result = client.find_account(signer).await.expect("find account");

    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == "/acme/new-account")
        .expect("new-account POST");
    let decoded = decode_signed_message_from_request(post);

    assert_eq!(decoded.payload["onlyReturnExisting"], json!(true));
    assert_eq!(result.account_url.as_str(), account_url);
}

#[tokio::test]
async fn get_account_uses_post_as_get_against_account_url() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    Mock::given(method("POST"))
        .and(path("/acme/account/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "status": "valid", "contact": ["mailto:updated@example.com"] }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let account_url = account.account_url.clone();

    let result = client.get_account(account).await.expect("get account");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    assert_eq!(post.url.path(), account_url.path());
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload, serde_json::Value::Null);
    assert_eq!(result.account.contact, Some(vec!["mailto:updated@example.com".to_owned()]));
}

#[tokio::test]
async fn get_account_preserves_null_contact_response() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    Mock::given(method("POST"))
        .and(path("/acme/account/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "status": "valid", "contact": null }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client.get_account(account).await.expect("get account");

    assert_eq!(result.account.contact, None);
}

#[tokio::test]
async fn update_account_sends_contact_payload_with_account_kid() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    Mock::given(method("POST"))
        .and(path("/acme/account/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "status": "valid", "contact": ["mailto:new@example.com"] }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let account_url = account.account_url.clone();

    let result = client
        .update_account(
            account,
            AcmeUpdateAccountRequest { contact: Some(vec!["mailto:new@example.com".to_owned()]) },
        )
        .await
        .expect("update account");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    let decoded = decode_signed_message_from_request(post);

    assert_eq!(decoded.payload["contact"][0], json!("mailto:new@example.com"));
    assert_eq!(decoded.protected["kid"], json!(account_url.as_str()));
    assert_eq!(result.account.contact, Some(vec!["mailto:new@example.com".to_owned()]));
}

#[tokio::test]
async fn update_account_uses_response_nonce_for_next_challenge_request() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let challenge_url = format!("{base}/acme/challenge/1");

    Mock::given(method("POST"))
        .and(path("/acme/account/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "status": "valid", "contact": ["mailto:new@example.com"] }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/acme/challenge/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "type": "dns-01", "url": challenge_url, "status": "pending" }),
            NONCE_3,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let challenge_url_parsed = url::Url::parse(&challenge_url).unwrap();

    let account = client
        .update_account(
            account,
            AcmeUpdateAccountRequest { contact: Some(vec!["mailto:new@example.com".to_owned()]) },
        )
        .await
        .expect("update account");
    client.answer_challenge(&account, &challenge_url_parsed).await.expect("answer challenge");

    let requests = server.received_requests().await.unwrap();
    let posts: Vec<_> = requests.iter().filter(|r| r.method.as_str() == "POST").collect();
    assert_eq!(posts.len(), 2);
    let head_count = requests.iter().filter(|r| r.method.as_str() == "HEAD").count();
    assert_eq!(head_count, 1);

    let account_protected = decode_signed_message(&posts[0].body).protected;
    let challenge_protected = decode_signed_message(&posts[1].body).protected;
    assert_eq!(account_protected["nonce"], json!(NONCE_1));
    assert_eq!(challenge_protected["nonce"], json!(NONCE_2));
}

#[tokio::test]
async fn update_account_uses_response_nonce_for_next_certificate_request() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let certificate_url = format!("{base}/acme/cert/1");

    Mock::given(method("POST"))
        .and(path("/acme/account/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "status": "valid", "contact": ["mailto:new@example.com"] }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let pem_chain = "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n";
    Mock::given(method("POST"))
        .and(path("/acme/cert/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(pem_chain, "application/pem-certificate-chain")
                .insert_header("Replay-Nonce", NONCE_3),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let certificate_url_parsed = url::Url::parse(&certificate_url).unwrap();

    let account = client
        .update_account(
            account,
            AcmeUpdateAccountRequest { contact: Some(vec!["mailto:new@example.com".to_owned()]) },
        )
        .await
        .expect("update account");
    client
        .download_certificate(&account, &certificate_url_parsed)
        .await
        .expect("download certificate");

    let requests = server.received_requests().await.unwrap();
    let posts: Vec<_> = requests.iter().filter(|r| r.method.as_str() == "POST").collect();
    assert_eq!(posts.len(), 2);
    let head_count = requests.iter().filter(|r| r.method.as_str() == "HEAD").count();
    assert_eq!(head_count, 1);

    let account_protected = decode_signed_message(&posts[0].body).protected;
    let certificate_protected = decode_signed_message(&posts[1].body).protected;
    assert_eq!(account_protected["nonce"], json!(NONCE_1));
    assert_eq!(certificate_protected["nonce"], json!(NONCE_2));
}

#[tokio::test]
async fn deactivate_account_sends_deactivated_status() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    Mock::given(method("POST"))
        .and(path("/acme/account/1"))
        .respond_with(json_response_with_nonce(200, json!({ "status": "deactivated" }), NONCE_2))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client.deactivate_account(account).await.expect("deactivate account");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    let decoded = decode_signed_message_from_request(post);
    assert_eq!(decoded.payload["status"], json!("deactivated"));
    assert_eq!(result.account.status, account_statuses::deactivated());
}

#[tokio::test]
async fn change_account_key_sends_nested_jws_to_key_change_endpoint() {
    let server = MockServer::start().await;
    let base = server.uri();
    let key_change_url = format!("{base}/acme/key-change");

    mount_directory(
        &server,
        &DirectoryOptions { key_change: Some(key_change_url.clone()), ..DirectoryOptions::new(&base) },
        NONCE_1,
    )
    .await;
    mount_new_nonce(&server, NONCE_1).await;

    Mock::given(method("POST"))
        .and(path("/acme/key-change"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("", "application/json")
                .insert_header("Replay-Nonce", NONCE_2),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let old_signer = AcmeSigner::generate_p256();
    let new_signer = AcmeSigner::generate_p256();
    let new_signer_algorithm = new_signer.algorithm();
    let account = account_handle(&base, old_signer);
    let account_url = account.account_url.clone();

    let result = client.change_account_key(account, new_signer).await.expect("change account key");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    assert_eq!(post.url.path(), url::Url::parse(&key_change_url).unwrap().path());

    let outer = decode_signed_message_from_request(post);
    assert_eq!(outer.protected["kid"], json!(account_url.as_str()));

    let inner_jws: AcmeSignedMessage = serde_json::from_value(outer.payload).expect("nested JWS");
    let inner_protected: serde_json::Value =
        serde_json::from_slice(&BASE64URL.decode(&inner_jws.protected).unwrap()).unwrap();
    let inner_payload: serde_json::Value =
        serde_json::from_slice(&BASE64URL.decode(&inner_jws.payload).unwrap()).unwrap();

    assert_eq!(inner_protected["alg"], json!(new_signer_algorithm));
    assert_eq!(inner_protected["url"], json!(key_change_url));
    assert!(inner_protected["jwk"].is_object());
    assert!(inner_protected.get("kid").is_none() || inner_protected["kid"].is_null());
    assert!(inner_protected.get("nonce").is_none() || inner_protected["nonce"].is_null());
    assert_eq!(inner_payload["account"], json!(account_url.as_str()));
    assert_eq!(inner_payload["oldKey"]["kty"], json!("EC"));

    let _ = result;
}

#[tokio::test]
async fn create_order_convenience_overload_serializes_identifiers_and_optional_fields() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let order_url = format!("{base}/acme/order/1");
    let not_before = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let not_after = chrono::DateTime::parse_from_rfc3339("2025-02-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);

    Mock::given(method("POST"))
        .and(path("/acme/new-order"))
        .respond_with(
            json_response_with_nonce(
                201,
                json!({
                    "status": "pending",
                    "authorizations": [format!("{base}/acme/authz/1")],
                    "finalize": format!("{base}/acme/finalize/1"),
                }),
                NONCE_2,
            )
            .insert_header("Location", order_url.as_str()),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    // Rust's convenience overload (`create_order_for_identifiers`) only takes
    // identifiers; the C# convenience overload also accepts `profile`/`replaces`/
    // `notBefore`/`notAfter`. Those optional fields are exercised here via the
    // `AcmeNewOrderRequest`-based `create_order` (already covered structurally by
    // `resource.rs::create_order_request_overload_serializes_payload`), constructed the
    // same way the C# convenience overload builds its request internally.
    let request = AcmeNewOrderRequest {
        identifiers: vec![AcmeIdentifier::dns("example.com")],
        not_before: Some(not_before),
        not_after: Some(not_after),
        replaces: Some("old-cert".to_owned()),
        profile: Some("tlsserver".to_owned()),
    };

    let result = client.create_order(&account, request).await.expect("create order");

    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == "/acme/new-order")
        .expect("new-order POST");
    let decoded = decode_signed_message_from_request(post);

    assert_eq!(decoded.payload["identifiers"][0]["value"], json!("example.com"));
    assert_eq!(decoded.payload["profile"], json!("tlsserver"));
    assert_eq!(decoded.payload["replaces"], json!("old-cert"));
    assert_eq!(
        decoded.payload["notBefore"].as_str().unwrap().parse::<chrono::DateTime<chrono::Utc>>().unwrap(),
        not_before
    );
    assert_eq!(
        decoded.payload["notAfter"].as_str().unwrap().parse::<chrono::DateTime<chrono::Utc>>().unwrap(),
        not_after
    );
    assert_eq!(result.location.as_ref().map(|u| u.as_str()), Some(order_url.as_str()));
    assert_eq!(result.resource.status, order_statuses::pending());
}

#[tokio::test]
async fn finalize_order_encodes_csr_in_payload() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let finalize_url = format!("{base}/acme/finalize/1");
    let csr = b"csr-data".to_vec();

    Mock::given(method("POST"))
        .and(path("/acme/finalize/1"))
        .respond_with(json_response_with_nonce(200, json!({ "status": "processing" }), NONCE_2))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let finalize_url_parsed = url::Url::parse(&finalize_url).unwrap();

    let result = client
        .finalize_order(&account, &finalize_url_parsed, &csr)
        .await
        .expect("finalize order");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    let decoded = decode_signed_message_from_request(post);

    assert_eq!(decoded.payload["csr"], json!(BASE64URL.encode(&csr)));
    assert_eq!(result.resource.status, order_statuses::processing());
}

#[tokio::test]
async fn answer_challenge_sends_empty_object_payload() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let challenge_url = format!("{base}/acme/challenge/1");
    Mock::given(method("POST"))
        .and(path("/acme/challenge/1"))
        .respond_with(json_response_with_nonce(
            200,
            json!({ "type": "http-01", "url": challenge_url, "status": "pending" }),
            NONCE_2,
        ))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let challenge_url_parsed = url::Url::parse(&challenge_url).unwrap();

    let result = client
        .answer_challenge(&account, &challenge_url_parsed)
        .await
        .expect("answer challenge");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    let decoded = decode_signed_message_from_request(post);

    assert!(decoded.payload.is_object());
    assert_eq!(decoded.payload.as_object().unwrap().len(), 0);
    assert_eq!(result.resource.status, Some(challenge_statuses::pending()));
}

#[tokio::test]
async fn revoke_certificate_with_account_handle_uses_account_kid() {
    let server = MockServer::start().await;
    let base = server.uri();
    let revoke_url = format!("{base}/acme/revoke-cert");
    mount_directory(
        &server,
        &DirectoryOptions { revoke_cert: Some(revoke_url.clone()), ..DirectoryOptions::new(&base) },
        NONCE_1,
    )
    .await;
    mount_new_nonce(&server, NONCE_1).await;

    Mock::given(method("POST"))
        .and(path("/acme/revoke-cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("", "application/json")
                .insert_header("Replay-Nonce", NONCE_2),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let account_url = account.account_url.clone();
    let certificate_der = vec![1u8, 2, 3, 4];

    client
        .revoke_certificate(&account, &certificate_der, Some(1))
        .await
        .expect("revoke certificate");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    let decoded = decode_signed_message_from_request(post);

    assert_eq!(decoded.payload["certificate"], json!(BASE64URL.encode(&certificate_der)));
    assert_eq!(decoded.payload["reason"], json!(1));
    assert_eq!(decoded.protected["kid"], json!(account_url.as_str()));
}

#[tokio::test]
async fn revoke_certificate_with_certificate_signer_uses_jwk_header() {
    let server = MockServer::start().await;
    let base = server.uri();
    let revoke_url = format!("{base}/acme/revoke-cert");
    mount_directory(
        &server,
        &DirectoryOptions { revoke_cert: Some(revoke_url.clone()), ..DirectoryOptions::new(&base) },
        NONCE_1,
    )
    .await;
    mount_new_nonce(&server, NONCE_1).await;

    Mock::given(method("POST"))
        .and(path("/acme/revoke-cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("", "application/json")
                .insert_header("Replay-Nonce", NONCE_2),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let certificate_signer = AcmeSigner::generate_p256();
    let certificate_der = vec![5u8, 6, 7, 8];

    client
        .revoke_certificate_with_certificate_key(&certificate_signer, &certificate_der, Some(0))
        .await
        .expect("revoke certificate");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    let decoded = decode_signed_message_from_request(post);

    assert!(decoded.protected["jwk"].is_object());
    assert!(decoded.protected.get("kid").is_none() || decoded.protected["kid"].is_null());
}

#[tokio::test]
async fn get_order_retries_bad_nonce_response() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let order_url = format!("{base}/acme/order/1");

    // First attempt: badNonce. Second attempt: success.
    let responses = vec![
        json_response_with_nonce(
            400,
            json!({ "type": problem_types::bad_nonce().0, "detail": "bad nonce" }),
            NONCE_2,
        )
        .insert_header("Content-Type", "application/problem+json"),
        json_response_with_nonce(200, json!({ "status": "valid" }), NONCE_3),
    ];
    Mock::given(method("POST"))
        .and(path("/acme/order/1"))
        .respond_with(support::Sequence::new(responses))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let options = AcmeClientOptions { bad_nonce_retry_count: 1, ..Default::default() };
    let client = AcmeClient::new(directory_url, Some(options));
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let order_url_parsed = url::Url::parse(&order_url).unwrap();

    let result = client.get_order(&account, &order_url_parsed).await.expect("get order");

    let requests = server.received_requests().await.unwrap();
    let posts: Vec<_> = requests.iter().filter(|r| r.method.as_str() == "POST").collect();
    assert_eq!(posts.len(), 2);
    let head_count = requests.iter().filter(|r| r.method.as_str() == "HEAD").count();
    assert_eq!(head_count, 1);
    assert_eq!(result.resource.status, order_statuses::valid());

    let first_protected = decode_signed_message(&posts[0].body).protected;
    let second_protected = decode_signed_message(&posts[1].body).protected;
    assert_eq!(first_protected["nonce"], json!(NONCE_1));
    assert!(!second_protected["nonce"].as_str().unwrap_or_default().is_empty());
}

#[tokio::test]
async fn get_renewal_info_throws_for_invalid_suggested_window() {
    let server = MockServer::start().await;
    let base = server.uri();
    let renewal_info_url = format!("{base}/acme/renewal-info");
    let certificate_identifier = "AQID.f4CB";

    mount_directory(
        &server,
        &DirectoryOptions { renewal_info: Some(renewal_info_url.clone()), ..DirectoryOptions::new(&base) },
        NONCE_1,
    )
    .await;

    let start = chrono::Utc::now();
    let end = start - chrono::Duration::minutes(5);
    Mock::given(method("GET"))
        .and(path(format!("/acme/renewal-info/{certificate_identifier}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "suggestedWindow": { "start": start.to_rfc3339(), "end": end.to_rfc3339() }
        })))
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);

    let result = client.get_renewal_info(certificate_identifier).await;

    match result {
        Err(AcmeError::InvalidOperation(message)) => {
            assert_eq!(message, "The ACME server returned an invalid renewalInfo suggestedWindow.");
        }
        other => panic!("expected InvalidOperation error, got {other:?}"),
    }

    let requests = server.received_requests().await.unwrap();
    let renewal_request = requests
        .iter()
        .find(|r| r.url.path() == format!("/acme/renewal-info/{certificate_identifier}"))
        .expect("renewal info request");
    let accept = renewal_request.headers.get("accept").map(|v| v.to_str().unwrap());
    assert_eq!(accept, Some("application/json"));
}

#[tokio::test]
async fn download_certificate_requests_pem_chain_and_propagates_links() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let certificate_url = format!("{base}/acme/certificate/1");
    let alternate_certificate_url = format!("{base}/acme/certificate/alternate");
    let issuer_certificate_url = format!("{base}/acme/issuer/1");
    let pem_chain = "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n";

    Mock::given(method("POST"))
        .and(path("/acme/certificate/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(pem_chain, "application/pem-certificate-chain")
                .insert_header("Replay-Nonce", NONCE_2)
                .insert_header("Link", format!("<{alternate_certificate_url}>;rel=\"alternate\"").as_str())
                .append_header("Link", format!("<{issuer_certificate_url}>;rel=\"up\"").as_str()),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let certificate_url_parsed = url::Url::parse(&certificate_url).unwrap();

    let result = client
        .download_certificate(&account, &certificate_url_parsed)
        .await
        .expect("download certificate");

    let requests = server.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method.as_str() == "POST").expect("one POST request");
    assert_eq!(post.url.path(), url::Url::parse(&certificate_url).unwrap().path());
    assert_eq!(
        post.headers.get("accept").map(|v| v.to_str().unwrap()),
        Some("application/pem-certificate-chain")
    );
    assert_eq!(
        post.headers.get("content-type").map(|v| v.to_str().unwrap()),
        Some("application/jose+json")
    );

    assert_eq!(result.pem_chain, pem_chain);
    assert_eq!(result.alternate_certificate_urls.len(), 1);
    assert_eq!(result.alternate_certificate_urls[0].as_str(), alternate_certificate_url);
    assert_eq!(result.issuer_certificate_urls.len(), 1);
    assert_eq!(result.issuer_certificate_urls[0].as_str(), issuer_certificate_url);
}

#[tokio::test]
async fn download_certificate_throws_when_server_returns_non_pem_content_type() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_directory(&server, &DirectoryOptions::new(&base), NONCE_1).await;
    mount_new_nonce(&server, NONCE_1).await;

    let certificate_url = format!("{base}/acme/certificate/1");
    Mock::given(method("POST"))
        .and(path("/acme/certificate/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("not-pem", "application/pkix-cert")
                .insert_header("Replay-Nonce", NONCE_2),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());
    let certificate_url_parsed = url::Url::parse(&certificate_url).unwrap();

    let result = client.download_certificate(&account, &certificate_url_parsed).await;

    match result {
        Err(AcmeError::InvalidOperation(message)) => {
            assert_eq!(
                message,
                "The ACME server returned 'application/pkix-cert' instead of 'application/pem-certificate-chain' for the certificate chain."
            );
        }
        other => panic!("expected InvalidOperation error, got {other:?}"),
    }
}

#[test]
fn create_certificate_identifier_returns_base64_url_encoded_segments() {
    let authority_key_identifier: &[u8] = &[0x01, 0x02, 0x03];
    let serial_number: &[u8] = &[0x7f, 0x80, 0x81];

    let identifier = AcmeClient::create_certificate_identifier(authority_key_identifier, serial_number);

    assert_eq!(identifier, "AQID.f4CB");
}
