//! Mirrors `AcmeClientMetadataTests.cs`: `Location`/`Retry-After`/`Link` header
//! propagation onto `AcmeResult` on success, and onto `AcmeError::Protocol` on a
//! problem+json (429 rate-limited) error response.

mod support;

use std::time::Duration;

use acmebot_acme::models::{problem_types, AcmeIdentifier, AcmeNewOrderRequest};
use acmebot_acme::{AcmeClient, AcmeError, AcmeSigner};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use support::{account_handle, json_response_with_nonce, NONCE_1, NONCE_2};

async fn mount_minimal_directory(server: &MockServer) {
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
        .mount(server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", NONCE_1))
        .mount(server)
        .await;
}

#[tokio::test]
async fn create_order_propagates_location_retry_after_and_links() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_minimal_directory(&server).await;

    let order_url = format!("{base}/acme/order/1");
    let alternate_order_url = format!("{base}/acme/order/alternate");

    Mock::given(method("POST"))
        .and(path("/acme/new-order"))
        .respond_with(
            json_response_with_nonce(201, json!({ "status": "pending" }), NONCE_2)
                .insert_header("Location", order_url.as_str())
                .insert_header("Retry-After", "30")
                .insert_header(
                    "Link",
                    format!("<{alternate_order_url}>;rel=\"alternate\";title=\"alternate order\"").as_str(),
                ),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client
        .create_order(
            &account,
            AcmeNewOrderRequest::new(vec![AcmeIdentifier::dns("example.com")]),
        )
        .await
        .expect("create order");

    assert_eq!(result.location.as_ref().map(|u| u.as_str()), Some(order_url.as_str()));
    assert_eq!(result.retry_after, Some(Duration::from_secs(30)));
    assert_eq!(result.links.len(), 1);
    assert_eq!(result.links[0].uri.as_str(), alternate_order_url);
    assert_eq!(result.links[0].relation.as_deref(), Some("alternate"));
    assert_eq!(result.links[0].title.as_deref(), Some("alternate order"));
}

#[tokio::test]
async fn create_order_throws_protocol_exception_when_problem_details_include_retry_after_and_links() {
    let server = MockServer::start().await;
    let base = server.uri();
    mount_minimal_directory(&server).await;

    let documentation_url = format!("{base}/docs/rate-limit");
    let new_order_url = format!("{base}/acme/new-order");

    Mock::given(method("POST"))
        .and(path("/acme/new-order"))
        .respond_with(
            json_response_with_nonce(
                429,
                json!({
                    "type": problem_types::rate_limited().0,
                    "detail": "too many orders",
                    "status": 429,
                }),
                NONCE_2,
            )
            .insert_header("Content-Type", "application/problem+json")
            .insert_header("Retry-After", "120")
            .insert_header("Link", format!("<{documentation_url}>;rel=\"help\";type=\"text/html\"").as_str()),
        )
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);
    let account = account_handle(&base, AcmeSigner::generate_p256());

    let result = client
        .create_order(
            &account,
            AcmeNewOrderRequest::new(vec![AcmeIdentifier::dns("example.com")]),
        )
        .await;

    match result {
        Err(AcmeError::Protocol {
            status_code,
            message,
            request_url,
            problem,
            replay_nonce,
            retry_after,
            links,
        }) => {
            assert_eq!(status_code, 429);
            assert_eq!(request_url.as_ref().map(|u| u.as_str()), Some(new_order_url.as_str()));
            assert_eq!(replay_nonce.as_deref(), Some(NONCE_2));
            assert_eq!(retry_after, Some(Duration::from_secs(120)));
            assert_eq!(message, "too many orders");

            let problem = problem.expect("problem details should be parsed");
            assert_eq!(problem.r#type, Some(problem_types::rate_limited()));
            assert_eq!(problem.status, Some(429));

            assert_eq!(links.len(), 1);
            assert_eq!(links[0].uri.as_str(), documentation_url);
            assert_eq!(links[0].relation.as_deref(), Some("help"));
            assert_eq!(links[0].media_type.as_deref(), Some("text/html"));
        }
        other => panic!("expected Protocol error, got {other:?}"),
    }
}
