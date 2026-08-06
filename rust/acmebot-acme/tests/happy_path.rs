//! Integration test mirroring the full happy-path ACME flow exercised by the C#
//! `AcmeClientTests` (against a mock ACME server): directory discovery -> account
//! creation -> order creation -> authorization fetch -> dns-01 challenge response ->
//! poll until valid -> finalize with a CSR -> poll order until valid -> download the
//! PEM certificate chain.

use std::sync::atomic::{AtomicUsize, Ordering};

use acmebot_acme::models::{
    account_statuses, authorization_statuses, challenge_statuses, challenge_types,
    order_statuses, AcmeIdentifier, AcmeNewAccountRequest,
};
use acmebot_acme::{AcmeChallengeInstructions, AcmeClient, AcmeSigner};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const REPLAY_NONCE: &str = "AAECAwQFBgcICQ";

/// Returns a `ResponseTemplate` builder pre-populated with the JOSE `Replay-Nonce`
/// header every ACME response carries.
fn json_response(status: u16, body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .set_body_json(body)
        .insert_header("Replay-Nonce", REPLAY_NONCE)
}

/// Mirrors the authorization polling loop: the first `GET_AUTHZ_PENDING_RESPONSES`
/// requests report `pending`, then the authorization flips to `valid` -- simulating a
/// CA that needs a couple of polls before the dns-01 challenge validates.
struct AuthorizationPoller {
    identifier: &'static str,
    token: &'static str,
    challenge_url: String,
    call_count: AtomicUsize,
}

impl Respond for AuthorizationPoller {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let call = self.call_count.fetch_add(1, Ordering::SeqCst);
        let status = if call < 1 { "pending" } else { "valid" };

        json_response(
            200,
            json!({
                "identifier": { "type": "dns", "value": self.identifier },
                "status": status,
                "challenges": [{
                    "type": "dns-01",
                    "url": self.challenge_url,
                    "status": if status == "valid" { "valid" } else { "pending" },
                    "token": self.token,
                }],
            }),
        )
    }
}

/// Mirrors polling the order resource: `processing` once, then `valid` with a
/// certificate URL once finalize has been called.
struct OrderPoller {
    identifiers: serde_json::Value,
    finalize_url: String,
    certificate_url: String,
    call_count: AtomicUsize,
}

impl Respond for OrderPoller {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let call = self.call_count.fetch_add(1, Ordering::SeqCst);
        let status = if call < 1 { "processing" } else { "valid" };

        let mut body = json!({
            "status": status,
            "identifiers": self.identifiers,
            "finalize": self.finalize_url,
        });

        if status == "valid" {
            body["certificate"] = json!(self.certificate_url);
        }

        json_response(200, body)
    }
}

#[tokio::test]
async fn full_happy_path_dns01_order_flow() {
    let server = MockServer::start().await;
    let base = server.uri();

    let new_nonce_url = format!("{base}/acme/new-nonce");
    let new_account_url = format!("{base}/acme/new-account");
    let new_order_url = format!("{base}/acme/new-order");
    let account_url = format!("{base}/acme/account/1");
    let order_url = format!("{base}/acme/order/1");
    let authz_url = format!("{base}/acme/authz/1");
    let challenge_url = format!("{base}/acme/challenge/1");
    let finalize_url = format!("{base}/acme/finalize/1");
    let certificate_url = format!("{base}/acme/certificate/1");

    // 1. Directory discovery.
    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(json_response(
            200,
            json!({
                "newNonce": new_nonce_url,
                "newAccount": new_account_url,
                "newOrder": new_order_url,
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    // 2. Nonce bootstrap (HEAD /new-nonce).
    Mock::given(method("HEAD"))
        .and(path("/acme/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", REPLAY_NONCE))
        .mount(&server)
        .await;

    // 3. Account creation.
    Mock::given(method("POST"))
        .and(path("/acme/new-account"))
        .and(header("content-type", "application/jose+json"))
        .respond_with(
            json_response(201, json!({ "status": "valid" }))
                .insert_header("Location", account_url.as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;

    // 4. Order creation.
    Mock::given(method("POST"))
        .and(path("/acme/new-order"))
        .respond_with(
            json_response(
                201,
                json!({
                    "status": "pending",
                    "identifiers": [{ "type": "dns", "value": "example.com" }],
                    "authorizations": [authz_url],
                    "finalize": finalize_url,
                }),
            )
            .insert_header("Location", order_url.as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;

    // 5. Authorization polling: pending, then valid.
    Mock::given(method("POST"))
        .and(path("/acme/authz/1"))
        .respond_with(AuthorizationPoller {
            identifier: "example.com",
            token: "dGVzdC10b2tlbg",
            challenge_url: challenge_url.clone(),
            call_count: AtomicUsize::new(0),
        })
        .mount(&server)
        .await;

    // 6. Answering the dns-01 challenge.
    Mock::given(method("POST"))
        .and(path("/acme/challenge/1"))
        .respond_with(json_response(
            200,
            json!({
                "type": "dns-01",
                "url": challenge_url,
                "status": "processing",
                "token": "dGVzdC10b2tlbg",
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    // 7. Finalize with the CSR.
    Mock::given(method("POST"))
        .and(path("/acme/finalize/1"))
        .respond_with(json_response(
            200,
            json!({
                "status": "processing",
                "identifiers": [{ "type": "dns", "value": "example.com" }],
                "finalize": finalize_url,
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    // 8. Order polling: processing, then valid with a certificate URL.
    Mock::given(method("POST"))
        .and(path("/acme/order/1"))
        .respond_with(OrderPoller {
            identifiers: json!([{ "type": "dns", "value": "example.com" }]),
            finalize_url: finalize_url.clone(),
            certificate_url: certificate_url.clone(),
            call_count: AtomicUsize::new(0),
        })
        .mount(&server)
        .await;

    // 9. Certificate chain download.
    let pem_chain = "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n";
    Mock::given(method("POST"))
        .and(path("/acme/certificate/1"))
        .and(header("accept", "application/pem-certificate-chain"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(pem_chain, "application/pem-certificate-chain")
                .insert_header("Replay-Nonce", REPLAY_NONCE),
        )
        .expect(1)
        .mount(&server)
        .await;

    let directory_url = url::Url::parse(&format!("{base}/directory")).unwrap();
    let client = AcmeClient::new(directory_url, None);

    // Directory discovery.
    let directory = client.get_directory().await.expect("directory");
    assert_eq!(directory.new_account.as_str(), format!("{new_account_url}"));

    // Create/find account.
    let signer = AcmeSigner::generate_p256();
    let account = client
        .create_account(
            signer,
            AcmeNewAccountRequest {
                terms_of_service_agreed: Some(true),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("create account");
    assert_eq!(account.account.status, account_statuses::valid());
    assert_eq!(account.account_url.as_str(), account_url);

    // Create an order for a single DNS identifier.
    let order_result = client
        .create_order_for_identifiers(&account, vec![AcmeIdentifier::dns("example.com")])
        .await
        .expect("create order");
    let order_location = order_result.location.clone().expect("order location");
    assert_eq!(order_location.as_str(), order_url);
    assert_eq!(order_result.resource.status, order_statuses::pending());
    let authorization_url = order_result.resource.authorizations[0].clone();
    let finalize = order_result.resource.finalize.clone().expect("finalize url");

    // Fetch the authorization; the first poll reports pending.
    let authz_result = client
        .get_authorization(&account, &authorization_url)
        .await
        .expect("get authorization (pending)");
    assert_eq!(authz_result.resource.status, authorization_statuses::pending());

    let dns01_challenge = authz_result
        .resource
        .challenges
        .iter()
        .find(|c| c.r#type == challenge_types::dns01())
        .expect("dns-01 challenge")
        .clone();

    // Build the dns-01 key authorization / TXT record instructions.
    let dns01_instruction =
        AcmeChallengeInstructions::create_dns01(&account, &authz_result.resource, &dns01_challenge)
            .expect("dns01 instruction");
    assert_eq!(dns01_instruction.record_name, "_acme-challenge.example.com.");
    assert!(!dns01_instruction.record_value.is_empty());

    // Answer the challenge.
    let answered = client
        .answer_challenge(&account, &dns01_challenge.url)
        .await
        .expect("answer challenge");
    assert_eq!(answered.resource.status, Some(challenge_statuses::processing()));

    // Poll the authorization again; this time it's valid.
    let authz_result = client
        .get_authorization(&account, &authorization_url)
        .await
        .expect("get authorization (valid)");
    assert_eq!(authz_result.resource.status, authorization_statuses::valid());

    // Finalize the order with a (fake, for test purposes) DER-encoded CSR.
    let fake_csr_der = vec![0x30, 0x03, 0x02, 0x01, 0x00];
    let finalize_result = client
        .finalize_order(&account, &finalize, &fake_csr_der)
        .await
        .expect("finalize order");
    assert_eq!(finalize_result.resource.status, order_statuses::processing());

    // Poll the order: first report is still processing...
    let order_result = client
        .get_order(&account, &order_location)
        .await
        .expect("get order (processing)");
    assert_eq!(order_result.resource.status, order_statuses::processing());

    // ...and the next poll reports valid with a certificate URL.
    let order_result = client
        .get_order(&account, &order_location)
        .await
        .expect("get order (valid)");
    assert_eq!(order_result.resource.status, order_statuses::valid());
    let certificate = order_result.resource.certificate.clone().expect("certificate url");

    // Download the PEM certificate chain.
    let chain = client
        .download_certificate(&account, &certificate)
        .await
        .expect("download certificate");
    assert_eq!(chain.pem_chain, pem_chain);
    assert_eq!(chain.certificates_der.len(), 1);
}
