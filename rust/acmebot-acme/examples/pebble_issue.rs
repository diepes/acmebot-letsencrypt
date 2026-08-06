//! Real end-to-end validation of `acmebot-acme` against a locally running Pebble ACME
//! CA (see `.tools/pebble/scripts/start-pebble.sh`), mirroring the equivalent .NET
//! harness at `tools/pebble-parity` so both implementations can be compared against
//! the same CA. See `CONTEXT.md` ("Contract testing against a real ACME server").
//!
//! Prerequisites: Pebble + pebble-challtestsrv running locally
//!   (.tools/pebble/scripts/start-pebble.sh), reachable at:
//!     - https://127.0.0.1:14000/dir (ACME directory)
//!     - http://127.0.0.1:8055     (challtestsrv management API for DNS-01 TXT records)
//!
//! Usage: cargo run --example pebble_issue -- <domain>
//!   e.g. cargo run --example pebble_issue -- rustbot.pebble

use std::time::Duration;

use acmebot_acme::challenges::AcmeChallengeInstructions;
use acmebot_acme::models::{authorization_statuses, challenge_types, order_statuses, AcmeIdentifier, AcmeNewAccountRequest, AcmeNewOrderRequest};
use acmebot_acme::{AcmeClient, AcmeSigner};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = std::env::args().nth(1).unwrap_or_else(|| "rustbot.pebble".to_owned());
    println!("[Rust parity] Issuing certificate for '{domain}' against local Pebble CA");

    // Pebble's TLS certificate (test/certs/localhost) is not trusted by the system
    // store, so trust it explicitly for this example only.
    let http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let mgmt_client = reqwest::Client::new();

    let directory_url = Url::parse("https://127.0.0.1:14000/dir")?;
    let client = AcmeClient::with_http_client(http_client, directory_url, None);
    let signer = AcmeSigner::generate_p256();

    let account = client
        .create_account(
            signer,
            AcmeNewAccountRequest {
                contact: vec!["mailto:admin@example.pebble".to_owned()],
                terms_of_service_agreed: Some(true),
                only_return_existing: None,
            },
            None,
        )
        .await?;
    println!("[Rust parity] Account: {}", account.account_url);

    let order_result = client
        .create_order(
            &account,
            AcmeNewOrderRequest::new(vec![AcmeIdentifier::dns(domain.clone())]),
        )
        .await?;
    let mut order = order_result.resource;
    let order_url = order_result
        .location
        .ok_or("The ACME server did not return an order URL.")?;
    println!("[Rust parity] Order status: {}", order.status.0);

    for authorization_url in order.authorizations.clone() {
        let authorization = client.get_authorization(&account, &authorization_url).await?.resource;
        let challenge = authorization
            .challenges
            .iter()
            .find(|c| c.r#type == challenge_types::dns01())
            .ok_or("No dns-01 challenge offered")?
            .clone();

        let instruction = AcmeChallengeInstructions::create_dns01(&account, &authorization, &challenge)
            .map_err(|e| format!("Failed to build dns-01 instruction: {e}"))?;

        set_txt(&mgmt_client, &domain, &instruction.record_value).await?;
        println!(
            "[Rust parity] Set TXT for {} = {}",
            instruction.record_name, instruction.record_value
        );

        let result = async {
            client.answer_challenge(&account, &challenge.url).await?;

            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let polled = client.get_authorization(&account, &authorization_url).await?.resource;
                if polled.status != authorization_statuses::pending() {
                    if polled.status != authorization_statuses::valid() {
                        return Err(format!(
                            "Authorization for {domain} ended in status '{}'.",
                            polled.status.0
                        )
                        .into());
                    }
                    break;
                }
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;

        clear_txt(&mgmt_client, &domain).await?;
        result?;
        println!("[Rust parity] Authorization valid for {domain}");
    }

    let (csr_der, _key_pair) = create_csr(&domain)?;
    let finalize_url = order.finalize.clone().ok_or("Order has no finalize URL")?;
    order = client.finalize_order(&account, &finalize_url, &csr_der).await?.resource;

    while order.status == order_statuses::processing() {
        tokio::time::sleep(Duration::from_secs(1)).await;
        order = client.get_order(&account, &order_url).await?.resource;
    }

    if order.status != order_statuses::valid() {
        return Err(format!("Order for {domain} ended in status '{}' without a certificate.", order.status.0).into());
    }

    let certificate_url = order.certificate.clone().ok_or("Order is valid but has no certificate URL")?;
    let chain = client.download_certificate(&account, &certificate_url).await?;

    let output_path = format!("{domain}.rust.pem");
    std::fs::write(&output_path, &chain.pem_chain)?;
    println!(
        "[Rust parity] Certificate issued ({} cert(s) in chain), written to {output_path}",
        chain.certificates_der.len()
    );
    println!("[Rust parity] Done.");

    Ok(())
}

async fn set_txt(client: &reqwest::Client, domain: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({ "host": format!("_acme-challenge.{domain}."), "value": value });
    client
        .post("http://127.0.0.1:8055/set-txt")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn clear_txt(client: &reqwest::Client, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::json!({ "host": format!("_acme-challenge.{domain}.") });
    client
        .post("http://127.0.0.1:8055/clear-txt")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

fn create_csr(domain: &str) -> Result<(Vec<u8>, rcgen::KeyPair), Box<dyn std::error::Error>> {
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec![domain.to_owned()])?;
    let csr = params.serialize_request(&key_pair)?;
    Ok((csr.der().to_vec(), key_pair))
}
