//! Implements the `issue` subcommand: obtain a certificate for one or more DNS
//! identifiers via the ACME dns-01 challenge, using an operator-supplied DNS hook
//! script (or manual/interactive mode if no hook is configured).

use std::time::Duration;

use acmebot_acme::challenges::AcmeChallengeInstructions;
use acmebot_acme::models::{
    authorization_statuses, challenge_types, order_statuses, AcmeIdentifier,
    AcmeNewAccountRequest, AcmeNewOrderRequest,
};
use acmebot_acme::{AcmeClient, AcmeSigner};
use clap::Args;
use url::Url;

use crate::dns_hook;

#[derive(Args)]
pub struct IssueArgs {
    /// The ACME server's directory URL (e.g. Let's Encrypt production/staging, or a
    /// local Pebble instance).
    #[arg(long)]
    directory_url: Url,

    /// A DNS identifier (SAN) to include on the certificate. Repeat for multiple SANs.
    #[arg(long = "domain", required = true)]
    domains: Vec<String>,

    /// Contact email address for the ACME account (e.g. "admin@example.com").
    #[arg(long)]
    contact: Option<String>,

    /// Shell command (run via `sh -c`) that publishes the dns-01 TXT record. Receives
    /// ACME_TXT_DOMAIN and ACME_TXT_VALUE in its environment. If omitted, the operator
    /// is prompted to set the record manually.
    #[arg(long)]
    dns_txt_set_command: Option<String>,

    /// Shell command (run via `sh -c`) that removes the dns-01 TXT record. Same
    /// environment as `--dns-txt-set-command`. If omitted, a manual removal notice is
    /// printed.
    #[arg(long)]
    dns_txt_clear_command: Option<String>,

    /// Path to write the issued PEM certificate chain to.
    #[arg(long)]
    out_cert: std::path::PathBuf,

    /// Path to write the PEM-encoded private key to.
    #[arg(long)]
    out_key: std::path::PathBuf,
}

pub async fn run(args: IssueArgs) -> Result<(), String> {
    if args.domains.is_empty() {
        return Err("at least one --domain is required".to_owned());
    }

    let client = AcmeClient::new(args.directory_url.clone(), None);

    // Only ES256 (P-256 ECDSA) ACME account keys are supported for now, matching the
    // documented scope of `acmebot_acme::AcmeSigner`.
    let signer = AcmeSigner::generate_p256();

    let contact = args
        .contact
        .as_ref()
        .map(|email| format!("mailto:{email}"))
        .into_iter()
        .collect::<Vec<_>>();

    let account = client
        .create_account(
            signer,
            AcmeNewAccountRequest {
                contact,
                terms_of_service_agreed: Some(true),
                only_return_existing: None,
            },
            None,
        )
        .await
        .map_err(|e| format!("failed to create/find ACME account: {e}"))?;

    println!("Account: {}", account.account_url);

    let identifiers = args
        .domains
        .iter()
        .map(|d| AcmeIdentifier::dns(d.clone()))
        .collect::<Vec<_>>();

    let order_result = client
        .create_order(&account, AcmeNewOrderRequest::new(identifiers))
        .await
        .map_err(|e| format!("failed to create order: {e}"))?;
    let mut order = order_result.resource;
    let order_url = order_result
        .location
        .ok_or_else(|| "the ACME server did not return an order URL".to_owned())?;

    for authorization_url in order.authorizations.clone() {
        let authorization = client
            .get_authorization(&account, &authorization_url)
            .await
            .map_err(|e| format!("failed to fetch authorization: {e}"))?
            .resource;

        // Already valid (e.g. re-using a cached authorization) — nothing to do.
        if authorization.status == authorization_statuses::valid() {
            continue;
        }

        let challenge = authorization
            .challenges
            .iter()
            .find(|c| c.r#type == challenge_types::dns01())
            .ok_or_else(|| format!("no dns-01 challenge offered for {}", authorization.identifier.value))?
            .clone();

        let instruction = AcmeChallengeInstructions::create_dns01(&account, &authorization, &challenge)
            .map_err(|e| format!("failed to build dns-01 challenge instruction: {e}"))?;

        dns_hook::set_txt_record(
            args.dns_txt_set_command.as_deref(),
            &instruction.record_name,
            &instruction.record_value,
        )?;

        let poll_result = async {
            client
                .answer_challenge(&account, &challenge.url)
                .await
                .map_err(|e| format!("failed to answer dns-01 challenge: {e}"))?;

            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let polled = client
                    .get_authorization(&account, &authorization_url)
                    .await
                    .map_err(|e| format!("failed to poll authorization: {e}"))?
                    .resource;

                if polled.status == authorization_statuses::pending() {
                    continue;
                }

                if polled.status != authorization_statuses::valid() {
                    return Err(format!(
                        "authorization for {} ended in status '{}'",
                        authorization.identifier.value, polled.status.0
                    ));
                }

                return Ok(());
            }
        }
        .await;

        dns_hook::clear_txt_record(
            args.dns_txt_clear_command.as_deref(),
            &instruction.record_name,
            &instruction.record_value,
        )?;

        poll_result?;
        println!("Authorization valid for {}", authorization.identifier.value);
    }

    let (csr_der, key_pair) = create_csr(&args.domains)?;
    let finalize_url = order
        .finalize
        .clone()
        .ok_or_else(|| "order has no finalize URL".to_owned())?;
    order = client
        .finalize_order(&account, &finalize_url, &csr_der)
        .await
        .map_err(|e| format!("failed to finalize order: {e}"))?
        .resource;

    while order.status == order_statuses::processing() {
        tokio::time::sleep(Duration::from_secs(2)).await;
        order = client
            .get_order(&account, &order_url)
            .await
            .map_err(|e| format!("failed to poll order: {e}"))?
            .resource;
    }

    if order.status != order_statuses::valid() {
        return Err(format!(
            "order ended in status '{}' without a certificate",
            order.status.0
        ));
    }

    let certificate_url = order
        .certificate
        .clone()
        .ok_or_else(|| "order is valid but has no certificate URL".to_owned())?;
    let chain = client
        .download_certificate(&account, &certificate_url)
        .await
        .map_err(|e| format!("failed to download certificate: {e}"))?;

    std::fs::write(&args.out_cert, &chain.pem_chain)
        .map_err(|e| format!("failed to write certificate to {}: {e}", args.out_cert.display()))?;
    std::fs::write(&args.out_key, key_pair.serialize_pem())
        .map_err(|e| format!("failed to write private key to {}: {e}", args.out_key.display()))?;

    println!(
        "Success: issued {} certificate(s) in chain for [{}]",
        chain.certificates_der.len(),
        args.domains.join(", ")
    );
    println!("Order URL: {order_url}");
    println!("Certificate written to: {}", args.out_cert.display());
    println!("Private key written to: {}", args.out_key.display());

    Ok(())
}

/// Generates a fresh EC (P-256) key pair and a DER-encoded CSR for the given domains,
/// mirroring the approach in `acmebot-acme`'s `pebble_issue` example.
fn create_csr(domains: &[String]) -> Result<(Vec<u8>, rcgen::KeyPair), String> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("failed to generate certificate key pair: {e}"))?;
    let params = rcgen::CertificateParams::new(domains.to_vec())
        .map_err(|e| format!("failed to build certificate parameters: {e}"))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("failed to serialize CSR: {e}"))?;
    Ok((csr.der().to_vec(), key_pair))
}
