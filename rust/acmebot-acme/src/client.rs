use std::time::Duration;

use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use sha2::{Sha256, Sha384, Sha512};
use url::Url;

use crate::account_handle::AcmeAccountHandle;
use crate::certificate_chain::AcmeCertificateChain;
use crate::client_options::AcmeClientOptions;
use crate::error::AcmeError;
use crate::internal::protocol_types::{
    AcmeAccountStatusUpdateRequest, AcmeAuthorizationStatusUpdateRequest,
    AcmeExternalAccountProtectedHeader, AcmeJsonWebKey, AcmeKeyChangeRequest,
    AcmeProtectedHeader, JsonObjectAccountRequest,
};
use crate::internal::{parse_link_headers, AcmeEmptyObject, AcmeNonceStore};
use crate::models::{
    account_statuses, authorization_statuses, AcmeAccountResource, AcmeAuthorizationResource,
    AcmeChallengeResource, AcmeDirectoryResource, AcmeExternalAccountBindingOptions,
    AcmeFinalizeOrderRequest, AcmeIdentifier, AcmeLinkHeader, AcmeNewAccountRequest,
    AcmeNewAuthorizationRequest, AcmeNewOrderRequest, AcmeOrderListResource, AcmeOrderResource,
    AcmeProblemDetails, AcmeRenewalInfoResource, AcmeRevocationRequest, AcmeSignedMessage,
    AcmeUpdateAccountRequest,
};
use crate::result::AcmeResult;
use crate::signer::AcmeSigner;

const JOSE_MEDIA_TYPE: &str = "application/jose+json";
const PEM_CERTIFICATE_CHAIN_MEDIA_TYPE: &str = "application/pem-certificate-chain";
const BASE64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Mirrors `Acmebot.Acme.AcmeClient`: an async client for the ACME v2 protocol
/// (RFC 8555), covering directory discovery, account management, order/authorization/
/// challenge lifecycle, and certificate download.
pub struct AcmeClient {
    http_client: reqwest::Client,
    directory_url: Url,
    options: AcmeClientOptions,
    nonce_store: AcmeNonceStore,
    directory: tokio::sync::Mutex<Option<AcmeDirectoryResource>>,
}

struct RawResponse {
    status: StatusCode,
    body: Vec<u8>,
    replay_nonce: Option<String>,
    location: Option<Url>,
    retry_after: Option<Duration>,
    links: Vec<AcmeLinkHeader>,
    content_type: Option<String>,
}

impl AcmeClient {
    /// Mirrors `AcmeClient(Uri, AcmeClientOptions?)`: builds its own `reqwest::Client`.
    pub fn new(directory_url: Url, options: Option<AcmeClientOptions>) -> Self {
        Self::with_http_client(reqwest::Client::new(), directory_url, options)
    }

    /// Mirrors `AcmeClient(HttpClient, Uri, AcmeClientOptions?)`.
    pub fn with_http_client(
        http_client: reqwest::Client,
        directory_url: Url,
        options: Option<AcmeClientOptions>,
    ) -> Self {
        Self {
            http_client,
            directory_url,
            options: options.unwrap_or_default(),
            nonce_store: AcmeNonceStore::new(),
            directory: tokio::sync::Mutex::new(None),
        }
    }

    /// Mirrors `AcmeClient.GetDirectoryAsync`.
    pub async fn get_directory(&self) -> Result<AcmeDirectoryResource, AcmeError> {
        self.ensure_directory(false).await
    }

    /// Mirrors `AcmeClient.CreateAccountAsync`.
    pub async fn create_account(
        &self,
        signer: AcmeSigner,
        request: AcmeNewAccountRequest,
        external_account_binding: Option<&AcmeExternalAccountBindingOptions>,
    ) -> Result<AcmeAccountHandle, AcmeError> {
        let directory = self.ensure_directory(false).await?;
        let payload = serialize(&request)?;

        let signed_payload = if let Some(eab) = external_account_binding {
            let mut envelope: JsonObjectAccountRequest = deserialize(&payload)?;
            envelope.external_account_binding = Some(Self::create_external_account_binding(
                &directory.new_account,
                eab,
                &signer,
            )?);
            serialize(&envelope)?
        } else {
            payload
        };

        let response = self
            .send_signed_request(&directory.new_account, &signer, None, signed_payload, None)
            .await?;

        let resource: AcmeAccountResource = deserialize(&response.body)?;
        let location = response.location.clone().ok_or_else(|| {
            self.protocol_error(
                &response,
                &directory.new_account,
                "The ACME server did not return an account URL.".to_owned(),
            )
        })?;

        Ok(AcmeAccountHandle {
            account_url: location,
            signer,
            account: resource,
        })
    }

    /// Mirrors `AcmeClient.FindAccountAsync`.
    pub async fn find_account(&self, signer: AcmeSigner) -> Result<AcmeAccountHandle, AcmeError> {
        self.create_account(
            signer,
            AcmeNewAccountRequest {
                only_return_existing: Some(true),
                ..Default::default()
            },
            None,
        )
        .await
    }

    /// Mirrors `AcmeClient.GetAccountAsync`.
    pub async fn get_account(
        &self,
        account: AcmeAccountHandle,
    ) -> Result<AcmeAccountHandle, AcmeError> {
        let response = self
            .send_post_as_get(&account.signer, &account.account_url, &account.account_url, None)
            .await?;
        let resource: AcmeAccountResource = deserialize(&response.body)?;

        Ok(AcmeAccountHandle {
            account_url: account.account_url,
            signer: account.signer,
            account: resource,
        })
    }

    /// Mirrors `AcmeClient.UpdateAccountAsync`.
    pub async fn update_account(
        &self,
        account: AcmeAccountHandle,
        request: AcmeUpdateAccountRequest,
    ) -> Result<AcmeAccountHandle, AcmeError> {
        let response = self
            .send_signed_request(
                &account.account_url,
                &account.signer,
                Some(&account.account_url),
                serialize(&request)?,
                None,
            )
            .await?;
        let resource: AcmeAccountResource = deserialize(&response.body)?;

        Ok(AcmeAccountHandle {
            account_url: account.account_url,
            signer: account.signer,
            account: resource,
        })
    }

    /// Mirrors `AcmeClient.DeactivateAccountAsync`.
    pub async fn deactivate_account(
        &self,
        account: AcmeAccountHandle,
    ) -> Result<AcmeAccountHandle, AcmeError> {
        let request = AcmeAccountStatusUpdateRequest {
            status: account_statuses::deactivated(),
        };
        let response = self
            .send_signed_request(
                &account.account_url,
                &account.signer,
                Some(&account.account_url),
                serialize(&request)?,
                None,
            )
            .await?;
        let resource: AcmeAccountResource = deserialize(&response.body)?;

        Ok(AcmeAccountHandle {
            account_url: account.account_url,
            signer: account.signer,
            account: resource,
        })
    }

    /// Mirrors `AcmeClient.ChangeAccountKeyAsync`.
    pub async fn change_account_key(
        &self,
        account: AcmeAccountHandle,
        new_signer: AcmeSigner,
    ) -> Result<AcmeAccountHandle, AcmeError> {
        let directory = self.ensure_directory(false).await?;
        let key_change_url = directory.key_change.clone().ok_or_else(|| {
            AcmeError::InvalidOperation(
                "The ACME server does not advertise the keyChange resource.".to_owned(),
            )
        })?;

        let inner_payload = serialize(&AcmeKeyChangeRequest {
            account: account.account_url.clone(),
            old_key: account.signer.export_json_web_key(),
        })?;
        let inner_jws = self.create_signed_message(&key_change_url, &new_signer, None, inner_payload, None)?;
        let outer_payload = serialize(&inner_jws)?;

        let response = self
            .send_signed_request(
                &key_change_url,
                &account.signer,
                Some(&account.account_url),
                outer_payload,
                None,
            )
            .await?;

        let resource = if response.body.is_empty() {
            account.account
        } else {
            deserialize(&response.body)?
        };

        Ok(AcmeAccountHandle {
            account_url: account.account_url,
            signer: new_signer,
            account: resource,
        })
    }

    /// Mirrors `AcmeClient.GetOrdersAsync`.
    pub async fn get_orders(
        &self,
        account: &AcmeAccountHandle,
        orders_url: Option<&Url>,
    ) -> Result<AcmeResult<AcmeOrderListResource>, AcmeError> {
        let target_url = orders_url
            .or(account.account.orders.as_ref())
            .ok_or_else(|| {
                AcmeError::InvalidOperation(
                    "The account resource does not include an orders URL.".to_owned(),
                )
            })?
            .clone();

        let response = self
            .send_post_as_get(&account.signer, &account.account_url, &target_url, None)
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.CreateOrderAsync(AcmeAccountHandle, AcmeNewOrderRequest, ...)`.
    pub async fn create_order(
        &self,
        account: &AcmeAccountHandle,
        request: AcmeNewOrderRequest,
    ) -> Result<AcmeResult<AcmeOrderResource>, AcmeError> {
        let directory = self.ensure_directory(false).await?;
        let response = self
            .send_signed_request(
                &directory.new_order,
                &account.signer,
                Some(&account.account_url),
                serialize(&request)?,
                None,
            )
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.CreateOrderAsync(AcmeAccountHandle, IReadOnlyList<AcmeIdentifier>, ...)`.
    pub async fn create_order_for_identifiers(
        &self,
        account: &AcmeAccountHandle,
        identifiers: Vec<AcmeIdentifier>,
    ) -> Result<AcmeResult<AcmeOrderResource>, AcmeError> {
        self.create_order(account, AcmeNewOrderRequest::new(identifiers))
            .await
    }

    /// Mirrors `AcmeClient.GetOrderAsync`.
    pub async fn get_order(
        &self,
        account: &AcmeAccountHandle,
        order_url: &Url,
    ) -> Result<AcmeResult<AcmeOrderResource>, AcmeError> {
        let response = self
            .send_post_as_get(&account.signer, &account.account_url, order_url, None)
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.FinalizeOrderAsync`.
    pub async fn finalize_order(
        &self,
        account: &AcmeAccountHandle,
        finalize_url: &Url,
        certificate_signing_request_der: &[u8],
    ) -> Result<AcmeResult<AcmeOrderResource>, AcmeError> {
        let request = AcmeFinalizeOrderRequest {
            csr: BASE64URL.encode(certificate_signing_request_der),
        };

        let response = self
            .send_signed_request(
                finalize_url,
                &account.signer,
                Some(&account.account_url),
                serialize(&request)?,
                None,
            )
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.CreateAuthorizationAsync` (`newAuthz`, pre-order authorization).
    pub async fn create_authorization(
        &self,
        account: &AcmeAccountHandle,
        identifier: AcmeIdentifier,
    ) -> Result<AcmeResult<AcmeAuthorizationResource>, AcmeError> {
        let directory = self.ensure_directory(false).await?;
        let new_authorization = directory.new_authorization.clone().ok_or_else(|| {
            AcmeError::InvalidOperation(
                "The ACME server does not advertise the newAuthz resource.".to_owned(),
            )
        })?;

        let request = AcmeNewAuthorizationRequest { identifier };
        let response = self
            .send_signed_request(
                &new_authorization,
                &account.signer,
                Some(&account.account_url),
                serialize(&request)?,
                None,
            )
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.GetAuthorizationAsync`.
    pub async fn get_authorization(
        &self,
        account: &AcmeAccountHandle,
        authorization_url: &Url,
    ) -> Result<AcmeResult<AcmeAuthorizationResource>, AcmeError> {
        let response = self
            .send_post_as_get(&account.signer, &account.account_url, authorization_url, None)
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.DeactivateAuthorizationAsync`.
    pub async fn deactivate_authorization(
        &self,
        account: &AcmeAccountHandle,
        authorization_url: &Url,
    ) -> Result<AcmeResult<AcmeAuthorizationResource>, AcmeError> {
        let request = AcmeAuthorizationStatusUpdateRequest {
            status: authorization_statuses::deactivated(),
        };
        let response = self
            .send_signed_request(
                authorization_url,
                &account.signer,
                Some(&account.account_url),
                serialize(&request)?,
                None,
            )
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.GetChallengeAsync`.
    pub async fn get_challenge(
        &self,
        account: &AcmeAccountHandle,
        challenge_url: &Url,
    ) -> Result<AcmeResult<AcmeChallengeResource>, AcmeError> {
        let response = self
            .send_post_as_get(&account.signer, &account.account_url, challenge_url, None)
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.AnswerChallengeAsync`.
    pub async fn answer_challenge(
        &self,
        account: &AcmeAccountHandle,
        challenge_url: &Url,
    ) -> Result<AcmeResult<AcmeChallengeResource>, AcmeError> {
        let response = self
            .send_signed_request(
                challenge_url,
                &account.signer,
                Some(&account.account_url),
                serialize(&AcmeEmptyObject::default())?,
                None,
            )
            .await?;

        Ok(Self::to_result(&response, deserialize(&response.body)?))
    }

    /// Mirrors `AcmeClient.DownloadCertificateAsync`.
    pub async fn download_certificate(
        &self,
        account: &AcmeAccountHandle,
        certificate_url: &Url,
    ) -> Result<AcmeCertificateChain, AcmeError> {
        let response = self
            .send_post_as_get(
                &account.signer,
                &account.account_url,
                certificate_url,
                Some(PEM_CERTIFICATE_CHAIN_MEDIA_TYPE),
            )
            .await?;

        if let Some(content_type) = &response.content_type {
            // Mirrors the C# `response.ContentType?.MediaType` check: compare only the
            // media-type portion of the header, ignoring any `; charset=...` parameters
            // (e.g. Pebble returns "application/pem-certificate-chain; charset=utf-8").
            let media_type = content_type.split(';').next().unwrap_or(content_type).trim();
            if !media_type.eq_ignore_ascii_case(PEM_CERTIFICATE_CHAIN_MEDIA_TYPE) {
                return Err(AcmeError::InvalidOperation(format!(
                    "The ACME server returned '{content_type}' instead of '{PEM_CERTIFICATE_CHAIN_MEDIA_TYPE}' for the certificate chain."
                )));
            }
        }

        let pem_text = String::from_utf8(response.body.clone())
            .map_err(|e| AcmeError::InvalidOperation(format!("The PEM response was not valid UTF-8/ASCII: {e}")))?;
        let certificates_der = parse_pem_certificate_chain(&pem_text)?;

        Ok(AcmeCertificateChain {
            pem_chain: pem_text,
            certificates_der,
            alternate_certificate_urls: response
                .links
                .iter()
                .filter(|l| matches_relation(l, "alternate"))
                .map(|l| l.uri.clone())
                .collect(),
            issuer_certificate_urls: response
                .links
                .iter()
                .filter(|l| matches_relation(l, "up"))
                .map(|l| l.uri.clone())
                .collect(),
        })
    }

    /// Mirrors `AcmeClient.RevokeCertificateAsync(AcmeAccountHandle, ...)`.
    pub async fn revoke_certificate(
        &self,
        account: &AcmeAccountHandle,
        certificate_der: &[u8],
        reason: Option<i32>,
    ) -> Result<(), AcmeError> {
        let directory = self.ensure_directory(false).await?;
        let revoke_certificate = directory.revoke_certificate.clone().ok_or_else(|| {
            AcmeError::InvalidOperation(
                "The ACME server does not advertise the revokeCert resource.".to_owned(),
            )
        })?;

        let request = AcmeRevocationRequest {
            certificate: BASE64URL.encode(certificate_der),
            reason,
        };

        self.send_signed_request(
            &revoke_certificate,
            &account.signer,
            Some(&account.account_url),
            serialize(&request)?,
            None,
        )
        .await?;

        Ok(())
    }

    /// Mirrors `AcmeClient.RevokeCertificateAsync(AcmeSigner, ...)`: revocation signed by
    /// the certificate's own key rather than an account key.
    pub async fn revoke_certificate_with_certificate_key(
        &self,
        certificate_signer: &AcmeSigner,
        certificate_der: &[u8],
        reason: Option<i32>,
    ) -> Result<(), AcmeError> {
        let directory = self.ensure_directory(false).await?;
        let revoke_certificate = directory.revoke_certificate.clone().ok_or_else(|| {
            AcmeError::InvalidOperation(
                "The ACME server does not advertise the revokeCert resource.".to_owned(),
            )
        })?;

        let request = AcmeRevocationRequest {
            certificate: BASE64URL.encode(certificate_der),
            reason,
        };

        self.send_signed_request(
            &revoke_certificate,
            certificate_signer,
            None,
            serialize(&request)?,
            None,
        )
        .await?;

        Ok(())
    }

    /// Mirrors `AcmeClient.GetAdvertisedProfilesAsync`: fetches (and caches, via the
    /// same directory cache as `GetDirectoryAsync`) the `meta.profiles` map advertised
    /// by the server.
    pub async fn get_advertised_profiles(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, AcmeError> {
        let directory = self.ensure_directory(false).await?;
        Ok(crate::profile_validation::get_advertised_profiles(&directory))
    }

    /// Mirrors `AcmeClient.IsProfileAdvertisedAsync`.
    pub async fn is_profile_advertised(&self, profile: &str) -> Result<bool, AcmeError> {
        let directory = self.ensure_directory(false).await?;
        Ok(crate::profile_validation::is_profile_advertised(&directory, profile))
    }

    /// Mirrors `AcmeClient.EnsureProfileIsAdvertisedAsync`.
    pub async fn ensure_profile_is_advertised(&self, profile: &str) -> Result<(), AcmeError> {
        let directory = self.ensure_directory(false).await?;
        crate::profile_validation::ensure_profile_is_advertised(&directory, profile)
            .map_err(AcmeError::InvalidOperation)
    }

    /// Mirrors the `AcmeClient.CreateCertificateIdentifier(ReadOnlySpan<byte>,
    /// ReadOnlySpan<byte>)` byte-span overload: `base64url(authorityKeyIdentifier) + "."
    /// + base64url(serialNumber)`, used to build ACME Renewal Information (ARI)
    /// certificate identifiers without depending on `X509Certificate2`/ASN.1 parsing.
    pub fn create_certificate_identifier(authority_key_identifier: &[u8], serial_number: &[u8]) -> String {
        format!(
            "{}.{}",
            BASE64URL.encode(authority_key_identifier),
            BASE64URL.encode(serial_number)
        )
    }

    /// Mirrors `AcmeClient.GetRenewalInfoAsync(string, ...)` (ACME Renewal Information / ARI).
    pub async fn get_renewal_info(
        &self,
        certificate_identifier: &str,
    ) -> Result<AcmeResult<AcmeRenewalInfoResource>, AcmeError> {
        let directory = self.ensure_directory(false).await?;
        let renewal_info = directory.renewal_info.clone().ok_or_else(|| {
            AcmeError::InvalidOperation(
                "The ACME server does not advertise the renewalInfo resource.".to_owned(),
            )
        })?;

        let request_url = create_resource_url(&renewal_info, certificate_identifier);
        let response = self
            .send_bootstrap_request(Method::GET, &request_url, Some("application/json"))
            .await?;
        let resource: AcmeRenewalInfoResource = deserialize(&response.body)?;

        if resource.suggested_window.end <= resource.suggested_window.start {
            return Err(AcmeError::InvalidOperation(
                "The ACME server returned an invalid renewalInfo suggestedWindow.".to_owned(),
            ));
        }

        Ok(Self::to_result(&response, resource))
    }

    // ---- internal plumbing -------------------------------------------------

    async fn ensure_directory(&self, force_refresh: bool) -> Result<AcmeDirectoryResource, AcmeError> {
        {
            let guard = self.directory.lock().await;
            if !force_refresh {
                if let Some(directory) = guard.as_ref() {
                    return Ok(directory.clone());
                }
            }
        }

        let mut guard = self.directory.lock().await;

        if !force_refresh {
            if let Some(directory) = guard.as_ref() {
                return Ok(directory.clone());
            }
        }

        let response = self
            .send_bootstrap_request(Method::GET, &self.directory_url, None)
            .await?;
        let directory: AcmeDirectoryResource = deserialize(&response.body)?;
        *guard = Some(directory.clone());

        Ok(directory)
    }

    async fn send_post_as_get(
        &self,
        signer: &AcmeSigner,
        account_url: &Url,
        request_url: &Url,
        accept: Option<&str>,
    ) -> Result<RawResponse, AcmeError> {
        self.send_signed_request(request_url, signer, Some(account_url), Vec::new(), accept)
            .await
    }

    async fn send_signed_request(
        &self,
        request_url: &Url,
        signer: &AcmeSigner,
        key_id: Option<&Url>,
        payload: Vec<u8>,
        accept: Option<&str>,
    ) -> Result<RawResponse, AcmeError> {
        let mut attempt = 0u32;

        loop {
            let nonce = self.get_nonce().await?;
            let message = self.create_signed_message(request_url, signer, key_id, payload.clone(), Some(nonce))?;
            let content_bytes = serialize(&message)?;

            let mut request = self
                .http_client
                .request(Method::POST, request_url.clone())
                .header(reqwest::header::CONTENT_TYPE, JOSE_MEDIA_TYPE)
                .body(content_bytes);

            if let Some(accept) = accept {
                request = request.header(reqwest::header::ACCEPT, accept);
            }

            request = self.apply_standard_headers(request);

            let response = request.send().await?;
            let raw_response = Self::to_raw_response(response).await?;
            self.nonce_store.add(raw_response.replay_nonce.as_deref());

            if raw_response.status.is_success() {
                return Ok(raw_response);
            }

            let error = self.create_protocol_error(&raw_response, request_url);

            if error.is_bad_nonce() && attempt < self.options.bad_nonce_retry_count {
                attempt += 1;
                continue;
            }

            return Err(error);
        }
    }

    async fn get_nonce(&self) -> Result<String, AcmeError> {
        if let Some(nonce) = self.nonce_store.try_take() {
            return Ok(nonce);
        }

        let directory = self.ensure_directory(false).await?;
        let response = self
            .send_bootstrap_request(Method::HEAD, &directory.new_nonce, None)
            .await?;

        response.replay_nonce.clone().ok_or_else(|| {
            self.protocol_error(
                &response,
                &directory.new_nonce,
                "The ACME server did not provide a Replay-Nonce header.".to_owned(),
            )
        })
    }

    async fn send_bootstrap_request(
        &self,
        method: Method,
        request_url: &Url,
        accept: Option<&str>,
    ) -> Result<RawResponse, AcmeError> {
        let mut request = self.http_client.request(method, request_url.clone());

        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }

        request = self.apply_standard_headers(request);

        let response = request.send().await?;
        let raw_response = Self::to_raw_response(response).await?;

        if raw_response.status.is_success() {
            Ok(raw_response)
        } else {
            Err(self.create_protocol_error(&raw_response, request_url))
        }
    }

    fn create_signed_message(
        &self,
        request_url: &Url,
        signer: &AcmeSigner,
        key_id: Option<&Url>,
        payload: Vec<u8>,
        nonce: Option<String>,
    ) -> Result<AcmeSignedMessage, AcmeError> {
        let protected_header = AcmeProtectedHeader {
            alg: signer.algorithm().to_owned(),
            nonce,
            url: request_url.to_string(),
            jwk: if key_id.is_none() {
                Some(signer.export_json_web_key())
            } else {
                None
            },
            kid: key_id.map(|u| u.to_string()),
        };

        let protected_header_bytes = serialize(&protected_header)?;
        let protected_header_encoded = BASE64URL.encode(protected_header_bytes);
        let payload_encoded = if payload.is_empty() {
            String::new()
        } else {
            BASE64URL.encode(&payload)
        };
        let signing_input = format!("{protected_header_encoded}.{payload_encoded}");
        let signature = signer.sign_data(signing_input.as_bytes());

        Ok(AcmeSignedMessage {
            protected: protected_header_encoded,
            payload: payload_encoded,
            signature: BASE64URL.encode(signature),
        })
    }

    fn create_external_account_binding(
        request_url: &Url,
        options: &AcmeExternalAccountBindingOptions,
        signer: &AcmeSigner,
    ) -> Result<AcmeSignedMessage, AcmeError> {
        let protected_header = AcmeExternalAccountProtectedHeader {
            alg: options.algorithm.clone(),
            kid: options.key_identifier.clone(),
            url: request_url.to_string(),
        };

        let payload: AcmeJsonWebKey = signer.export_json_web_key();
        let payload_bytes = serialize(&payload)?;
        let protected_header_bytes = serialize(&protected_header)?;
        let protected_header_encoded = BASE64URL.encode(protected_header_bytes);
        let payload_encoded = BASE64URL.encode(&payload_bytes);
        let signing_input = format!("{protected_header_encoded}.{payload_encoded}");
        let signature = compute_hmac(&options.algorithm, &options.hmac_key, signing_input.as_bytes())?;

        Ok(AcmeSignedMessage {
            protected: protected_header_encoded,
            payload: payload_encoded,
            signature: BASE64URL.encode(signature),
        })
    }

    fn apply_standard_headers(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request = request.header(reqwest::header::USER_AGENT, self.options.user_agent.as_str());

        if let Some(accept_language) = &self.options.accept_language {
            if !accept_language.trim().is_empty() {
                request = request.header(reqwest::header::ACCEPT_LANGUAGE, accept_language.as_str());
            }
        }

        request
    }

    async fn to_raw_response(response: reqwest::Response) -> Result<RawResponse, AcmeError> {
        let status = response.status();
        let headers = response.headers().clone();
        let replay_nonce = get_single_header(&headers, "replay-nonce");
        let location = get_single_header(&headers, "location").and_then(|v| Url::parse(&v).ok());
        let retry_after = get_retry_after(&headers);
        let content_type = get_single_header(&headers, "content-type");
        let links = parse_link_headers(header_values(&headers, "link").iter().map(|s| s.as_str()));
        let body = response.bytes().await?.to_vec();

        Ok(RawResponse {
            status,
            body,
            replay_nonce,
            location,
            retry_after,
            links,
            content_type,
        })
    }

    fn protocol_error(&self, response: &RawResponse, request_url: &Url, message: String) -> AcmeError {
        AcmeError::Protocol {
            status_code: response.status.as_u16(),
            message,
            request_url: Some(request_url.clone()),
            problem: None,
            replay_nonce: response.replay_nonce.clone(),
            retry_after: response.retry_after,
            links: response.links.clone(),
        }
    }

    fn create_protocol_error(&self, response: &RawResponse, request_url: &Url) -> AcmeError {
        let problem: Option<AcmeProblemDetails> = if response.body.is_empty() {
            None
        } else {
            serde_json::from_slice(&response.body).ok()
        };

        let message = problem
            .as_ref()
            .and_then(|p| p.detail.clone())
            .unwrap_or_else(|| {
                format!(
                    "The ACME server returned {} ({}).",
                    response.status.as_u16(),
                    response.status
                )
            });

        AcmeError::Protocol {
            status_code: response.status.as_u16(),
            message,
            request_url: Some(request_url.clone()),
            problem,
            replay_nonce: response.replay_nonce.clone(),
            retry_after: response.retry_after,
            links: response.links.clone(),
        }
    }

    fn to_result<T>(response: &RawResponse, resource: T) -> AcmeResult<T> {
        AcmeResult {
            resource,
            location: response.location.clone(),
            retry_after: response.retry_after,
            links: response.links.clone(),
        }
    }
}

fn matches_relation(link: &AcmeLinkHeader, relation: &str) -> bool {
    link.relation
        .as_deref()
        .is_some_and(|r| r.eq_ignore_ascii_case(relation))
}

fn create_resource_url(base_url: &Url, relative_path: &str) -> Url {
    let mut url_str = base_url.as_str().trim_end_matches('/').to_owned();
    url_str.push('/');
    url_str.push_str(&url::form_urlencoded::byte_serialize(relative_path.as_bytes()).collect::<String>());
    Url::parse(&url_str).expect("base_url plus an escaped path segment is always a valid URL")
}

fn compute_hmac(algorithm: &str, key: &[u8], data: &[u8]) -> Result<Vec<u8>, AcmeError> {
    match algorithm {
        "HS256" => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "HS384" => {
            let mut mac =
                Hmac::<Sha384>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        "HS512" => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        other => Err(AcmeError::InvalidOperation(format!(
            "Only HS256, HS384, and HS512 external account binding algorithms are supported (got {other})."
        ))),
    }
}

fn serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, AcmeError> {
    serde_json::to_vec(value).map_err(|source| AcmeError::Json {
        type_name: std::any::type_name::<T>(),
        source,
    })
}

fn deserialize<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, AcmeError> {
    serde_json::from_slice(data).map_err(|source| AcmeError::Json {
        type_name: std::any::type_name::<T>(),
        source,
    })
}

fn get_single_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v: &HeaderValue| v.to_str().ok())
        .map(|s| s.to_owned())
}

fn header_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .collect()
}

fn get_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = get_single_header(headers, "retry-after")?;

    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let date = chrono::DateTime::parse_from_rfc2822(value.trim()).ok()?;
    let delta = date.with_timezone(&chrono::Utc) - chrono::Utc::now();

    Some(delta.to_std().unwrap_or(Duration::ZERO))
}

/// Mirrors `AcmeClient.ParsePemCertificateChain`: splits a `PEM_CERTIFICATE_CHAIN`
/// response body into the DER bytes of each `CERTIFICATE` block, in order.
fn parse_pem_certificate_chain(pem_text: &str) -> Result<Vec<Vec<u8>>, AcmeError> {
    let blocks = pem::parse_many(pem_text)
        .map_err(|e| AcmeError::InvalidOperation(format!("The PEM response contains invalid data: {e}")))?;

    if blocks.is_empty() {
        return Err(AcmeError::InvalidOperation(
            "The PEM response did not contain any certificates.".to_owned(),
        ));
    }

    let mut certificates = Vec::with_capacity(blocks.len());

    for block in blocks {
        if block.tag() != "CERTIFICATE" {
            return Err(AcmeError::InvalidOperation(
                "The PEM response contains data other than certificates.".to_owned(),
            ));
        }

        certificates.push(block.contents().to_vec());
    }

    Ok(certificates)
}
