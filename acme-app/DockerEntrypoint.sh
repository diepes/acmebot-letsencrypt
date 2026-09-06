#!/usr/bin/env bash
# Entrypoint for the acmebot container (see CONTEXT.md).
#
# Issues/renews a certificate with acme.sh using DNS-01 validation, then
# imports the resulting cert+key into an Azure Key Vault.
#
# Required env vars:
#   DOMAIN                    Primary domain to issue a certificate for.
#   ACME_EMAIL                Email address registered with the ACME server.
#   DNS_PROVIDER               acme.sh dns hook to use: dns_azure | dns_aws
#   AZURE_KEYVAULT_NAME         Target Key Vault name.
#
# Optional env vars:
#   SAN_DOMAINS                 Space separated list of additional SAN domains.
#   AZURE_KEYVAULT_CERT_NAME     Key Vault certificate name (default: DOMAIN with
#                                dots replaced by dashes).
#
# DNS provider credentials (per acme.sh dnsapi docs) must also be set, e.g.:
#   dns_azure : AZUREDNS_SUBSCRIPTIONID, AZUREDNS_TENANTID, AZUREDNS_APPID,
#               AZUREDNS_CLIENTSECRET (or rely on managed identity)
#   dns_aws   : AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
set -euo pipefail

: "${DOMAIN:?DOMAIN env var is required}"
: "${ACME_EMAIL:?ACME_EMAIL env var is required}"
: "${DNS_PROVIDER:?DNS_PROVIDER env var is required (dns_azure or dns_aws)}"
: "${AZURE_KEYVAULT_NAME:?AZURE_KEYVAULT_NAME env var is required}"
AZURE_KEYVAULT_CERT_NAME="${AZURE_KEYVAULT_CERT_NAME:-${DOMAIN//./-}}"

ACME_SH="${ACME_HOME:-/acme.cert.store}/acme.sh"
CERT_DIR="/certs/${DOMAIN}"
mkdir -p "${CERT_DIR}"

san_args=()
for san in ${SAN_DOMAINS:-}; do
  san_args+=(-d "${san}")
done

echo "==> Issuing certificate for ${DOMAIN} via ${DNS_PROVIDER}"
"${ACME_SH}" --issue \
  --email "${ACME_EMAIL}" \
  --dns "${DNS_PROVIDER}" \
  -d "${DOMAIN}" "${san_args[@]}" \
  --fullchain-file "${CERT_DIR}/fullchain.pem" \
  --key-file "${CERT_DIR}/key.pem"

# `az keyvault certificate import` expects a single PEM (or PFX) containing
# both the certificate chain and the private key.
cat "${CERT_DIR}/fullchain.pem" "${CERT_DIR}/key.pem" > "${CERT_DIR}/full.pem"

# Prefer the container's managed identity when available; falls back to
# whatever `az login` state already exists (e.g. injected via `az login
# --service-principal` before this script runs).
az login --identity --output none 2>/dev/null || true

echo "==> Importing certificate into Key Vault '${AZURE_KEYVAULT_NAME}' as '${AZURE_KEYVAULT_CERT_NAME}'"
az keyvault certificate import \
  --vault-name "${AZURE_KEYVAULT_NAME}" \
  --name "${AZURE_KEYVAULT_CERT_NAME}" \
  --file "${CERT_DIR}/full.pem" \
  --output none

echo "==> Done: ${DOMAIN} -> ${AZURE_KEYVAULT_NAME}/${AZURE_KEYVAULT_CERT_NAME}"
