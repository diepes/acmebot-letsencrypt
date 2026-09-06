#!/usr/bin/env bash
# Cron-update alternate entrypoint (see CONTEXT.md): automated, recurring
# renewal step run by the k8s CronJob. Reads the domain list and the
# mounted Account key (ACME_HOME), issues/renews via DNS persist mode (no
# DNS credentials needed), then imports the cert + Certificate key into
# Azure Key Vault (Phase 1: local folder first, then `az keyvault
# certificate import`).
#
# Required env vars:
#   ACME_DOMAINS          Comma separated list of domains for the
#                         certificate's SAN set. The first entry is the
#                         primary domain (CN); it also names the local cert
#                         folder and the default Key Vault certificate name.
#   ACME_EMAIL            Email address registered with the ACME server.
#   AZURE_KEYVAULT_NAME   Target Key Vault name.
#
# Optional env vars:
#   ACME_SERVER               ACME server to target (default:
#                             letsencrypt_test). Pass letsencrypt
#                             deliberately for production.
#   AZURE_KEYVAULT_CERT_NAME  Key Vault certificate name (default: primary
#                             domain with dots replaced by dashes).
set -euo pipefail

: "${ACME_DOMAINS:?ACME_DOMAINS env var is required (comma separated list of domains)}"
: "${ACME_EMAIL:?ACME_EMAIL env var is required}"
: "${AZURE_KEYVAULT_NAME:?AZURE_KEYVAULT_NAME env var is required}"
ACME_SERVER="${ACME_SERVER:-letsencrypt_test}"

IFS=',' read -r -a domain_list <<< "${ACME_DOMAINS}"
primary_domain="${domain_list[0]}"
domain_args=()
for domain in "${domain_list[@]}"; do
  domain_args+=(-d "${domain}")
done

AZURE_KEYVAULT_CERT_NAME="${AZURE_KEYVAULT_CERT_NAME:-${primary_domain//./-}}"
CERT_DIR="/certs/${primary_domain}"
mkdir -p "${CERT_DIR}"

echo "==> Issuing/renewing certificate for: ${ACME_DOMAINS} (dns-persist mode, server: ${ACME_SERVER})"
acme.sh --config-home "${ACME_HOME:-/acme.cert.store}" \
  --issue \
  --server "${ACME_SERVER}" \
  --email "${ACME_EMAIL}" \
  --dns-persist \
  "${domain_args[@]}" \
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

echo "==> Done: ${primary_domain} -> ${AZURE_KEYVAULT_NAME}/${AZURE_KEYVAULT_CERT_NAME}"
