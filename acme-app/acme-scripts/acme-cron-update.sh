#!/usr/bin/env bash
# Cron-update alternate entrypoint (see CONTEXT.md): automated, recurring
# renewal step run by the k8s CronJob. Reads the domain list and the
# Account key, issues/renews via DNS persist mode (no DNS credentials
# needed), then writes the cert + Certificate key to /certs/<primary domain>
# (Phase 1: local folder always) and, if AZ_KV_NAME is set, also imports it
# into Azure Key Vault via `az keyvault certificate import`.
#
# Required env vars:
#   ACME_DOMAINS          Comma separated list of domains for the
#                         certificate's SAN set. The first entry is the
#                         primary domain (CN); it also names the local cert
#                         folder and the default Key Vault certificate name.
#   ACME_EMAIL            Email address registered with the ACME server.
#
# The Account key must be available one of two ways:
#   - ACME_ID_SECRET_KEY  The key itself (as printed by acme-bootstrap.sh),
#                         written to ACME_HOME/account.key before issuing.
#                         Lets this step run from just an env file/.env,
#                         with no volume shared with the bootstrap step
#                         (handy for local testing).
#   - a pre-populated ACME_HOME (e.g. a k8s Secret/PVC mounted from a prior
#     acme-bootstrap.sh run) already containing account.key at that path.
# If neither is present, acme.sh has no registered account to issue with.
#
# Optional env vars:
#   ACME_SERVER      ACME server to target (default: letsencrypt_test).
#                    Pass letsencrypt deliberately for production.
#   AZ_KV_NAME       Target Key Vault name. Phase 1: the certificate is
#                    always written to /certs/<primary domain> regardless;
#                    leave AZ_KV_NAME empty/unset to skip the Key Vault
#                    import step entirely (local-folder-only mode).
#   AZ_KV_CERT_NAME  Key Vault certificate name (default: primary domain
#                    with dots replaced by dashes). Ignored if AZ_KV_NAME
#                    is empty/unset.
#
# Azure auth (only consulted if AZ_KV_NAME is set): the container's managed
# identity is tried first (`az login --identity`, real k8s deployment). For
# local/CI testing where no managed identity is available, set all three of:
#   AZURE_CLIENT_ID       Service principal (app registration) ID.
#   AZURE_CLIENT_SECRET   Service principal secret.
#   AZURE_TENANT_ID       Azure AD tenant ID.
# to fall back to an explicit `az login --service-principal`. These three
# are NOT auto-detected by the `az` CLI itself (unlike the Azure SDKs'
# DefaultAzureCredential) — this script passes them to `az login` itself.
# The principal needs "Key Vault Certificates Officer" (or equivalent
# import) rights on AZ_KV_NAME. If none of the above apply, whatever `az
# login` state already exists in the container (e.g. a prior interactive
# `az login`) is used as a last resort.
set -euo pipefail

: "${ACME_DOMAINS:?ACME_DOMAINS env var is required (comma separated list of domains)}"
: "${ACME_EMAIL:?ACME_EMAIL env var is required}"
ACME_SERVER="${ACME_SERVER:-letsencrypt_test}"

# Same fixed path acme-bootstrap.sh uses (see its comments for why it's
# fixed rather than acme.sh's internal, CA-specific layout). NOTE: there is
# no `--accountkeypath` CLI flag — acme.sh only honours this as the
# ACCOUNT_KEY_PATH env var, so it must be exported, not passed as an arg.
export ACCOUNT_KEY_PATH="${ACME_HOME:-/acme.cert.store}/account.key"
if [[ -n "${ACME_ID_SECRET_KEY:-}" ]]; then
  mkdir -p "$(dirname "${ACCOUNT_KEY_PATH}")"
  # ACME_ID_SECRET_KEY arrives as a single line with literal `\n` sequences
  # (see acme-bootstrap.sh: docker's --env-file/env_file parser has no
  # multiline value support), so unescape them back to real newlines with
  # `%b` before writing the PEM file.
  printf '%b\n' "${ACME_ID_SECRET_KEY}" > "${ACCOUNT_KEY_PATH}"
  chmod 600 "${ACCOUNT_KEY_PATH}"
elif [[ ! -s "${ACCOUNT_KEY_PATH}" ]]; then
  echo "ERROR: ACME_ID_SECRET_KEY env var is not set, and no account.key found at ${ACCOUNT_KEY_PATH} (see comment above)" >&2
  exit 1
fi

IFS=',' read -r -a domain_list <<< "${ACME_DOMAINS}"
primary_domain="${domain_list[0]}"
domain_args=()
for domain in "${domain_list[@]}"; do
  domain_args+=(-d "${domain}")
done

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
# both the private key and the certificate chain — but it's picky about the
# exact format: the private key must come FIRST (chain after), and it must
# be PKCS#8 (`-----BEGIN PRIVATE KEY-----`). acme.sh writes EC keys as
# SEC1/PKCS#1 (`-----BEGIN EC PRIVATE KEY-----`), which Key Vault rejects
# with "BadParameter ... unexpected format" — so convert it first.
openssl pkcs8 -topk8 -nocrypt \
  -in "${CERT_DIR}/key.pem" \
  -out "${CERT_DIR}/key.pkcs8.pem"
cat "${CERT_DIR}/key.pkcs8.pem" "${CERT_DIR}/fullchain.pem" > "${CERT_DIR}/full.pem"

if [[ -z "${AZ_KV_NAME:-}" ]]; then
  echo "==> AZ_KV_NAME not set: skipping Key Vault import, certificate left in ${CERT_DIR}"
  exit 0
fi
AZ_KV_CERT_NAME="${AZ_KV_CERT_NAME:-${primary_domain//./-}}"

# Auth to Azure: prefer the container's managed identity (real k8s
# deployment); for local/CI testing (no identity available), fall back to
# an explicit service-principal login if AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/
# AZURE_TENANT_ID are set — NOTE these are NOT auto-detected by `az` itself
# (unlike the Azure SDKs' DefaultAzureCredential), so they must be passed
# explicitly to `az login --service-principal` as done below. If neither
# succeeds, falls back to whatever `az login` state already exists (e.g. a
# prior interactive `az login` baked into this shell/session).
if az login --identity --output none 2>/dev/null; then
  echo "==> Authenticated via managed identity"
elif [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" && -n "${AZURE_TENANT_ID:-}" ]]; then
  echo "==> Authenticating as service principal ${AZURE_CLIENT_ID}"
  az login --service-principal \
    -u "${AZURE_CLIENT_ID}" \
    -p "${AZURE_CLIENT_SECRET}" \
    --tenant "${AZURE_TENANT_ID}" \
    --output none
else
  # Report exactly which of the three vars this container actually sees —
  # so if .env.acmebot has them but they're not reaching the container
  # (e.g. wrong --env-file path, a value dropped during env-file parsing,
  # or simply not exported into this shell), that's obvious immediately
  # instead of surfacing later as an opaque "Please run az login" error
  # from `az keyvault certificate import` below.
  missing=()
  [[ -n "${AZURE_CLIENT_ID:-}" ]] || missing+=("AZURE_CLIENT_ID")
  [[ -n "${AZURE_CLIENT_SECRET:-}" ]] || missing+=("AZURE_CLIENT_SECRET")
  [[ -n "${AZURE_TENANT_ID:-}" ]] || missing+=("AZURE_TENANT_ID")
  echo "WARNING: no managed identity available and not all of AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID are set (missing: ${missing[*]}) — skipping explicit az login. Falling back to whatever az CLI session already exists in this container (likely none, in a fresh 'docker run'). The Key Vault import below will fail with 'Please run az login' unless one of those two auth paths is available." >&2
fi

# Fail fast with a clear message rather than the opaque "Please run az
# login" error `az keyvault certificate import` would otherwise give —
# covers both the no-auth-path-attempted case above and a service-principal
# login that ran but failed to actually establish a session (e.g. an
# expired secret from create-sanbox-az-kv.sh's AZ_TAG_delete_after_days
# expiry).
if ! az account show --output none 2>/dev/null; then
  echo "ERROR: az CLI is not authenticated — cannot import into Key Vault. Check AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID are all set and reaching this container (e.g. via --env-file .env.acmebot), and that the service principal's secret hasn't expired (re-run create-sanbox-az-kv.sh to reissue one if needed)." >&2
  exit 1
fi

echo "==> Importing certificate into Key Vault '${AZ_KV_NAME}' as '${AZ_KV_CERT_NAME}'"
az keyvault certificate import \
  --vault-name "${AZ_KV_NAME}" \
  --name "${AZ_KV_CERT_NAME}" \
  --file "${CERT_DIR}/full.pem" \
  --output none

echo "==> Done: ${primary_domain} -> ${AZ_KV_NAME}/${AZ_KV_CERT_NAME}"
