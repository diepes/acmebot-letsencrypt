#!/usr/bin/env bash
# Bootstrap alternate entrypoint (see CONTEXT.md): manual, one-time, per
# domain-set step. Registers the ACME account (first run only, under
# ACME_HOME) and prints the Persist TXT record(s) to publish by hand at the
# DNS provider. Never touches Azure / DNS API credentials.
#
# Required env vars:
#   ACME_DOMAINS  Comma separated list of domains for the certificate's SAN
#                 set. Order doesn't matter for bootstrap (unlike
#                 acme-cron-update.sh, there's no "primary" domain here).
#   ACME_EMAIL    Email address to register with the ACME server.
#
# Optional env vars:
#   ACME_SERVER   ACME server to target (default: letsencrypt_test). Pass
#                 letsencrypt deliberately for production (see CONTEXT.md).
set -euo pipefail

: "${ACME_DOMAINS:?ACME_DOMAINS env var is required (comma separated list of domains)}"
: "${ACME_EMAIL:?ACME_EMAIL env var is required}"
ACME_SERVER="${ACME_SERVER:-letsencrypt_test}"

IFS=',' read -r -a domain_list <<< "${ACME_DOMAINS}"
domain_args=()
wildcard_args=()
for domain in "${domain_list[@]}"; do
  domain_args+=(-d "${domain}")
  # A "*.example.com" entry needs the persist record to authorize wildcard
  # issuance too; one match is enough to add the flag for the whole call.
  if [[ "${domain}" == \*.* ]]; then
    wildcard_args=(--dns-persist-wildcard)
  fi
done

echo "==> Registering ACME account (if needed) and printing Persist TXT record(s) for: ${ACME_DOMAINS} (server: ${ACME_SERVER})"
acme.sh --config-home "${ACME_HOME:-/acme.cert.store}" \
  --server "${ACME_SERVER}" --make-dns-persist-value \
  --email "${ACME_EMAIL}" \
  "${domain_args[@]}" \
  "${wildcard_args[@]}"

echo "==> Publish the TXT record(s) printed above at your DNS provider, then run acme-cron-update.sh."
