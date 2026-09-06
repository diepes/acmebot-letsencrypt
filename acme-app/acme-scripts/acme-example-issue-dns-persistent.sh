#!/usr/bin/env bash
#
# Script to issue a DNS-01 challenge certificate manually using acme.sh
#
set -euo pipefail

DOMAIN="${DOMAIN:-example.com}"
: "${ACME_EMAIL:?ACME_EMAIL env var is required}"
echo "# Issuing DNS-persist mode challenge certificate for domain: ${DOMAIN}"
acme.sh --server letsencrypt --make-dns-persist-value \
  --home "${ACME_HOME:-/acme.cert.store}" \
  --email "${ACME_EMAIL}" \
  --dns-persist-wildcard \
  --dns -d "${DOMAIN}" -d "www.${DOMAIN}" -d "cp.${DOMAIN}"

# [Fri Sep  4 11:15:41 UTC 2026] ACCOUNT_THUMBPRINT='539myAjgzUqiewe_vScj0yHBDSz0tSLs5GH3HsM27lc'
