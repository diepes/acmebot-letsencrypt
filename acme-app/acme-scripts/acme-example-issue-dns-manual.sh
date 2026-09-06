#!/usr/bin/env bash
#
# Script to issue a DNS-01 challenge certificate manually using acme.sh
#
set -euo pipefail

DOMAIN="${DOMAIN:-example.com}"
: "${ACME_EMAIL:?ACME_EMAIL env var is required}"
acme.sh --issue --email "${ACME_EMAIL}" --dns -d "${DOMAIN}" -d "www.${DOMAIN}" -d "cp.${DOMAIN}" \
  --yes-I-know-dns-manual-mode-enough-go-ahead-please
