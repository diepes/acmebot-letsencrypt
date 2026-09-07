#!/usr/bin/env bash
# Bootstrap alternate entrypoint (see CONTEXT.md): manual, one-time, per
# domain-set step. Registers the ACME account (first run only) and prints a
# ready-to-paste `.env` block — ACME_DOMAINS/ACME_EMAIL/ACME_SERVER plus the
# new ACME_DNS_KEY/ACME_DNS_VALUE (the Persist TXT record to publish),
# ACME_ID_SECRET_KEY (the Account key), and empty AZ_KV_NAME/AZ_KV_CERT_NAME
# placeholders (filled in by hand, or left empty for Phase 1
# local-folder-only mode; see acme-cron-update.sh) — so the whole result of
# this one-time step can be captured from the terminal into `.env.acmebot`
# for acme-cron-update.sh, with no mounted volume required for local
# testing. Never touches Azure / DNS API credentials.
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

# A fixed, well-known path (rather than acme.sh's internal, CA-specific
# `ca/<host>/directory/account.key` layout) so both this script and
# acme-cron-update.sh can read/write the Account key without caring which
# --server was used. acme.sh creates it here if it doesn't exist yet.
# NOTE: there is no `--accountkeypath` CLI flag — acme.sh only honours this
# as the ACCOUNT_KEY_PATH env var (see its _initpath()), so it must be
# exported, not passed as an argument.
export ACCOUNT_KEY_PATH="${ACME_HOME:-/acme.cert.store}/account.key"

IFS=',' read -r -a domain_list <<< "${ACME_DOMAINS}"

# acme.sh's --make-dns-persist-value only ever computes a record for the
# FIRST -d given to it on the command line: any further -d flags are parsed
# into an internal "alt domains" list that this particular subcommand never
# looks at (see makednspersistvalue()/its call site in acme.sh's source —
# there's no upstream flag to make it consider more than one domain per
# invocation). So rather than a single call with every domain as -d (which
# would silently compute a record for only the first one), call it once per
# unique apex domain, stripping any leading "*." so a domain + its wildcard
# (e.g. example.com + *.example.com) share one call/record, and passing the
# bare apex (never "*.<apex>") sidesteps acme.sh's wildcard record-name bug
# (see below) entirely for our own invocations.
declare -A apex_wildcard
apex_order=()
for domain in "${domain_list[@]}"; do
  apex="${domain#\*.}"
  if [[ -z "${apex_wildcard[${apex}]+set}" ]]; then
    apex_order+=("${apex}")
    apex_wildcard[${apex}]=0
  fi
  if [[ "${domain}" == \*.* ]]; then
    apex_wildcard[${apex}]=1
  fi
done

echo "# ==> Registering ACME account (if needed) and printing Persist TXT record(s) for: ${ACME_DOMAINS} (server: ${ACME_SERVER})"
persist_output=""
for apex in "${apex_order[@]}"; do
  wildcard_args=()
  if [[ "${apex_wildcard[${apex}]}" -eq 1 ]]; then
    wildcard_args=(--dns-persist-wildcard)
  fi
  # Stream acme.sh's output live (via `tee`) instead of only holding it in
  # memory: `set -e` would otherwise abort the script the instant this
  # command fails, silently discarding the captured output (you'd see
  # nothing but the line above, even though acme.sh printed a real error).
  # Temporarily disable errexit so we can inspect the real exit status
  # ourselves first.
  set +e
  call_output="$(acme.sh --config-home "${ACME_HOME:-/acme.cert.store}" \
    --server "${ACME_SERVER}" --make-dns-persist-value \
    --email "${ACME_EMAIL}" \
    -d "${apex}" \
    "${wildcard_args[@]}" 2>&1 | tee /dev/stderr)"
  acme_status="${PIPESTATUS[0]}"
  set -e
  if [[ "${acme_status}" -ne 0 ]]; then
    echo "# ==> ERROR: acme.sh exited with status ${acme_status} for domain ${apex} (see output above for details)" >&2
    exit "${acme_status}"
  fi
  persist_output+="${call_output}"$'\n'
done

# acme.sh prints one "TXT persist domain:"/"TXT persist value :" pair per
# call above, each line prefixed with acme.sh's own "[<timestamp>] " log
# prefix — hence matching ".*TXT persist ..." rather than anchoring at the
# start of the line. Known acme.sh bug: if a wildcard domain is ever passed
# directly as -d (not the case for our own calls above, which always pass
# the bare apex), it prints the record name with a literal "*." label (e.g.
# "_validation-persist.*.example.com"), which does not work as a real DNS
# name — stripped here defensively either way (see
# https://github.com/acmesh-official/acme.sh/issues/7168).
mapfile -t txt_keys < <(sed -nE 's/.*TXT persist domain:[[:space:]]*//p' <<< "${persist_output}" \
  | sed -E 's/_validation-persist\.\*\./_validation-persist./')
mapfile -t txt_values < <(sed -nE 's/.*TXT persist value[[:space:]]*:[[:space:]]*//p' <<< "${persist_output}" \
  | sed -E 's/^"(.*)"$/\1/')

if [[ ${#txt_keys[@]} -eq 0 ]]; then
  echo "# ==> WARNING: could not find any 'TXT persist domain:' line in acme.sh's output above" >&2
fi

echo
echo "# ==> Copy the block below into .env.acmebot (see .env.acmebot.example), then run acme-cron-update.sh:"
echo "# ----------------------------------------------------------------------"
echo "ACME_DOMAINS=${ACME_DOMAINS}"
echo "ACME_EMAIL=${ACME_EMAIL}"
echo "ACME_SERVER=${ACME_SERVER}"
if [[ ${#txt_keys[@]} -eq 1 ]]; then
  # Common case: every domain shares one apex, so there's exactly one record.
  echo "ACME_DNS_KEY=${txt_keys[0]}"
  echo "ACME_DNS_VALUE=${txt_values[0]}"
else
  # Multiple apex domains in ACME_DOMAINS produce multiple records; numbered
  # so none of them are silently dropped. Publish all of them.
  for i in "${!txt_keys[@]}"; do
    echo "ACME_DNS_KEY_$((i + 1))=${txt_keys[$i]}"
    echo "ACME_DNS_VALUE_$((i + 1))=${txt_values[$i]:-}"
  done
fi
# acme-bootstrap.sh never touches Azure, so these are only printed as empty
# placeholders/reminders for acme-cron-update.sh's Key Vault import step —
# fill them in, or leave them empty for Phase 1 local-folder-only mode (see
# acme-cron-update.sh).
echo "AZ_KV_NAME="
echo "AZ_KV_CERT_NAME="
if [[ -r "${ACCOUNT_KEY_PATH}" ]]; then
  # `docker run --env-file`/compose's `env_file:` use a plain KEY=VALUE
  # parser: no quoting, no multiline values (a literal newline starts a new
  # "variable" with no '=', which docker rejects). So the PEM's real
  # newlines are escaped to a literal `\n` here, single-line, and
  # acme-cron-update.sh unescapes them back with `printf '%b'` before
  # writing the key file.
  key_content="$(cat "${ACCOUNT_KEY_PATH}")"
  echo "ACME_ID_SECRET_KEY=${key_content//$'\n'/\\n}"
else
  echo "# WARNING: no account key found at ${ACCOUNT_KEY_PATH}" >&2
fi
echo "# ----------------------------------------------------------------------"
echo "# ==> Then publish the ACME_DNS_KEY/VALUE record(s) above at your DNS provider by hand."
echo
echo "# ==> Once published, validate propagation with (may take a few minutes to appear):"
for txt_key in "${txt_keys[@]}"; do
  echo "#   dig +short TXT ${txt_key}"
done
