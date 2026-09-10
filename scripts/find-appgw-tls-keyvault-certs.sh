#!/usr/bin/env bash
# One-off local helper (NOT part of the acmebot container/image, not run by
# the CronJob): read-only inventory script. Finds every Application Gateway
# across every subscription in an Azure tenant, and for each HTTPS listener
# resolves the SSL certificate it uses back to the Azure Key Vault it's
# sourced from (if any) — so you can see which App Gateways already depend
# on which Key Vault certificate, e.g. before onboarding that certificate
# name to acme-cron-update.sh (AZ_KV_NAME/AZ_KV_CERT_NAME) or granting its
# identity access to the right vault.
#
# Assumes you're already logged in (`az login`) with at least Reader on
# every subscription/App Gateway you want listed, plus a certificate "get"
# permission on each Key Vault (Key Vault Certificates Officer/Reader RBAC
# role, or an access-policy grant) if you want the Expiration/SAN
# columns populated — without it those two columns just come back blank
# for that vault (everything else still works with Reader alone). Does
# not log you in itself.
#
# Usage:
#   ./scripts/find-appgw-tls-keyvault-certs.sh
#
# Optional env vars:
#   AZURE_TENANT_ID       Restrict to subscriptions in this tenant only.
#                         (default: every subscription the current `az
#                         login` session can see, across all tenants)
#   AZURE_SUBSCRIPTION_IDS  Comma separated list of subscription IDs to
#                         scan instead of discovering them all via `az
#                         account list`. Overrides AZURE_TENANT_ID.
#   OUTPUT_FORMAT         "text" (default, compact grouped-by-gateway
#                         report for humans — see below), "tsv" (one row
#                         per line, tab separated, for piping into other
#                         tools), or "json" (one array element per row,
#                         same fields).
#   DEBUG                 If set (non-empty), print the stderr of any
#                         failed `az keyvault certificate show` call to
#                         stderr (prefixed "DEBUG: ..."), instead of
#                         silently leaving the Expiration/SAN
#                         columns blank for that certificate. Use this to
#                         diagnose why a specific vault/cert comes back
#                         blank (e.g. permission denied, vault firewall,
#                         soft-deleted/purged cert, wrong name).
#   MAX_PARALLEL          Max number of subscriptions/cert lookups running
#                         concurrently (default: 8). Each `az` invocation
#                         is a separate process with its own token/REST
#                         round-trip latency, so scanning subscriptions
#                         (and resolving cert expiry/SAN) in parallel
#                         rather than one-at-a-time is what makes this
#                         script fast; raise/lower if you hit throttling.
#
# Output is one row per (Application Gateway, TLS certificate) pair — one
# row for every certificate configured on the gateway (sslCertificates[]),
# whether or not any HTTPS listener currently uses it — with a count of
# how many HTTPS listeners reference it (0 if none).
#
# "text" format (default) groups rows by gateway:
#   <appGatewayName> - <subscriptionName>
#       x<listenerCount two-digit padded> <sslCertName>  <status>  SAN=<san>  <shortKeyVaultId>
#       ...(one line per certificate on that gateway)...
#   <shortKeyVaultId> is <vaultName>/<secretName>/<version> (shortened
#   from the full secret URL, for compact display only — see tsv/json
#   below for the full URL).
#
# tsv/json fields: appGatewayName, subscriptionName, sslCertName,
#   listenerCount, status, san, keyVaultId
#   keyVaultId is the certificate's full Key Vault secret URL (e.g.
#   https://myvault.vault.azure.net/secrets/mycert/<version>) — empty when
#   the certificate was uploaded directly to the gateway rather than
#   sourced from Key Vault; status/san are also empty in that
#   case. san is the certificate's Subject Alternative Names (DNS names),
#   comma separated (falling back to the subject Common Name if the
#   certificate has no SAN entries). status summarizes the certificate's
#   expiry, e.g. "EXPIRED 12d ago (2026-01-01)", "EXPIRING in 5d
#   (2026-02-01)", "Valid, expires 2027-01-01 (300d)". If keyVaultId is
#   set but the Key Vault lookup failed (e.g. this identity lacks
#   certificate "get" permission on that vault, the vault/cert doesn't
#   exist, or a network/firewall block), status instead shows a short
#   "ERR: <reason>" and san is "?" — set DEBUG=1 to also print the full
#   raw `az` error to stderr for that lookup. In the "text" format,
#   status is colour-coded by days remaining: green (>30d), yellow (>7d
#   and <=30d), red (<=7d or already expired, and always for "ERR: ..."
#   rows) — disabled automatically when not attached to a terminal (e.g.
#   piped/redirected) or when NO_COLOR is set.
set -euo pipefail

# --- macOS compatibility ------------------------------------------------------
# This script relies on bash 4+ features (mapfile/readarray, associative
# arrays, `[[ -v ... ]]`). macOS ships /bin/bash 3.2 (last GPLv2 release) as
# /usr/bin/env bash's default resolution on many systems, so re-exec with a
# newer bash if the one currently running us is too old. Install one via
# `brew install bash` if none is found.
if [[ -z "${ACMEBOT_BASH_REEXEC:-}" && "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash /usr/local/opt/bash/bin/bash; do
    if [[ -x "${candidate}" ]]; then
      ACMEBOT_BASH_REEXEC=1 exec "${candidate}" "$0" "$@"
    fi
  done
  echo "ERROR: bash ${BASH_VERSINFO[0]} is too old (need bash 4+)." >&2
  echo "       On macOS: brew install bash   (then re-run this script)" >&2
  exit 1
fi

command -v az >/dev/null 2>&1 || { echo "ERROR: az CLI not found on PATH." >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found on PATH (needed to parse Application Gateway config in a single 'az ... show' call)." >&2; exit 1; }
az account show --output none 2>/dev/null || { echo "ERROR: not logged in to Azure CLI. Run 'az login' first." >&2; exit 1; }

OUTPUT_FORMAT="${OUTPUT_FORMAT:-text}"
if [[ "${OUTPUT_FORMAT}" != "tsv" && "${OUTPUT_FORMAT}" != "text" && "${OUTPUT_FORMAT}" != "json" ]]; then
  echo "ERROR: OUTPUT_FORMAT must be 'text', 'tsv' or 'json' (got '${OUTPUT_FORMAT}')." >&2
  exit 1
fi

MAX_PARALLEL="${MAX_PARALLEL:-8}"
if ! [[ "${MAX_PARALLEL}" =~ ^[0-9]+$ ]] || [[ "${MAX_PARALLEL}" -lt 1 ]]; then
  echo "ERROR: MAX_PARALLEL must be a positive integer (got '${MAX_PARALLEL}')." >&2
  exit 1
fi

# Internal field separator for all row data this script builds/parses
# itself (raw_rows, cert attribute cache, final_rows, ...). NOT a tab:
# bash's `read`/`IFS` word-splitting silently collapses consecutive tab
# (and space/newline) delimiters even when IFS is set to just "\t",
# because those three characters are always treated as "IFS whitespace" —
# so any row with an *empty* field (e.g. no Key Vault secret, no
# expiry/SAN found) would shift every later field left by one.
# ASCII Unit Separator (0x1F) isn't whitespace to bash, so empty fields
# round-trip correctly. Only converted to real tabs at the very end, when
# emitting the tsv output format for external tools.
sep=$'\x1f'

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/find-appgw.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

# Run up to MAX_PARALLEL background jobs at a time. Call `pool_wait_slot`
# right after backgrounding a job (with `&`); it blocks until fewer than
# MAX_PARALLEL of the jobs started this way are still running.
pool_pids=()
pool_wait_slot() {
  pool_pids+=("$!")
  while [[ "${#pool_pids[@]}" -ge "${MAX_PARALLEL}" ]]; do
    wait -n 2>/dev/null || wait "${pool_pids[0]}"
    # Prune finished PIDs (best-effort; `wait -n` doesn't tell us which one).
    local still_running=()
    local pid
    for pid in "${pool_pids[@]}"; do
      kill -0 "${pid}" 2>/dev/null && still_running+=("${pid}")
    done
    pool_pids=("${still_running[@]}")
  done
}
pool_wait_all() {
  wait "${pool_pids[@]}" 2>/dev/null || true
  pool_pids=()
}

# --- Certificate expiry -> human status --------------------------------------
# Converts an ISO-8601 "expires" timestamp (as returned by `az keyvault
# certificate show`) to seconds-since-epoch, trying GNU date first (Linux),
# then python3 (portable fallback for macOS/BSD date, which uses different
# flags). Prints nothing if both are unavailable/fail.
iso_to_epoch() {
  local iso="$1"
  date -d "${iso}" +%s 2>/dev/null && return
  python3 -c "
import sys, datetime
try:
    print(int(datetime.datetime.fromisoformat(sys.argv[1].replace('Z', '+00:00')).timestamp()))
except Exception:
    pass
" "${iso}" 2>/dev/null
}

cert_days_left() {
  local expires_iso="$1"
  [[ -z "${expires_iso}" ]] && { printf ''; return; }
  local expires_epoch
  expires_epoch="$(iso_to_epoch "${expires_iso}")"
  [[ -z "${expires_epoch}" ]] && { printf ''; return; }
  printf '%d' $(( (expires_epoch - $(date +%s)) / 86400 ))
}

cert_status() {
  local expires_iso="$1" days="$2"
  [[ -z "${expires_iso}" ]] && { printf ''; return; }
  local expires_date="${expires_iso%%T*}"
  if [[ -z "${days}" ]]; then
    printf 'expires %s' "${expires_date}"
    return
  fi
  if (( days < 0 )); then
    printf 'EXPIRED %dd ago (%s)' "$(( -days ))" "${expires_date}"
  elif (( days <= 30 )); then
    printf 'EXPIRING in %dd (%s)' "${days}" "${expires_date}"
  else
    printf 'Valid, expires %s (%dd)' "${expires_date}" "${days}"
  fi
}

# Traffic-light colour for a certificate's remaining days: red (<=7 days
# left, or already expired), yellow (>7 and <=30 days left), green (>30
# days left), or empty/uncoloured if days is unknown.
cert_status_color() {
  local days="$1"
  [[ -z "${days}" ]] && { printf ''; return; }
  if (( days <= 7 )); then
    printf 'red'
  elif (( days <= 30 )); then
    printf 'yellow'
  else
    printf 'green'
  fi
}

# Shortens a Key Vault certificate secret URL for compact human display in
# the "text" report only (tsv/json keep the full URL, since those are
# meant for piping into other tools, e.g. copy-pasting into `az`):
#   https://myvault.vault.azure.net/secrets/mycert/<version>
#   -> myvault/mycert/<version>
kv_short() {
  local url="$1"
  [[ -z "${url}" ]] && { printf ''; return; }
  local rest="${url#https://}"
  local vault_name="${rest%%.*}"
  local secret_path="${rest#*/secrets/}"
  printf '%s/%s' "${vault_name}" "${secret_path}"
}

# Only colorize the interactive "text" report, never tsv/json (those are
# meant for other tools), and never when NOT connected to a terminal or
# when NO_COLOR is set (https://no-color.org), or piped through e.g. less.
use_color=0
if [[ "${OUTPUT_FORMAT}" == "text" && -t 1 && -z "${NO_COLOR:-}" ]]; then
  use_color=1
fi
color_wrap() {
  local color_name="$1" text="$2"
  if [[ "${use_color}" -ne 1 || -z "${color_name}" ]]; then
    printf '%s' "${text}"
    return
  fi
  local code
  case "${color_name}" in
    red) code='31' ;;
    yellow) code='33' ;;
    green) code='32' ;;
    *) code='' ;;
  esac
  [[ -z "${code}" ]] && { printf '%s' "${text}"; return; }
  printf '\033[%sm%s\033[0m' "${code}" "${text}"
}

# --- Enumerate subscriptions to scan -----------------------------------------
subscriptions=()
if [[ -n "${AZURE_SUBSCRIPTION_IDS:-}" ]]; then
  IFS=',' read -ra sub_ids <<< "${AZURE_SUBSCRIPTION_IDS}"
  for sub_id in "${sub_ids[@]}"; do
    sub_id="${sub_id// /}"
    [[ -z "${sub_id}" ]] && continue
    sub_name="$(az account show --subscription "${sub_id}" --query name --output tsv 2>/dev/null || echo "${sub_id}")"
    subscriptions+=("${sub_id}"$'\t'"${sub_name}")
  done
else
  sub_filter=""
  [[ -n "${AZURE_TENANT_ID:-}" ]] && sub_filter="?tenantId=='${AZURE_TENANT_ID}'"
  mapfile -t subscriptions < <(az account list --all --query "[${sub_filter}].[id,name]" --output tsv)
fi

if [[ "${#subscriptions[@]}" -eq 0 ]]; then
  echo "ERROR: no subscriptions found$( [[ -n "${AZURE_TENANT_ID:-}" ]] && echo " for tenant '${AZURE_TENANT_ID}'" ). Check az login / AZURE_TENANT_ID / AZURE_SUBSCRIPTION_IDS." >&2
  exit 1
fi
echo "==> Scanning ${#subscriptions[@]} subscription(s) for Application Gateways..." >&2

# --- Scan subscriptions in parallel -------------------------------------------
# Each subscription's per-certificate rows (subId\tsubName\trg\tgwName\t
# certName\tkvSecretId\tlistenerCount) are appended to its own tmp file by
# a background job, up to MAX_PARALLEL at a time. One row per certificate
# configured on the gateway (sslCertificates[]) — including ones no HTTPS
# listener currently references (listenerCount 0) — not one row per
# listener.
scan_subscription() {
  local sub_id="$1" sub_name="$2" out_file="$3"
  local gateway_ids gw_id resource_group gw_name
  mapfile -t gateway_ids < <(az network application-gateway list --subscription "${sub_id}" --query "[].id" --output tsv 2>/dev/null || true)
  echo "==> Subscription '${sub_name}' (${sub_id})... found ${#gateway_ids[@]} AppGW's" >&2
  [[ "${#gateway_ids[@]}" -eq 0 ]] && return 0

  for gw_id in "${gateway_ids[@]}"; do
    [[ -z "${gw_id}" ]] && continue
    # ARM id: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/applicationGateways/<name>
    IFS='/' read -ra id_parts <<< "${gw_id}"
    resource_group="${id_parts[4]}"
    gw_name="${id_parts[8]}"

    # Single 'show' call fetching the full gateway config as JSON; jq
    # emits one row per sslCertificate (not per listener), counting how
    # many HTTPS listeners reference each one. Fields joined with the
    # Unit Separator (not @tsv/real tabs) so empty fields (e.g. no Key
    # Vault secret) survive the `read` below intact — see `sep` comment.
    az network application-gateway show --ids "${gw_id}" --output json 2>/dev/null | jq -r --arg sep "${sep}" '
      (.httpListeners // []) as $listeners
      | (.sslCertificates // [])[]
      | . as $cert
      | ($listeners | map(select(.protocol == "Https" and ((.sslCertificate.id // "" | split("/") | last) == $cert.name))) | length) as $listenerCount
      | [$cert.name, ($cert.keyVaultSecretId // ""), ($listenerCount | tostring)]
      | join($sep)
    ' 2>/dev/null | while IFS="${sep}" read -r cert_name kv_secret_id listener_count; do
      printf "%s${sep}%s${sep}%s${sep}%s${sep}%s${sep}%s${sep}%s\n" \
        "${sub_id}" "${sub_name}" "${resource_group}" "${gw_name}" "${cert_name}" "${kv_secret_id}" "${listener_count}" >> "${out_file}"
    done || true  # pipefail: don't let one gateway's failed/empty show/jq abort the whole (backgrounded) subscription scan
  done
}

sub_out_files=()
for i in "${!subscriptions[@]}"; do
  sub_row="${subscriptions[$i]}"
  sub_id="${sub_row%%$'\t'*}"
  sub_name="${sub_row#*$'\t'}"
  out_file="${tmp_dir}/sub_${i}.tsv"
  : > "${out_file}"
  sub_out_files+=("${out_file}")
  scan_subscription "${sub_id}" "${sub_name}" "${out_file}" &
  pool_wait_slot
done
pool_wait_all

raw_rows=()  # fields joined by ${sep}: subId, subName, rg, gwName, certName, kvSecretId, listenerCount
for out_file in "${sub_out_files[@]}"; do
  [[ -s "${out_file}" ]] || continue
  mapfile -t -O "${#raw_rows[@]}" raw_rows < "${out_file}"
done

echo "==> Found ${#raw_rows[@]} certificate(s) across ${#subscriptions[@]} subscription(s); resolving expiry/SAN from Key Vault..." >&2

# Turns the raw stderr of a failed `az keyvault certificate show` into a
# short, human-readable reason so the report can show *why* a vault/cert
# came back blank instead of a bare "-". Falls back to the first line of
# the raw error (truncated) if it doesn't match a known pattern. Full raw
# stderr is always available via DEBUG=1.
classify_kv_error() {
  local err="$1"
  [[ -z "${err}" ]] && { printf 'no data returned (unknown reason; try DEBUG=1)'; return; }
  if grep -qiE "does not have (secrets|certificates)/get permission|is not authorized to perform|ForbiddenByRbac|Forbidden" <<< "${err}"; then
    printf 'no permission (need Key Vault certificates-get access)'
  elif grep -qiE "CertificateNotFound|SecretNotFound|was not found|\(NotFound\)" <<< "${err}"; then
    printf 'cert not found in vault (deleted/renamed?)'
  elif grep -qiE "VaultNotFound|does not exist|Could not resolve|Name or service not known|No such host" <<< "${err}"; then
    printf 'vault unreachable (deleted, wrong name, or DNS/network blocked)'
  elif grep -qiE "public network access is disabled|firewall" <<< "${err}"; then
    printf 'vault firewall/private-endpoint blocks this client'
  else
    printf '%s' "${err}" | head -1 | cut -c1-80
  fi
}

# --- Resolve each distinct Key Vault certificate's expiry + SAN, ------
# in parallel (one call per distinct vault+secret name, not per row).
resolve_cert_attrs() {
  local kv_name="$1" secret_name="$2" out_file="$3"
  local json expires san_names err_raw err_reason
  json="$(az keyvault certificate show --vault-name "${kv_name}" --name "${secret_name}" --output json 2> "${out_file}.err")" || true
  err_raw="$(cat "${out_file}.err" 2>/dev/null || true)"
  if [[ -n "${DEBUG:-}" && -s "${out_file}.err" ]]; then
    echo "DEBUG: az keyvault certificate show --vault-name ${kv_name} --name ${secret_name} failed:" >&2
    sed 's/^/    /' "${out_file}.err" >&2
  fi
  rm -f "${out_file}.err"
  expires=""
  san_names=""
  err_reason=""
  if [[ -n "${json}" ]]; then
    expires="$(printf '%s' "${json}" | jq -r '.attributes.expires // ""' 2>/dev/null || true)"
    san_names="$(printf '%s' "${json}" | jq -r '
      (.policy.x509CertificateProperties.subjectAlternativeNames.dnsNames // []) as $sans
      | if ($sans | length) > 0 then ($sans | join(", "))
        else ((.policy.x509CertificateProperties.subject // "") | sub("^CN=";""))
        end
    ' 2>/dev/null || true)"
    [[ -z "${expires}" && -z "${san_names}" ]] && err_reason="empty response from Key Vault (unexpected)"
  else
    err_reason="$(classify_kv_error "${err_raw}")"
  fi
  printf "%s${sep}%s${sep}%s${sep}%s${sep}%s\n" "${kv_name}" "${secret_name}" "${expires}" "${san_names}" "${err_reason}" > "${out_file}"
}

declare -A cert_attrs_seen=()
for row in "${raw_rows[@]}"; do
  IFS="${sep}" read -r _ _ _ _ _ kv_secret_id _ <<< "${row}"
  [[ -z "${kv_secret_id}" ]] && continue
  # https://<vault-name>.vault.azure.net/secrets/<secret-name>/<version>
  kv_name="${kv_secret_id#https://}"
  kv_name="${kv_name%%.*}"
  secret_name="${kv_secret_id#https://}"
  secret_name="${secret_name#*/secrets/}"
  secret_name="${secret_name%%/*}"
  cert_attrs_seen["${kv_name}${sep}${secret_name}"]=1
done

declare -A cert_attrs_cache=()  # "kvName<sep>secretName" -> "expires<sep>san<sep>errReason"
if [[ "${#cert_attrs_seen[@]}" -gt 0 ]]; then
  cert_out_files=()
  cert_i=0
  for tuple in "${!cert_attrs_seen[@]}"; do
    kv_name="${tuple%%${sep}*}"
    secret_name="${tuple#*${sep}}"
    out_file="${tmp_dir}/cert_${cert_i}.dat"
    cert_out_files+=("${out_file}")
    resolve_cert_attrs "${kv_name}" "${secret_name}" "${out_file}" &
    pool_wait_slot
    cert_i=$((cert_i + 1))
  done
  pool_wait_all

  for out_file in "${cert_out_files[@]}"; do
    [[ -s "${out_file}" ]] || continue
    IFS="${sep}" read -r kv_name secret_name expires san_names err_reason < "${out_file}"
    cert_attrs_cache["${kv_name}${sep}${secret_name}"]="${expires}${sep}${san_names}${sep}${err_reason}"
  done
fi

# --- Build final output rows: appGatewayName, subscriptionName, ------------
# sslCertName, listenerCount, status, san, keyVaultId (secret URL),
# daysLeft, isError (last two are internal-only, used to colorize "text"
# output — not printed as their own columns) --------------------------------
final_rows=()
for row in "${raw_rows[@]}"; do
  IFS="${sep}" read -r sub_id sub_name resource_group gw_name cert_name kv_secret_id listener_count <<< "${row}"
  status=""
  san_names=""
  days_left=""
  is_error=0
  if [[ -n "${kv_secret_id}" ]]; then
    kv_name="${kv_secret_id#https://}"
    kv_name="${kv_name%%.*}"
    secret_name="${kv_secret_id#https://}"
    secret_name="${secret_name#*/secrets/}"
    secret_name="${secret_name%%/*}"
    attrs="${cert_attrs_cache[${kv_name}${sep}${secret_name}]:-}"
    if [[ -n "${attrs}" ]]; then
      expires="$(cut -d "${sep}" -f1 <<< "${attrs}")"
      san_names="$(cut -d "${sep}" -f2 <<< "${attrs}")"
      err_reason="$(cut -d "${sep}" -f3- <<< "${attrs}")"
      if [[ -n "${expires}" ]]; then
        days_left="$(cert_days_left "${expires}")"
        status="$(cert_status "${expires}" "${days_left}")"
      elif [[ -n "${err_reason}" ]]; then
        status="ERR: ${err_reason}"
        san_names="?"
        is_error=1
      fi
    fi
  fi
  final_rows+=("${gw_name}${sep}${sub_name}${sep}${cert_name}${sep}${listener_count}${sep}${status}${sep}${san_names}${sep}${kv_secret_id}${sep}${days_left}${sep}${is_error}")
done

# Sort for readability: by subscription, then gateway, then cert name.
if [[ "${#final_rows[@]}" -gt 0 ]]; then
  mapfile -t final_rows < <(printf '%s\n' "${final_rows[@]}" | sort -t "${sep}" -k2,2 -k1,1 -k3,3)
fi

echo "==> ${#final_rows[@]} certificate row(s) across ${#subscriptions[@]} subscription(s)." >&2

if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
  {
    echo "["
    for i in "${!final_rows[@]}"; do
      IFS="${sep}" read -r appGatewayName subscriptionName sslCertName listenerCount status san keyVaultId _daysLeft _isError <<< "${final_rows[$i]}"
      printf '  {"appGatewayName":"%s","subscriptionName":"%s","sslCertName":"%s","listenerCount":%s,"status":"%s","san":"%s","keyVaultId":"%s"}%s\n' \
        "${appGatewayName}" "${subscriptionName}" "${sslCertName}" "${listenerCount}" "${status}" "${san}" "${keyVaultId}" \
        "$([[ "$i" -lt $((${#final_rows[@]} - 1)) ]] && echo ',')"
    done
    echo "]"
  }
elif [[ "${OUTPUT_FORMAT}" == "tsv" ]]; then
  printf 'appGatewayName\tsubscriptionName\tsslCertName\tlistenerCount\tstatus\tsan\tkeyVaultId\n'
  for row in "${final_rows[@]}"; do
    IFS="${sep}" read -r appGatewayName subscriptionName sslCertName listenerCount status san keyVaultId _daysLeft _isError <<< "${row}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${appGatewayName}" "${subscriptionName}" "${sslCertName}" "${listenerCount}" "${status}" "${san}" "${keyVaultId}"
  done
else
  # "text": compact, grouped-by-gateway report. status is padded to a
  # fixed width *before* being colour-wrapped, so the ANSI escape codes
  # (invisible on screen but counted by printf's %-Ns width) don't throw
  # off column alignment.
  last_group=""
  for row in "${final_rows[@]}"; do
    IFS="${sep}" read -r gw_name sub_name cert_name listener_count status san_names kv_secret_id days_left is_error <<< "${row}"
    group_key="${sub_name}${sep}${gw_name}"
    if [[ "${group_key}" != "${last_group}" ]]; then
      printf '%s - %s\n' "${gw_name}" "${sub_name}"
      last_group="${group_key}"
    fi
    padded_status="$(printf '%-30s' "${status:--}")"
    status_color="$(cert_status_color "${days_left}")"
    [[ "${is_error}" == "1" ]] && status_color="red"
    colored_status="$(color_wrap "${status_color}" "${padded_status}")"
    kv_display="$([[ -n "${kv_secret_id}" ]] && kv_short "${kv_secret_id}" || printf '(uploaded, not in Key Vault)')"
    printf '    x%02d %-28s %s SAN=%-40s %s\n' \
      "${listener_count}" "${cert_name}" "${colored_status}" "${san_names:--}" "${kv_display}"
  done
fi
