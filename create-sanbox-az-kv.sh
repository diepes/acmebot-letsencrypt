#!/usr/bin/env bash
# One-off local helper (NOT part of the acmebot container/image): creates a
# throwaway Azure Key Vault + service principal in a Sandbox subscription for
# testing acme-cron-update.sh's Key Vault import step (see README.md
# "Local/CI testing without a managed identity"). Idempotent: safe to
# re-run — reuses the vault/SPN if they already exist instead of failing.
# Tags the resource group/vault with owner_email/owner_platform/
# date_delete_after (required by this Sandbox subscription's Azure Policy —
# see AZ_TAG_owner_email/AZ_TAG_owner_platform below), plus purpose/
# managed_by for easy identification/cleanup. Requires the Azure CLI (`az`)
# logged in locally.
#
# Usage:
#   ./create-sanbox-az-kv.sh
#
# Optional env vars (all have defaults suitable for a quick throwaway test):
#   AZURE_TENANT_ID      Azure AD tenant to log into. Also the same var
#                        acme-cron-update.sh reads for its service-principal
#                        auth fallback — no separate AZ_-prefixed copy.
#                        Required — no hardcoded default (keeps this script
#                        free of any real tenant ID); set it in
#                        .env.acmebot or export it before running.
#   AZURE_SUBSCRIPTION_ID  Subscription name or ID to select (default:
#                        Sandbox). Once logged in, this script overwrites
#                        it with the actual resolved subscription GUID —
#                        no separate AZ_-prefixed copy of this value.
#   AZ_RESOURCE_GROUP    Resource group to create the vault in (created if
#                        missing). (default: rg-acmebot-test)
#   AZ_LOCATION          Azure region for the resource group/vault.
#                        (default: australiaeast)
#   AZ_KV_NAME           Key Vault name to create/reuse. Must be globally
#                        unique. Fixed default (rather than a random
#                        suffix) so re-running this script reuses the same
#                        vault; override if that name is already taken by
#                        someone else. (default: acmebot-sandbox-kv)
#   AZ_KV_CERT_NAME      Default Key Vault certificate name written to
#                        .env.acmebot for acme-cron-update.sh's
#                        AZ_KV_CERT_NAME (default: acmebot-sandbox-cert).
#
#   Tags — every resource group/vault tag this script sets comes from an
#   AZ_TAG_<tag key> env var (so any of them can be overridden directly, or
#   extended with more AZ_TAG_* vars of your own — this script will pick up
#   and apply any AZ_TAG_* var it finds):
#     AZ_TAG_owner_email      Required by this Sandbox subscription's
#                             "require-resourcegroup-tags-sandbox-policy"
#                             Azure Policy: must be an @eroad.com email
#                             address. No default — the script errors out
#                             if unset or not @eroad.com.
#     AZ_TAG_owner_platform   Required by the same policy: a non-empty
#                             value. (default: acmebot-letsencrypt)
#     AZ_TAG_delete_after_days  Number of days from today used to compute
#                             the actual "date_delete_after" tag (required
#                             by the same policy, as a Year-Month-Date
#                             value) — this var itself is NOT applied as a
#                             literal tag. Informational only — Azure
#                             doesn't auto-delete tagged resources; pair
#                             this with your own cleanup process/reminder.
#                             (default: 30)
#     AZ_TAG_purpose          (default: acmebot-testing)
#     AZ_TAG_managed_by       (default: create-sanbox-az-kv.sh)
#
#   AZ_SPN_NAME          Display name of the service principal to
#                        create/reuse and grant Key Vault access to (its
#                        credentials double as AZURE_CLIENT_ID/
#                        AZURE_CLIENT_SECRET for acme-cron-update.sh's
#                        service-principal auth fallback — see README.md).
#                        Skipped entirely if AZURE_CLIENT_ID is already set
#                        (see below). (default: sp-acmebot-test)
#
#   AZURE_CLIENT_ID      If already set, this script assumes you want to
#                        reuse an existing service principal: it skips SPN
#                        creation and only grants this appId certificate
#                        import/get/list rights on the vault.
#
# .env.acmebot integration: if ./.env.acmebot already exists, its values are
# loaded first (without overriding anything already set in the calling
# shell's own environment, which always takes priority) — so once you've
# filled in AZ_TAG_owner_email/AZURE_SUBSCRIPTION_ID/etc. there once, you don't
# need to re-export them every run. Any config var above not already
# present in that file (commented or not) is appended to it: as an active
# blank `KEY=` placeholder if it's required and has no default (currently
# just AZURE_TENANT_ID and AZ_TAG_owner_email), or as a commented-out
# `# KEY=<default>` documentation line otherwise — uncomment and edit to
# override. Once the vault/SPN are created (or reused), the actual
# resolved values — AZURE_SUBSCRIPTION_ID, AZ_KV_NAME, AZ_KV_CERT_NAME,
# AZURE_CLIENT_ID, AZURE_CLIENT_SECRET (only if freshly issued this run)
# and AZURE_TENANT_ID — are written back into .env.acmebot too (as active,
# uncommented lines, replacing any existing/blank value for that key), so
# subsequent runs of this script or of acme-cron-update.sh can pick them
# straight up with no manual copying.
set -euo pipefail

ENV_FILE=".env.acmebot"
CONFIG_VARS=(
  AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID AZ_RESOURCE_GROUP AZ_LOCATION AZ_KV_NAME
  AZ_KV_CERT_NAME AZ_TAG_owner_email AZ_TAG_owner_platform
  AZ_TAG_delete_after_days AZ_TAG_purpose AZ_TAG_managed_by AZ_SPN_NAME
)

# Rewrites/appends a single KEY=VALUE line in $ENV_FILE: replaces the
# existing line for that key if present (wherever it is in the file, in
# place), otherwise appends a new one. Avoids sed entirely so values
# containing '/', '&', etc. (e.g. secrets) never need special escaping.
set_env_file_var() {
  local key="$1" value="$2"
  local tmp found=0
  tmp="$(mktemp)"
  if [[ -f "${ENV_FILE}" ]]; then
    while IFS= read -r line || [[ -n "${line}" ]]; do
      if [[ "${line}" == "${key}="* ]]; then
        printf '%s=%s\n' "${key}" "${value}" >> "${tmp}"
        found=1
      else
        printf '%s\n' "${line}" >> "${tmp}"
      fi
    done < "${ENV_FILE}"
  fi
  if [[ "${found}" -eq 0 ]]; then
    printf '%s=%s\n' "${key}" "${value}" >> "${tmp}"
  fi
  mv "${tmp}" "${ENV_FILE}"
}

if [[ -f "${ENV_FILE}" ]]; then
  echo "# ==> Loading values from ${ENV_FILE} (env vars already set take priority)"
  while IFS='=' read -r key value; do
    [[ -z "${key}" || "${key}" == \#* ]] && continue
    # Only fill in vars this script cares about, and only if not already
    # set in the environment — an explicit `FOO=bar ./create-sanbox-az-kv.sh`
    # override must win over whatever's in the file.
    for cfg_var in "${CONFIG_VARS[@]}"; do
      if [[ "${key}" == "${cfg_var}" && -z "${!cfg_var:-}" ]]; then
        export "${key}=${value}"
      fi
    done
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}")
fi

AZURE_TENANT_ID="${AZURE_TENANT_ID:-}"
AZURE_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-Sandbox}"
AZ_RESOURCE_GROUP="${AZ_RESOURCE_GROUP:-rg-acmebot-test}"
AZ_LOCATION="${AZ_LOCATION:-australiaeast}"
AZ_KV_NAME="${AZ_KV_NAME:-acmebot-sandbox-kv}"
AZ_KV_CERT_NAME="${AZ_KV_CERT_NAME:-acmebot-sandbox-cert}"
AZ_TAG_owner_email="${AZ_TAG_owner_email:-}"
AZ_TAG_owner_platform="${AZ_TAG_owner_platform:-acmebot-letsencrypt}"
AZ_TAG_delete_after_days="${AZ_TAG_delete_after_days:-30}"
AZ_TAG_purpose="${AZ_TAG_purpose:-acmebot-testing}"
AZ_TAG_managed_by="${AZ_TAG_managed_by:-create-sanbox-az-kv.sh}"
AZ_SPN_NAME="${AZ_SPN_NAME:-sp-acmebot-test}"

# Ensure the file exists, then append a placeholder line for any config
# var not already present in it — as an active blank `KEY=` line for
# required vars with no default (so it's obvious they must be filled in),
# or as a commented-out `# KEY=<default>` documentation line for vars that
# already have a default/resolved value (uncomment + edit to override).
# Recognizes both commented and uncommented existing lines as "present" so
# a var you've deliberately commented out doesn't get re-added every run.
# Doesn't touch/reorder any existing lines.
[[ -f "${ENV_FILE}" ]] || touch "${ENV_FILE}"
missing_vars=()
for cfg_var in "${CONFIG_VARS[@]}"; do
  grep -qE "^#?[[:space:]]*${cfg_var}=" "${ENV_FILE}" || missing_vars+=("${cfg_var}")
done
if [[ ${#missing_vars[@]} -gt 0 ]]; then
  echo "# ==> Adding placeholders to ${ENV_FILE} for: ${missing_vars[*]}"
  {
    echo ""
    echo "# --- create-sanbox-az-kv.sh config (see script header for details) ---------"
    for cfg_var in "${missing_vars[@]}"; do
      current_value="${!cfg_var:-}"
      if [[ -z "${current_value}" ]]; then
        echo "${cfg_var}="
      else
        echo "# ${cfg_var}=${current_value}"
      fi
    done
  } >> "${ENV_FILE}"
fi

# No hardcoded tenant default in this script (keeps it free of any real
# tenant ID) — fail fast with a clear message rather than a confusing
# `az login` error.
if [[ -z "${AZURE_TENANT_ID}" ]]; then
  echo "ERROR: AZURE_TENANT_ID env var is required (set it in ${ENV_FILE} or export it before running)" >&2
  exit 1
fi

# This Sandbox subscription's "require-resourcegroup-tags-sandbox-policy"
# Azure Policy denies resource group creation without these tags — fail
# fast with a clear message rather than a confusing policy-denial error
# from `az group create` below.
if [[ -z "${AZ_TAG_owner_email}" ]]; then
  echo "ERROR: AZ_TAG_owner_email env var is required (must be an @eroad.com email — required by this subscription's tag policy)" >&2
  exit 1
fi
if [[ "${AZ_TAG_owner_email}" != *@eroad.com ]]; then
  echo "ERROR: AZ_TAG_owner_email must be an @eroad.com email address (got '${AZ_TAG_owner_email}')" >&2
  exit 1
fi

# `date`'s relative-date flag differs between GNU (Linux, `-d`) and BSD/macOS
# (`-v`) — try GNU syntax first, fall back to BSD syntax if that fails.
if date -u -d "+${AZ_TAG_delete_after_days} days" +%Y-%m-%d >/dev/null 2>&1; then
  delete_after_date="$(date -u -d "+${AZ_TAG_delete_after_days} days" +%Y-%m-%d)"
else
  delete_after_date="$(date -u -v+"${AZ_TAG_delete_after_days}"d +%Y-%m-%d)"
fi

# Every AZ_TAG_<key> var above becomes a "<key>=<value>" tag — add more by
# exporting further AZ_TAG_* vars of your own before running this script.
# AZ_TAG_delete_after_days is the sole exception: it's an input (number of
# days) used to compute the "date_delete_after" tag below, not a literal
# tag value itself (the policy requires a Year-Month-Date, not a day count).
common_tags=()
for var_name in "${!AZ_TAG_@}"; do
  [[ "${var_name}" == "AZ_TAG_delete_after_days" ]] && continue
  tag_key="${var_name#AZ_TAG_}"
  common_tags+=("${tag_key}=${!var_name}")
done
common_tags+=("date_delete_after=${delete_after_date}")

echo "# ==> Logging into tenant ${AZURE_TENANT_ID} (if not already)"
az account show --output none 2>/dev/null || az login --tenant "${AZURE_TENANT_ID}" --output none
az account set --subscription "${AZURE_SUBSCRIPTION_ID}"
# Overwrite with the resolved GUID (AZURE_SUBSCRIPTION_ID above may have
# been a subscription name like "Sandbox") so what gets persisted/printed
# below is always the actual subscription ID.
AZURE_SUBSCRIPTION_ID="$(az account show --query id --output tsv)"

echo "# ==> Ensuring resource group '${AZ_RESOURCE_GROUP}' exists in ${AZ_LOCATION}"
az group create \
  --name "${AZ_RESOURCE_GROUP}" \
  --location "${AZ_LOCATION}" \
  --tags "${common_tags[@]}" \
  --output none

if az keyvault show --name "${AZ_KV_NAME}" --resource-group "${AZ_RESOURCE_GROUP}" --output none 2>/dev/null; then
  echo "# ==> Key Vault '${AZ_KV_NAME}' already exists — reusing it"
  az keyvault update \
    --name "${AZ_KV_NAME}" \
    --resource-group "${AZ_RESOURCE_GROUP}" \
    --set "tags.date_delete_after=${delete_after_date}" \
    --output none
else
  echo "# ==> Creating Key Vault '${AZ_KV_NAME}' (expiry tag: ${delete_after_date})"
  az keyvault create \
    --name "${AZ_KV_NAME}" \
    --resource-group "${AZ_RESOURCE_GROUP}" \
    --location "${AZ_LOCATION}" \
    --tags "${common_tags[@]}" \
    --output none
fi

# Service principal for acme-cron-update.sh's AZURE_CLIENT_ID/
# AZURE_CLIENT_SECRET/AZURE_TENANT_ID auth fallback (see README.md). If
# AZURE_CLIENT_ID is already set, assume it's an existing SPN to reuse and
# just grant it access below — no secret to print/persist since we didn't
# create it.
spn_client_id="${AZURE_CLIENT_ID:-}"
spn_client_secret=""
if [[ -z "${spn_client_id}" ]]; then
  spn_client_id="$(az ad app list --display-name "${AZ_SPN_NAME}" --query "[0].appId" --output tsv)"
  if [[ -z "${spn_client_id}" ]]; then
    echo "# ==> Creating service principal '${AZ_SPN_NAME}'"
    az ad sp create-for-rbac --name "${AZ_SPN_NAME}" --output none
    spn_client_id="$(az ad app list --display-name "${AZ_SPN_NAME}" --query "[0].appId" --output tsv)"
  else
    echo "# ==> Service principal '${AZ_SPN_NAME}' already exists (appId ${spn_client_id}) — reusing it"
  fi
  # (Re)issue a secret with a known expiry either way, so this script always
  # has a fresh, valid secret to print/persist — credentials from a prior
  # run of this same script aren't retrievable again after the fact.
  echo "# ==> Issuing a new secret for '${AZ_SPN_NAME}' (expiry: ${delete_after_date})"
  spn_client_secret="$(az ad app credential reset \
    --id "${spn_client_id}" \
    --end-date "${delete_after_date}" \
    --query password --output tsv)"
fi

# Persist the actual resolved values into .env.acmebot (creating the file
# if it doesn't exist yet) right away — before attempting the access-grant
# step below — so a freshly-issued secret is never lost even if that step
# fails (e.g. RBAC-mode vaults rejecting `az keyvault set-policy`; see
# below). Existing lines for these keys are replaced in place;
# AZURE_CLIENT_SECRET is only written if we actually issued a new one this
# run (reusing an already-set AZURE_CLIENT_ID never yields a secret to
# persist).
[[ -f "${ENV_FILE}" ]] || touch "${ENV_FILE}"
set_env_file_var AZURE_SUBSCRIPTION_ID "${AZURE_SUBSCRIPTION_ID}"
set_env_file_var AZ_KV_NAME "${AZ_KV_NAME}"
set_env_file_var AZ_KV_CERT_NAME "${AZ_KV_CERT_NAME}"
set_env_file_var AZURE_TENANT_ID "${AZURE_TENANT_ID}"
set_env_file_var AZURE_CLIENT_ID "${spn_client_id}"
if [[ -n "${spn_client_secret}" ]]; then
  set_env_file_var AZURE_CLIENT_SECRET "${spn_client_secret}"
fi
echo "# ==> ${ENV_FILE} updated with AZURE_SUBSCRIPTION_ID/AZ_KV_NAME/AZ_KV_CERT_NAME/AZURE_TENANT_ID/AZURE_CLIENT_ID$([[ -n "${spn_client_secret}" ]] && echo "/AZURE_CLIENT_SECRET") — no manual copy/paste needed."

# Grant the service principal certificate import/get/list rights on the
# vault. Key Vaults created with `--enable-rbac-authorization` reject the
# classic access-policy API (`az keyvault set-policy` errors with "Cannot
# set policies to a vault with '--enable-rbac-authorization' specified")
# and need an RBAC role assignment instead — detect which mode this vault
# uses and grant access the right way for it.
rbac_enabled="$(az keyvault show \
  --name "${AZ_KV_NAME}" \
  --resource-group "${AZ_RESOURCE_GROUP}" \
  --query properties.enableRbacAuthorization --output tsv)"
vault_id="$(az keyvault show \
  --name "${AZ_KV_NAME}" \
  --resource-group "${AZ_RESOURCE_GROUP}" \
  --query id --output tsv)"
if [[ "${rbac_enabled}" == "true" ]]; then
  echo "# ==> Vault uses RBAC authorization — assigning 'Key Vault Certificates Officer' role to ${spn_client_id}"
  # A just-created service principal can take a little while to propagate
  # through Azure AD, so a role assignment right after creation sometimes
  # fails with "principal ... does not exist" — retry a few times.
  role_assigned=0
  for _attempt in 1 2 3 4 5; do
    if az role assignment create \
      --role "Key Vault Certificates Officer" \
      --assignee "${spn_client_id}" \
      --scope "${vault_id}" \
      --output none 2>/dev/null; then
      role_assigned=1
      break
    fi
    sleep 5
  done
  if [[ "${role_assigned}" -ne 1 ]]; then
    echo "ERROR: failed to assign 'Key Vault Certificates Officer' role to ${spn_client_id} after retries (AAD propagation delay?). Re-run this script to retry — .env.acmebot already has the credentials from this run." >&2
    exit 1
  fi
else
  echo "# ==> Granting certificate import rights to service principal ${spn_client_id}"
  az keyvault set-policy \
    --name "${AZ_KV_NAME}" \
    --spn "${spn_client_id}" \
    --certificate-permissions import get list \
    --output none
fi

# Also grant the currently signed-in user (you, running this script) rights
# to view and download the certs/secrets in this vault via the portal or
# CLI — separate from the SPN grant above, which only covers the
# container's automated access. Resolves to the signed-in user's Azure AD
# object id; if you're logged in as a service principal instead of a user
# (e.g. in CI), there's no "signed-in user" to grant, so this is skipped.
current_user_object_id="$(az ad signed-in-user show --query id --output tsv 2>/dev/null || true)"
if [[ -z "${current_user_object_id}" ]]; then
  echo "# ==> Skipping local-user access grant (not logged in as a user — e.g. running as a service principal)"
elif [[ "${rbac_enabled}" == "true" ]]; then
  for user_role in "Key Vault Certificates Officer" "Key Vault Secrets User"; do
    # Skip if already assigned (idempotent — safe to re-run this script).
    if [[ -n "$(az role assignment list --assignee "${current_user_object_id}" --role "${user_role}" --scope "${vault_id}" --query "[0].id" --output tsv 2>/dev/null)" ]]; then
      echo "# ==> '${user_role}' already assigned to current user ${current_user_object_id}"
      continue
    fi
    echo "# ==> Assigning '${user_role}' role to current user ${current_user_object_id}"
    user_role_assigned=0
    for _attempt in 1 2 3; do
      if az role assignment create \
        --role "${user_role}" \
        --assignee-object-id "${current_user_object_id}" \
        --assignee-principal-type User \
        --scope "${vault_id}" \
        --output none 2>/dev/null; then
        user_role_assigned=1
        break
      fi
      sleep 3
    done
    [[ "${user_role_assigned}" -eq 1 ]] || echo "WARNING: failed to assign '${user_role}' to current user ${current_user_object_id} — you may not be able to see/download certs & secrets in the portal. Re-run this script to retry." >&2
  done
else
  echo "# ==> Granting current user ${current_user_object_id} rights to view/download certs & secrets"
  az keyvault set-policy \
    --name "${AZ_KV_NAME}" \
    --object-id "${current_user_object_id}" \
    --certificate-permissions get list \
    --secret-permissions get list \
    --output none
fi

echo
echo "# Resource group: ${AZ_RESOURCE_GROUP} (location: ${AZ_LOCATION}, subscription: ${AZURE_SUBSCRIPTION_ID})"
echo "# Tags: ${common_tags[*]}"
echo "# (date_delete_after is a reminder only — Azure does not auto-delete on tag expiry)"

# Deleting the resource group removes everything created by this script in
# one go (vault, and anything else you've added to it since). The vault
# itself still lands in Key Vault's soft-delete state afterward though, so
# a separate purge is needed to fully release its name — do that too.
cleanup_cmd="az group delete --name ${AZ_RESOURCE_GROUP} --yes && az keyvault purge --name ${AZ_KV_NAME} --location ${AZ_LOCATION}"
echo "# To clean up later: ${cleanup_cmd}"

# Keep this reminder up to date in .env.acmebot too (replacing any prior
# one) so a local tester re-discovering this file later knows how to tear
# the throwaway resources back down.
if [[ -f "${ENV_FILE}" ]]; then
  grep -v '^# CLEANUP: ' "${ENV_FILE}" > "${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "${ENV_FILE}"
fi
echo "# CLEANUP: ${cleanup_cmd}" >> "${ENV_FILE}"
