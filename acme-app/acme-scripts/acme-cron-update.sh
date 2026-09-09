#!/usr/bin/env bash
# Cron-update alternate entrypoint (see CONTEXT.md): automated, recurring
# renewal step run by the k8s CronJob. Reads the domain list and the
# Account key, issues/renews the cert (dns-persist mode by default; see
# ACME_DNS_MODE below for a fully-automated Azure DNS API alternative that
# works with production Let's Encrypt today), then writes the cert +
# Certificate key to /certs/<primary domain> (Phase 1: local folder always)
# and, if AZ_KV_NAME is set, also imports it into Azure Key Vault via
# `az keyvault certificate import`.
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
# If neither is present, acme.sh has no registered account to issue with
# (ACME_DNS_MODE=azure below can still auto-register one on first run).
#
# Optional env vars:
#   ACME_SERVER      ACME server to target (default: letsencrypt_test).
#                    Pass letsencrypt deliberately for production — NOTE:
#                    as of this writing, no public CA (Let's Encrypt,
#                    ZeroSSL, Buypass, Google Trust Services) has shipped
#                    dns-persist-01 in production yet, only on staging
#                    (letsencrypt_test) — see https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468.
#                    For real/trusted certs today, use ACME_DNS_MODE=azure
#                    instead (works with production right now).
#   ACME_KEYLENGTH   Domain certificate key type/size passed to acme.sh's
#                    --keylength (default: 2048, i.e. RSA-2048). acme.sh
#                    itself defaults to ec-256 (EC/prime256v1) if not told
#                    otherwise, but Azure Key Vault's PFX certificate
#                    import has real, documented problems with EC-keyed
#                    certificates — RSA is forced here as the safe
#                    default. Set to e.g. "4096" for a larger RSA key, or
#                    "ec-256"/"ec-384" only if EC import is confirmed
#                    reliable for your vault.
#   RENEWAL_THRESHOLD_DAYS  (default: 30) If AZ_KV_NAME is set, this script
#                    queries Key Vault for the existing certificate's
#                    expiry before ever calling acme.sh, and skips issuance
#                    entirely if it's still valid more than this many days
#                    away. Needed because acme.sh's own skip-if-not-due
#                    logic depends on its internal ACME_HOME state, which
#                    does NOT persist across container runs in this repo's
#                    docker-compose.yml (nor, unless a PVC backs ACME_HOME,
#                    a typical k8s CronJob) — without this check every run
#                    would look like a first-ever issuance and re-issue
#                    unconditionally, burning Let's Encrypt's rate limit.
#                    NOTE: this Key Vault pre-check and the Azure DNS zone
#                    access pre-check (ACME_DNS_MODE=azure, below) always
#                    BOTH run to completion on every invocation, regardless
#                    of what the other one finds — so a broken DNS setup
#                    can't stay hidden just because Key Vault said the
#                    current cert is still valid, and vice versa. Any
#                    failure(s) from either are reported together in one
#                    combined error before exiting. Once both pass, the
#                    script prints a one-line summary of what happened
#                    (e.g. "new certificate ... added to Key Vault", "...
#                    renewed and updated...", "... force-renewed...", or
#                    "update skipped ... still valid for N days"). Also
#                    verifies the existing Key Vault certificate's SANs
#                    (subject alternative names) still match ACME_DOMAINS —
#                    a mismatch always forces re-issuance regardless of
#                    expiry (best-effort: a failed/empty SAN lookup only
#                    warns and falls back to the expiry-only decision,
#                    since AZ_KV_CERT_NAME is just a label and nothing
#                    stops ACME_DOMAINS changing later while it stays the
#                    same, which would otherwise make expiry alone "prove"
#                    the wrong domains are still covered).
#   FORCE_RENEW      (default: false) Set to "true" to bypass the Key Vault
#                    renewal check above and always issue/renew.
#   SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH  (default: false) Set to "true"
#                    for a stricter, migration-safe variant of the SAN
#                    check above: instead of only warning on a mismatch (or
#                    a missing/unverifiable SAN list) and still proceeding
#                    to issue/overwrite, any of the following becomes a
#                    hard pre-flight failure (added to the combined error
#                    report below, blocking issuance/import entirely):
#                    no existing certificate found under AZ_KV_CERT_NAME, a
#                    confirmed SAN mismatch, or the SAN lookup itself
#                    failing/returning nothing. Intended for cutting over
#                    an existing, already-in-production Key Vault
#                    certificate (issued by some other CA/process) to this
#                    script/Let's Encrypt — protects against a typo'd
#                    AZ_KV_NAME/AZ_KV_CERT_NAME or wrong ACME_DOMAINS
#                    silently creating a wrongly-named certificate or
#                    overwriting an unrelated one. Applies even when
#                    FORCE_RENEW=true is also set (this is about which
#                    certificate gets touched, not renewal timing).
#   ACME_DNS_MODE    "persist" (default) — the manual-TXT-record-once
#                    dns-persist-01 flow bootstrapped by acme-bootstrap.sh.
#                    Currently only validates on ACME_SERVER=letsencrypt_test
#                    (see note above), so certs issued this way are NOT
#                    publicly trusted until Let's Encrypt ships production
#                    support.
#                    "azure" — fully automated dns-01 via acme.sh's
#                    dns_azure plugin, using the Azure DNS zone's API
#                    directly (no persist record, no manual DNS step, ever).
#                    Works with production Let's Encrypt today. Requires
#                    AZUREDNS_SUBSCRIPTIONID/AZUREDNS_TENANTID/
#                    AZUREDNS_APPID/AZUREDNS_CLIENTSECRET (falls back to
#                    AZURE_SUBSCRIPTION_ID/AZURE_TENANT_ID/AZURE_CLIENT_ID/
#                    AZURE_CLIENT_SECRET if the AZUREDNS_* ones aren't set —
#                    reusing the same service principal as the Key Vault
#                    import below, provided it's also granted "DNS Zone
#                    Contributor" on the domain's Azure DNS zone).
#                    "aws" — fully automated dns-01 via acme.sh's dns_aws
#                    plugin, using the Route53 API directly (no persist
#                    record, no manual DNS step, ever). Works with
#                    production Let's Encrypt today. Uses the standard
#                    AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY env vars if
#                    set; otherwise falls back automatically to the
#                    container/instance IAM role (ECS task role or EC2
#                    instance profile — no vars needed at all in that
#                    case). The principal/role needs Route53
#                    ChangeResourceRecordSets/GetChange/ListHostedZones*
#                    rights on the domain's hosted zone.
#   ACME_DEBUG       Optional: passes acme.sh's own --debug flag through
#                    (1 -> --debug; 2 or 3 -> --debug 2/--debug 3 for more
#                    detail). Useful to see the raw DNS API request/response
#                    when e.g. ACME_DNS_MODE=azure fails with "Invalid
#                    domain" — usually means AZUREDNS_SUBSCRIPTIONID doesn't
#                    match the subscription that actually hosts the
#                    domain's Azure DNS zone, or the principal lacks list/
#                    read rights on it (dns_azure lists all zones in that
#                    subscription and matches by name — a wrong
#                    subscription or missing rights both look identical:
#                    the zone is simply never found). Higher levels may
#                    print secrets — local/CI troubleshooting only.
#   AZ_KV_NAME       Target Key Vault name. Phase 1: the certificate is
#                    always written to /certs/<primary domain> regardless;
#                    leave AZ_KV_NAME empty/unset to skip the Key Vault
#                    import step entirely (local-folder-only mode).
#   AZ_KV_CERT_NAME  Key Vault certificate name (default: primary domain
#                    with dots replaced by dashes). Ignored if AZ_KV_NAME
#                    is empty/unset. If set explicitly, must be a valid Key
#                    Vault object name (1-127 chars, letters/digits/dashes
#                    only) — checked up front and rejected with a clear
#                    error before any Azure calls if not.
#   KEYVAULT_CERT_TAGS  Optional, unset/empty by default. Comma and/or
#                    semicolon (with optional surrounding whitespace)
#                    separated k=v pairs, e.g. "env=prod, team=platform" or
#                    "env=prod; team=platform" (both accepted
#                    interchangeably — a tag value containing a literal
#                    comma or semicolon can't be represented this way,
#                    since it would itself be split as a separator),
#                    applied to the Key Vault certificate via `az keyvault
#                    certificate import --tags`. Ignored if AZ_KV_NAME is
#                    empty/unset. Each pair must contain a literal "=" or
#                    the script fails fast before calling `az` at all.
#   KEYVAULT_CERT_PFX_PASSWORD  Optional, unset/empty by default (a fresh
#                    random password is generated per run otherwise). Set
#                    this to a known password if you need to later export/
#                    download the PFX back out of Key Vault yourself — Key
#                    Vault keeps an imported certificate's PFX encrypted
#                    with whatever password it was imported under, and
#                    that password cannot be changed or recovered
#                    afterwards, only set at import time.
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

# Bump this manually on any change to this file — printed as the very
# first line of output below (alongside a content sha256 and a UTC
# timestamp) so a running container's actual code, and exactly when this
# run started, can both be confirmed at a glance without having to compare
# a full hash by hand.
SCRIPT_VERSION="26"

# Printed first, before anything else runs, so every run's log always
# starts with an unambiguous "what code, and when" header — useful both to
# confirm this container is actually running the code you think it is (vs.
# a stale image from a build that didn't actually pick up a source change,
# or a cached layer) and to correlate a specific run with external logs
# (Key Vault activity log, Let's Encrypt rate-limit windows, etc). sha256
# is computed from the running script itself so it can never go stale/out
# of sync the way a hand-maintained version string alone could — compare
# it against `sha256sum acme-app/acme-scripts/acme-cron-update.sh` on your
# host.
echo "==> acme-cron-update.sh version=${SCRIPT_VERSION} sha256=$(sha256sum "$0" | cut -d' ' -f1) date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Shared auth helper — used both by the Key Vault renewal pre-check (below,
# right after CERT_DIR is set) and later for the actual certificate import.
# Prefers the container's managed identity (real k8s deployment); falls
# back to an explicit service-principal login if AZURE_CLIENT_ID/
# AZURE_CLIENT_SECRET/AZURE_TENANT_ID are set — NOTE these are NOT
# auto-detected by `az` itself (unlike the Azure SDKs' DefaultAzureCredential),
# so they must be passed explicitly to `az login --service-principal` as
# done below. Returns non-zero (rather than exiting the whole script)
# if neither auth path succeeds — this lets both callers (the Key Vault
# renewal pre-check, and the later real import) decide for themselves
# whether to fail immediately or, in the pre-check's case, first collect
# this alongside the DNS zone pre-check's own result so both can be
# reported together (see the combined pre-flight-checks summary below).
azure_kv_login() {
  if az login --identity --output none 2>/dev/null; then
    echo "==> Authenticated to Azure via managed identity"
  elif [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" && -n "${AZURE_TENANT_ID:-}" ]]; then
    echo "==> Authenticating to Azure as service principal ${AZURE_CLIENT_ID}"
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
    # instead of surfacing later as an opaque "Please run az login" error.
    missing=()
    [[ -n "${AZURE_CLIENT_ID:-}" ]] || missing+=("AZURE_CLIENT_ID")
    [[ -n "${AZURE_CLIENT_SECRET:-}" ]] || missing+=("AZURE_CLIENT_SECRET")
    [[ -n "${AZURE_TENANT_ID:-}" ]] || missing+=("AZURE_TENANT_ID")
    echo "WARNING: no managed identity available and not all of AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID are set (missing: ${missing[*]}) — skipping explicit az login. Falling back to whatever az CLI session already exists in this container (likely none, in a fresh 'docker run')." >&2
  fi

  # Report failure with a clear message rather than the opaque "Please run
  # az login" error Key Vault calls would otherwise give — covers both the
  # no-auth-path-attempted case above and a service-principal login that
  # ran but failed to actually establish a session (e.g. an expired secret
  # from create-sanbox-az-kv.sh's AZ_TAG_delete_after_days expiry). Returns
  # 1 rather than exiting so callers can decide what to do (see above).
  if ! az account show --output none 2>/dev/null; then
    echo "ERROR: az CLI is not authenticated — cannot access Key Vault. Check AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID are all set and reaching this container (e.g. via --env-file .env.acmebot), and that the service principal's secret hasn't expired (re-run create-sanbox-az-kv.sh to reissue one if needed)." >&2
    return 1
  fi
}


: "${ACME_DOMAINS:?ACME_DOMAINS env var is required (comma separated list of domains)}"
: "${ACME_EMAIL:?ACME_EMAIL env var is required}"
ACME_SERVER="${ACME_SERVER:-letsencrypt_test}"
ACME_DNS_MODE="${ACME_DNS_MODE:-persist}"
# acme.sh defaults to EC-256 (DEFAULT_DOMAIN_KEY_LENGTH=ec-256) if not told
# otherwise. Force RSA-2048 instead: Azure Key Vault's PFX certificate
# import has real, documented problems with EC-keyed certificates (generic
# "BadParameter: unexpected format" errors reported by multiple users even
# with a byte-correct PKCS#12 file — see e.g.
# https://github.com/Azure/AzureKeyVault/issues/22 and
# https://learn.microsoft.com/en-us/answers/questions/1179985/), whereas
# RSA import is universally reliable. Override with ACME_KEYLENGTH if a
# different RSA size (e.g. 4096) or, once EC import is confirmed reliable
# for your vault, an EC curve (e.g. ec-256/ec-384) is genuinely needed.
ACME_KEYLENGTH="${ACME_KEYLENGTH:-2048}"

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
elif [[ ! -s "${ACCOUNT_KEY_PATH}" && "${ACME_DNS_MODE}" != "azure" && "${ACME_DNS_MODE}" != "aws" ]]; then
  # Only fatal for "persist" mode: its TXT record is tied to a specific,
  # already-registered account (from acme-bootstrap.sh), so there's no
  # account to fall back to creating here. "azure"/"aws" modes have no such
  # constraint — acme.sh registers a fresh account itself on first run if
  # none exists yet, so a missing key here is fine and not an error.
  echo "ERROR: ACME_ID_SECRET_KEY env var is not set, and no account.key found at ${ACCOUNT_KEY_PATH} (see comment above)" >&2
  exit 1
fi

IFS=',' read -r -a domain_list <<< "${ACME_DOMAINS}"
# Trim stray whitespace/CR from each domain entry. Docker's `--env-file`
# does NOT strip trailing `\r` from values — if .env.acmebot ever picks up
# CRLF line endings (e.g. saved on Windows), the last domain in the list
# silently gets a trailing `\r` baked into it. acme.sh's IDN detector
# (`_is_idn`) treats any character outside [0-9a-zA-Z*.,-_] as evidence the
# domain is an IDN and refuses to proceed without the `idn` package — so a
# stray `\r` (or an accidental leading/trailing space after a comma)
# produces a confusing "It seems that <domain> is an IDN" false positive
# for a perfectly ordinary ASCII domain.
for i in "${!domain_list[@]}"; do
  d="${domain_list[$i]//$'\r'/}"
  d="${d#"${d%%[![:space:]]*}"}"
  d="${d%"${d##*[![:space:]]}"}"
  domain_list[$i]="$d"
done
primary_domain="${domain_list[0]}"
domain_args=()
for domain in "${domain_list[@]}"; do
  [[ -n "${domain}" ]] || continue
  domain_args+=(-d "${domain}")
done

# Compute (and validate) the Key Vault certificate name up front, before the
# potentially rate-limited acme.sh --issue call below — this way a bad
# AZ_KV_CERT_NAME fails immediately instead of after a real certificate has
# already been issued/renewed against the ACME server (only to then fail at
# the Key Vault import step). Harmless to compute even if AZ_KV_NAME ends up
# unset/empty (Key Vault import skipped entirely) since it's cheap and pure.
AZ_KV_CERT_NAME="${AZ_KV_CERT_NAME:-${primary_domain//./-}}"
# Key Vault object names must match ^[0-9a-zA-Z-]+$ (letters, digits, dashes
# only — no dots, underscores, or wildcards) and be 1-127 chars. The default
# above already replaces dots with dashes, but an explicit AZ_KV_CERT_NAME
# override (e.g. still containing a domain's dots) would otherwise only
# surface as an opaque "BadParameter: The request URI contains an invalid
# name" from the `az` call itself.
if [[ ! "${AZ_KV_CERT_NAME}" =~ ^[0-9a-zA-Z-]{1,127}$ ]]; then
  echo "ERROR: AZ_KV_CERT_NAME '${AZ_KV_CERT_NAME}' is not a valid Key Vault certificate name" >&2
  echo "       (must be 1-127 chars, letters/digits/dashes only — no dots, underscores, or wildcards)" >&2
  exit 1
fi

CERT_DIR="/certs/${primary_domain}"
mkdir -p "${CERT_DIR}"

# Skip re-issuing entirely if Key Vault already holds a still-valid
# certificate under this name. This matters because acme.sh's own
# skip-if-not-due renewal logic relies on its *own* state directory
# (ACME_HOME, default /acme.cert.store) to remember when a domain was last
# issued — and per docker-compose.yml (and, unless a PVC backs ACME_HOME in
# the real k8s CronJob too) that directory is NOT persisted across
# container runs. Without this check, every single run would look like a
# brand new domain to acme.sh and re-issue unconditionally — which is
# exactly what caused the Let's Encrypt production rate-limit hit earlier
# (see README Troubleshooting). Key Vault itself, however, IS persistent
# and authoritative, so ask it directly instead.
#
# NOTE: this only records its outcome in kv_check_error/kv_skip_renewal/
# kv_found/kv_expires/kv_days_remaining below — it deliberately does NOT
# exit here, even when the cert turns out to still be valid. That's so the
# DNS zone pre-check (below, for ACME_DNS_MODE=azure) still always runs
# too, and both pre-checks' results get reported together — otherwise a
# broken DNS setup would stay hidden on every run where the KV check alone
# would have skipped, only to surface as a surprise failure on the one run
# where a real renewal was actually due.
RENEWAL_THRESHOLD_DAYS="${RENEWAL_THRESHOLD_DAYS:-30}"
FORCE_RENEW="${FORCE_RENEW:-false}"
SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH="${SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH:-false}"
kv_check_error=""
kv_skip_renewal=false
kv_found=false
kv_expires=""
kv_days_remaining=""
kv_sans_mismatch=false
kv_sans_verified=false
kv_sans_normalized=""
requested_normalized=""
if [[ -n "${AZ_KV_NAME:-}" ]]; then
  if ! azure_kv_login; then
    kv_check_error="unable to authenticate to Azure (see error above)"
  elif [[ "${FORCE_RENEW}" == "true" && "${SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH}" != "true" ]]; then
    echo "==> FORCE_RENEW=true: skipping the Key Vault renewal check, issuing/renewing unconditionally"
  else
    if [[ "${FORCE_RENEW}" == "true" ]]; then
      echo "==> FORCE_RENEW=true, but SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH=true: still checking Key Vault '${AZ_KV_NAME}' for an existing certificate's domains before issuing (the renewal-skip decision itself is bypassed by FORCE_RENEW; only the safety check below still runs)..."
    else
      echo "==> Checking Key Vault '${AZ_KV_NAME}' for an existing, still-valid certificate '${AZ_KV_CERT_NAME}' before issuing..."
    fi
    # Capture stdout+stderr together (rather than discarding stderr) so a
    # real query failure — most commonly the identity having
    # "import"/"create" rights but NOT "get" on certificates, which is an
    # easy split to get wrong when assigning Key Vault access policies/RBAC
    # — is distinguishable from the cert genuinely not existing yet (a 404,
    # which is the normal/expected case on a brand new cert name). Getting
    # this distinction wrong is exactly what silently defeated this whole
    # check before: a permission error looked identical to "not found",
    # so every run re-issued unconditionally even right after a successful
    # import, never actually skipping.
    kv_show_output="$(az keyvault certificate show --vault-name "${AZ_KV_NAME}" --name "${AZ_KV_CERT_NAME}" --query "attributes.expires" -o tsv 2>&1)" && kv_show_status=0 || kv_show_status=$?
    if [[ ${kv_show_status} -ne 0 ]]; then
      if [[ "${kv_show_output}" == *"not be found"* || "${kv_show_output}" == *"CertificateNotFound"* || "${kv_show_output}" == *"was not found"* ]]; then
        kv_expires=""
        echo "==> No existing certificate '${AZ_KV_CERT_NAME}' found in Key Vault '${AZ_KV_NAME}' — proceeding with issuance (this is expected for a brand new certificate name)."
      else
        # Anything else (permission denied, network error, vault not found,
        # etc.) is NOT the same as "doesn't exist yet" — surface it as a
        # real pre-check failure rather than silently guessing "not found"
        # and re-issuing every single run without ever actually skipping.
        kv_check_error="failed to query Key Vault '${AZ_KV_NAME}' for certificate '${AZ_KV_CERT_NAME}': ${kv_show_output}. If this looks like a permission error, check the identity has the Key Vault 'Certificates - Get' right (import/create rights alone are NOT enough for this read-only check to work — see README Troubleshooting)."
      fi
    else
      kv_expires="${kv_show_output}"
    fi
    kv_expires_epoch=""
    [[ -n "${kv_expires}" ]] && kv_expires_epoch="$(date -d "${kv_expires}" +%s 2>/dev/null || true)"
    if [[ -n "${kv_expires_epoch}" ]]; then
      kv_found=true
      now_epoch="$(date +%s)"
      kv_days_remaining=$(( (kv_expires_epoch - now_epoch) / 86400 ))
      threshold_epoch=$(( now_epoch + RENEWAL_THRESHOLD_DAYS * 86400 ))

      # Also verify the SANs on the *existing* Key Vault certificate still
      # match the domains actually being requested this run, before trusting
      # its expiry alone to decide whether to skip issuance. AZ_KV_CERT_NAME
      # is just a fixed label (defaulted from the primary domain, but often
      # overridden to something static/unrelated — e.g. a name like
      # 'acme-cert-wildcard-example' for a *.example.com domain) — nothing
      # stops ACME_DOMAINS from being changed later while
      # AZ_KV_CERT_NAME stays the same, which would otherwise make this
      # check happily skip issuance forever using an unrelated cert's
      # expiry as "proof" the (wrong) domains are covered.
      #
      # Best-effort by default: a failure/empty result here does NOT block
      # the expiry-based decision below (older certs, or an unexpected Key
      # Vault policy shape, might not have a queryable SAN list) — it only
      # warns, unless SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH=true (see below,
      # after this check), which turns an unverifiable/mismatched result
      # into a hard failure instead. A SUCCESSFULLY DETECTED mismatch always
      # forces a real re-issuance regardless of how far away the expiry is
      # (unless the safety flag blocks it entirely first), since that's the
      # actual bug this check exists to catch.
      kv_sans_csv="$(az keyvault certificate show --vault-name "${AZ_KV_NAME}" --name "${AZ_KV_CERT_NAME}" --query "join(',', policy.x509CertificateProperties.subjectAlternativeNames.dnsNames)" -o tsv 2>&1)" && kv_sans_status=0 || kv_sans_status=$?
      if [[ ${kv_sans_status} -eq 0 && -n "${kv_sans_csv}" ]]; then
        kv_sans_verified=true
        kv_sans_normalized="$(echo "${kv_sans_csv}" | tr ',' '\n' | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u | paste -sd, -)"
        requested_normalized="$(printf '%s\n' "${domain_list[@]}" | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd, -)"
        if [[ "${kv_sans_normalized}" != "${requested_normalized}" ]]; then
          kv_sans_mismatch=true
          echo "==> WARNING: Key Vault certificate '${AZ_KV_CERT_NAME}' covers a different domain set than requested — stored SANs: [${kv_sans_normalized}], requested ACME_DOMAINS: [${requested_normalized}]. Forcing re-issuance regardless of expiry (likely ACME_DOMAINS changed, or AZ_KV_CERT_NAME is reused across unrelated domains)."
        else
          echo "==> Key Vault certificate '${AZ_KV_CERT_NAME}' SANs confirmed to match requested domains: [${kv_sans_normalized}]."
        fi
      else
        echo "==> Could not verify Key Vault certificate '${AZ_KV_CERT_NAME}''s domain list (SANs) against ACME_DOMAINS (${kv_sans_csv:-no policy/SANs returned}) — proceeding based on expiry alone."
      fi

      if [[ "${FORCE_RENEW}" == "true" ]]; then
        : # renewal-skip decision doesn't apply under FORCE_RENEW — only the
          # SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH gate below still applies.
      elif [[ "${kv_sans_mismatch}" == "true" ]]; then
        : # fall through below: kv_skip_renewal stays false, issuance proceeds
      elif [[ "${kv_expires_epoch}" -gt "${threshold_epoch}" ]]; then
        kv_skip_renewal=true
        echo "==> Key Vault certificate '${AZ_KV_CERT_NAME}' is still valid until ${kv_expires} (${kv_days_remaining} days away, more than ${RENEWAL_THRESHOLD_DAYS}-day threshold) — will skip issuance once the DNS zone pre-check below also completes. Set FORCE_RENEW=true to override, or lower RENEWAL_THRESHOLD_DAYS."
      else
        echo "==> Key Vault certificate '${AZ_KV_CERT_NAME}' expires ${kv_expires} (${kv_days_remaining} days away) — within ${RENEWAL_THRESHOLD_DAYS} days, proceeding with renewal."
      fi
    elif [[ -z "${kv_check_error}" && -n "${kv_expires}" ]]; then
      echo "==> Key Vault certificate '${AZ_KV_CERT_NAME}' found but its expiry ('${kv_expires}') could not be parsed as a date — proceeding with issuance."
    fi
  fi

  # SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH: optional, "false" by default.
  # Aimed at migrating existing, already-in-production certificates in Key
  # Vault (issued by some other CA/process) over to this script/Let's
  # Encrypt: it's easy to get AZ_KV_CERT_NAME or ACME_DOMAINS subtly wrong
  # on that first cutover run (typo, wrong vault, copy-paste from the wrong
  # environment, ...), and the normal behavior above is deliberately
  # permissive — a SAN mismatch only warns and still re-issues/overwrites,
  # and a brand new cert name is treated as the expected, normal case. That
  # permissiveness is wrong for a migration: overwriting a real, currently
  # trusted production certificate under the wrong name (or writing a
  # first-ever cert under a name that was supposed to already exist) can
  # take a production endpoint down. When this flag is "true", the checks
  # above are unchanged (same messages/logging), but this additional gate
  # turns three specific outcomes into a hard pre-flight failure — added to
  # the same combined error report as the Key Vault/DNS pre-checks below,
  # so nothing is ever issued or imported this run — instead of silently
  # proceeding:
  #   - no existing certificate found at all under AZ_KV_CERT_NAME (can't
  #     confirm a match against something that doesn't exist).
  #   - a confirmed SAN mismatch (the exact case the check above already
  #     warns about, just escalated to fatal here).
  #   - the SAN lookup itself failed/returned nothing (can't confirm a
  #     match either way).
  # Applies even when FORCE_RENEW=true is also set (see above) — safety
  # here is about *which* certificate gets touched, not renewal timing, so
  # FORCE_RENEW is not allowed to bypass it.
  if [[ "${SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH}" == "true" && -z "${kv_check_error}" ]]; then
    if [[ "${kv_found}" != "true" ]]; then
      kv_check_error="SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH=true but no existing certificate '${AZ_KV_CERT_NAME}' was found in Key Vault '${AZ_KV_NAME}' to verify against — refusing to blindly create/overwrite it. Unset SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH to allow issuing a brand new certificate under this name, or double check AZ_KV_NAME/AZ_KV_CERT_NAME point at the certificate you intend to migrate."
    elif [[ "${kv_sans_mismatch}" == "true" ]]; then
      kv_check_error="SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH=true and the existing Key Vault certificate '${AZ_KV_CERT_NAME}' covers a different domain set than requested (stored SANs: [${kv_sans_normalized}], requested ACME_DOMAINS: [${requested_normalized}]) — refusing to overwrite it. Double check AZ_KV_CERT_NAME/ACME_DOMAINS point at the certificate you intend to migrate before unsetting this flag."
    elif [[ "${kv_sans_verified}" != "true" ]]; then
      kv_check_error="SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH=true but the existing Key Vault certificate '${AZ_KV_CERT_NAME}''s domain list (SANs) could not be verified against ACME_DOMAINS — refusing to update it without that confirmation. Unset SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH to proceed anyway, once you've manually confirmed this is the right certificate."
    fi
  fi
fi

# Build the DNS validation flag(s) for this mode. "azure" needs acme.sh's
# native AZUREDNS_* var names; "aws" needs the standard AWS_ACCESS_KEY_ID/
# AWS_SECRET_ACCESS_KEY names (or no vars at all, via IAM role — see below).
# AZUREDNS_SUBSCRIPTIONID is always required;
# beyond that there are two auth options (acme.sh's dns_azure plugin talks
# to Azure directly — no `az` CLI/login involved here, unlike the Key Vault
# step below):
#   - AZUREDNS_MANAGEDIDENTITY=true — real k8s deployment: the pod's
#     managed identity is used (no secret at all); AZUREDNS_TENANTID/
#     AZUREDNS_APPID/AZUREDNS_CLIENTSECRET are not needed/read in this mode.
#   - otherwise, service-principal auth: AZUREDNS_TENANTID/AZUREDNS_APPID/
#     AZUREDNS_CLIENTSECRET are all required (a real secret — NOT something
#     acme.sh generates or receives; you must create/provide it, e.g. via
#     `az ad sp create-for-rbac`). Falls back to the same AZURE_* creds used
#     for the Key Vault import below if the AZUREDNS_*-specific ones aren't
#     set separately (only sensible if that principal is ALSO granted "DNS
#     Zone Contributor" on the domain's Azure DNS zone; a distinct, more
#     narrowly scoped principal is safer and can be supplied via the
#     AZUREDNS_* vars instead without touching AZURE_*).
dns_check_error=""
case "${ACME_DNS_MODE}" in
  persist)
    dns_args=(--dns-persist)
    ;;
  azure)
    : "${AZUREDNS_SUBSCRIPTIONID:=${AZURE_SUBSCRIPTION_ID:-}}"
    : "${AZUREDNS_SUBSCRIPTIONID:?ACME_DNS_MODE=azure requires AZUREDNS_SUBSCRIPTIONID (or AZURE_SUBSCRIPTION_ID) to be set}"
    export AZUREDNS_SUBSCRIPTIONID
    if [[ "${AZUREDNS_MANAGEDIDENTITY:-false}" == "true" ]]; then
      echo "==> Using Azure managed identity for DNS validation (AZUREDNS_MANAGEDIDENTITY=true) — no client secret needed"
      export AZUREDNS_MANAGEDIDENTITY
    else
      : "${AZUREDNS_TENANTID:=${AZURE_TENANT_ID:-}}"
      : "${AZUREDNS_APPID:=${AZURE_CLIENT_ID:-}}"
      : "${AZUREDNS_CLIENTSECRET:=${AZURE_CLIENT_SECRET:-}}"
      : "${AZUREDNS_TENANTID:?ACME_DNS_MODE=azure requires AZUREDNS_TENANTID (or AZURE_TENANT_ID), or AZUREDNS_MANAGEDIDENTITY=true, to be set}"
      : "${AZUREDNS_APPID:?ACME_DNS_MODE=azure requires AZUREDNS_APPID (or AZURE_CLIENT_ID), or AZUREDNS_MANAGEDIDENTITY=true, to be set}"
      : "${AZUREDNS_CLIENTSECRET:?ACME_DNS_MODE=azure requires AZUREDNS_CLIENTSECRET (or AZURE_CLIENT_SECRET), or AZUREDNS_MANAGEDIDENTITY=true, to be set}"
      export AZUREDNS_TENANTID AZUREDNS_APPID AZUREDNS_CLIENTSECRET
    fi
    dns_args=(--dns dns_azure)

    # Fail fast, before ever calling acme.sh (and burning a Let's Encrypt
    # rate-limit attempt), if this identity can't actually see the Azure DNS
    # zone(s) needed for the requested domain(s). acme.sh's dns_azure plugin
    # itself only reports this late and opaquely — "Invalid domain" /
    # "invalid domain" after it's already tried and failed to add the TXT
    # record — this reproduces the same subscription-wide zone-list call
    # dns_azure uses internally, and matches it against each requested
    # domain by suffix (the exact same logic dns_azure uses), so a missing
    # zone or missing rights surfaces immediately and clearly here instead.
    echo "==> Verifying Azure DNS zone access for: ${ACME_DOMAINS}"
    if [[ "${AZUREDNS_MANAGEDIDENTITY:-false}" == "true" ]]; then
      az login --identity --output none
    else
      az login --service-principal \
        -u "${AZUREDNS_APPID}" \
        -p "${AZUREDNS_CLIENTSECRET}" \
        --tenant "${AZUREDNS_TENANTID}" \
        --output none
    fi || dns_check_error="failed to authenticate to Azure for the DNS zone access check. Check AZUREDNS_TENANTID/AZUREDNS_APPID/AZUREDNS_CLIENTSECRET (or AZUREDNS_MANAGEDIDENTITY=true) are correct."

    if [[ -z "${dns_check_error}" ]]; then
      # Resolve exactly which identity we just authenticated as, so it can be
      # printed alongside any failure below — makes it trivial to go check
      # (in the Azure Portal or via `az role assignment list --assignee
      # <this-value>`) whether *this specific* identity actually has a role
      # assignment on the DNS zone/resource group, instead of having to
      # cross-reference AZUREDNS_APPID/managed-identity config by hand.
      dns_identity="$(az account show --query user.name -o tsv 2>/dev/null || echo "unknown")"
      # Also resolve its human-readable display name (the SPN/app name, or
      # the managed identity's resource name) via Microsoft Graph, purely for
      # readability in the messages below — this requires the identity to
      # have Graph read rights (e.g. Application.Read.All, or just being able
      # to read its own service principal, which is on by default for most
      # SPs), so it's best-effort: silently falls back to "unknown" without
      # failing the whole check if this identity can't read its own SPN.
      dns_identity_name="$(az ad sp show --id "${dns_identity}" --query displayName -o tsv 2>/dev/null || echo "unknown")"

      if ! zone_names="$(az network dns zone list --subscription "${AZUREDNS_SUBSCRIPTIONID}" --query "[].name" -o tsv 2>&1)"; then
        dns_check_error="failed to list Azure DNS zones in subscription '${AZUREDNS_SUBSCRIPTIONID}' as identity '${dns_identity}' (SPN name: '${dns_identity_name}') — this identity likely lacks 'Reader' rights on the resource group (or subscription) hosting the zone (dns_azure needs to list ALL zones to find a suffix match; a role scoped only to the zone itself is NOT enough for this list call to succeed). Azure response: ${zone_names}"
      fi
    fi

    if [[ -z "${dns_check_error}" ]]; then
      missing_zone_domains=()
      for domain in "${domain_list[@]}"; do
        bare_domain="${domain#\*.}"
        matched=0
        while IFS= read -r zone; do
          [[ -n "${zone}" ]] || continue
          if [[ "${bare_domain}" == "${zone}" || "${bare_domain}" == *".${zone}" ]]; then
            matched=1
            break
          fi
        done <<< "${zone_names}"
        [[ "${matched}" -eq 1 ]] || missing_zone_domains+=("${domain}")
      done

      if [[ "${#missing_zone_domains[@]}" -gt 0 ]]; then
        zone_names_csv="$(echo "${zone_names}" | tr '\n' ',' | sed 's/,$//')"
        dns_check_error="no accessible Azure DNS zone found for: ${missing_zone_domains[*]} (subscription ${AZUREDNS_SUBSCRIPTIONID}, identity '${dns_identity}', SPN name: '${dns_identity_name}'). Either the zone doesn't exist in this subscription, AZUREDNS_SUBSCRIPTIONID points at the wrong subscription, or this identity lacks 'Reader' on the zone's resource group — see README Troubleshooting for the exact role assignments needed. Zones this identity CAN see in this subscription: ${zone_names_csv:-<none>}"
      fi
    fi

    if [[ -z "${dns_check_error}" ]]; then
      echo "==> Azure DNS zone access confirmed for: ${ACME_DOMAINS} (identity '${dns_identity}', SPN name: '${dns_identity_name}')"
    fi
    ;;
  aws)
    # acme.sh's dns_aws plugin uses the standard AWS_ACCESS_KEY_ID/
    # AWS_SECRET_ACCESS_KEY env var names directly (no ACMEBOT-specific
    # prefix needed, unlike Azure's AZUREDNS_* naming) — talks to the
    # Route53 API directly, no `aws` CLI/login involved. If both are set,
    # use them; otherwise the plugin itself falls back automatically to the
    # container/instance IAM role (ECS task role or EC2 instance profile
    # via IMDS) with no vars needed at all, so nothing is required here.
    if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
      echo "==> Using AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY for DNS validation (Route53)"
      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
    else
      echo "==> No AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY set — relying on the container/instance IAM role for DNS validation (Route53)"
    fi
    dns_args=(--dns dns_aws)
    ;;
  *)
    echo "ERROR: unknown ACME_DNS_MODE '${ACME_DNS_MODE}' — must be 'persist', 'azure', or 'aws'" >&2
    exit 1
    ;;
esac

# Combined pre-flight report: both the Key Vault renewal check (above,
# right after CERT_DIR was set) and the Azure DNS zone access check (above,
# in the "azure" case) always run to completion regardless of what the
# other one found, specifically so a broken DNS setup can't stay hidden on
# every run where the Key Vault check alone would have skipped issuance —
# and, conversely, so an expired/misconfigured Key Vault credential is
# reported even on a run where DNS access is fine. Report anything either
# one found together, then decide what to do next.
precheck_errors=()
[[ -n "${kv_check_error}" ]] && precheck_errors+=("Key Vault pre-check: ${kv_check_error}")
[[ -n "${dns_check_error}" ]] && precheck_errors+=("DNS zone pre-check: ${dns_check_error}")
if [[ "${#precheck_errors[@]}" -gt 0 ]]; then
  echo "ERROR: ${#precheck_errors[@]} pre-flight check(s) failed for ${primary_domain}:" >&2
  for e in "${precheck_errors[@]}"; do
    echo "  - ${e}" >&2
  done
  exit 1
fi

# Both pre-checks passed. If the Key Vault check found a still-valid
# certificate (and FORCE_RENEW wasn't set), skip issuance now — this is the
# only place that decision takes effect, deliberately deferred until here
# so the DNS check above always got a chance to run and report first.
if [[ "${kv_skip_renewal}" == "true" ]]; then
  echo "==> Summary: update skipped for ${primary_domain} — certificate '${AZ_KV_CERT_NAME}' in Key Vault '${AZ_KV_NAME}' is still valid for ${kv_days_remaining} days (until ${kv_expires})."
  exit 0
fi

# Optional: pass acme.sh's own --debug flag through for troubleshooting (e.g. a
# DNS API "Invalid domain"/auth failure that needs the raw REST request/response
# to diagnose). ACME_DEBUG=1 (or unset) -> --debug; ACME_DEBUG=2/3 -> --debug 2/3
# for progressively more verbose output (may print secrets — local/CI use only).
debug_args=()
if [[ -n "${ACME_DEBUG:-}" ]]; then
  if [[ "${ACME_DEBUG}" == "1" ]]; then
    debug_args=(--debug)
  else
    debug_args=(--debug "${ACME_DEBUG}")
  fi
fi

echo "==> Issuing/renewing certificate for: ${ACME_DOMAINS} (ACME_DNS_MODE=${ACME_DNS_MODE}, server: ${ACME_SERVER})"
acme.sh --config-home "${ACME_HOME:-/acme.cert.store}" \
  --issue \
  --server "${ACME_SERVER}" \
  --email "${ACME_EMAIL}" \
  --keylength "${ACME_KEYLENGTH}" \
  "${dns_args[@]}" \
  "${domain_args[@]}" \
  "${debug_args[@]}" \
  --fullchain-file "${CERT_DIR}/fullchain.pem" \
  --key-file "${CERT_DIR}/key.pem"

# Print the full chain's subject/issuer for every cert in fullchain.pem, in
# order (leaf -> intermediate -> ... ), so you can eyeball which root this
# chain ultimately signs back to. This matters because `ACME_SERVER=letsencrypt`
# (production) chains to the real, universally-trusted "ISRG Root X1", but
# `letsencrypt_test` (staging, used above while iterating to avoid rate
# limits) chains to a *different*, untrusted "(STAGING) ..." root instead —
# so a chain check here only tells you anything meaningful once you're
# actually running against production. fullchain.pem has no depth/count
# metadata, so we split it into individual PEM blocks with awk and print
# each one's subject/issuer via openssl.
echo "==> Certificate chain for ${primary_domain} (leaf -> root):"
awk '/-----BEGIN CERTIFICATE-----/{n++} {print > ("'"${CERT_DIR}"'/.chain-" n ".pem")} /-----END CERTIFICATE-----/{close("'"${CERT_DIR}"'/.chain-" n ".pem")}' \
  "${CERT_DIR}/fullchain.pem"
depth=0
last_issuer=""
for chain_cert in "${CERT_DIR}"/.chain-*.pem; do
  [[ -f "${chain_cert}" ]] || continue
  depth=$((depth + 1))
  cert_info="$(openssl x509 -noout -subject -issuer -in "${chain_cert}")"
  last_issuer="$(echo "${cert_info}" | sed -n 's/^issuer=//p')"
  echo "  [${depth}] $(echo "${cert_info}" | tr '\n' ' ')"
done
rm -f "${CERT_DIR}"/.chain-*.pem
echo "==> Verify the final [${depth}] entry's issuer above is 'ISRG Root X1' before trusting this chain in production (it will instead say '(STAGING) ...' while ACME_SERVER=letsencrypt_test)."

# SAFETY_ALERT_IF_ROOT_CA_NOT: optional, unset/empty by default (opt-in).
# If set to a substring (e.g. "CN=ISRG Root X1", Let's Encrypt production's
# trust anchor), fails fast here — before wasting time on a Key Vault
# import — if the final chain entry's issuer doesn't contain it. Useful as
# a guard rail once you're confident you want production only (the issuer
# string may be prefixed or contain other RDNs depending on cross-sign
# chain length, so this is a substring match, not exact equality). Leave
# unset while iterating against ACME_SERVER=letsencrypt_test (staging),
# whose chain never contains "ISRG Root X1" — this check would otherwise
# always fail. Comparison strips all whitespace from both sides first:
# `openssl x509 -issuer` formats RDNs as either "CN=X" or "CN = X" (with
# spaces around "=") depending on the openssl build/version, and a
# straight substring match would otherwise be brittle to that difference.
SAFETY_ALERT_IF_ROOT_CA_NOT="${SAFETY_ALERT_IF_ROOT_CA_NOT:-}"
if [[ -n "${SAFETY_ALERT_IF_ROOT_CA_NOT}" ]]; then
  last_issuer_nospace="${last_issuer// /}"
  safety_alert_root_ca_nospace="${SAFETY_ALERT_IF_ROOT_CA_NOT// /}"
  if [[ "${last_issuer_nospace}" != *"${safety_alert_root_ca_nospace}"* ]]; then
    echo "ERROR: certificate chain for ${primary_domain} does not link back to the expected root CA. Final [${depth}] entry's issuer is '${last_issuer}', expected it to contain '${SAFETY_ALERT_IF_ROOT_CA_NOT}'. Unset SAFETY_ALERT_IF_ROOT_CA_NOT to disable this check (e.g. when deliberately testing against ACME_SERVER=letsencrypt_test)." >&2
    exit 1
  fi
fi

# `az keyvault certificate import` accepts PEM or PFX (PKCS#12). We used to
# hand-build a PEM (PKCS#8 key + fullchain, in that exact order — see git
# history if you need the gory details of what breaks when you get the
# format/order wrong). A single PFX is less to get wrong: openssl bundles
# the chain and key into one binary file itself, so there's no manual
# concatenation or ordering to mess up, and no separate PKCS#1->PKCS#8 key
# conversion (acme.sh's own `--to-pkcs12` is this exact same openssl
# command, just writing to acme.sh's internal per-domain directory instead
# of ours, so we run it ourselves and skip the extra indirection).
#
# -legacy: OpenSSL 3.x defaults to PBES2/AES-256 for PKCS#12, which Azure
# Key Vault (and Windows CryptoAPI generally) can't read. Our first attempt
# at fixing this manually forced `-keypbe/-certpbe PBE-SHA1-3DES` (3DES for
# BOTH the cert and key bags) — that still failed identically against a
# real Key Vault. `-legacy` instead reproduces openssl 1.x's actual
# historical default combo: pbeWithSHA1And40BitRC2-CBC for the CERT bag,
# pbeWithSHA1And3-KeyTripleDES-CBC for the KEY bag (verified via `openssl
# pkcs12 -legacy -info -noout`) — this is the specific combination Windows
# CryptoAPI/Key Vault's PFX parser expects; using 3DES for the cert bag
# (as we did before) apparently isn't recognized the same way even though
# it's still valid PKCS#12. See https://words.filippo.io/pkcs12-pbes2-cng/.
# Requires this container's openssl to have the legacy provider available;
# if it doesn't, this fails loudly and immediately here instead of
# producing a subtly-wrong file that only fails later at Key Vault.
#
# A real (non-empty) password is required here, confirmed against a real
# Key Vault: both no --password at all AND --password "" (empty string)
# fail identically with "BadParameter: The specified PEM X.509 certificate
# content is in an unexpected format" — Key Vault's import API apparently
# treats an empty string the same as "no password", and then misparses a
# genuine PKCS#12 file as PEM. By default generated fresh per run and used
# only in-process (never written to disk or logged) since it protects
# nothing real — the PFX exists only transiently in this container before
# import. Optionally overridden by KEYVAULT_CERT_PFX_PASSWORD (unset/empty
# falls back to the random default, same as leaving it unset entirely) —
# useful if you need a known, reproducible password to later `az keyvault
# secret download`/export the PFX back out of Key Vault yourself (Key
# Vault stores an imported certificate's PFX as a linked secret, still
# encrypted with the password it was imported with — there is no way to
# change or clear that password after import, so this only helps for
# certs imported from here on).
PFX_PASSWORD="${KEYVAULT_CERT_PFX_PASSWORD:-$(openssl rand -base64 24)}"
openssl pkcs12 -export -legacy -passout "pass:${PFX_PASSWORD}" \
  -inkey "${CERT_DIR}/key.pem" \
  -in "${CERT_DIR}/fullchain.pem" \
  -out "${CERT_DIR}/full.pfx"

# Sanity-check the PFX this container's own openssl just produced is
# actually readable, *before* handing it to `az` — if this container's
# openssl build can't even parse its own output back (e.g. the legacy
# provider needed for `-legacy`/RC2-40 isn't available/registered here,
# silently producing a malformed file instead of erroring) that's the real
# problem, not anything on Key Vault's side. Print openssl's own
# subject/issuer/serial parse as proof the file is sound. `-legacy` is
# needed again here too, to decrypt the RC2-40-encrypted cert bag.
echo "==> Verifying generated PFX (openssl $(openssl version)):"
openssl pkcs12 -legacy -in "${CERT_DIR}/full.pfx" -passin "pass:${PFX_PASSWORD}" -nodes 2>&1 \
  | openssl x509 -noout -subject -issuer -serial

if [[ -z "${AZ_KV_NAME:-}" ]]; then
  echo "==> AZ_KV_NAME not set: skipping Key Vault import, certificate left in ${CERT_DIR}"
  echo "==> Summary: certificate for ${primary_domain} issued/renewed locally only (${CERT_DIR}) — AZ_KV_NAME not set, no Key Vault import."
  exit 0
fi
# AZ_KV_CERT_NAME was already computed and format-validated up front (see
# above, before the acme.sh --issue call) — nothing more to do here.
# (version/sha256/date header was already printed as the very first line
# of output, right after set -euo pipefail — see top of file.)

# Already authenticated to Azure above (azure_kv_login, called during the
# Key Vault renewal check right after CERT_DIR was set) — that call is
# unconditional whenever AZ_KV_NAME is set (this section is only reached
# at all when AZ_KV_NAME is set, since the check above exits early
# otherwise), so no need to log in again here.

echo "==> Importing certificate into Key Vault '${AZ_KV_NAME}' as '${AZ_KV_CERT_NAME}'"
# --password must be the real, non-empty password the PFX was exported with
# above (PFX_PASSWORD).
#
# --policy: THE ACTUAL FIX for "BadParameter: The specified PEM X.509
# certificate content is in an unexpected format" persisting across every
# combination of password/PBE-algorithm/key-type we tried. Root cause: Azure
# Key Vault stores a certificate *policy* (including
# secret_properties.content_type) per certificate NAME, and every import of
# a new *version* under that same name reuses the EXISTING policy unless a
# new one is explicitly supplied (undocumented on the API, confirmed via
# https://winterdom.com/2019/10/31/importing-keyvault-certificates-api and
# https://stackoverflow.com/questions/77954676/azure-certificate-import-bad-parameter).
# If any earlier import under this cert name ever got recorded with
# content_type=application/x-pem-file (e.g. from early hand-built-PEM
# attempts), Key Vault keeps trying to parse every subsequent PFX as PEM —
# which fails with this exact generic error — no matter how correct the PFX
# itself is. Passing --policy here forces content_type back to
# application/x-pkcs12 on every import, regardless of what an earlier
# version's policy said.
#
# KEYVAULT_CERT_TAGS: optional, unset/empty by default. Comma and/or
# semicolon (with optional surrounding whitespace) separated k=v pairs,
# e.g. "env=prod, team=platform" or "env=prod; team=platform" (both
# separators are accepted interchangeably — NOTE this means a tag value
# containing a literal comma or semicolon cannot be represented this way,
# since it would itself be split as a separator) — passed through to
# `az keyvault certificate import --tags`, which itself expects one or
# more space-separated k=v arguments (neither comma nor semicolon
# separated), so we split/trim/re-join here. Each pair must contain a
# literal "=" or the script fails fast below with a clear error, before
# ever calling `az`, rather than sending a malformed --tags argument and
# getting an opaque az/API error back.
import_args=(
  --vault-name "${AZ_KV_NAME}"
  --name "${AZ_KV_CERT_NAME}"
  --file "${CERT_DIR}/full.pfx"
  --password "${PFX_PASSWORD}"
  --policy '{"secret_properties":{"content_type":"application/x-pkcs12"}}'
  --output none
)
KEYVAULT_CERT_TAGS="${KEYVAULT_CERT_TAGS:-}"
if [[ -n "${KEYVAULT_CERT_TAGS}" ]]; then
  tag_args=()
  IFS=',;' read -ra tag_pairs <<< "${KEYVAULT_CERT_TAGS}"
  for pair in "${tag_pairs[@]}"; do
    # Trim leading/trailing whitespace from around each separated pair.
    pair="${pair#"${pair%%[![:space:]]*}"}"
    pair="${pair%"${pair##*[![:space:]]}"}"
    [[ -z "${pair}" ]] && continue
    if [[ "${pair}" != *=* ]]; then
      echo "ERROR: KEYVAULT_CERT_TAGS entry '${pair}' is not a valid k=v pair (expected e.g. \"env=prod, team=platform\" or \"env=prod; team=platform\")." >&2
      exit 1
    fi
    tag_args+=("${pair}")
  done
  if [[ ${#tag_args[@]} -gt 0 ]]; then
    echo "==> Tagging Key Vault certificate with: ${tag_args[*]}"
    import_args+=(--tags "${tag_args[@]}")
  fi
fi
az keyvault certificate import "${import_args[@]}"


echo "==> Done: ${primary_domain} -> ${AZ_KV_NAME}/${AZ_KV_CERT_NAME}"
if [[ "${FORCE_RENEW}" == "true" ]]; then
  echo "==> Summary: certificate for ${primary_domain} force-renewed (FORCE_RENEW=true) and updated in Key Vault '${AZ_KV_NAME}' as '${AZ_KV_CERT_NAME}'."
elif [[ "${kv_found}" == "true" ]]; then
  echo "==> Summary: certificate for ${primary_domain} renewed and updated in Key Vault '${AZ_KV_NAME}' as '${AZ_KV_CERT_NAME}' (previous version was ${kv_days_remaining} day(s) from expiry: ${kv_expires})."
else
  echo "==> Summary: new certificate for ${primary_domain} added to Key Vault '${AZ_KV_NAME}' as '${AZ_KV_CERT_NAME}' (no valid previous version found)."
fi
