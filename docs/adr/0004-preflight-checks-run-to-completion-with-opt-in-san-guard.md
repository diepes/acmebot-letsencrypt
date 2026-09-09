# Pre-flight checks always run to completion with combined error reporting; SAN-match escalation is opt-in

Status: accepted

`acme-cron-update.sh` cannot rely on `acme.sh`'s own skip-if-not-due renewal logic,
since its state doesn't persist across separate container runs. Instead it runs its
own pre-flight checks before ever calling `acme.sh --issue`: a Key Vault renewal
pre-check (does a still-valid certificate already exist under `AZ_KV_CERT_NAME`, and
do its SANs match `ACME_DOMAINS`?) and, only for `ACME_DNS_MODE=azure`, a DNS zone
access pre-check.

We run both checks to completion on every invocation regardless of what the other
finds, and report any failures from either together as one combined error, rather
than exiting at the first failure. This is deliberate: a broken DNS setup must not
stay hidden just because the Key Vault check happened to decide issuance should be
skipped anyway, and vice versa — the operator gets the full picture in one run
instead of fixing one problem only to discover the next on the following cron tick.

Within the Key Vault check, a SAN mismatch is by default only a signal to force
re-issuance (since `AZ_KV_CERT_NAME` is a static label, decoupled from the domain
list, a mismatch is far more likely to mean "domains changed" than "wrong
certificate"); an unverifiable SAN lookup falls back to deciding on expiry alone. We
added an opt-in escalation, `SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH`, for the one case
where that permissiveness is actively dangerous: cutting an already-in-production Key
Vault certificate (issued by another CA or process) over to this script, where a
misconfigured name or domain list could otherwise silently overwrite the wrong
certificate. When set, a not-found certificate, a confirmed SAN mismatch, or a failed
SAN lookup all become hard pre-flight failures instead — and this applies even under
`FORCE_RENEW=true`, since that flag controls renewal timing, not which certificate is
safe to touch.

Consequence: the permissive default favors uninterrupted renewal for ongoing
operation; the strict flag is intended to be temporary — enabled only for the first
cutover run per domain, then unset once the migration is confirmed safe.
