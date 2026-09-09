# Reinstate live DNS API paths as an active (not legacy) fallback until Let's Encrypt ships dns-persist-01 to production

Status: accepted

ADR 0001 chose DNS persist mode as the default and called the live DNS API path
(`dns_azure`/`dns_aws`) "legacy", kept only as a documented fallback for domains whose
CA never adopts persist mode. In practice, as of writing, *no* public CA (Let's
Encrypt, ZeroSSL, Buypass, Google Trust Services) has shipped `dns-persist-01` to
production — only Let's Encrypt staging (`letsencrypt_test`) accepts it. Certificates
issued via persist mode today are therefore never publicly trusted, which is not
"legacy/fallback" territory — it's the only way to get a real certificate right now
for any domain onboarded before production support lands.

We add two `ACME_DNS_MODE` values to `acme-cron-update.sh`:
- `azure`: a fully-automated `acme.sh --dns dns_azure` path, authenticated via
  `AZUREDNS_*` env vars (falling back to the same `AZURE_CLIENT_ID`/
  `AZURE_CLIENT_SECRET`/`AZURE_TENANT_ID`/`AZURE_SUBSCRIPTION_ID` already used for the
  Key Vault import, provided that principal is also granted "DNS Zone Contributor" on
  the domain's Azure DNS zone).
- `aws`: a fully-automated `acme.sh --dns dns_aws` path against Route53, using the
  standard `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars if set, or falling
  back automatically to the container/instance IAM role (ECS task role or EC2
  instance profile) if unset — that role/user needs Route53
  `ChangeResourceRecordSets`/`GetChange`/`ListHostedZones*` rights on the domain's
  hosted zone.

Both reinstate standing DNS write credentials (or an equivalent IAM role) in the
CronJob for any domain run this way — the exact trade-off ADR 0001 avoided —
accepted deliberately, per-domain, as the only way to issue trusted certificates
today. Which one applies to a given domain depends purely on which DNS provider
actually hosts its zone (Azure DNS vs. Route53); a domain hosted elsewhere needs a
different `dns_*` plugin not yet wired up here.

`ACME_DNS_MODE=persist` (unchanged default) still avoids DNS credentials entirely for
domains that don't need production-trusted certs yet (e.g. active development against
staging), and remains ready to become the default again for all domains once
production support ships (tracked at
https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468).

Consequence for the Bootstrap step: it is **only required for `persist`-mode
domains** (it registers the account and prints the Persist TXT record they depend
on). A domain run entirely with `ACME_DNS_MODE=azure` or `ACME_DNS_MODE=aws` never
needs `acme-bootstrap.sh` — `acme-cron-update.sh` self-registers the ACME account on
first run when `ACME_ID_SECRET_KEY`/`ACME_HOME` aren't already populated.

We will revisit this once Let's Encrypt (or another supported CA) ships
`dns-persist-01` to production: switch existing `azure`/`aws`-mode domains back to
`persist` and stop granting them standing DNS write access, restoring ADR 0001's
original, more restrictive default.
