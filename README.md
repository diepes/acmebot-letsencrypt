# Cert issuer for Azure Key Vault using Let's Encrypt

A small container that issues/renews TLS certificates with [acme.sh](https://github.com/acmesh-official/acme.sh)
and stores them in Azure Key Vault. Runs as a k8s CronJob.

## TODO:
- Terraform
  - Cert k8s nginx
      kubectl_manifest.secret-provider-class will be updated in-place
      ~ resource "kubectl_manifest" "secret-provider-class"
         objectVersion:
  - New/Update CERT - GlobalSign
      infrastructure/spoke-infra/src/modules/shared-keyvault/main.tf
        - infrastructure/spoke-infra/src/modules/shared-keyvault/main.tf
        - module "domain_cert" {
      # module.sharedkv.module.domain_cert[0].azurerm_key_vault_certificate.wildcard-cert will be updated in-place
      ~ resource "azurerm_key_vault_certificate" "wildcard-cert" {
           name = "wildcard-cert-agic-backoffice"
           >>> Manual state delete P + NP, logic to bloc aue + backoffice
      # module.sharedkv.module.domain_cert[0].azurerm_key_vault_secret.wildcard-cert-key will be updated in-place
      ~ resource "azurerm_key_vault_secret" "wildcard-cert-key" {
           name = "wildcard-cert-agic-backoffice-key"
           >>> Manual state delete P + NP, logic to bloc aue + backoffice

  - AppGW
      # azurerm_application_gateway.app_gateway will be updated in-place
      ~ resource "azurerm_application_gateway" "app_gateway" {
           name = "p-aue-backoffice-appgw"
           name = "p-usc-backoffice-appgw"
           tags = { "managed-by-k8s-ingress" = "1.9.4/a2166a43/2025-12-01-12:33T-0800" }
           >>> pr AZR-5543 versionless_secret_id
  - Nginx restricted
      # helm_release.nginx-ingress-controller-restricted will be updated in-place
      ~ resource "helm_release" "nginx-ingress-controller-restricted" {
          id/name = "ingress-nginx-restricted"
          >>>> infrastructure/spoke-infra/src/modules/aks-addons/internal_ingress.tf
  - aks - secret-provider-class ?? kv integration
      # kubectl_manifest.secret-provider-class will be updated in-place
      ~ resource "kubectl_manifest" "secret-provider-class" {
          name = "azure-kv-spc"
          keyvaultName: pauebackofficesharedkv
          objectName: wildcard-cert-agic-backoffice
          objectName: wildcard-cert-agic-backoffice-key

## How it works

The container's default entrypoint is acme.sh itself. Two scripts baked into the
image act as alternate entrypoints for this container's actual workflows — see
[CONTEXT.md](CONTEXT.md) for terms and rationale:

- `acme-bootstrap.sh` — manual, one-time setup (below)
- `acme-cron-update.sh` — automated, recurring renewal (the k8s CronJob)

Both take a single `ACME_DOMAINS` env var: a comma separated list of every domain in the
certificate's SAN set (wildcard entries like `*.example.com` allowed).
`acme-cron-update.sh` treats the first entry as the primary domain (CN).

Uses acme.sh's **DNS persist mode** (`--dns-persist`) by default, so `acme-cron-update.sh`
never needs DNS write credentials.

**Production availability note:** Let's Encrypt currently accepts `dns-persist-01`
on its staging endpoint, but the production endpoint may still reject it with
`Supported validation types are: dns-01`. Use `ACME_SERVER=letsencrypt_test` for
testing this flow. Production rollout was targeted for Q2 2026, but no firm
availability date is currently published. See the [Let's Encrypt DNS-PERSIST-01
announcement](https://letsencrypt.org/2026/02/18/dns-persist-01) and [current
challenge documentation](https://letsencrypt.org/docs/challenge-types/).

**Need a publicly-trusted certificate today?** Set `ACME_DNS_MODE=azure` (Azure DNS)
or `ACME_DNS_MODE=aws` (Route53) on `acme-cron-update.sh` instead — fully-automated
alternatives using acme.sh's `dns_azure`/`dns_aws` plugins against the domain's DNS
zone API directly (work with production Let's Encrypt right now; see ADR
[0002](docs/adr/0002-dns-api-fallback-until-persist-ships.md)). Both modes:
- **azure**: needs `AZUREDNS_SUBSCRIPTIONID`, plus either `AZUREDNS_MANAGEDIDENTITY=true`
  (real k8s deployment: uses the pod's managed identity, no secret needed) or — for
  local/CI testing without one — reuses the same `AZURE_CLIENT_ID`/
  `AZURE_CLIENT_SECRET`/`AZURE_TENANT_ID` already used for the Key Vault import
  below (no separate `AZUREDNS_*` credential vars needed, unless this domain's zone
  should use a different, more narrowly-scoped principal). Either way, that
  principal/identity needs "DNS Zone Contributor" on the domain's Azure DNS zone.
- **aws**: uses the standard `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` vars if set;
  otherwise falls back automatically to the container/instance IAM role (ECS task
  role or EC2 instance profile — no vars needed at all in that case). That
  role/user needs Route53 `ChangeResourceRecordSets`/`GetChange`/`ListHostedZones*`
  rights on the domain's hosted zone.
- Puts standing DNS write credentials in the CronJob — the trade-off `--dns-persist`
  exists to avoid — so only use it while persist mode is unavailable in production.
- Skips the Bootstrap step below entirely: `acme-cron-update.sh` self-registers the
  ACME account on first run, no `ACME_ID_SECRET_KEY`/pre-populated `ACME_HOME`
  required.

### 1. Bootstrap (manual, once per domain set — only for `ACME_DNS_MODE=persist`, the default)

No local acme.sh install needed — use the same image the CronJob runs, with its
entrypoint overridden to `acme-bootstrap.sh`. No volume mount is needed either: the
script prints everything worth keeping (the Persist TXT record(s) to publish, and the
Account key) as a ready-to-paste `.env` block, so nothing from this container's
filesystem needs to survive:

```sh
# 1a. create .env.acmebot and fill in ACME_DOMAINS / ACME_EMAIL
cp .env.acmebot.example .env.acmebot
# 1b. build updated local container
docker build -t acmebot:local acme-app
# 1c. Registers the ACME account (first run only) and prints the Persist TXT
# record(s) plus the Account key as a copy-pasteable `.env` block.
# acme-bootstrap.sh
docker run --rm -it \
  --entrypoint /home/app/acme-bootstrap.sh \
  --env-file .env.acmebot \
  acmebot:local
  # env ACME_DOMAINS, _EMAIL, _SERVER
```

1d. Copy the printed block into `.env.acmebot` (see `.env.acmebot.example`), then add
the `ACME_DNS_KEY`/`ACME_DNS_VALUE` TXT record at your DNS provider by hand —
no DNS API credentials needed. Since no `ACME_HOME` volume is mounted here, each
bootstrap run registers a brand new ACME account with its own Account key and Persist
TXT value — treat bootstrap as a single one-time step per domain set, keep whichever
`.env.acmebot` you generate from it, and don't rerun it unless you intend to replace
the account (which also means republishing the new TXT value).

### 2. Run the CronJob

Optionally add to `.env.acmebot` (alongside the block pasted in step 1) to also
import the certificate into Azure Key Vault — leave both unset/empty for Phase 1
local-folder-only mode (the certificate is always written to `/certs` regardless):

- `AZ_KV_NAME` — Key Vault to store the certificate in
- `AZ_KV_CERT_NAME` — certificate name in the vault (default: primary domain with
  dots replaced by dashes)

Each run, with the entrypoint overridden to `acme-cron-update.sh`. `ACME_ID_SECRET_KEY`
(from `.env.acmebot`) is written to `ACME_HOME/account.key` at startup, so — for local
testing — no volume needs to be mounted at `ACME_HOME` either; only `/certs` (the
output) is bind-mounted:

```sh
# acme-cron-update.sh
docker build -t acmebot:local acme-app
docker run --rm \
  --entrypoint /home/app/acme-cron-update.sh \
  --env-file .env.acmebot.default.shared \
  --env-file .env.acmebot.cert.config \
  -v "$(pwd)/out/certs:/certs" \
  acmebot:local
  # env +AZ_KV_NAME, _CERT_NAME, ACME_DNS_MODE
```

To get a publicly-trusted certificate today (persist mode isn't validated by
production Let's Encrypt yet — see above):
- **Azure DNS**: add `ACME_DNS_MODE=azure` plus `AZUREDNS_SUBSCRIPTIONID` to
  `.env.acmebot` — it reuses the `AZURE_SUBSCRIPTION_ID`/`AZURE_TENANT_ID`/
  `AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET` already set above for auth (no separate
  `AZUREDNS_*` credentials needed, unless this domain's DNS zone should use a
  different principal), provided that principal also has "DNS Zone Contributor" on
  the domain's Azure DNS zone — or set `AZUREDNS_MANAGEDIDENTITY=true` in a real k8s
  deployment to use the pod's managed identity instead.
- **Route53**: add `ACME_DNS_MODE=aws` to `.env.acmebot`, plus `AWS_ACCESS_KEY_ID`/
  `AWS_SECRET_ACCESS_KEY` for local/CI testing (a real access key needs Route53
  rights on the domain's hosted zone) — or leave both unset in a real ECS/EC2
  deployment to use the container/instance IAM role instead.

Either way, also set `ACME_SERVER=letsencrypt` for a
real (non-staging) certificate. No Bootstrap step needed for domains run this way.

acme.sh only reissues when a certificate is due for renewal. **Phase 1** (current):
the cert + Certificate key are always written to a local folder; if `AZ_KV_NAME` is
set, they're then also imported into Azure Key Vault with `az keyvault certificate
import` (Azure CLI, via the container's managed identity).

**Local/CI testing without a managed identity**: `az login --identity` will fail in
a plain `docker run` (there's no Azure identity to assume), so add these three to
`.env.acmebot` to fall back to an explicit service-principal login instead — the
principal needs "Key Vault Certificates Officer" (or equivalent import) rights on
`AZ_KV_NAME`:

- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `AZURE_TENANT_ID`

Note these are plain env vars consulted by `acme-cron-update.sh` itself, not
automatically read by the `az` CLI (unlike the Azure SDKs' `DefaultAzureCredential`).

Need a throwaway vault + service principal to test against? `./create-sanbox-az-kv.sh`
(repo root, run locally with `az` logged in — not part of the container image)
creates both in a Sandbox subscription, tags the resource group/vault with
`owner_email`/`owner_platform`/`date_delete_after`/`purpose`/`managed_by` (required by
this subscription's tag policy — `AZ_TAG_owner_email` must be set to an `@eroad.com`
address; the script fails fast with a clear error otherwise). Tags are built generically
from whatever `AZ_TAG_<key>=<value>` env vars are set (e.g. `AZ_TAG_owner_email`,
`AZ_TAG_owner_platform`), so extra tags can be added without touching the script.
It also grants the service principal certificate import/get/list rights on the vault,
and automatically loads/updates `.env.acmebot` in place: any config vars not yet in the
file get appended as blank placeholders, and once the vault/SPN are ready it writes the
resolved `AZURE_SUBSCRIPTION_ID`/`AZ_KV_NAME`/`AZ_KV_CERT_NAME`/`AZURE_TENANT_ID`/
`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET` values straight into `.env.acmebot` — no manual
copy/paste needed. Safe to re-run — it reuses the vault/service principal if they
already exist rather than failing (and won't overwrite `AZURE_CLIENT_SECRET` unless it
actually issues a fresh one); set `AZURE_CLIENT_ID` beforehand to grant an existing
service principal access instead of creating a new one.

In a real k8s deployment, `.env.acmebot`'s contents (particularly `ACME_ID_SECRET_KEY`)
should instead be stored as a Secret and injected as env vars into the CronJob, rather
than kept in a plain file.

Try both steps locally with `docker-compose.yml` (`docker compose run --rm bootstrap`
/ `docker compose run --rm acmebot`) — see `.env.acmebot.example`.

Migrating existing App Gateways' TLS certificates to this project? `./scripts/`
(repo root) holds other one-off, read-only `az` CLI helpers not run by the
container/CronJob — e.g. `find-appgw-tls-keyvault-certs.sh`, which scans every
Application Gateway across a subscription/tenant and reports each HTTPS listener's
certificate and the Key Vault it's sourced from (if any), useful for finding
`AZ_KV_NAME`/`AZ_KV_CERT_NAME` values before onboarding an existing certificate (see
`SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH` in Troubleshooting below for the accompanying
migration safety check). Run locally with `az` already logged in — see the script's
own header comment for options.

## Troubleshooting

- **`ACME_DNS_MODE=azure` fails with `Invalid domain` / `invalid domain`**: the
  `dns_azure` plugin lists all Azure DNS zones in `AZUREDNS_SUBSCRIPTIONID` (falling
  back to `AZURE_SUBSCRIPTION_ID`) and matches the challenge domain against zone names
  by suffix; this error means it never found a match. **`acme-cron-update.sh` now
  checks this itself, before ever calling acme.sh** — it does the exact same
  subscription-wide zone list + suffix match, and fails fast with a clear
  `ERROR: no accessible Azure DNS zone found for: ...` (or a zone-list
  permission error) instead of letting acme.sh burn a Let's Encrypt attempt only to
  fail opaquely later. This DNS zone access pre-check and the Key Vault renewal
  pre-check (see `RENEWAL_THRESHOLD_DAYS`/`FORCE_RENEW` above) always **both** run
  to completion on every invocation, regardless of what the other one finds — so a
  broken DNS setup can't stay hidden on a run where Key Vault said the current cert
  is still valid, and vice versa. If both fail, both errors are printed together
  under one `ERROR: N pre-flight check(s) failed for <domain>:` message rather than
  only reporting whichever failed first. The two indistinguishable causes behind either error are
  (a) that subscription ID isn't the one hosting the domain's actual Azure DNS
  zone (e.g. it's reusing the Key Vault's subscription, not the DNS one), or (b) the
  service principal/managed identity lacks read/list rights on that zone (or the whole
  subscription's DNS zones). Set `ACME_DEBUG=1` (or `2`/`3` for more detail) to see the
  raw zone-list REST response and confirm which. If it's (b) — a JSON body like
  `"AuthorizationFailed": ... does not have authorization to perform action
  'Microsoft.Network/dnszones/read' over scope '/subscriptions/<id>'` with HTTP 403 —
  grant the principal DNS rights. **Important**: the failing call is a
  *list-by-subscription* request, and Azure DNS does not filter that list down to
  individually-scoped resources — a role assigned only at the zone itself is NOT
  enough for the list to succeed. Grant two role assignments instead (least privilege):
  ```sh
  # 1. Reader on the resource group — lets the list-zones call see it:
  az role assignment create --assignee <AZUREDNS_APPID-or-object-id> \
    --role "Reader" --scope "/subscriptions/<sub>/resourceGroups/<rg>"
  # 2. DNS Zone Contributor on the specific zone — lets it read/write the TXT record:
  az role assignment create --assignee <AZUREDNS_APPID-or-object-id> \
    --role "DNS Zone Contributor" \
    --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/dnszones/<zone-name>"
  ```
  (Or grant "DNS Zone Contributor" directly on the resource group instead of both —
  simpler, but grants write access to every zone in that RG, not just this one.)
  If it's (a), fix `AZUREDNS_SUBSCRIPTIONID` to point at the subscription that
  actually hosts the zone instead.

- **`too many certificates (N) already issued for this exact set of identifiers`
  (HTTP 429, `urn:ietf:params:acme:error:rateLimited`)**: Let's Encrypt's production
  server (`ACME_SERVER=letsencrypt`) allows only 5 certificates per exact set of
  domains per rolling 168h (7-day) window — burned quickly if you re-run
  `acme-cron-update.sh` repeatedly against production while iterating on this
  script/config. The error message includes the exact retry time (UTC); there is no
  way to bypass it early. **To avoid this**: do all iteration/testing against
  `ACME_SERVER=letsencrypt_test` (staging) first — it exercises the exact same
  issue → PFX-build → Key Vault import path with its own, much higher rate limits,
  and only switch to `ACME_SERVER=letsencrypt` once the whole flow is confirmed
  working end-to-end. Staging certs aren't publicly trusted, but Key Vault import
  and metadata (Subject/Issuer/SAN) work identically for verifying the pipeline.
  **Also note**: `acme-cron-update.sh` now checks Key Vault for an existing,
  still-valid certificate (see `RENEWAL_THRESHOLD_DAYS`/`FORCE_RENEW` in
  `.env.acmebot.example`) before ever calling acme.sh, specifically to prevent
  routine re-runs (e.g. a k8s CronJob) from burning this rate limit — but manual,
  repeated `docker compose run` iterations while debugging will still bypass that
  check every time the cert genuinely doesn't exist yet or `FORCE_RENEW=true` is set.

- **The Key Vault renewal check always says "No existing certificate found",
  even right after a successful import**: this means the identity has rights
  to *import*/*create* certificates but not to *read* them back — the two are
  separate Key Vault permissions and it's easy to grant one without the other.
  Without a fix, this used to fail silently: the script treated "permission
  denied" identically to "certificate genuinely doesn't exist yet" and just
  re-issued unconditionally on every single run, defeating the whole point of
  the check (and burning the rate limit above, one run at a time). It's now
  fixed to tell the two apart and fail loudly instead — a permission problem
  surfaces as `ERROR: ... Key Vault pre-check: failed to query Key Vault ...`
  rather than silently proceeding. If you see that error, grant the identity
  the Key Vault **`Certificates - Get`** right (Access Policy) or the
  **`Key Vault Certificates Officer`** RBAC role (which includes get) on
  `AZ_KV_NAME` — `import`/`create`-only rights are not enough.

- **Does the renewal check verify the Key Vault certificate actually covers
  the right domains, or only its expiry?** Both. `AZ_KV_CERT_NAME` is just a
  fixed label (often overridden to something static, unrelated to the
  current `ACME_DOMAINS` — see the "Getting Started" example vault name) —
  nothing stops the domain list changing later while that name stays the
  same. So on top of the expiry check, `acme-cron-update.sh` also compares
  the existing Key Vault certificate's SANs against `ACME_DOMAINS`; a
  mismatch always forces re-issuance regardless of how far away the expiry
  is (`==> WARNING: Key Vault certificate '...' covers a different domain
  set than requested ...`). This is best-effort: if the SAN lookup itself
  fails or returns nothing (e.g. an older cert with an unexpected policy
  shape), it only warns and falls back to the expiry-only decision rather
  than blocking the run.

- **Migrating an existing, already-in-production Key Vault certificate
  (issued by some other CA/process) over to this script**: the SAN check
  above is deliberately permissive by default — a mismatch or an
  unverifiable SAN list only warns and still proceeds to issue/overwrite,
  and a brand new certificate name is treated as the normal case. That's
  the wrong tradeoff for a one-off cutover, where a typo'd
  `AZ_KV_NAME`/`AZ_KV_CERT_NAME` or wrong `ACME_DOMAINS` could otherwise
  silently overwrite an unrelated, currently trusted production certificate
  (or create a wrongly-named one) without ever pausing. Set
  `SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH=true` to make that scenario a hard
  pre-flight failure instead: issuance/import is refused unless an existing
  certificate is found under `AZ_KV_CERT_NAME` **and** its SANs are
  confirmed to already match `ACME_DOMAINS`. Recommended usage: set it just
  for the first cutover run (verifying the identity/name/domain wiring is
  all correct against the real existing certificate), then unset it for
  normal ongoing renewals. Applies even when `FORCE_RENEW=true` is also
  set — this flag is about *which* certificate gets touched, not renewal
  timing.

- **`ERROR: (Conflict) A new key vault certificate can not be created or
  imported while a pending key vault certificate's status is inProgress`**
  from `az keyvault certificate import`: Key Vault flatly refuses any new
  certificate create/import for a name while that name already has a
  "pending" certificate operation — check with `az keyvault certificate
  pending show --vault-name <vault> --name <cert-name>` (a `"status":
  "inProgress"` in the output confirms it). This is usually left over from
  a CSR-based "Generate"/"Create" flow started via the Portal/CLI and never
  merged or canceled, or a prior run of this script that crashed between
  starting one and completing the import. This script now checks for this
  as part of the Key Vault pre-check, on every run (even under
  `FORCE_RENEW=true`, since this isn't about renewal timing), and fails
  fast with this same guidance instead of only surfacing as this opaque
  error from the import step. Fix it with `az keyvault certificate pending
  delete --vault-name <vault> --name <cert-name>`, or set
  `KEYVAULT_CANCEL_PENDING_CERT_OP=true` to have this script cancel a stale
  `inProgress` pending operation itself before proceeding (only do this
  once you've confirmed nothing else is legitimately mid-flight against
  that certificate name).

- **`ERROR: (BadParameter) The specified PEM X.509 certificate content is in an
  unexpected format` from `az keyvault certificate import`, even though the file
  being imported is a genuinely valid PFX/PKCS#12** (correct password, correct PBE
  algorithm, RSA or EC key — none of these matter for this specific error): Azure
  Key Vault stores a certificate **policy** (including
  `secret_properties.content_type`) per certificate *name*, and reuses that stored
  policy for every subsequent import of a new *version* under the same name unless
  a new policy is explicitly supplied with the import call. If any earlier import
  attempt under that name was ever recorded with `content_type=application/x-pem-file`
  (e.g. from a hand-built PEM approach, even a broken one), Key Vault keeps trying
  to parse every later PFX upload as PEM text — which fails with this exact generic
  error, no matter how correct the PFX itself is. This script now always passes
  `--policy '{"secret_properties":{"content_type":"application/x-pkcs12"}}'`
  on import to force the content type back to PKCS#12 regardless of history. If you
  still hit this error after updating, you can also just delete (and purge, since
  soft-delete is mandatory) the certificate object once — `az keyvault certificate
  delete` + `az keyvault certificate purge` — to drop the stale policy entirely and
  start clean. (Refs:
  [winterdom.com](https://winterdom.com/2019/10/31/importing-keyvault-certificates-api),
  [Stack Overflow #77954676](https://stackoverflow.com/questions/77954676/azure-certificate-import-bad-parameter).)

## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Security Policy](SECURITY.md)

## License

This project is licensed under the [Apache License 2.0](https://github.com/polymind-inc/acmebot/blob/master/LICENSE)
