# CONTEXT: container that uses acme.sh to get certificates and put them in Azure KV

Runs as a k8s CronJob: issues/renews TLS certificates for one or more domains
(wildcard or not) and stores them in Azure Key Vault.

## Language

**Bootstrap step**:
A manual, one-time, per domain-set operation, run via the `acme-bootstrap.sh`
entrypoint, that registers the ACME account (if it doesn't exist yet) and prints the
Persist TXT record(s) to publish. Not automated, not run by the CronJob.

**Account key**:
The ACME account's private key, generated during the Bootstrap step and stored under
`ACME_HOME`. Identifies the registered account to the CA and is shared across every
domain issued under that `ACME_HOME`. This is what the CronJob is given; it never
touches DNS credentials. `ACME_HOME` (acme.sh's `--config-home`) holds only this
data — the acme.sh script itself installs elsewhere in the image — so it's always
safe to mount an empty volume/PVC there.
_Avoid_: "the key" (ambiguous with Certificate key)

**Certificate key**:
The private key generated fresh for a domain's certificate each time `acme.sh --issue`
runs. Written to a local folder, then imported into Azure Key Vault. Unrelated to the
Account key.
_Avoid_: "the key"

**Persist TXT record**:
The `_validation-persist.<domain>` DNS TXT record printed by the Bootstrap step and
published once, manually, at the domain's DNS provider. Reused for every future
issuance/renewal; the CronJob never writes to DNS.

**ACME_DOMAINS**:
A comma separated env var, shared by both entrypoint scripts, listing every domain in
a certificate's SAN set (wildcard entries such as `*.example.com` allowed).
`acme-cron-update.sh` treats the first entry as the primary domain (the certificate's
CN, and the source of its local cert folder + default Key Vault name); order doesn't
matter for `acme-bootstrap.sh`, which just prints a Persist TXT record per entry.
_Avoid_: DOMAIN, DOMAINS, SAN_DOMAINS (superseded — this container no longer has a
space-separated SAN list separate from the primary domain)

**CronJob**:
The unattended, recurring container invocation (the `acme-cron-update.sh` entrypoint)
that renews certificates: reads `ACME_DOMAINS` and the mounted Account key, runs `acme.sh
--issue --dns-persist`, then (Phase 1) writes the certificate + Certificate key to a
local folder and imports them into Azure Key Vault via the Azure CLI. Has no DNS write
access.
_Avoid_: operator (the operator is the human running the Bootstrap step)

## Chosen validation approach: DNS persist mode

We use acme.sh's [DNS persist mode](https://github.com/acmesh-official/acme.sh/wiki/DNS-persist-mode)
([draft-ietf-acme-dns-persist-01](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/)):
the Persist TXT record is published once, by hand, so the CronJob never needs DNS
write credentials — only the mounted Account key.

Caveat: requires the CA to support `dns-persist-01`. Let's Encrypt supports it on
**staging** (`letsencrypt_test`) only, not yet production (tracked at
https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468).
Point `ACME_SERVER` at `letsencrypt_test` until production support lands.

## Flow

The container's default `ENTRYPOINT` is acme.sh itself; the two workflows below are
alternate entrypoints selected at run time (`--entrypoint` in `docker run`, `command:`
in k8s) — see `acme-app/acme-scripts/`.

1. **Bootstrap** (manual, `acme-bootstrap.sh`): `acme.sh --make-dns-persist-value -d
   <domain> [-d <domain>...] [--dns-persist-wildcard]` → operator publishes the
   printed TXT record(s) by hand.
2. **CronJob** (automated, `acme-cron-update.sh`): `acme.sh --issue -d <domain> [-d
   <domain>...] --dns-persist` → **Phase 1**: write cert + key locally, then `az
   keyvault certificate import` into Azure Key Vault.

## Legacy: DNS API mode

Older issuance used acme.sh's live DNS API hooks (`dns_azure`/`dns_aws`), which need
standing DNS write credentials in the CronJob. No longer the default; kept only as a
fallback for domains whose CA never adopts persist mode.
