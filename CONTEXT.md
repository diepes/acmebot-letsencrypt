# CONTEXT: Docker container that uses acmesh to get certificates and put them in Azure KV

## Based around docker container ran as k8s CronJob

- Debian base container.
- Schedule daily cron for each wildcard cert
- Tools acme.sh, Azure CLI, AWS CLI, curl

## acmesh
https://github.com/acmesh-official/acme.sh

## Chosen validation approach: DNS persist mode

We are standardizing on acme.sh's **DNS persist mode**
(https://github.com/acmesh-official/acme.sh/wiki/DNS-persist-mode), which implements
the IETF draft [draft-ietf-acme-dns-persist-01](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/).

Why: a `_validation-persist.<domain>` TXT record is provisioned **once**, out-of-band
(manually, or via Terraform/Bicep — not by the container), and is then reused for every
future issuance and renewal. The recurring k8s CronJob no longer needs live DNS API
credentials (`AZUREDNS_*` / `AWS_ACCESS_KEY_ID`+`AWS_SECRET_ACCESS_KEY`) at issuance
time — it just asks the CA to read the persistent record. This removes the DNS
write-access blast radius from the routine renewal path entirely; DNS API credentials
are only needed once, for the initial `--make-dns-persist-value` bootstrap step (and
only if we choose to automate publishing the TXT record instead of adding it by hand).

Caveat: this only works if the **CA** also implements `dns-persist-01`, not just the
client. See "Proposed flow targeting Let's Encrypt" below for current CA support status
and how we bridge the gap until Let's Encrypt's production support lands.

### Verified working (acme.sh client-side)

```sh
# Print the persistent TXT record to publish once (see below for --server choice)
acme.sh --make-dns-persist-value -d example.com --dns-persist-wildcard

# Add the printed _validation-persist.example.com TXT record at the DNS provider
# (manually, or scripted with dns_azure/dns_aws one time — see below)

# Issue / renew — no DNS API credentials needed at this step
acme.sh --issue -d example.com --dns-persist
```

## Proposed flow targeting Let's Encrypt

Let's Encrypt's `dns-persist-01` support, as of writing:
- **Staging** (`https://acme-staging-v02.api.letsencrypt.org/directory`): supported today,
  tracking an early draft revision — usable for testing our plumbing end-to-end.
- **Production** (`https://acme-v02.api.letsencrypt.org/directory`): not yet live. Original
  target was Q2 2026; it has slipped pending IETF working-group consensus on the draft.
  Track status at https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468.

Because production support isn't available yet, we propose a **two-phase rollout**,
switched by an env var (e.g. `VALIDATION_MODE=dns-api|dns-persist`) so the same
container image and entrypoint work in both phases without a rebuild:

1. **Phase 1 — now (production certs via DNS API mode)**
   - `VALIDATION_MODE=dns-api`, `DNS_PROVIDER=dns_azure|dns_aws` (current default; unchanged).
   - Requires `AZUREDNS_*` / `AWS_ACCESS_KEY_ID`+`AWS_SECRET_ACCESS_KEY` present at every
     renewal, as today.
   - In parallel, validate the persist-mode plumbing against LE **staging**
     (`acme.sh --server letsencrypt_test`) so the persist-mode code path is exercised
     and battle-tested well before we need to flip it on for production.

2. **Bootstrap step — one-time, per domain, whenever we're ready to adopt persist mode**
   - Run `acme.sh --make-dns-persist-value -d <domain> --server letsencrypt
     [--dns-persist-wildcard] [--dns-persist-days N]` to print the TXT record value.
   - Publish the `_validation-persist.<domain>` TXT record at the DNS provider (Azure DNS /
     Route 53), either by hand or as a one-off Terraform/Bicep change — this is the only
     point where DNS write access is exercised going forward.

3. **Phase 2 — once Let's Encrypt enables `dns-persist-01` in production**
   - Flip `VALIDATION_MODE=dns-persist` for that domain's CronJob.
   - `acme.sh --issue -d <domain> --dns-persist --server letsencrypt` — no DNS API
     credentials required in the CronJob at all; `AZUREDNS_*`/`AWS_*` secrets can be
     dropped from that job's environment.
   - Certificate import into Azure Key Vault (`az keyvault certificate import`) is
     unchanged in both phases.

Rollout is per-domain and reversible: domains can stay on DNS API mode indefinitely if
their CA doesn't support persist mode, while others move over as support lands.

## Reference: DNS API mode (current default, Phase 1 above)

1. https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_azure
       export AZUREDNS_SUBSCRIPTIONID="<SUBSCRIPTIONID>"
       export AZUREDNS_TENANTID="<TENANTID>"
       export AZUREDNS_APPID="<APPID>"
       export AZUREDNS_CLIENTSECRET="<CLIENTSECRET>"
       Then you can issue your certificates with:
       ./acme.sh --issue --dns dns_azure -d example.com -d *.example.com

2. https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_aws
       export  AWS_ACCESS_KEY_ID="<key id>"
       export  AWS_SECRET_ACCESS_KEY="<secret>"
       To issue a cert:
       ./acme.sh --issue --dns dns_aws -d example.com -d *.example.com

