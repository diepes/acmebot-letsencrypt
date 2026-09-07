# Cert issuer for Azure Key Vault using Let's Encrypt

A small container that issues/renews TLS certificates with [acme.sh](https://github.com/acmesh-official/acme.sh)
and stores them in Azure Key Vault. Runs as a k8s CronJob.

## How it works

The container's default entrypoint is acme.sh itself. Two scripts baked into the
image act as alternate entrypoints for this container's actual workflows — see
[CONTEXT.md](CONTEXT.md) for terms and rationale:

- `acme-bootstrap.sh` — manual, one-time setup (below)
- `acme-cron-update.sh` — automated, recurring renewal (the k8s CronJob)

Both take a single `ACME_DOMAINS` env var: a comma separated list of every domain in the
certificate's SAN set (wildcard entries like `*.example.com` allowed).
`acme-cron-update.sh` treats the first entry as the primary domain (CN).

Uses acme.sh's **DNS persist mode** (`--dns-persist`) so `acme-cron-update.sh` never
needs DNS write credentials.

### 1. Bootstrap (manual, once per domain set)

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
docker run --rm \
  --entrypoint /home/app/acme-cron-update.sh \
  --env-file .env.acmebot \
  -v "$(pwd)/out/certs:/certs" \
  acmebot:local
  # env +AZ_KV_NAME, _CERT_NAME
```

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

## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Security Policy](SECURITY.md)

## License

This project is licensed under the [Apache License 2.0](https://github.com/polymind-inc/acmebot/blob/master/LICENSE)
