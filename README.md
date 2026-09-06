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
entrypoint overridden to `acme-bootstrap.sh`. `ACME_HOME` only ever holds
account/config data (acme.sh's own script installs elsewhere in the image, see
CONTEXT.md), so a plain bind mount of an empty host directory works fine here:

```sh
docker build -t acmebot:local acme-app

# Registers the ACME account (first run only) and prints the Persist TXT
# record(s) to publish.

ACME_EMAIL="acme-app.example@vigor.nz"
ACME_DOMAINS="acme-test.vigor.nz,acme-test2.vigor.nz"
ACME_SERVER="letsencrypt_test"
docker run --rm -it \
  --entrypoint /home/app/acme-bootstrap.sh \
  -e ACME_DOMAINS="${ACME_DOMAINS}" \
  -e ACME_EMAIL="${ACME_EMAIL}" \
  -e ACME_SERVER="${ACME_SERVER}" \
  -v "$(pwd)/acme-home:/acme.cert.store" \
  acmebot:local

```

Add the printed `_validation-persist.<domain>` TXT record(s) at your DNS provider by
hand — no DNS API credentials needed. Reuse the same `./acme-home` directory across
domain sets; only the TXT record(s) are per-domain. Package `./acme-home` as the k8s
Secret/PVC the CronJob mounts at `ACME_HOME`.

### 2. Run the CronJob

Mount the `./acme-home` directory from step 1 (the Account key) at `ACME_HOME`, and
set:

- `ACME_DOMAINS` — same comma separated list as the bootstrap step
- `ACME_EMAIL` — email registered with the ACME server
- `AZURE_KEYVAULT_NAME` — Key Vault to store the certificate in

Each run, with the entrypoint overridden to `acme-cron-update.sh`:

```sh
docker run --rm \
  --entrypoint /home/app/acme-cron-update.sh \
  -e ACME_DOMAINS="example.com,*.example.com" \
  -e ACME_EMAIL="you@example.org" \
  -e AZURE_KEYVAULT_NAME="my-keyvault" \
  -v "$(pwd)/acme-home:/acme.cert.store" \
  -v "$(pwd)/out/certs:/certs" \
  acmebot:local
```

acme.sh only reissues when a certificate is due for renewal. **Phase 1** (current):
the cert + Certificate key are written to a local folder, then imported into Azure Key
Vault with `az keyvault certificate import` (Azure CLI, via the container's managed
identity).

Try both steps locally with `docker-compose.yml` (`docker compose run --rm bootstrap`
/ `docker compose run --rm acmebot`) — see `.env.acmebot.example`.

## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Security Policy](SECURITY.md)

## License

This project is licensed under the [Apache License 2.0](https://github.com/polymind-inc/acmebot/blob/master/LICENSE)
