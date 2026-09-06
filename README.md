# Cert issuer for Azure Key Vault using Let's Encrypt

A small container that issues/renews TLS certificates with [acme.sh](https://github.com/acmesh-official/acme.sh)
and stores them in Azure Key Vault. Runs as a k8s CronJob.

## How it works

Uses acme.sh's **DNS persist mode** (`--dns-persist`) so the recurring renewal job
never needs DNS write credentials. See [CONTEXT.md](CONTEXT.md) for terms and
rationale.

### 1. Bootstrap (manual, once per domain)

```sh
acme.sh --home ./acme-home --server letsencrypt \
  --make-dns-persist-value -d example.com --dns-persist-wildcard
```

Add the printed `_validation-persist.example.com` TXT record at your DNS provider
by hand — no DNS API credentials needed. Reuse the same `--home` directory across
domains; only the TXT record is per-domain.

### 2. Run the CronJob

Mount the `./acme-home` directory from step 1 (the ACME account key) at `ACME_HOME`,
and set:

- `DOMAIN` (+ optional `SAN_DOMAINS`) — domain(s) to issue for, wildcard or not
- `AZURE_KEYVAULT_NAME` — Key Vault to store the certificate in

Each run:

```sh
acme.sh --home "$ACME_HOME" --issue -d example.com --dns-persist
```

acme.sh only reissues when a certificate is due for renewal. **Phase 1** (current):
the cert + key are written to a local folder, then imported into Azure Key Vault with
`az keyvault certificate import` (Azure CLI, via the container's managed identity).

Try it locally with `docker-compose.yml` — see `.env.acmebot.example` and
`acme-app/DockerEntrypoint.sh`.

## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Security Policy](SECURITY.md)

## License

This project is licensed under the [Apache License 2.0](https://github.com/polymind-inc/acmebot/blob/master/LICENSE)
