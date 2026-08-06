<h1 align="center">
  Acmebot for Microsoft Azure KV
</h1>
<p align="center">
  ACME SSL/TLS certificate automation for Microsoft Azure, built around DNS-01 validation and Azure Key Vault
  Forked and ported to rust from - https://github.com/polymind-inc/acmebot
  <br>
  (App Service / Container Apps / Application Gateway / Front Door / Web PubSub / Event Grid / others)
</p>
<p align="center">
  <a href="https://github.com/diepes/acmebot-letsencrypt/actions/workflows/ci.yml" rel="nofollow"><img src="https://github.com/diepes/acmebot-letsencrypt/workflows/CI/badge.svg" alt="CI" style="max-width: 100%;"></a>
  <a href="https://github.com/diepes/acmebot-letsencrypt/releases/latest" rel="nofollow"><img src="https://badgen.net/github/release/diepes/acmebot-letsencrypt" alt="Release" style="max-width: 100%;"></a>
  <a href="https://github.com/diepes/acmebot-letsencrypt/stargazers" rel="nofollow"><img src="https://badgen.net/github/stars/diepes/acmebot-letsencrypt" alt="Stargazers" style="max-width: 100%;"></a>
  <a href="https://github.com/diepes/acmebot-letsencrypt/network/members" rel="nofollow"><img src="https://badgen.net/github/forks/diepes/acmebot-letsencrypt" alt="Forks" style="max-width: 100%;"></a>
  <a href="https://github.com/diepes/acmebot-letsencrypt/blob/master/LICENSE"><img src="https://badgen.net/github/license/diepes/acmebot-letsencrypt" alt="License" style="max-width: 100%;"></a>
  <a href="https://registry.terraform.io/modules/polymind-inc/acmebot/azurerm/latest" rel="nofollow"><img src="https://badgen.net/badge/terraform/registry/5c4ee5" alt="Terraform" style="max-width: 100%;"></a>
  <br>
  <a href="https://github.com/diepes/acmebot-letsencrypt/commits/master" rel="nofollow"><img src="https://badgen.net/github/last-commit/diepes/acmebot-letsencrypt" alt="Last commit" style="max-width: 100%;"></a>
  <a href="https://acmebot.dev/guide/" rel="nofollow"><img src="https://badgen.net/badge/documentation/available/ff7733" alt="Documentation" style="max-width: 100%;"></a>
  <a href="https://github.com/diepes/acmebot-letsencrypt/discussions" rel="nofollow"><img src="https://badgen.net/badge/discussions/welcome/ff7733" alt="Discussions" style="max-width: 100%;"></a>
</p>

## Motivation

Acmebot helps Azure platform and operations teams automate ACME certificate issuance and renewal without building a dedicated certificate pipeline. It uses DNS-01 validation, stores private keys and issued certificates in Azure Key Vault, and exposes a dashboard and HTTP API for day-to-day operations.

Acmebot is designed for teams that need to:

- Store SSL/TLS certificates securely in Azure Key Vault
- Centralize certificates for multiple Azure services and domains
- Automate certificate fleets with per-certificate renewal state and predictable operational behavior
- Monitor certificate operations through Application Insights and webhooks
- Keep DNS provider credentials and Azure access scoped to the resources Acmebot manages

## Feature Support

- Issue certificates for zone apex names, wildcards, and SANs (multiple domains)
- Dedicated dashboard for certificate management
- ARI-aware renewal scheduling for each managed certificate, with CA-provided renewal windows, `Retry-After` timing, and an expiry-based fallback
- Independent renewal state and next-check timing per certificate, built for long-running certificate fleets
- Support for ACME v2 compliant Certification Authorities
  - [Let's Encrypt](https://letsencrypt.org/)
  - [GlobalSign](https://www.globalsign.com/) (Requires EAB Credentials)
  - [Google Trust Services](https://pki.goog/) (Requires EAB Credentials)
  - [SSL.com](https://www.ssl.com/how-to/order-free-90-day-ssl-tls-certificates-with-acme/) (Requires EAB Credentials)
  - [ZeroSSL](https://zerossl.com/features/acme/) (Requires EAB Credentials)
- Certificates can be used with many Azure services
  - App Service (Web Apps / Functions / Containers)
  - Container Apps (Include custom DNS suffix)
  - Front Door (Standard / Premium)
  - Application Gateway v2
  - API Management
  - Web PubSub (Premium)
  - Event Grid Namespaces
  - SignalR Service (Premium)
  - Virtual Machine

## Deployment


## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Security Policy](SECURITY.md)

## License

This project is licensed under the [Apache License 2.0](https://github.com/polymind-inc/acmebot/blob/master/LICENSE)
