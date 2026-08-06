# Contributing

Thanks for your interest in contributing to Acmebot.

## Before You Start

- Use GitHub Discussions for usage questions and design discussions.
- Use GitHub Issues for confirmed bugs and feature requests.
- Do not report security vulnerabilities in public issues or discussions. Follow [SECURITY.md](SECURITY.md).

## Development Setup

### Prerequisites

- .NET SDK 10
- Rust (stable toolchain)
- Azure CLI
- Git

### Clone the repository

```bash
git clone https://github.com/polymind-inc/acmebot.git
cd acmebot
```

## Build and Validation

Run these commands from the repository root.

```bash
dotnet restore ./Acmebot.slnx
dotnet build -c Release ./Acmebot.slnx
dotnet format --verify-no-changes --verbosity detailed --no-restore ./Acmebot.slnx
```

For changes to the Rust ACME client (`rust/acmebot-acme`), also run:

```bash
scripts/ci/pebble-acme-test.sh
```

This is the same check CI runs: `cargo test` plus a live certificate issuance against
a local Pebble CA. See `CONTEXT.md` for background on the Rust rewrite.

These commands cover the contributor-facing validation checks.

## Pull Request Guidelines

- Keep pull requests focused on a single change.
- Include documentation updates when behavior, configuration, or deployment changes.
- Add or update tests when the change affects behavior that can be validated automatically.
- Avoid unrelated refactoring in the same pull request.
- Do not commit secrets, certificates, or populated `local.settings.json` values.

## Release Publishing

The `Release` workflow runs for version tags such as `v5.0.0`. Before pushing the tag, create a matching draft GitHub Release. The workflow uploads the Function App package and then publishes the draft release.

## Submission Checklist

- Build succeeds locally.
- Formatting check passes locally.
- The pull request description explains the problem and the proposed fix.

## Code of Conduct

This project follows the guidelines in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
