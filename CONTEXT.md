# CONTEXT: Rust Rewrite — Validation Strategy

This document captures how to validate a potential Rust rewrite of Acmebot against the
existing .NET implementation (222 passing tests across `Acmebot.Acme.Tests`,
`Acmebot.App.Tests`, `Acmebot.Cli.Tests`, all xUnit v3 on .NET 10).

## Why the existing tests can't be reused directly

The xUnit test suite only executes .NET assemblies — `cargo test` cannot run them.
`AcmeTestSupport.cs` mocks HTTP responses inline in C# rather than via external fixture
files, so there is nothing to load from Rust as-is. The suite is still valuable as a
**behavioral spec and regression oracle**, just not as directly-executable code.

## Options for validating a Rust rewrite

1. **Port test cases as a spec, not code.** Manually translate each C# test's inputs and
   assertions into Rust test cases (`#[test]`), using an equivalent HTTP mocking layer
   (e.g. `wiremock-rs`, `mockito`).

2. **Golden-file / differential testing.** Extract the data currently hardcoded in the C#
   tests (JWS payloads, ACME directory/order responses, certificate chains, DNS-01
   tokens) into shared JSON/PEM fixture files checked into the repo. Both the C# suite
   and a new Rust suite load the same fixtures and assert the same expected outputs —
   this diffs behavior byte-for-byte without duplicating logic by hand.

3. **Contract testing against a real ACME server (recommended primary approach).**
   Since Acmebot is protocol-heavy (ACME v2 per RFC 8555, DNS-01 validation), spin up
   [Pebble](https://github.com/letsencrypt/pebble) — Let's Encrypt's small test/staging
   ACME CA designed for exactly this kind of client validation — in CI, and run *both*
   the existing C# implementation and the new Rust implementation against it as clients.
   Compare:
   - Account registration / key rollover behavior
   - Order creation, authorization, and challenge flows (DNS-01)
   - Certificate issuance results (chain, SANs, validity)
   - Error handling for malformed/expired/rejected challenges

   This validates real protocol behavior independent of language or internal
   implementation details, and doesn't require porting any C# test code. Pebble supports
   configurable strictness flags and can simulate CA-side quirks (e.g. `retry-after`
   values, alternate chains) that are otherwise hard to reproduce with mocks. Run it as
   a docker-compose service (`letsencrypt/pebble`) alongside both clients in a CI job
   dedicated to cross-implementation parity, separate from each project's own unit
   tests.

4. **Shadow / strangler rollout.** Keep the C# service as the production source of
   truth, run the new Rust service in parallel against the same inputs, and diff outputs
   before cutover. The existing 222 passing .NET tests remain the regression baseline
   that production behavior is checked against, even though Rust never executes them
   directly.

## Suggested next step

Start with option 2 (extract current mocked test data into shared JSON/PEM fixtures) as
a low-cost first step, then stand up a Pebble-based contract test job (option 3) once
enough of the Rust ACME client exists to run a real issuance flow end-to-end.

## Status: Rust ACME core client + Pebble contract validation (done)

As a first vertical slice of the rewrite, `rust/acmebot-acme` ports the core ACME v2
protocol client from `src/Acmebot.Acme` (directory discovery, account creation/lookup,
order/authorization/challenge lifecycle, dns-01 challenge instructions, CSR finalize,
certificate chain download). See the crate's own docs (`rust/acmebot-acme/src/lib.rs`)
for exact scope and deviations (only ES256/P-256 is implemented; DNS provider
integrations, Key Vault, Durable Functions orchestration, the HTTP API, and the CLI are
intentionally out of scope for this crate).

Both implementations were independently validated end-to-end against a real local
[Pebble](https://github.com/letsencrypt/pebble) CA (v2.10.1, prebuilt binaries in
`.tools/pebble/`, started with `.tools/pebble/scripts/start-pebble.sh`):

- **.NET reference harness**: `tools/pebble-parity` (`dotnet run --project
  tools/pebble-parity -- <domain>`) drives the existing `Acmebot.Acme.AcmeClient`
  through account creation → order → dns-01 challenge (via
  `pebble-challtestsrv`'s management API) → CSR finalize → certificate download.
  Confirmed working: a real 2-certificate chain issued by "Pebble Intermediate CA".
- **Rust example**: `rust/acmebot-acme/examples/pebble_issue.rs` (`cargo run --example
  pebble_issue -- <domain>`) drives the new Rust `AcmeClient` through the identical
  flow against the same Pebble instance. Confirmed working after one fix (see below).

This is a working instance of option 3 above, not just a plan: both clients
successfully issued real certificates from the same CA for different test domains in
this session.

### Bug found and fixed via cross-implementation testing

The Rust `download_certificate` content-type check compared the raw `Content-Type`
header value directly, but Pebble returns `application/pem-certificate-chain;
charset=utf-8` (with a `charset` parameter). The C# implementation compares only
`response.ContentType?.MediaType` (the parsed media type, parameters stripped), so the
Rust check was stricter than the original and rejected a valid response. Fixed in
`rust/acmebot-acme/src/client.rs` to split on `;` before comparing — this is exactly
the kind of behavioral discrepancy contract testing against a real CA is meant to
catch (a mocked/hand-written unit test would likely never have exercised this exact
header shape).

### Status: full C# test-behavior parity for `Acmebot.Acme.Tests` (done)

All five remaining `tests/Acmebot.Acme.Tests/*.cs` files (`AcmeClientErrorTests`,
`AcmeClientMetadataTests`, `AcmeClientProtocolTests`, `AcmeClientResourceTests`,
`AcmeClientTests`) have been ported into `rust/acmebot-acme/tests/*.rs` using
`wiremock`, following the pattern established by `happy_path.rs`/`error_paths.rs`. A
shared `tests/support/mod.rs` module mirrors `AcmeTestSupport.cs`/`RecordingHandler`/
`RecordedRequest` (default directory/nonce builders, an `AcmeAccountHandle` factory,
and a `decode_signed_message` helper that base64url-decodes a JWS `protected`/`payload`
body into `serde_json::Value` for structural assertions).

- **Total test count**: 24 → **60** (18 unit tests in `src/`, 42 integration tests
  across `tests/happy_path.rs`, `tests/error_paths.rs`, `tests/metadata.rs`,
  `tests/protocol.rs`, `tests/resource.rs`, `tests/client_tests.rs`).
- **New client methods added** to reach parity: `AcmeClient::get_advertised_profiles`,
  `is_profile_advertised`, `ensure_profile_is_advertised` (thin async wrappers over the
  existing `profile_validation` free functions plus the cached directory, mirroring the
  C# client's own caching/async surface) and `AcmeClient::create_certificate_identifier`
  (the byte-span overload only — see `src/lib.rs` deviation notes).
- **Intentionally skipped** (2 cases, both `X509Certificate2`/ASN.1-dependent, per this
  crate's existing deviation notes): `AcmeClientResourceTests.GetRenewalInfoAsync_CertificateOverload_UsesDerivedIdentifier`
  and `CreateCertificateIdentifier_CertificateOverload_ReturnsBase64UrlEncodedSegments`
  (both derive an authority-key-identifier/serial-number pair from a parsed X.509
  certificate; the portable byte-span overload they ultimately call is fully covered).
  `DownloadCertificateAsync_RequestsPemChainAndParsesCertificate`'s `Thumbprint`
  assertion was also dropped for the same reason, but the rest of that test (PEM
  content, Accept/Content-Type request headers, alternate/up Link propagation) is
  ported as `download_certificate_requests_pem_chain_and_propagates_links`.
- No further behavioral deviations or bugs were found while porting this pass beyond
  the content-type charset fix already recorded above; the client's nonce-chaining,
  bad-nonce retry, EAB/key-change JWS nesting, and header-propagation behavior all
  matched the C# reference exactly once mirrored in wiremock.

### Automated CI: `scripts/ci/pebble-acme-test.sh`

The manual validation above (mocked test suite + live Pebble issuance) is now
automated in `scripts/ci/pebble-acme-test.sh` and wired into the `acme-tests` job in
`.github/workflows/ci.yml`. Run it locally with no arguments to reproduce exactly what
CI does:

```
scripts/ci/pebble-acme-test.sh
```

It installs Pebble (idempotent — downloads prebuilt binaries + test config/certs from
the upstream GitHub release/source tarball into `.tools/pebble/` only if not already
present), then runs, in order:

1. `cargo test --workspace` (Rust, mocked HTTP, no Pebble needed)
2. Starts Pebble + `pebble-challtestsrv`, waits for readiness, then issues a real
   certificate through `cargo run --example pebble_issue`
3. Stops Pebble/challtestsrv and prints a pass/fail summary (non-zero exit if
   anything failed)

Useful flags: `--skip-mocked-tests`, `--skip-parity`, `--keep-pebble` (leaves Pebble
running afterwards for manual poking). See `scripts/ci/pebble-acme-test.sh --help` for
the full list.

This script no longer runs any C# steps — it was simplified to be Rust-only once the
Rust port reached full test parity with `Acmebot.Acme.Tests` (see above). The C#
harness (`tools/pebble-parity`) and `Acmebot.Acme.Tests` still exist and still pass
under `dotnet test`/`dotnet run`, but they're no longer part of the automated script;
they remain available for manual side-by-side comparison until `src/Acmebot.Acme` is
actually removed (see the C# removal plan below).

### Remaining rewrite backlog (not yet started)

- DNS-01 provider integrations (Cloudflare, Route53, Azure DNS, GoDaddy, etc. — see
  `src/Acmebot.App/Options/*.cs` and `src/Acmebot.App/Providers`)
- Key Vault-backed certificate/key storage
- Durable Functions orchestration equivalent (renewal scheduling, retry/backoff,
  per-certificate state)
- HTTP API (dashboard backend) and the `Acmebot.Cli` command-line client
- RS256/ES384/ES512 signer support (only ES256/P-256 is implemented in
  `rust/acmebot-acme` so far)

### Container image: `rust/acmebot-cli` (the `acmebot` binary)

The project is now container/Kubernetes-only (all Bicep/ARM deployment code and
docs have been removed — see `deploy/k8s/`). The `Dockerfile` no longer builds the
.NET Azure Functions app; it builds `rust/acmebot-cli`, a new workspace member that
wraps `acmebot-acme` in a general-purpose ACME v2 issuance CLI (binary name
`acmebot`, subcommand `acmebot issue ...`). It works against any ACME directory URL
(Let's Encrypt prod/staging, Pebble, etc.) and automates the dns-01 challenge via
operator-supplied `--dns-txt-set-command`/`--dns-txt-clear-command` shell hooks
(falling back to a certbot-style manual prompt if omitted) — this sidesteps the
still-unimplemented DNS provider integrations listed above while remaining useful
today.

The `Dockerfile` is a multi-stage build: a `rust:1-slim-bookworm` builder stage
(with a Cargo-registry cache mount and a dummy-`main.rs`/`lib.rs` warm-up layer for
dependency caching) cross-compiles the release binary for the requested
`TARGETPLATFORM`, and a minimal `debian:bookworm-slim` runtime stage runs it as a
non-root user. `.dockerignore` now excludes everything except `rust/` (the .NET
build no longer needs the context). CI (`.github/workflows/ci.yml`,
`container-build` job) validates the image builds for both `linux/amd64` and
`linux/arm64` via `docker buildx build --platform ...` (QEMU + Buildx actions); it
does not push anywhere yet — no registry/publish step has been requested.


