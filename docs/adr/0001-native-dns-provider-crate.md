# Native DNS provider integrations live in a new `acmebot-dns` crate, ported one provider at a time

Status: accepted

The Rust rewrite's dns-01 flow currently only supports a shell-hook or manual-prompt
(`rust/acmebot-cli/src/dns_hook.rs`); the 17 native provider integrations behind
`src/Acmebot.App/Providers/*.cs` (Cloudflare, Azure DNS, Route53, GoDaddy, etc.) are
still on the backlog and block removing the C# app.

We decided to port them into a new workspace member, `rust/acmebot-dns`, rather than as
modules inside `acmebot-cli`, so the trait and provider implementations can be unit
tested with `wiremock` independently of the CLI/orchestration layer, and so a future
HTTP API/orchestrator crate can depend on `acmebot-dns` directly without pulling in CLI
concerns. The core is a single async `DnsProvider` trait mirroring the C# `IDnsProvider`
shape (`name`, `propagation_delay`, `list_zones`, `create_txt_record`,
`delete_txt_record`), using native `async fn` in traits (dyn-dispatch is not required
today since the CLI selects one concrete provider at startup; if/when the future
orchestrator needs to hold multiple heterogeneous providers behind one type, we'll
either switch to `async-trait` or an enum wrapper at that point rather than pay the
`Box<dyn Future>` cost now for a need that doesn't exist yet).

Providers are ported incrementally in the same order of complexity used for
`acmebot-acme`'s test-parity pass: Cloudflare first (simple bearer-token REST API,
directly comparable against `CloudflareProvider.cs`), then Azure DNS/Route53/GoDaddy,
then the remaining long tail. Each provider gets its own module with inline `wiremock`
tests (`#[cfg(test)] mod tests` in the provider file itself, since each provider's test
surface is small enough not to need the shared `tests/support/` fixture module
`acmebot-acme` uses).

The trait methods are declared as native `async fn` desugared explicitly to `fn ... ->
impl Future<Output = ...> + Send`, not plain `async fn` in trait — plain `async fn` in
a trait produces a non-`Send` future by default, which fails to compile once a provider
is awaited from the CLI's multi-threaded `#[tokio::main]` runtime (e.g. via
`tokio::spawn`). This was confirmed as a real (not hypothetical) compiler warning
(`async_fn_in_trait`) during the first implementation pass.
