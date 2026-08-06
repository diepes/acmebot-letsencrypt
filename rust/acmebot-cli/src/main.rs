//! `acmebot` — a general-purpose ACME v2 (RFC 8555) certificate issuance CLI built on
//! the [`acmebot_acme`] library crate.
//!
//! Scope: this CLI issues certificates against any ACME v2 server (Let's Encrypt
//! production/staging, Pebble, etc.) using the dns-01 challenge, either driven by an
//! operator-supplied shell hook (`--dns-txt-set-command`/`--dns-txt-clear-command`) or
//! interactively ("manual mode", printing the TXT record and waiting for Enter — akin
//! to certbot's manual plugin). It intentionally does **not** implement DNS provider
//! integrations, renewal scheduling/orchestration, or Key Vault-backed key storage —
//! see `CONTEXT.md` at the repository root for the full rewrite backlog. Only ES256
//! (P-256 ECDSA) ACME account keys are supported, consistent with `acmebot-acme`'s
//! documented scope.

mod dns_hook;
mod issue;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "acmebot", version, about = "ACME v2 certificate issuance CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Issue a new certificate via the ACME dns-01 challenge.
    Issue(issue::IssueArgs),
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Issue(args) => run_issue(args),
    };

    if let Err(message) = result {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

fn run_issue(args: issue::IssueArgs) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start async runtime: {e}"))?;

    runtime.block_on(issue::run(args))
}
