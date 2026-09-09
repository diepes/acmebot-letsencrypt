# CONTEXT: container that uses acme.sh to get certificates and put them in Azure KV

Runs as a k8s CronJob: issues/renews TLS certificates for one or more domains
(wildcard or not) and stores them in Azure Key Vault.

## Language

**Bootstrap step**:
A manual, one-time, per domain-set operation, run via the `acme-bootstrap.sh`
entrypoint, that registers the ACME account (if it doesn't exist yet) and prints the
Persist TXT record(s) to publish. Not automated, not run by the CronJob.
Only required for domains run with `ACME_DNS_MODE=persist` (the default) — a domain
run entirely with `ACME_DNS_MODE=azure` or `ACME_DNS_MODE=aws` never needs it, since
`acme-cron-update.sh` self-registers the ACME account on first run in those modes
(see ADR 0002).

**Account key**:
The ACME account's private key, generated during the Bootstrap step. Identifies the
registered account to the CA and is shared across every domain issued under that
account. Both entrypoint scripts read/write it at a fixed path,
`ACME_HOME/account.key` (exported to acme.sh via the `ACCOUNT_KEY_PATH` env var — there
is no `--accountkeypath` CLI flag), rather than relying on acme.sh's internal,
CA-specific `ca/<host>/directory/account.key` layout.
Exposed as the `ACME_ID_SECRET_KEY` env var — printed by `acme-bootstrap.sh` in its
final `.env`-ready block as a single line (the PEM's real newlines escaped to literal
`\n`, since `docker run --env-file`/compose's `env_file:` have no multiline value
support — see README.md), unescaped back to a real PEM by `acme-cron-update.sh`
(written to `ACME_HOME/account.key` at startup) so the CronJob can run from just an
env file, with no volume/PVC shared with the Bootstrap step. `ACME_HOME` (acme.sh's
`--config-home`) holds only this data — the acme.sh script itself installs elsewhere
in the image — so
it's always safe to mount an empty (or no) volume there.
_Avoid_: "the key" (ambiguous with Certificate key)

**Certificate key**:
The private key generated fresh for a domain's certificate each time `acme.sh --issue`
runs. Written to a local folder, then — if `AZ_KV_NAME` is set — also imported into
Azure Key Vault. Unrelated to the Account key.
_Avoid_: "the key"

**Import PFX**:
The single PKCS#12 file `acme-cron-update.sh` builds (via `openssl pkcs12 -export
-legacy`) from the Certificate key and full chain, and the only artifact ever handed
to `az keyvault certificate import` — never a hand-built PEM (see ADR 0003). Protected
by a fresh random password each run unless `KEYVAULT_CERT_PFX_PASSWORD` is set to a
fixed value (needed to export the same PFX back out of Key Vault later).
_Avoid_: "the certificate file" (ambiguous — the local cert folder also has separate
`.cer`/`.key`/`fullchain.pem` files that are never sent to Key Vault)

### Pre-flight safety checks

Run before ever calling `acme.sh --issue`; see ADR 0004 for why both always run to
completion and report combined errors, rather than stopping at the first failure.

**Renewal pre-check**:
If `AZ_KV_NAME` is set, queries Key Vault for the existing certificate named
`AZ_KV_CERT_NAME`'s expiry and SANs, to decide whether issuance is actually needed.
Exists because `acme.sh`'s own internal skip-if-not-due logic can't be relied on — its
state doesn't persist across separate container runs.
_Avoid_: "renewal check" alone (ambiguous with acme.sh's own internal logic, which this
replaces for this container's purposes)

**SAN match check**:
Inside the Renewal pre-check, compares the existing Key Vault certificate's stored
SANs against the domains actually requested this run (`ACME_DOMAINS`) — necessary
because `AZ_KV_CERT_NAME` is just a static label, decoupled from the domain list.
Default behavior: a mismatch forces re-issuance regardless of expiry; an unverifiable
lookup only warns and falls back to the expiry-only decision.
_Avoid_: "domain check"

**Migration safety guard** (`SAFETY_ONLY_UPD_IF_EXISTING_SAN_MATCH`):
An opt-in, stricter variant of the SAN match check, meant to be enabled only for the
one cutover run per domain and then unset — not a permanent operating mode. Escalates
a not-found certificate, a confirmed SAN mismatch, or an unverifiable SAN lookup into a
hard pre-flight failure (blocking issuance/import) instead of the default warning.
Applies even under `FORCE_RENEW=true` — it guards *which* certificate is touched, not
renewal timing. Exists to prevent silently overwriting the wrong, already-in-production
Key Vault certificate when migrating an existing domain (issued by another CA/process)
onto this script.
_Avoid_: "strict mode" (too vague — there's only this one specific escalation)

**DNS zone access pre-check**:
Only for `ACME_DNS_MODE=azure`: lists the identity's accessible Azure DNS zones and
matches by suffix against every requested domain — the same lookup `acme.sh`'s own
`dns_azure` plugin performs internally — so a missing zone or missing read/list rights
fails fast with a clear, actionable error instead of surfacing only after acme.sh's
DNS-01 challenge attempt fails opaquely later.

**Root CA safety check** (`SAFETY_ALERT_IF_ROOT_CA_NOT`):
An opt-in guard, fails fast before the Key Vault import if the issued certificate's
chain doesn't link back to a given root CA substring — catches e.g. an accidental
staging (`letsencrypt_test`) issuance mistaken for production. Renamed from
`VALIDATE_ROOT_CA` for clarity on what "failure" means (an alert/hard-stop, not silent
validation).
_Avoid_: "chain check", "cert validation" (too generic — this checks one specific
thing, the root)

**Persist TXT record**:
The `_validation-persist.<domain>` DNS TXT record printed by the Bootstrap step and
published once, manually, at the domain's DNS provider. Reused for every future
issuance/renewal; the CronJob never writes to DNS. Exposed as the
`ACME_DNS_KEY`/`ACME_DNS_VALUE` env var pair in `acme-bootstrap.sh`'s printed
`.env` block (one shared record per apex domain — a domain plus its wildcard, e.g.
`example.com` + `*.example.com`, need only one; multiple distinct apex domains in one
`ACME_DOMAINS` produce numbered `_1`/`_2`... pairs instead). `acme.sh`'s
`--make-dns-persist-value` only ever computes a record for the *first* `-d` given to
it — any further `-d` flags are silently ignored by that subcommand — so
`acme-bootstrap.sh` calls it once per unique apex domain rather than once with every
`-d` flag. `acme.sh` also has a known bug
([acmesh-official/acme.sh#7168](https://github.com/acmesh-official/acme.sh/issues/7168))
where passing a wildcard domain (e.g. `*.example.com`) directly as `-d` prints the
record name with a literal `*.` label (`_validation-persist.*.example.com`); calling
it with the bare apex only (as `acme-bootstrap.sh` does) avoids ever triggering this,
though the parsing still strips it defensively.

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
that renews certificates: reads `ACME_DOMAINS` and the Account key (from
`ACME_ID_SECRET_KEY` or a pre-populated `ACME_HOME` — required for `ACME_DNS_MODE=persist`,
optional for `ACME_DNS_MODE=azure`/`ACME_DNS_MODE=aws`, which self-register instead), runs
`acme.sh --issue` with `--dns-persist`, `--dns dns_azure`, or `--dns dns_aws` depending
on `ACME_DNS_MODE`,
then (Phase 1) writes the certificate + Certificate key to a local folder always, and
imports them into Azure Key Vault via the Azure CLI only if `AZ_KV_NAME` is set
(empty/unset means local-folder-only). Has no DNS write access in `persist` mode;
in `azure`/`aws` mode it holds standing DNS write credentials (see ADR 0002).
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
   <apex-domain> [--dns-persist-wildcard]`, once per unique apex domain in
   `ACME_DOMAINS` → prints a copy-pasteable `.env` block (`ACME_DOMAINS`/
   `ACME_EMAIL`/`ACME_SERVER`/`ACME_DNS_KEY`/`ACME_DNS_VALUE`/
   `ACME_ID_SECRET_KEY`, plus empty `AZ_KV_NAME`/`AZ_KV_CERT_NAME`
   placeholders); operator publishes the TXT record(s) by hand.
2. **CronJob** (automated, `acme-cron-update.sh`): `acme.sh --issue -d <domain> [-d
   <domain>...] --dns-persist` → **Phase 1**: write cert + key locally always, then
   (only if `AZ_KV_NAME` is set) `az keyvault certificate import` into Azure Key
   Vault.

## Legacy: DNS API mode

~~Older issuance used acme.sh's live DNS API hooks (`dns_azure`/`dns_aws`), which need
standing DNS write credentials in the CronJob.~~ **Superseded by ADR 0002**: these are
now actively-used, opt-in per-domain modes (`ACME_DNS_MODE=azure`/`ACME_DNS_MODE=aws`),
not merely historical — they're the only way to get a publicly-trusted certificate
today, since no
public CA has shipped `dns-persist-01` to production yet. Kept alongside `persist`
mode (the default) rather than replacing it; expected to shrink back to true
legacy/fallback status once production persist support ships. See ADR 0002.
