# Use acme.sh DNS persist mode instead of live DNS API credentials for renewal

Status: accepted

The CronJob container previously issued/renewed certificates with acme.sh's live DNS
API hooks (`dns_azure`/`dns_aws`), which requires standing DNS write credentials in
the recurring renewal job. We instead have a human operator run a one-time, per-domain
Bootstrap step (`acme.sh --make-dns-persist-value`) and manually publish the resulting
Persist TXT record. The CronJob then renews with `acme.sh --issue --dns-persist`,
using only the mounted Account key — no DNS credentials at all in the routine path.

We accepted the trade-off that this depends on the CA supporting
`draft-ietf-acme-dns-persist-01`, which Let's Encrypt only offers on staging today (not
production, as of writing), and that adding a new domain now requires a manual
operator step instead of being fully self-service. We judged this an acceptable cost
for removing DNS write access from the unattended renewal path. Legacy DNS API mode is
kept only as a documented fallback for domains whose CA never adopts persist mode.
