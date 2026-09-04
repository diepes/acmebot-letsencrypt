# syntax=docker/dockerfile:1
# Builds the `acmebot` container: acme.sh handles ACME DNS-01 validation
# (dns_azure or dns_aws, see CONTEXT.md and
# https://github.com/acmesh-official/acme.sh/wiki/dnsapi) and the Azure CLI
# imports the issued certificate + key into an Azure Key Vault.
#
# acme.sh's dns_azure and dns_aws hooks are pure shell + curl/openssl (no
# aws-cli / extra SDKs required), so the only extra tool needed on top of a
# plain Debian base is the Azure CLI itself.
#
# https://www.debian.org/releases/
# Debian 13 "trixie" was released 2025-08-09 and is the current stable release.
FROM debian:trixie-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# packages.microsoft.com has no "trixie" dist yet; InstallAzureCLIDeb.sh
# detects that and automatically falls back to its "bookworm" packages,
# which install and run fine on trixie.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl bash openssl socat coreutils gnupg lsb-release \
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. Everything below that needs root (installing
# acme.sh, copying the entrypoint) still runs as root; we only drop
# privileges via `USER app` at the very end, after ownership is fixed up.
RUN groupadd -r app && useradd -r -m -d /home/app -g app app

# Installs to /home/app/.acme.sh; --nocron avoids scheduling a renewal
# cronjob inside the image (renewals are driven by re-running the container).
#
# Pinned to a specific commit (tag 3.1.4) instead of piping get.acme.sh/master
# into `sh`, for two reasons:
#   1. Security: avoids executing an unpinned, mutable branch tip as root.
#   2. Correctness: acme.sh is not a standalone file — it needs its sibling
#      dnsapi/dns_azure.sh and dnsapi/dns_aws.sh hook scripts (and deploy/
#      notify hooks), which only come from the full repo tarball, not from
#      curling the single raw acme.sh file.
# Bump ACME_SH_COMMIT (and the checksum) deliberately to pick up updates.
ARG ACME_SH_COMMIT=3661fd86b6304115e42f43910e6dd452ab9866d6
ARG ACME_SH_SHA256=9af3ad3d775a5782246df4cdd4b4e7b9b3179deb63c509b10e3ba0433093a884
ARG ACME_EMAIL=acme@example.com
ENV ACME_HOME=/home/app/.acme.sh

RUN curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/${ACME_SH_COMMIT}.tar.gz" -o /tmp/acme.sh.tar.gz \
    && echo "${ACME_SH_SHA256}  /tmp/acme.sh.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/acme.sh \
    && tar -xzf /tmp/acme.sh.tar.gz -C /usr/src/acme.sh --strip-components=1 \
    && rm /tmp/acme.sh.tar.gz \
    && (cd /usr/src/acme.sh && ./acme.sh --install --home "${ACME_HOME}" --nocron --email "${ACME_EMAIL}") \
    && rm -rf /usr/src/acme.sh \
    && chown -R app:app "${ACME_HOME}"
ENV PATH="${ACME_HOME}:${PATH}"

# /certs is where the entrypoint writes issued certs before importing them
# into Key Vault; pre-create it with `app` ownership since it runs non-root.
RUN mkdir -p /certs && chown app:app /certs

COPY DockerEntrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER app

ENTRYPOINT ["/entrypoint.sh"]
