# syntax=docker/dockerfile:1
# Builds the `acmebot` container: acme.sh handles ACME DNS-01 validation via
# DNS persist mode (`--dns-persist`, see CONTEXT.md and
# https://github.com/acmesh-official/acme.sh/wiki/DNS-persist-mode) and the
# Azure CLI imports the issued certificate + key into an Azure Key Vault.
#
# acme.sh is pure shell + curl/openssl, so the only extra tool needed on top
# of a plain Debian base is the Azure CLI itself.
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
# acme.sh) still runs as root; we only drop privileges via `USER app` at the
# very end, after ownership is fixed up.
RUN groupadd -r app && useradd -r -m -d /home/app -g app app

# Installs acme.sh's script/CA-hook files to ACME_INSTALL_HOME (baked into
# the image, never mounted) and points its persistent, writable state
# (account key, per-domain renewal config) at ACME_HOME via --config-home
# (a separate directory, safe to bind-mount or back with a k8s PVC). Keeping
# these distinct matters: acme.sh's --home is *also* where it installs its
# own acme.sh script, so if that were the mount point, an empty/fresh volume
# at ACME_HOME would shadow the installed script itself ("acme.sh: command
# not found"). --nocron avoids scheduling a renewal cronjob inside the image
# (renewals are driven by re-running the container).
#
# ACME_HOME is a dedicated top-level path rather than /home/app/.acme.sh so
# that the one directory that needs to persist across container runs (the
# ACME account key + per-domain renewal state) has a stable, well-known mount
# point independent of the runtime user's home directory. This matters
# because Kubernetes/OpenShift-style security contexts often run the
# container as an arbitrary non-root UID with no usable $HOME, and because a
# dedicated path makes the volume's purpose unambiguous wherever it's mounted
# (docker-compose bind mount or k8s PersistentVolumeClaim).
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
ENV ACME_INSTALL_HOME=/opt/acme.sh
ENV ACME_HOME=/acme.cert.store
# Staging by default so debugging can't burn production rate limits; set
# ACME_SERVER=letsencrypt deliberately at runtime for real certificates.
ENV ACME_SERVER=letsencrypt_test
# Create both directories as root first, then hand ownership to `app`
# explicitly, so the image layer itself has the correct owner before any
# volume is ever mounted at ACME_HOME.
RUN mkdir -p "${ACME_INSTALL_HOME}" "${ACME_HOME}" \
    && chown app:app "${ACME_INSTALL_HOME}" "${ACME_HOME}"

RUN curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/${ACME_SH_COMMIT}.tar.gz" -o /tmp/acme.sh.tar.gz \
    && echo "${ACME_SH_SHA256}  /tmp/acme.sh.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/src/acme.sh \
    && tar -xzf /tmp/acme.sh.tar.gz -C /usr/src/acme.sh --strip-components=1 \
    && rm /tmp/acme.sh.tar.gz \
    && (cd /usr/src/acme.sh && ./acme.sh --install \
          --home "${ACME_INSTALL_HOME}" \
          --config-home "${ACME_HOME}" \
          --nocron) \
    && rm -rf /usr/src/acme.sh \
    && chown -R app:app "${ACME_INSTALL_HOME}" "${ACME_HOME}" \
    && ln -s "${ACME_INSTALL_HOME}/acme.sh" /home/app/acme.sh
ENV PATH="${ACME_INSTALL_HOME}:${PATH}"

# /certs is where acme-cron-update.sh writes issued certs before importing
# them into Key Vault; pre-create it with `app` ownership since it runs
# non-root.
RUN mkdir -p /certs && chown app:app /certs

USER app
WORKDIR /home/app
# --chown is required here: plain COPY always writes root:root, even under
# `USER app`, so chmod as the non-root `app` user would otherwise fail with
# "Operation not permitted" (app doesn't own the files).
COPY --chown=app:app acme-scripts/* /home/app/
RUN chmod +x /home/app/acme-*.sh

# Default entrypoint is acme.sh itself, so any acme.sh flag can be passed
# straight to `docker run`/k8s `args:` without overriding anything. The two
# scripts below are alternate entrypoints for this container's actual
# workflows (see CONTEXT.md) and are selected with `--entrypoint` (docker
# run) or `command:` (k8s):
#   /home/app/acme-bootstrap.sh    manual, one-time account + TXT record setup
#   /home/app/acme-cron-update.sh  automated, recurring issue/renew + KV import
ENTRYPOINT ["acme.sh"]
