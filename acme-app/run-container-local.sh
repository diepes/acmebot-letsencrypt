#!/usr/bin/env bash
set -euo pipefail

docker build -t acmebot-dev ./
docker run -it --rm --entrypoint bash acmebot-dev
