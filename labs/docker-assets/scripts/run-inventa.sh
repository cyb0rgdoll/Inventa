#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
docker compose up -d --build
docker compose run --rm scanner \
  -s labs/docker-assets/scope.txt \
  -t labs/docker-assets/targets.txt \
  -w labs/docker-assets/websites.txt \
  -W standard \
  --cloud-enum \
  --cloud-provider aws \
  --report both \
  -o /workspace/results/docker-lab
