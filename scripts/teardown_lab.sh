#!/bin/bash
# Tear down the Inventa hybrid lab
set -e

echo "[*] Stopping and removing lab containers..."
docker rm -f inventa-web-server inventa-db-server inventa-file-server \
  inventa-dmz-web inventa-dmz-mail inventa-localstack 2>/dev/null || true

echo "[*] Removing lab networks..."
docker network rm corp-lan dmz-net 2>/dev/null || true

echo "[✓] Lab torn down."
