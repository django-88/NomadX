#!/usr/bin/env bash
# Deploy the NomadX Zig payload type into the local Mythic install.
#
# The original C++ payload type at InstalledServices/nomad is left alone.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)/"
MYTHIC_DIR="${MYTHIC_DIR:-$HOME/Tools/Mythic}"
DST="$MYTHIC_DIR/InstalledServices/nomadx"
COMPOSE="$MYTHIC_DIR/docker-compose.yml"

if [[ ! -d "$MYTHIC_DIR" ]]; then
    echo "Mythic directory not found: $MYTHIC_DIR" >&2
    exit 1
fi
if [[ ! -f "$COMPOSE" ]]; then
    echo "Mythic compose file not found: $COMPOSE" >&2
    exit 1
fi

echo "[*] syncing $SRC -> $DST"
sudo rsync -a --delete \
    --exclude '.toolchain/' \
    --exclude '.zig-cache/' \
    --exclude 'zig-out/' \
    --exclude 'dist/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude '.pytest_cache/' \
    --exclude 'nomadx/custom-donut/donut' \
    --exclude 'nomadx/custom-donut/*.o' \
    "$SRC" "$DST/"

echo "[*] registering the nomadx service with Mythic"
sudo "$MYTHIC_DIR/mythic-cli" add nomadx

echo "[*] building the nomadx payload type image"
sudo docker compose -f "$COMPOSE" build nomadx

# Start only the services needed for a NomadX callback. Starting the whole
# compose file can try to build unrelated installed agents (for example the
# broken Kassandra compose entry on this host).
CORE_SERVICES=(
    mythic_postgres
    mythic_rabbitmq
    mythic_graphql
    mythic_nginx
    mythic_server
    mythic_react
    http
    nomadx
)

echo "[*] starting Mythic core services and nomadx"
sudo docker compose -f "$COMPOSE" up -d "${CORE_SERVICES[@]}"

echo "[*] waiting for the nomadx container"
sleep 5
sudo docker ps --filter name=nomadx --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'

echo "[+] deployed. Open the Mythic UI and build an EXE with payload type nomadx and the http profile."
