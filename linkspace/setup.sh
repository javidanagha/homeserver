#!/bin/bash
# Generates .env with random secrets and the Guacamole DB schema, then starts the stack.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
    read -rp "Domain (leave empty for localhost): " DOMAIN
    cat > .env <<EOF
LINKSPACE_DOMAIN=${DOMAIN:-localhost}
VNC_PASSWORD=$(openssl rand -hex 8)
DB_PASSWORD=$(openssl rand -hex 16)
VNC_GEOMETRY=1280x720
EOF
    chmod 600 .env
    echo ".env created"
fi

mkdir -p initdb
if [ ! -s initdb/initdb.sql ]; then
    docker run --rm guacamole/guacamole:1.5.5 /opt/guacamole/bin/initdb.sh --postgresql > initdb/initdb.sql
    echo "initdb.sql generated"
fi

docker compose up -d --build
docker compose ps
