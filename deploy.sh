#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v docker >/dev/null
command -v iptables >/dev/null
command -v ebtables >/dev/null
command -v ip >/dev/null
if ! python3 -m venv .venv 2>/dev/null; then
    apt-get update
    apt-get install -y python3-venv
    python3 -m venv .venv
fi
.venv/bin/python -m pip install -r mcp-kali/requirements.txt
docker build -f docker/Dockerfile.mcp -t kali-mcp:1 docker
docker run --rm -i --network none kali-mcp:1 python3 < docker/build-catalog.py > kali-catalog.slim.json.tmp
mv kali-catalog.slim.json.tmp kali-catalog.slim.json
.venv/bin/python -m compileall -q mcp-kali
echo 'Core image ready. Enable HTTPS with: sh deploy-http.sh YOUR_DOMAIN'
