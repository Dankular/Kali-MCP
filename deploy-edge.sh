#!/bin/sh
# Optional: share an occupied 443 listener by TLS hostname, preserving its backend.
set -eu
cd /opt/kali-mcp
DOMAIN=${1:?Usage: sh deploy-edge.sh DOMAIN PUBLIC_IPV4 [--prepare]}
PUBLIC_IP=${2:?Provide the host public IPv4 address}
case "$DOMAIN" in *[!a-zA-Z0-9.-]*|'') echo 'Invalid domain' >&2; exit 1;; esac
.venv/bin/python -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$PUBLIC_IP"
command -v haproxy >/dev/null
mkdir -p /etc/haproxy
cat > /etc/haproxy/kali-mcp.cfg <<EOF
global
    log stdout format raw local0
    user haproxy
    group haproxy
    maxconn 4096

defaults
    log global
    mode tcp
    timeout connect 10s
    timeout client 24h
    timeout server 24h

frontend tls_hostnames
    bind 0.0.0.0:10443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend kali_mcp if { req.ssl_sni -i $DOMAIN }
    default_backend existing_https

backend kali_mcp
    server kali 127.0.0.1:9443

backend existing_https
    server existing 127.0.0.1:443
EOF
haproxy -c -f /etc/haproxy/kali-mcp.cfg
umask 077
cat > edge.env <<EOF
KALI_MCP_EDGE_PUBLIC_IP=$PUBLIC_IP
KALI_MCP_EDGE_PORT=10443
EOF
.venv/bin/python - "$DOMAIN" <<'PY'
from pathlib import Path
import sys
domain = sys.argv[1]
path = Path('http.env')
changes = {
    'MCP_KALI_ALLOWED_HOSTS': f'{domain},{domain}:443,{domain}:9443',
    'MCP_KALI_ALLOWED_ORIGINS': f'https://{domain},https://{domain}:443,https://{domain}:9443',
    'MCP_KALI_PUBLIC_URL': f'https://{domain}',
}
lines = [line for line in path.read_text().splitlines() if line.split('=',1)[0] not in changes]
path.write_text('\n'.join(lines + [f'{key}={value}' for key,value in changes.items()]) + '\n')
PY
install -m 644 kali-mcp-edge.service /etc/systemd/system/
systemctl daemon-reload
if [ "${3:-}" = --prepare ]; then
    echo 'Prepared only. Test the edge listener before enabling kali-mcp-edge.service.'
else
    systemctl restart kali-mcp-http.service
    systemctl enable --now kali-mcp-edge.service
fi
