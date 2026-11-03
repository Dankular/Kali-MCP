#!/bin/sh
set -eu
cd /opt/kali-mcp
DOMAIN=${1:-kali.khosa.co}
case "$DOMAIN" in *[!a-zA-Z0-9.-]*|'') echo 'Invalid domain' >&2; exit 1;; esac
python3 -m venv .certbot
.certbot/bin/python -m pip install 'certbot>=5.4,<6'
.certbot/bin/certbot certonly --standalone --non-interactive --agree-tos \
    --register-unsafely-without-email --cert-name kali-mcp -d "$DOMAIN" --keep-until-expiring
existing_image=$(sed -n 's/^MCP_KALI_IMAGE=//p' http.env 2>/dev/null | tail -n 1 || true)
existing_catalog=$(sed -n 's/^MCP_KALI_CATALOG_PATH=//p' http.env 2>/dev/null | tail -n 1 || true)
umask 077
cat > http.env <<EOF
MCP_KALI_HTTP_HOST=0.0.0.0
MCP_KALI_HTTP_PORT=9443
MCP_KALI_PUBLIC_URL=https://$DOMAIN:9443
MCP_KALI_ALLOWED_HOSTS=$DOMAIN:9443
MCP_KALI_ALLOWED_ORIGINS=https://$DOMAIN:9443
MCP_KALI_ALLOW_PRIVATE=0
MCP_KALI_IMAGE=${existing_image:-kali-mcp:1}
MCP_KALI_CATALOG_PATH=${existing_catalog:-/opt/kali-mcp/kali-catalog.slim.json}
MCP_KALI_CGROUP_PARENT=kali-mcp-workers.slice
MCP_KALI_TLS_CERT=/etc/letsencrypt/live/kali-mcp/fullchain.pem
MCP_KALI_TLS_KEY=/etc/letsencrypt/live/kali-mcp/privkey.pem
EOF
install -m 644 kali-mcp-http.service kali-mcp-cert-renew.service kali-mcp-cert-renew.timer kali-mcp-workers.slice /etc/systemd/system/
systemctl daemon-reload
systemctl start kali-mcp-workers.slice
systemctl enable --now kali-mcp-cert-renew.timer
systemctl enable kali-mcp-http.service
systemctl restart kali-mcp-http.service
echo "HTTPS MCP endpoint: https://$DOMAIN:9443/mcp"
