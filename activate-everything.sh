#!/bin/sh
set -eu
cd /opt/kali-mcp
docker image inspect kali-mcp:everything >/dev/null
.venv/bin/python prune-kali-cache.py
docker run --rm --read-only --cap-drop ALL --memory 512m --network none \
    kali-mcp:everything cat /opt/kali-catalog.json > kali-catalog.everything.json.tmp
mv kali-catalog.everything.json.tmp kali-catalog.everything.json
.venv/bin/python - <<'PY'
import json
from pathlib import Path
dest = Path('kali-catalog.everything.json')
data = json.loads(dest.read_text())
assert any(p['name'] == 'kali-linux-everything' for p in data['packages']), 'Everything metapackage missing'
print('Activating full image with', len(data['packages']), 'installed packages')
PY
sed -i '/^MCP_KALI_IMAGE=/d; /^MCP_KALI_CATALOG_PATH=/d; /^MCP_KALI_CGROUP_PARENT=/d' http.env
cat >> http.env <<'EOF'
MCP_KALI_IMAGE=kali-mcp:everything
MCP_KALI_CATALOG_PATH=/opt/kali-mcp/kali-catalog.everything.json
MCP_KALI_CGROUP_PARENT=kali-mcp-workers.slice
EOF
install -m 644 kali-mcp-workers.slice /etc/systemd/system/
systemctl daemon-reload
systemctl start kali-mcp-workers.slice
systemctl restart kali-mcp-http.service
