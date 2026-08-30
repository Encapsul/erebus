#!/usr/bin/env bash
# deploy_registry.sh — one-shot deploy of the erebus registry on a fresh VPS.
#
# Usage: sudo bash deploy_registry.sh [domain]
#   domain: default registry.erebus.io
#
# Does NOT obtain TLS certs — run `certbot` afterwards or provide your own.
set -euo pipefail

DOMAIN="${1:-registry.erebus.io}"
INSTALL_DIR="/opt/erebus-registry"
DATA_DIR="$INSTALL_DIR/data"
USER="erebus"

echo "== erebus registry deploy (domain=$DOMAIN) =="

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run as root (or with sudo)"
  exit 1
fi

# 1. Create service user (no login, no home)
if ! id "$USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi

# 2. Install Python deps (stdlib only — nothing to install)
#    The registry_server.py uses only stdlib + the system python3.

# 3. Copy artifacts
mkdir -p "$INSTALL_DIR" "$DATA_DIR"
cp scripts/registry_server.py "$INSTALL_DIR/"
cp scripts/registry.service /etc/systemd/system/erebus-registry.service
chown -R "$USER:$USER" "$INSTALL_DIR" "$DATA_DIR"
chmod +x "$INSTALL_DIR/registry_server.py"

# 4. Render nginx config
sed -i "s/registry\.erebus\.io/$DOMAIN/g" scripts/nginx-registry.conf
cp scripts/nginx-registry.conf /etc/nginx/sites-available/erebus-registry
ln -sf /etc/nginx/sites-available/erebus-registry /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# 5. Install periodic integrity timer
cp scripts/registry-integrity.service /etc/systemd/system/erebus-registry-integrity.service
cp scripts/registry-integrity.timer /etc/systemd/system/erebus-registry-integrity.timer
systemctl daemon-reload
systemctl enable --now erebus-registry-integrity.timer

# 6. Enable + start
systemctl daemon-reload
systemctl enable --now erebus-registry.service

# 6. Bootstrap admin user (first registration becomes owner/admin)
echo ""
echo "== bootstrap =="
echo "1. Register first user:"
echo "   curl -s -X POST https://$DOMAIN/auth/register \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"username\":\"admin\",\"password\":\"<10+ chars>\"}'"
echo ""
echo "2. Obtain TLS cert (if not already done):"
echo "   certbot --nginx -d $DOMAIN"
echo ""
echo "3. Verify:"
echo "   curl -s https://$DOMAIN/health"
echo "   curl -s https://$DOMAIN/stats"
echo ""
echo "Registry deployed to https://$DOMAIN"
