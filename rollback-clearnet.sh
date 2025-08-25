#!/usr/bin/env bash
# rollback-clearnet.sh - Restore stock tailscaled to clearnet operation
# 
# This script removes Tor HTTP proxy configuration and restores normal
# tailscaled behavior for connecting to clearnet control servers.

set -Eeuo pipefail

echo "== Rollback to clearnet operation: $(date -Is) =="

### ====== STEP 1: Remove systemd proxy override =================================
OVERRIDE_DIR="/etc/systemd/system/tailscaled.service.d"

if [ -f "${OVERRIDE_DIR}/proxy.conf" ]; then
    echo "[*] Removing systemd proxy override"
    sudo rm -f "${OVERRIDE_DIR}/proxy.conf"
    
    # Remove directory if empty
    if [ -d "${OVERRIDE_DIR}" ] && [ ! "$(ls -A ${OVERRIDE_DIR})" ]; then
        sudo rmdir "${OVERRIDE_DIR}"
        echo "[*] Removed empty override directory"
    fi
else
    echo "[*] No systemd proxy override found"
fi

### ====== STEP 2: Reload and restart tailscaled ==============================
echo "[*] Reloading systemd and restarting tailscaled"
sudo systemctl daemon-reload
sudo systemctl restart tailscaled

# Verify tailscaled is running
sleep 1
if systemctl is-active --quiet tailscaled; then
    echo "[*] tailscaled restarted successfully"
    TAILSCALED_PID="$(pidof tailscaled || true)"
    echo "[*] tailscaled PID: $TAILSCALED_PID"
else
    echo "[!] tailscaled failed to start"
    sudo systemctl status tailscaled
    exit 1
fi

### ====== STEP 3: Optional - Remove Tor HTTPTunnelPort (if added by harness) ===
TOR_CONFIG="/etc/tor/torrc"
TOR_HTTP_PROXY="${TOR_HTTP_PROXY:-127.0.0.1:9152}"

echo "[*] Checking if HTTPTunnelPort should be removed from Tor config"
if grep -qE "^\s*HTTPTunnelPort\s+${TOR_HTTP_PROXY//\./\\.}$" "$TOR_CONFIG" 2>/dev/null; then
    read -p "Remove HTTPTunnelPort ${TOR_HTTP_PROXY} from ${TOR_CONFIG}? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "[*] Removing HTTPTunnelPort from Tor config"
        sudo sed -i "/^\s*HTTPTunnelPort\s\+${TOR_HTTP_PROXY//\./\\.}$/d" "$TOR_CONFIG"
        echo "[*] Restarting Tor"
        sudo systemctl restart tor
    else
        echo "[*] Keeping HTTPTunnelPort in Tor config"
    fi
else
    echo "[*] No HTTPTunnelPort found in Tor config"
fi

### ====== STEP 4: Verify clearnet operation ====================================
echo "[*] Testing clearnet connectivity"

# Give tailscaled a moment to initialize
sleep 2

# Test basic tailscale commands work
if sudo tailscale status --peers=false >/dev/null 2>&1; then
    echo "[*] tailscale status working"
else
    echo "[!] tailscale status failed - check configuration"
fi

# Check if there are any proxy-related environment variables still set
echo "[*] Current tailscaled service environment:"
sudo systemctl show tailscaled --property=Environment

### ====== STEP 5: Instructions for re-enrollment ===========================
echo
echo "=== ROLLBACK COMPLETE ==="
echo
echo "tailscaled is now configured for clearnet operation."
echo
echo "To connect to a standard control server:"
echo "  sudo tailscale up --login-server=https://your-headscale.example.com"
echo "  # OR for Tailscale SaaS:"
echo "  sudo tailscale up"
echo
echo "To check current status:"
echo "  sudo tailscale status"
echo "  sudo systemctl status tailscaled"
echo
echo "If you need to return to Tor operation, run:"
echo "  ./stock-tailscale-tor-harness.sh"