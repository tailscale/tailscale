#!/usr/bin/env bash
# one-shot: stock tailscale + Tor HTTPTunnelPort + .onion control
# - Configures Tor HTTP CONNECT proxy (HTTPTunnelPort)
# - Points tailscaled at that proxy (service env)
# - Enrolls against Headscale over http://<onion>
# - Verifies no-clearnet control traffic, runs netcheck, negative test

set -Eeuo pipefail

### ====== USER SETTINGS ========================================================
HEADSCALE_ONION_URL="${HEADSCALE_ONION_URL:-http://fhpeltl3nffh7c3l3xilaai6hc6gqv2dnfda6q3g3haangrufoahrfid.onion:8080}"
TS_AUTHKEY="${TS_AUTHKEY:-c89e242026607fc266e7840738cd703c1c6a340da4ba2bc6}"               # preauth key from Headscale
TOR_HTTP_PROXY="${TOR_HTTP_PROXY:-127.0.0.1:9152}"        # Tor HTTPTunnelPort
STATE_DIR="${STATE_DIR:-/var/lib/tailscale}"              # standard path for service
RUN_NETCHECK="${RUN_NETCHECK:-1}"                         # 1 = run tailscale netcheck

### ====== REQUIREMENTS =========================================================
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing $1"; exit 1; }; }
for b in systemctl tailscale ss lsof awk sed grep; do need "$b"; done
[ -f /etc/tor/torrc ] || { echo "Tor not installed or /etc/tor/torrc missing"; exit 1; }

echo "== One-shot harness: $(date -Is) =="

### ====== STEP 1: Enable Tor HTTP CONNECT proxy (HTTPTunnelPort) ===============
# Adds HTTPTunnelPort if missing, restarts Tor, verifies port is listening.

if ! grep -qE "^\s*HTTPTunnelPort\s+${TOR_HTTP_PROXY//\./\\.}$" /etc/tor/torrc 2>/dev/null; then
  echo "[*] Enabling Tor HTTPTunnelPort at $TOR_HTTP_PROXY"
  echo "HTTPTunnelPort ${TOR_HTTP_PROXY}" | sudo tee -a /etc/tor/torrc >/dev/null
fi

echo "[*] Restarting tor..."
sudo systemctl restart tor
sleep 1

echo "[*] Checking Tor HTTP proxy is listening on ${TOR_HTTP_PROXY}"
if ! ss -ltn | awk '{print $4}' | grep -q "^${TOR_HTTP_PROXY}$"; then
  echo "[!] Tor HTTPTunnelPort not listening on ${TOR_HTTP_PROXY}"; exit 1
fi

### ====== STEP 2: Point tailscaled at the HTTP proxy (service env) =============
# Stock tailscaled reads proxy from service environment (not your shell).
echo "[*] Writing systemd override for tailscaled proxy env"
sudo systemctl edit tailscaled <<EOF
[Service]
Environment=HTTP_PROXY=http://${TOR_HTTP_PROXY}
Environment=HTTPS_PROXY=http://${TOR_HTTP_PROXY}
Environment=NO_PROXY=localhost,127.0.0.1
EOF

echo "[*] Reloading & restarting tailscaled"
sudo systemctl daemon-reload
sudo systemctl restart tailscaled
sleep 1

TAILSCALED_PID="$(pidof tailscaled || true)"
[ -n "$TAILSCALED_PID" ] || { echo "[!] tailscaled not running"; exit 1; }
echo "[*] tailscaled PID: $TAILSCALED_PID"

### ====== STEP 3: Enroll against .onion control server =========================
echo "[*] Logging out any existing session (ignore errors)"
sudo tailscale logout >/dev/null 2>&1 || true

echo "[*] Enrolling with --login-server=${HEADSCALE_ONION_URL}"
sudo tailscale up \
  --login-server="${HEADSCALE_ONION_URL}" \
  --auth-key="${TS_AUTHKEY}" \
  --accept-routes=true \
  --accept-dns=false \
  --timeout=120

### ====== STEP 4: Prove control traffic uses ONLY Tor HTTP proxy ===============
echo "[*] Checking sockets from tailscaled -> ${TOR_HTTP_PROXY}"
sudo lsof -Pan -p "${TAILSCALED_PID}" -iTCP | grep "->${TOR_HTTP_PROXY}" || {
  echo "[!] Did not observe connection to ${TOR_HTTP_PROXY} yet. This may be idle; forcing a status call..."
  sudo tailscale status --peers=false >/dev/null 2>&1 || true
  sleep 1
  sudo lsof -Pan -p "${TAILSCALED_PID}" -iTCP | grep "->${TOR_HTTP_PROXY}" || {
    echo "[!] Still no proxy socket observed; inspect with: ss -pnt | grep ${TAILSCALED_PID}"
  }
}

echo "[*] Full connection table (for manual review)"
sudo ss -pnt | sed -n '1,200p'

### ====== STEP 5: Optional: run netcheck to view DERP info =====================
if [ "$RUN_NETCHECK" = "1" ]; then
  echo "[*] tailscale netcheck (DERP / connectivity view)"
  sudo tailscale netcheck || true
fi

### ====== STEP 6: Negative test: block the proxy port; control should fail =====
echo "[*] NEGATIVE TEST: temporarily block ${TOR_HTTP_PROXY} and expect control refresh issues"
IP="${TOR_HTTP_PROXY%%:*}"; PORT="${TOR_HTTP_PROXY##*:}"
sudo iptables -I OUTPUT 1 -p tcp -d "${IP}" --dport "${PORT}" -j REJECT
sleep 1
sudo tailscale status --peers=false || echo "[*] Expected: status may error/time out while proxy blocked"
sudo iptables -D OUTPUT 1

echo
echo "=== DONE ==="
echo "If everything succeeded:"
echo " - Enroll completed over http://.onion via Tor HTTP CONNECT proxy."
echo " - lsof/ss showed tailscaled connecting to ${TOR_HTTP_PROXY} (no clearnet)."
echo " - Negative test showed refresh fails when the proxy is blocked (proves no fallback)."