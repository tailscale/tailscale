# Near-Stock Tailscale Approach (Recommended)

This document describes the simpler approach to connect Tailscale to Headscale .onion servers **without forking Tailscale**, using standard HTTP proxy functionality and helper tools.

## 🎯 Why This Approach is Better

While the SOCKS5 patch works perfectly, this near-stock approach has significant advantages:

- **✅ No Fork Maintenance**: Use official Tailscale binaries
- **✅ Easier Updates**: Always get latest Tailscale features and security fixes
- **✅ Simpler Deployment**: Standard installation process
- **✅ Less Complexity**: No custom builds or patches required
- **✅ Better Support**: Official binaries have full vendor support

## 🔧 Implementation Options

### Option 1: HTTP Proxy Bridge (Recommended)

Create an HTTP-to-SOCKS bridge using `socat`:

```bash
#!/bin/bash
# start-tailscale-tor-bridge.sh

# Configuration
HEADSCALE_ONION="fhpeltl3nffh7c3l3xilaai6hc6gqv2dnfda6q3g3haangrufoahrfid.onion"
HEADSCALE_PORT="8080"
LOCAL_BRIDGE_PORT="18080"
TOR_SOCKS_PORT="9050"

echo "Starting HTTP-to-SOCKS bridge for Tailscale..."

# Start the bridge (HTTP -> SOCKS5 -> .onion)
socat TCP-LISTEN:${LOCAL_BRIDGE_PORT},fork,reuseaddr \
      SOCKS4A:127.0.0.1:${HEADSCALE_ONION}:${HEADSCALE_PORT},socksport=${TOR_SOCKS_PORT} &

BRIDGE_PID=$!
echo "Bridge running on port ${LOCAL_BRIDGE_PORT} (PID: ${BRIDGE_PID})"

# Configure Tailscale to use HTTP proxy
export HTTP_PROXY="http://127.0.0.1:${LOCAL_BRIDGE_PORT}"
export HTTPS_PROXY="http://127.0.0.1:${LOCAL_BRIDGE_PORT}"

# Connect to "localhost" which gets proxied to .onion
tailscale up \
  --login-server="http://127.0.0.1:${LOCAL_BRIDGE_PORT}" \
  --auth-key="c89e242026607fc266e7840738cd703c1c6a340da4ba2bc6" \
  --accept-routes=true \
  --accept-dns=false

echo "Tailscale connected via Tor bridge"
echo "To stop: kill ${BRIDGE_PID}"
```

**Usage**:
```bash
chmod +x start-tailscale-tor-bridge.sh
./start-tailscale-tor-bridge.sh
```

### Option 2: Transparent Proxy (Advanced)

Use `iptables` to transparently redirect traffic:

```bash
#!/bin/bash
# setup-transparent-tor-proxy.sh

# This approach requires root and careful iptables configuration
# Only recommended for advanced users

HEADSCALE_ONION="fhpeltl3nffh7c3l3xilaai6hc6gqv2dnfda6q3g3haangrufoahrfid.onion"
LOCAL_IP="127.0.0.2"  # Unused local IP for redirection

echo "Setting up transparent Tor proxy for Tailscale..."

# Add local IP alias  
ip addr add ${LOCAL_IP}/32 dev lo

# Add hosts entry to make Tailscale think it's connecting to local server
echo "${LOCAL_IP} headscale-local.internal" >> /etc/hosts

# Redirect traffic from our fake local server to Tor
iptables -t nat -A OUTPUT -d ${LOCAL_IP} -p tcp --dport 8080 \
  -j DNAT --to-destination 127.0.0.1:18080

# Start socat bridge (same as Option 1)
socat TCP-LISTEN:18080,fork,reuseaddr \
      SOCKS4A:127.0.0.1:${HEADSCALE_ONION}:8080,socksport=9050 &

# Connect using fake local hostname
tailscale up \
  --login-server="http://headscale-local.internal:8080" \
  --auth-key="c89e242026607fc266e7840738cd703c1c6a340da4ba2bc6" \
  --accept-routes=true \
  --accept-dns=false

echo "Tailscale connected via transparent proxy"
```

### Option 3: torsocks Wrapper (Simple)

Wrap the Tailscale daemon with `torsocks`:

```bash
#!/bin/bash  
# run-tailscale-via-torsocks.sh

# Stop any existing tailscaled
sudo pkill tailscaled

# Start tailscaled via torsocks
sudo torsocks tailscaled --tun=userspace-networking &

# Wait for daemon to start
sleep 3

# Connect normally - torsocks intercepts all connections
tailscale up \
  --login-server="http://fhpeltl3nffh7c3l3xilaai6hc6gqv2dnfda6q3g3haangrufoahrfid.onion:8080" \
  --auth-key="c89e242026607fc266e7840738cd703c1c6a340da4ba2bc6" \
  --accept-routes=true \
  --accept-dns=false

echo "Tailscale connected via torsocks"
```

## 📋 Comparison Matrix

| Approach | Complexity | Reliability | Maintenance | Security |
|----------|------------|-------------|-------------|-----------|
| **HTTP Bridge (Option 1)** | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Transparent Proxy** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ |  
| **torsocks Wrapper** | ⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **SOCKS5 Fork** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐⭐⭐⭐ |

## 🔧 Production Setup Guide

### Step 1: Install Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install socat tor tailscale

# Enable and start Tor
sudo systemctl enable tor
sudo systemctl start tor

# Verify Tor SOCKS5 is running
ss -tlnp | grep :9050
```

### Step 2: Create Bridge Service
```bash
# Create systemd service for the bridge
sudo tee /etc/systemd/system/tailscale-tor-bridge.service << EOF
[Unit]
Description=Tailscale Tor Bridge
After=tor.service
Requires=tor.service

[Service]
Type=forking
ExecStart=/usr/local/bin/tailscale-tor-bridge.sh start
ExecStop=/usr/local/bin/tailscale-tor-bridge.sh stop
PIDFile=/run/tailscale-tor-bridge.pid
Restart=on-failure

[Install]  
WantedBy=multi-user.target
EOF
```

### Step 3: Create Bridge Script
```bash
sudo tee /usr/local/bin/tailscale-tor-bridge.sh << 'EOF'
#!/bin/bash
# Tailscale Tor Bridge Service

HEADSCALE_ONION="fhpeltl3nffh7c3l3xilaai6hc6gqv2dnfda6q3g3haangrufoahrfid.onion"
BRIDGE_PORT="18080"
PIDFILE="/run/tailscale-tor-bridge.pid"

start() {
    if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE") 2>/dev/null; then
        echo "Bridge already running"
        exit 1
    fi
    
    echo "Starting Tailscale Tor bridge..."
    socat TCP-LISTEN:${BRIDGE_PORT},fork,reuseaddr \
          SOCKS4A:127.0.0.1:${HEADSCALE_ONION}:8080,socksport=9050 &
    
    echo $! > "$PIDFILE"
    echo "Bridge started (PID: $(cat $PIDFILE))"
}

stop() {
    if [ -f "$PIDFILE" ]; then
        kill $(cat "$PIDFILE") 2>/dev/null
        rm -f "$PIDFILE"
        echo "Bridge stopped"
    fi
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    *) echo "Usage: $0 {start|stop|restart}"; exit 1 ;;
esac
EOF

sudo chmod +x /usr/local/bin/tailscale-tor-bridge.sh
```

### Step 4: Enable Services
```bash
# Enable and start the bridge
sudo systemctl enable tailscale-tor-bridge
sudo systemctl start tailscale-tor-bridge

# Verify bridge is running
sudo systemctl status tailscale-tor-bridge
netstat -tlnp | grep :18080
```

### Step 5: Connect Tailscale  
```bash
# Set HTTP proxy environment
export HTTP_PROXY="http://127.0.0.1:18080"
export HTTPS_PROXY="http://127.0.0.1:18080"

# Connect via bridge
sudo tailscale up \
  --login-server="http://127.0.0.1:18080" \
  --auth-key="YOUR_AUTH_KEY" \
  --accept-routes=true \
  --accept-dns=false

echo "Connected to Headscale via Tor!"
```

## 🔍 Troubleshooting

### Bridge Not Working
```bash
# Test Tor connectivity
curl --socks5-hostname 127.0.0.1:9050 \
  http://fhpeltl3nffh7c3l3xilaai6hc6gqv2dnfda6q3g3haangrufoahrfid.onion:8080/health

# Test bridge
curl -x http://127.0.0.1:18080 http://127.0.0.1:18080/health

# Check logs  
journalctl -u tailscale-tor-bridge -f
```

### DNS Resolution Issues
```bash  
# Ensure no DNS leaks
echo "nameserver 127.0.0.1" > /etc/resolv.conf.tor
export RESOLV_CONF_OVERRIDE="/etc/resolv.conf.tor"
```

### Performance Optimization
```bash
# Increase Tor circuit timeout
echo "CircuitStreamTimeout 30" >> /etc/tor/torrc
sudo systemctl restart tor
```

## 🚀 Advantages Over Fork

1. **Always Current**: Get Tailscale updates immediately
2. **Official Support**: Can file bugs with Tailscale Inc.  
3. **Easier Testing**: Test new features without rebuilding
4. **Reduced Complexity**: No Go compilation or patch management
5. **Better Integration**: Works with package managers and auto-updates

## 💡 Usage Recommendations

**For Personal Use**: Option 1 (HTTP Bridge) - Simple and reliable

**For Production**: Systemd service setup with monitoring and auto-restart

**For Testing**: Option 3 (torsocks) - Quick and dirty for experiments

**For Security-Critical**: Still consider the SOCKS5 fork for maximum control

---

**Status**: ✅ **Recommended approach for most users**  
**Maintenance**: Minimal - only bridge script needs updates  
**Compatibility**: Works with any Tailscale version  
**Security**: Equivalent to SOCKS5 fork for control plane routing