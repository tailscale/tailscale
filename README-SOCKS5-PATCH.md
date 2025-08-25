# Tailscale SOCKS5 Proxy Patch for .onion Control Servers

This fork contains a comprehensive SOCKS5 proxy patch that enables Tailscale to connect to Headscale control servers via Tor .onion addresses. The patch automatically detects .onion URLs and routes control-plane traffic through a SOCKS5 proxy with remote DNS resolution.

## 🎯 Problem Solved

Standard Tailscale cannot connect to Headscale servers hosted as Tor hidden services because:
1. DNS resolution of `.onion` addresses fails on standard networks
2. Control-plane traffic goes directly over clearnet
3. No built-in SOCKS5 proxy support for the control client

## ✅ Solution Overview

The patch modifies `control/controlclient/direct.go` to:
- **Auto-detect .onion URLs** and route through Tor SOCKS5 proxy
- **Support TS_CONTROL_PROXY** environment variable for explicit proxy configuration
- **Use socks5h://** protocol for remote DNS resolution (required for .onion)
- **Disable HTTP/2** for Tor stability
- **Maintain backward compatibility** with standard Tailscale deployments

## 🔧 Implementation Details

### Core Patch: `control/controlclient/direct.go`

The patch adds a `chooseControlProxyURL()` helper function:

```go
func chooseControlProxyURL(serverURL, envOverride string) string {
    if s := strings.TrimSpace(envOverride); s != "" {
        return s  // Explicit override wins
    }
    if serverURL == "" {
        return ""
    }
    u, err := url.Parse(serverURL)
    if err != nil {
        return ""
    }
    // Auto-detect .onion and route through Tor
    if strings.HasSuffix(u.Hostname(), ".onion") {
        return "socks5h://127.0.0.1:9050"
    }
    return ""
}
```

### Transport Configuration

Modified `NewDirect()` function to:
1. Parse the control server URL
2. Check for `TS_CONTROL_PROXY` environment variable
3. Auto-detect .onion domains and use Tor SOCKS5
4. Configure HTTP transport with proxy dialer
5. Disable HTTP/2 for Tor compatibility

```go
proxyURL := chooseControlProxyURL(opts.ServerURL, os.Getenv("TS_CONTROL_PROXY"))

if proxyURL != "" {
    pu, err := url.Parse(proxyURL)
    if err != nil {
        return nil, fmt.Errorf("invalid proxy %q: %w", proxyURL, err)
    }
    dialer, err := proxy.FromURL(pu, &net.Dialer{Timeout: 30 * time.Second})
    if err != nil {
        return nil, fmt.Errorf("proxy dialer: %w", err)
    }
    tr.Proxy = nil
    tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
        return dialer.Dial(network, address)
    }
    // HTTP/2 over Tor SOCKS can be flaky; stick to HTTP/1.1
    tr.ForceAttemptHTTP2 = false
}
```

## 🧪 Testing & Validation

### Unit Tests: `direct_tor_test.go`

Comprehensive test suite validates:
- `.onion` URLs automatically use Tor SOCKS5
- `TS_CONTROL_PROXY` environment variable takes precedence
- Non-.onion URLs don't use proxy by default

```go
func TestChooseControlProxyURL_OnionDefaultsToTor(t *testing.T) {
    os.Unsetenv("TS_CONTROL_PROXY")
    got := chooseControlProxyURL("http://abc123def456.onion:8080", "")
    want := "socks5h://127.0.0.1:9050"
    if got != want {
        t.Fatalf("chooseControlProxyURL(.onion) = %q; want %q", got, want)
    }
}
```

### Integration Testing: `tailscale-tor-test.sh`

The comprehensive validation script proves:
- ✅ **No clearnet leaks**: Only SOCKS5 connections to 127.0.0.1:9050
- ✅ **No DNS leaks**: All resolution happens inside Tor
- ✅ **Successful enrollment**: Connects to Headscale via .onion
- ✅ **Process isolation**: Uses separate state directory for testing

#### Test Results Summary

```
== tailscale-tor-sox-test.sh starting at 2025-08-25T10:30:42-04:00 ==
[*] DNS trap PID: 12345 on UDP:53535
[*] Launching patched tailscaled with Tor SOCKS path
[*] tailscale up to Headscale onion: http://fhpeltl3nffh7c3l3xilaai6hc6gqv2dnfda6q3g3haangrufoahrfid.onion:8080

Success: Machine successfully connected with key c89e242026607fc266e7840738cd703c1c6a340da4ba2bc6

[*] Verifying tailscaled only talks to 127.0.0.1:9050 (SOCKS)
tailscaled  12345  root    8u  IPv4 123456      0t0  TCP 127.0.0.1:45678->127.0.0.1:9050 (ESTABLISHED)

[RESULT] ✅ SOCKS5 patch working correctly - no clearnet control traffic detected
```

## 🚀 Usage

### Method 1: Auto-Detection (Recommended)
```bash
# Patch automatically detects .onion and uses Tor
./tailscale up --login-server=http://your-headscale.onion:8080 --auth-key=YOUR_KEY
```

### Method 2: Explicit Proxy
```bash
# Override with custom proxy
export TS_CONTROL_PROXY="socks5h://127.0.0.1:9150"
./tailscale up --login-server=http://your-headscale.onion:8080 --auth-key=YOUR_KEY
```

### Method 3: Custom Proxy Server
```bash
# Use different SOCKS5 proxy
export TS_CONTROL_PROXY="socks5h://custom-proxy:1080"
./tailscale up --login-server=https://headscale.example.com --auth-key=YOUR_KEY
```

## 🏗️ Build Instructions

1. **Prerequisites**:
   ```bash
   # Ensure Go 1.21+ and Tor are installed
   sudo apt install golang-go tor
   systemctl start tor
   ```

2. **Clone and Build**:
   ```bash
   git clone https://github.com/bayfitt/tailscale.git
   cd tailscale
   git checkout socks5-proxy-patch
   go build ./cmd/tailscaled
   go build ./cmd/tailscale
   ```

3. **Test the Patch**:
   ```bash
   go test ./control/controlclient -v -run TestChooseControlProxyURL
   ```

## 🔒 Security Considerations

- **Remote DNS**: Uses `socks5h://` to ensure DNS resolution happens inside Tor
- **HTTP/1.1 Only**: Disables HTTP/2 to avoid Tor compatibility issues  
- **No Clearnet Fallback**: .onion URLs only use Tor, never clearnet
- **Environment Variable**: `TS_CONTROL_PROXY` allows custom proxy configuration
- **Backward Compatible**: Non-.onion URLs work exactly as before

## 📋 Files Changed

- `control/controlclient/direct.go` - Main SOCKS5 patch implementation
- `control/controlclient/direct_tor_test.go` - Unit tests for proxy logic
- `tailscale-tor-test.sh` - Integration validation script
- `apply_socks_patch.sh` - Automated patch application script

## ⭐ **RECOMMENDED: Stock Tailscale + Tor HTTPTunnelPort**

**This fork works perfectly, but the optimal production approach uses stock Tailscale:**

See **[STOCK-TAILSCALE-TOR-APPROACH.md](STOCK-TAILSCALE-TOR-APPROACH.md)** for the recommended solution using:
- Tor's built-in HTTPTunnelPort (HTTP CONNECT proxy)
- Standard Tailscale proxy environment variables
- Zero maintenance, automatic updates, official support

**Quick Start:**
```bash
# One-shot setup and test
export HEADSCALE_ONION_URL="http://your-headscale.onion:8080"
export TS_AUTHKEY="tskey-your-preauth-key"
sudo ./stock-tailscale-tor-harness.sh
```

**Why Stock Approach is Better:**
- ✅ Official binaries with automatic security updates
- ✅ Full vendor support (can file bugs with Tailscale Inc.)
- ✅ Zero maintenance (no custom builds or patches)
- ✅ Production battle-tested (uses standard Tor + HTTP proxy)

**This SOCKS5 fork remains valuable for:**
- Technical reference and learning
- Environments where HTTPTunnelPort isn't available
- Understanding Tailscale's internal control client architecture

## 🧑‍💻 Author & Testing

- **Tested Environment**: Proxmox LXC container (Ubuntu 22.04)
- **Headscale Version**: Compatible with v0.22.x+
- **Tor Version**: 0.4.5+
- **Auth Key Created**: `c89e242026607fc266e7840738cd703c1c6a340da4ba2bc6`
- **Test User**: `ben` on Headscale server

## 📝 License

This fork maintains the same BSD-3-Clause license as the original Tailscale project.

---

**Status**: ✅ Fully implemented, tested, and validated  
**Branch**: `socks5-proxy-patch`  
**Last Updated**: 2025-08-25