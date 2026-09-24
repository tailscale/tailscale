# Docker Compose Example

This directory provides a minimal `docker-compose.yml` file that runs
the Tailscale daemon in a container following the official Tailscale Docker
documentation at https://tailscale.com/kb/1282/docker.

## Setup

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and set your Tailscale authentication key:
   ```bash
   TS_AUTHKEY=your_auth_key_here
   ```
   Get your auth key from https://login.tailscale.com/admin/settings/keys

3. Start the container:
   ```bash
   docker compose up -d
   ```

## Configuration

The container uses:
- Host networking (`network_mode: host`)
- Kernel networking (`TS_USERSPACE=false`) with TUN device access
- `net_admin` capability for network configuration
- Persistent state storage in `./tailscale-state`

Once running, the container joins your tailnet and persists its state.

## Environment Variables

All configuration is optional. You can set additional parameters in your `.env` file:

### Authentication
- **`TS_AUTHKEY`** - Auth key used to authenticate the container. Get from https://login.tailscale.com/admin/settings/keys
  - Can also use OAuth client secret (requires `TS_EXTRA_ARGS=--advertise-tags=tag:ci`)
  - Append `?ephemeral=true` to mark node as ephemeral
- **`TS_AUTH_ONCE`** - Only log in if not already logged in (default: false)

### Networking
- **`TS_HOSTNAME`** - Set hostname for the node
- **`TS_ROUTES`** - Advertise subnet routes (e.g., `192.168.1.0/24,10.0.0.0/8`)
- **`TS_DEST_IP`** - Proxy all incoming Tailscale traffic to specified destination IP
- **`TS_ACCEPT_DNS`** - Accept DNS configuration from admin console (default: false)
- **`TS_USERSPACE`** - Enable userspace networking instead of kernel networking (default: true)

### State and Storage
- **`TS_STATE_DIR`** - Directory where tailscaled state is stored (default: `/var/lib/tailscale`)
- **`TS_SOCKET`** - Unix socket path for LocalAPI (default: `/var/run/tailscale/tailscaled.sock`)

### Health and Metrics (Tailscale 1.78+)
- **`TS_ENABLE_HEALTH_CHECK`** - Enable `/healthz` endpoint (default: false)
- **`TS_ENABLE_METRICS`** - Enable `/metrics` endpoint (default: false)
- **`TS_LOCAL_ADDR_PORT`** - Address/port for health/metrics endpoints (default: `[::]:9002`)
- **`TS_HEALTHCHECK_ADDR_PORT`** - ⚠️ Deprecated, use `TS_ENABLE_HEALTH_CHECK` instead

### Proxy Configuration
- **`TS_SOCKS5_SERVER`** - Set SOCKS5 proxy address/port (e.g., `:1055`)
- **`TS_OUTBOUND_HTTP_PROXY_LISTEN`** - Set HTTP proxy address/port

### Advanced Configuration
- **`TS_SERVE_CONFIG`** - JSON file path for Serve/Funnel configuration
- **`TS_KUBE_SECRET`** - Kubernetes secret name for state storage (default: `tailscale`)
- **`TS_EXTRA_ARGS`** - Additional flags for `tailscale up` command
- **`TS_TAILSCALED_EXTRA_ARGS`** - Additional flags for `tailscaled` daemon

### Example Configuration
```bash
# Basic setup
TS_AUTHKEY=tskey-auth-your-key-here
TS_HOSTNAME=my-docker-node

# Subnet routing
TS_ROUTES=192.168.1.0/24,10.0.0.0/8
TS_EXTRA_ARGS=--accept-routes --ssh

# Health monitoring
TS_ENABLE_HEALTH_CHECK=true
TS_ENABLE_METRICS=true
TS_LOCAL_ADDR_PORT=:9002

# DNS configuration
TS_ACCEPT_DNS=true
```

## Advanced Usage

### Sidecar Pattern
You can use Tailscale as a sidecar container to provide secure networking for other services. Here's an example with nginx:

```yaml
---
services:
  tailscaled:
    image: tailscale/tailscale:latest
    hostname: tailscaled-nginx
    environment:
      - TS_AUTHKEY=${TS_AUTHKEY}
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_USERSPACE=false
      - TS_EXTRA_ARGS=--advertise-tags=tag:container
    volumes:
      - ./tailscale-state:/var/lib/tailscale
    devices:
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - net_admin
    restart: unless-stopped
  
  nginx:
    image: nginx
    depends_on:
      - tailscaled
    network_mode: service:tailscaled
```

In this pattern:
- The `nginx` service shares the network namespace with `tailscaled`
- All traffic to/from nginx goes through the Tailscale connection
- The nginx service is accessible via the Tailscale network
