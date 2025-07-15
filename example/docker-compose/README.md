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
