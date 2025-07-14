# Docker Compose Example

This directory provides a minimal `docker-compose.yml` file that runs
the Tailscale daemon in a container. Supply your authentication key via
the `TS_AUTHKEY` environment variable. The container uses host
networking, requires the TUN device and runs in privileged mode.

Start the containers with:

```bash
docker compose up -d
```

Once running, the container joins your tailnet and persists its state in
`./tailscale-state`.
