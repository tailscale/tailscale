# `tsidp` - Tailscale OpenID Connect (OIDC) Identity Provider

[![status: experimental](https://img.shields.io/badge/status-experimental-blue)](https://tailscale.com/kb/1167/release-stages/#experimental)

`tsidp` is an OIDC Identity Provider (IdP) server that integrates with your Tailscale network. It allows you to use Tailscale identities for authentication in applications that support OpenID Connect, enabling single sign-on (SSO) capabilities within your tailnet.

## Prerequisites

- A Tailscale network (tailnet) with magicDNS and HTTPS enabled
- A Tailscale authentication key from your tailnet
- Docker installed on your system

## Installation using Docker

### Building from Source

The Tailscale project uses `mkctr` for building container images:

```bash
# Clone the Tailscale repository
git clone https://github.com/tailscale/tailscale.git
cd tailscale

# Build the tsidp image
TARGET=tsidp ./build_docker.sh
```

For development, you can publish to your own registry:
```bash
make publishdevtsidp REPO=ghcr.io/yourusername/tsidp
```

### Running the Container

Replace `YOUR_TAILSCALE_AUTHKEY` with your Tailscale authentication key:

```bash
docker run -d \
  --name tsidp \
  -p 443:443 \
  -e TS_AUTHKEY=YOUR_TAILSCALE_AUTHKEY \
  -e TAILSCALE_USE_WIP_CODE=1 \
  -v tsidp-data:/var/lib/tsidp \
  tailscale/tsidp:unstable \
  tsidp --hostname=idp --dir=/var/lib/tsidp
```

### Verify Installation
```bash
docker logs tsidp
```

Visit `https://idp.tailnet.ts.net` to confirm the service is running.

## Usage Example: Proxmox Integration

Here's how to configure Proxmox to use `tsidp` for authentication:

1. In Proxmox, navigate to Datacenter > Realms > Add OpenID Connect Server

2. Configure the following settings:
   - Issuer URL: `https://idp.velociraptor.ts.net`
   - Realm: `tailscale` (or your preferred name)
   - Client ID: `unused`
   - Client Key: `unused`
   - Default: `true`
   - Autocreate users: `true`
   - Username claim: `email`

3. Set up user permissions:
   - Go to Datacenter > Permissions > Groups
   - Create a new group (e.g., "tsadmins")
   - Click Permissions in the sidebar
   - Add Group Permission
   - Set Path to `/` for full admin access or scope as needed
   - Set the group and role
   - Add Tailscale-authenticated users to the group

## Configuration Options

The `tsidp` server supports several command-line flags:

- `--verbose`: Enable verbose logging
- `--port`: Port to listen on (default: 443)
- `--local-port`: Allow requests from localhost
- `--use-local-tailscaled`: Use local tailscaled instead of tsnet
- `--hostname`: tsnet hostname
- `--dir`: tsnet state directory

## Environment Variables

- `TS_AUTHKEY`: Your Tailscale authentication key (required)
- `TS_HOSTNAME`: Hostname for the `tsidp` server (default: "idp", Docker only)
- `TS_STATE_DIR`: State directory (default: "/var/lib/tsidp", Docker only)
- `TAILSCALE_USE_WIP_CODE`: Enable work-in-progress code (default: "1")

## Support

This is an [experimental](https://tailscale.com/kb/1167/release-stages#experimental), work in progress feature. For issues or questions, file issues on the [GitHub repository](https://github.com/tailscale/tailscale)

## License

BSD-3-Clause License. See [LICENSE](../../LICENSE) for details.
