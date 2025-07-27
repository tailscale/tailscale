# `tsidp` - Tailscale OpenID Connect (OIDC) Identity Provider

[![status: community project](https://img.shields.io/badge/status-community_project-blue)](https://tailscale.com/kb/1531/community-projects)

`tsidp` is an OIDC Identity Provider (IdP) server that integrates with your Tailscale network. It allows you to use Tailscale identities for authentication in applications that support OpenID Connect, enabling single sign-on (SSO) capabilities within your tailnet.

## Prerequisites

- A Tailscale network (tailnet) with magicDNS and HTTPS enabled
- A Tailscale authentication key from your tailnet
- Docker installed on your system

## Installation using Docker

### Building from Source

```bash
# Clone the Tailscale repository
git clone https://github.com/tailscale/tailscale.git
cd tailscale

# Build and publish to your own registry
make publishdevtsidp REPO=ghcr.io/yourusername/tsidp TAGS=v0.0.1 PUSH=true
```

### Running the Container

Replace `YOUR_TAILSCALE_AUTHKEY` with your Tailscale authentication key:

```bash
docker run -d \
  --name tsidp \
  -p 443:443 \
  -e TS_AUTHKEY=YOUR_TAILSCALE_AUTHKEY \
  -e TAILSCALE_USE_WIP_CODE=1 \
  -e TS_HOSTNAME=idp \
  -e TS_STATE_DIR=/var/lib/tsidp \
  -v tsidp-data:/var/lib/tsidp \
  tailscale/tsidp:unstable \
  tsidp
```

Or if you prefer command-line flags:

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
- `--funnel`: Use Tailscale Funnel to make tsidp available on the public internet
- `--hostname`: tsnet hostname (default: "idp")
- `--dir`: tsnet state directory; a default one will be created if not provided
- `--state`: Path to tailscale state file. Can also be set to use a Kubernetes Secret with the format `kube:<secret-name>`. If unset, `dir` is used for file-based state, or tsnet default if `dir` is also unset.
- `--funnel-clients-store`: Storage for funnel clients: 'file' (default) or 'kube:<secret-name>'
- `--login-server`: Optionally specifies the coordination server URL. If unset, the Tailscale default is used

## Environment Variables

All command-line flags can also be set via environment variables:

- `TSIDP_VERBOSE`: Enable verbose logging (same as `--verbose`)
- `TSIDP_PORT`: Port to listen on (same as `--port`)
- `TSIDP_LOCAL_PORT`: Allow requests from localhost (same as `--local-port`)
- `TSIDP_USE_LOCAL_TAILSCALED`: Use local tailscaled instead of tsnet (same as `--use-local-tailscaled`)
- `TSIDP_FUNNEL`: Use Tailscale Funnel (same as `--funnel`)
- `TSIDP_FUNNEL_CLIENTS_STORE`: Storage for funnel clients (same as `--funnel-clients-store`)
- `TSIDP_LOGIN_SERVER`: Coordination server URL (same as `--login-server`)
- `TS_HOSTNAME`: tsnet hostname (same as `--hostname`)
- `TS_STATE_DIR`: tsnet state directory (same as `--dir`)
- `TS_STATE`: Path to tailscale state file or `kube:<secret-name>` (same as `--state`)
- `TS_AUTHKEY`: Your Tailscale authentication key (required when using tsnet)
- `TAILSCALE_USE_WIP_CODE`: Enable work-in-progress code (required, set to "1")

## Storing State in Kubernetes Secrets

When running `tsidp` in a Kubernetes environment, you can configure it to store its state in a Kubernetes Secret. This is achieved by setting the `--state` flag (or `TS_STATE` environment variable) to `kube:<your-secret-name>`. The Secret will be created by `tsidp` if it doesn't already exist, and will be created in the same namespace where `tsidp` is running.

**Important**: Each Pod must use its own unique Secret. Multiple Pods cannot share the same Secret for state storage.

For example:
`./tsidp --state kube:my-tsidp-state-secret`

Or using the environment variable:
`TS_STATE=kube:my-tsidp-state-secret ./tsidp`

### StatefulSet Example for Multiple Pods

When deploying multiple `tsidp` instances, use a StatefulSet to ensure each Pod gets its own unique Secret:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: tsidp
spec:
  replicas: 1
  serviceName: tsidp
  selector:
    matchLabels:
      app: tsidp
  template:
    metadata:
      labels:
        app: tsidp
    spec:
      serviceAccountName: tsidp
      containers:
      - name: tsidp
        image: tailscale/tsidp:unstable
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: metadata.name
        - name: TS_STATE
          value: kube:$(POD_NAME)
        - name: TS_AUTHKEY
          valueFrom:
            secretKeyRef:
              name: tsidp-auth
              key: authkey
        - name: TAILSCALE_USE_WIP_CODE
          value: "1"
```

### Required RBAC Permissions

If you use Kubernetes Secret storage, the service account under which `tsidp` runs needs the following permissions on Secrets in the same namespace:
- `get`
- `patch` (primary mechanism for writing state)
- `create` (if the Secret does not already exist)
- `update` (for backwards compatibility, though patch is preferred)

Additionally, the service account needs the following permissions on Events (for debugging purposes when Secret operations fail):
- `create`
- `patch`
- `get`

Ensure that appropriate Role and RoleBinding are configured in your Kubernetes cluster.

## Support

This is an experimental, work in progress, [community project](https://tailscale.com/kb/1531/community-projects). For issues or questions, file issues on the [GitHub repository](https://github.com/tailscale/tailscale).

## License

BSD-3-Clause License. See [LICENSE](../../LICENSE) for details.
