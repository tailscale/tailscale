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
  -v tsidp-data:/var/lib/tsidp \
  ghcr.io/yourusername/tsidp:v0.0.1 \
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
- `--dir`: tsnet state directory; a default one will be created if not provided
- `--state`: Path to tailscale state file. Can also be set to use a Kubernetes Secret with the format `kube:<secret-name>`. If unset, `dir` is used for file-based state, or tsnet default if `dir` is also unset.

## Environment Variables

- `TS_AUTHKEY`: Your Tailscale authentication key (required)
- `TS_HOSTNAME`: Hostname for the `tsidp` server (default: "idp", Docker only)
- `TS_STATE_DIR`: Default state directory for `tsnet` (default: "/var/lib/tsidp" in Docker). This variable typically sets the default for the `--dir` flag in the Docker environment. `tsnet` uses the directory specified by `--dir` (or its internal default if `--dir` is not set) for its persistent files (e.g., node keys).
- `TS_STATE`: Path to tailscale state file or `kube:<secret-name>`. Overrides the `--state` flag if set.
- `TAILSCALE_USE_WIP_CODE`: Enable work-in-progress code (default: "1")

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
        image: tsidp:latest
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
