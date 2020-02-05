exec >&2
redo-ifchange Dockerfile relaynode
docker build -t tailscale .
