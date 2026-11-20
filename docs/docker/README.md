# Running the Tailscale container with Docker Compose

`compose.yaml` in this directory starts the `tailscale/tailscale` image and
gives it an auth key through a
[Docker Compose secret](https://docs.docker.com/compose/how-tos/use-secrets/)
rather than a plain environment variable.

## Why not just set `TS_AUTHKEY` to the key?

It works, but the key then sits in the container's environment. Anyone who can
run `docker inspect` on the host sees it:

```
$ docker inspect tailscale | grep TS_AUTH
                "TS_AUTHKEY=tskey-auth-k9i81....."
```

With a secret, Compose mounts the key as a file inside the container, and
`docker inspect` only shows the path.

## How it works

If the value of `TS_AUTHKEY` starts with `file:`, containerboot treats the rest
as a path and reads the key from that file. Leading and trailing whitespace is
trimmed, so a trailing newline in the file is fine. Compose mounts each secret
at `/run/secrets/<name>`, which gives:

```yaml
environment:
  TS_AUTHKEY: file:/run/secrets/ts_authkey
```

`TS_CLIENT_SECRET` and `TS_ID_TOKEN` accept the same `file:` prefix.

## Setup

1. Generate an [auth key](https://tailscale.com/kb/1085/auth-keys) in the
   admin console.
2. Save it to `ts_authkey` next to `compose.yaml`, and make it readable only by
   you: `chmod 600 ts_authkey`.
3. Run `docker compose up -d`.

Keep `ts_authkey` out of version control. Add it to `.gitignore`.

## Caveats

- This hides the key from `docker inspect`. It does not protect the file on the
  host, so the filesystem permissions on `ts_authkey` still matter.
- Keep the state volume (`tailscale-state` here). Without persisted state the
  container registers as a new node on every start and needs a key each time.
