# pgproxy

The pgproxy server was our old Tailscale proxy for the Postgres wire
protocol. See our [Introducing pgproxy blog post]
post](https://tailscale.com/blog/introducing-pgproxy/).

We changed our internal infrastructure such that we no longer depend on it.
Rather than pretend it's still maintained, we deleted it.

If community fork(s) emerge, we'll link from here.

If you want the old code, it's [still in git](https://raw.githubusercontent.com/tailscale/tailscale/d45c5ddfbbc1bb6ded8e3e9a15af9ece78bb4744/cmd/pgproxy/pgproxy.go)
or installable via `go install tailscale.com/cmd/pgproxy@d45c5ddfbbc1b`.

