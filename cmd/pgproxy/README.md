# pgproxy

The pgproxy server is a proxy for the Postgres wire protocol. [Read
more in our blog
post](https://tailscale.com/blog/introducing-pgproxy/) about it!

The proxy runs an in-process Tailscale instance, accepts postgres
client connections over Tailscale only, and proxies them to the
configured upstream postgres server.

This proxy exists because postgres clients default to very insecure
connection settings: either they "prefer" but do not require TLS; or
they set sslmode=require, which merely requires that a TLS handshake
took place, but don't verify the server's TLS certificate or the
presented TLS hostname.  In other words, sslmode=require enforces that
a TLS session is created, but that session can trivially be
machine-in-the-middled to steal credentials, data, inject malicious
queries, and so forth.

Because this flaw is in the client's validation of the TLS session,
you have no way of reliably detecting the misconfiguration
server-side. You could fix the configuration of all the clients you
know of, but the default makes it very easy to accidentally regress.

Instead of trying to verify client configuration over time, this proxy
removes the need for postgres clients to be configured correctly: the
upstream database is configured to only accept connections from the
proxy, and the proxy is only available to clients over Tailscale.

Therefore, clients must use the proxy to connect to the database. The
client<>proxy connection is secured end-to-end by Tailscale, which the
proxy enforces by verifying that the connecting client is a known
current Tailscale peer. The proxy<>server connection is established by
the proxy itself, using strict TLS verification settings, and the
client is only allowed to communicate with the server once we've
established that the upstream connection is safe to use.

A couple side benefits: because clients can only connect via
Tailscale, you can use Tailscale ACLs as an extra layer of defense on
top of the postgres user/password authentication. And, the proxy can
maintain an audit log of who connected to the database, complete with
the strongly authenticated Tailscale identity of the client.
