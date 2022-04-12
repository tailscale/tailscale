# nginx-auth

This is a tool that allows users to use Tailscale Whois authentication with
NGINX as a reverse proxy. This allows users that already have a bunch of
services hosted on an internal NGINX server to point those domains to the
Tailscale IP of the NGINX server and then seamlessly use Tailscale for
authentication.

Many thanks to [@zrail](https://twitter.com/zrail/status/1511788463586222087) on
Twitter for introducing the basic idea and offering some sample code. This
program is based on that sample code with security enhancements. Namely:

* This listens over a UNIX socket instead of a TCP socket, to prevent
  leakage to the network
* This uses systemd socket activation so that systemd owns the socket
  and can then lock down the service to the bare minimum required to do
  its job without having to worry about dropping permissions
* This provides additional information in HTTP response headers that can
  be useful for integrating with various services

## Configuration

In order to protect a service with this tool, do the following in the respective
`server` block:

Create an authentication location with the `internal` flag set:

```nginx
location /auth {
  internal;

  proxy_pass http://unix:/run/tailscale.nginx-auth.sock;
  proxy_pass_request_body off;

  proxy_set_header Host $http_host;
  proxy_set_header Remote-Addr $remote_addr;
  proxy_set_header Remote-Port $remote_port;
  proxy_set_header Original-URI $request_uri;
}
```

Then add the following to the `location /` block:

```
auth_request /auth;
auth_request_set $auth_user $upstream_http_tailscale_user;
auth_request_set $auth_name $upstream_http_tailscale_name;
auth_request_set $auth_login $upstream_http_tailscale_login;
auth_request_set $auth_tailnet $upstream_http_tailscale_tailnet;
auth_request_set $auth_profile_picture $upstream_http_tailscale_profile_picture;

proxy_set_header X-Webauth-User "$auth_user";
proxy_set_header X-Webauth-Name "$auth_name";
proxy_set_header X-Webauth-Login "$auth_login";
proxy_set_header X-Webauth-Tailnet "$auth_tailnet";
proxy_set_header X-Webauth-Profile-Picture "$auth_profile_picture";
```

When this configuration is used with a Go HTTP handler such as this:

```go
http.HandlerFunc(func (w http.ResponseWriter, r *http.Request) {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(r.Header)
})
```

You will get output like this:

```json
{
  "Accept": [
    "*/*"
  ],
  "Connection": [
    "upgrade"
  ],
  "User-Agent": [
    "curl/7.82.0"
  ],
  "X-Webauth-Login": [
    "Xe"
  ],
  "X-Webauth-Name": [
    "Xe Iaso"
  ],
  "X-Webauth-Profile-Picture": [
    "https://avatars.githubusercontent.com/u/529003?v=4"
  ],
  "X-Webauth-Tailnet": [
    "cetacean.org.github"
  ]
  "X-Webauth-User": [
    "Xe@github"
  ]
}
```

## Headers

The authentication service provides the following headers to decorate your
proxied requests:

| Header                      | Example Value                                                      | Description                                                                   |
| :------                     | :--------------                                                    | :----------                                                                   |
| `Tailscale-User`            | `azurediamond@hunter2.net`                                         | The Tailscale username the remote machine is logged in as in user@host form   |
| `Tailscale-Login`           | `azurediamond`                                                     | The user portion of the Tailscale username the remote machine is logged in as |
| `Tailscale-Name`            | `Azure Diamond`                                                    | The "real name" of the Tailscale user the machine is logged in as             |
| `Tailscale-Profile-Picture` | `https://i.kym-cdn.com/photos/images/newsfeed/001/065/963/ae0.png` | The profile picture provided by the Identity Provider your tailnet uses       |
| `Tailscale-Tailnet`          | `hunter2.net`                                       | The tailnet name                                                              |

Most of the time you can set `X-Webauth-User` to the contents of the
`Tailscale-User` header, but some services may not accept a username with an `@`
symbol in it. If this is the case, set `X-Webauth-User` to the `Tailscale-Login`
header.

The `Tailscale-Tailnet` header can help you identify which tailnet the session
is coming from. If you are using node sharing, this can help you make sure that
you aren't giving administrative access to people outside your tailnet. You will
need to be sure to check this in your application code. If you use OpenResty,
you may be able to do more complicated access controls than you can with NGINX
alone.

## Building

Install `cmd/mkpkg`:

```
cd .. && go install ./mkpkg
```

Then run `./mkdeb.sh`. It will emit a `.deb` and `.rpm` package for amd64
machines (Linux uname flag: `x86_64`). You can add these to your deployment
methods as you see fit.
