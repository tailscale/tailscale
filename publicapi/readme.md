> [!IMPORTANT]
> The Tailscale API documentation has moved to https://tailscale.com/api

# Tailscale API

The Tailscale API is a (mostly) RESTful API. Typically, both `POST` bodies and responses are JSON-encoded.

## Base URL

The base URL for the Tailscale API is `https://api.tailscale.com/api/v2/`.

Examples in this document may abbreviate this to `/api/v2/`.

## Authentication

Requests to the Tailscale API are authenticated with an API access token (sometimes called an API key).
Access tokens can be supplied as the username portion of HTTP Basic authentication (leave the password blank) or as an OAuth Bearer token:

```sh
# passing token with basic auth
curl -u "tskey-api-xxxxx:" https://api.tailscale.com/api/v2/...

# passing token as bearer token
curl -H "Authorization: Bearer tskey-api-xxxxx" https://api.tailscale.com/api/v2/...
```

Access tokens for individual users can be created and managed from the [**Keys**](https://login.tailscale.com/admin/settings/keys) page of the admin console.
These tokens will have the same permissions as the owning user, and can be set to expire in 1 to 90 days.
Access tokens are identifiable by the prefix `tskey-api-`.

Alternatively, an OAuth client can be used to create short-lived access tokens with scoped permission.
OAuth clients don't expire, and can therefore be used to provide ongoing access to the API, creating access tokens as needed.
OAuth clients and the access tokens they create are not tied to an individual Tailscale user.
OAuth client secrets are identifiable by the prefix `tskey-client-`.
Learn more about [OAuth clients](https://tailscale.com/kb/1215/).

## Errors

The Tailscale API returns status codes consistent with [standard HTTP conventions](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status).
In addition to the status code, errors may include additional information in the response body:

```jsonc
{
  "message": "additional error information"
}
```

## Pagination

The Tailscale API does not currently support pagination. All results are returned at once.

# APIs

**[Device](./device.md#device)**

- Get a device: [`GET /api/v2/device/{deviceid}`](./device.md#get-device)
- Delete a device: [`DELETE /api/v2/device/{deviceID}`](./device.md#delete-device)
- Expire device key: [`POST /api/v2/device/{deviceID}/expire`](./device.md#expire-device-key)
- [**Routes**](./device.md#routes)
  - Get device routes: [`GET /api/v2/device/{deviceID}/routes`](./device.md#get-device-routes)
  - Set device routes: [`POST /api/v2/device/{deviceID}/routes`](./device.md#set-device-routes)
- [**Authorize**](./device.md#authorize)
  - Authorize a device: [`POST /api/v2/device/{deviceID}/authorized`](./device.md#authorize-device)
- [**Tags**](./device.md#tags)
  - Update tags: [`POST /api/v2/device/{deviceID}/tags`](./device.md#update-device-tags)
- [**Keys**](./device.md#keys)
  - Update device key: [`POST /api/v2/device/{deviceID}/key`](./device.md#update-device-key)
- [**IP Addresses**](./device.md#ip-addresses)
  - Set device IPv4 address: [`POST /api/v2/device/{deviceID}/ip`](./device.md#set-device-ipv4-address)
- [**Device posture attributes**](./device.md#device-posture-attributes)
  - Get device posture attributes: [`GET /api/v2/device/{deviceID}/attributes`](./device.md#get-device-posture-attributes)
  - Set custom device posture attributes: [`POST /api/v2/device/{deviceID}/attributes/{attributeKey}`](./device.md#set-device-posture-attributes)
  - Delete custom device posture attributes: [`DELETE /api/v2/device/{deviceID}/attributes/{attributeKey}`](./device.md#delete-custom-device-posture-attributes)
- [**Device invites**](./device.md#invites-to-a-device)
  - List device invites: [`GET /api/v2/device/{deviceID}/device-invites`](./device.md#list-device-invites)
  - Create device invites: [`POST /api/v2/device/{deviceID}/device-invites`](./device.md#create-device-invites)

**[Tailnet](./tailnet.md#tailnet)**

- [**Policy File**](./tailnet.md#policy-file)
  - Get policy file: [`GET /api/v2/tailnet/{tailnet}/acl`](./tailnet.md#get-policy-file)
  - Update policy file: [`POST /api/v2/tailnet/{tailnet}/acl`](./tailnet.md#update-policy-file)
  - Preview rule matches: [`POST /api/v2/tailnet/{tailnet}/acl/preview`](./tailnet.md#preview-policy-file-rule-matches)
  - Validate and test policy file: [`POST /api/v2/tailnet/{tailnet}/acl/validate`](./tailnet.md#validate-and-test-policy-file)
- [**Devices**](./tailnet.md#devices)
  - List tailnet devices: [`GET /api/v2/tailnet/{tailnet}/devices`](./tailnet.md#list-tailnet-devices)
- [**Keys**](./tailnet.md#tailnet-keys)
  - List tailnet keys: [`GET /api/v2/tailnet/{tailnet}/keys`](./tailnet.md#list-tailnet-keys)
  - Create an auth key: [`POST /api/v2/tailnet/{tailnet}/keys`](./tailnet.md#create-auth-key)
  - Get a key: [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](./tailnet.md#get-key)
  - Delete a key: [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](./tailnet.md#delete-key)
- [**DNS**](./tailnet.md#dns)
  - [**Nameservers**](./tailnet.md#nameservers)
    - Get nameservers: [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](./tailnet.md#get-nameservers)
    - Set nameservers: [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](./tailnet.md#set-nameservers)
  - [**Preferences**](./tailnet.md#preferences)
    - Get DNS preferences: [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](./tailnet.md#get-dns-preferences)
    - Set DNS preferences: [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](./tailnet.md#set-dns-preferences)
  - [**Search Paths**](./tailnet.md#search-paths)
    - Get search paths: [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths`](./tailnet.md#get-search-paths)
    - Set search paths: [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](./tailnet.md#set-search-paths)
  - [**Split DNS**](./tailnet.md#split-dns)
    - Get split DNS: [`GET /api/v2/tailnet/{tailnet}/dns/split-dns`](./tailnet.md#get-split-dns)
    - Update split DNS: [`PATCH /api/v2/tailnet/{tailnet}/dns/split-dns`](./tailnet.md#update-split-dns)
    - Set split DNS: [`PUT /api/v2/tailnet/{tailnet}/dns/split-dns`](./tailnet.md#set-split-dns)
- [**User invites**](./tailnet.md#tailnet-user-invites)
  - List user invites: [`GET /api/v2/tailnet/{tailnet}/user-invites`](./tailnet.md#list-user-invites)
  - Create user invites: [`POST /api/v2/tailnet/{tailnet}/user-invites`](./tailnet.md#create-user-invites)

**[User invites](./userinvites.md#user-invites)**

- Get user invite: [`GET /api/v2/user-invites/{userInviteId}`](./userinvites.md#get-user-invite)
- Delete user invite: [`DELETE /api/v2/user-invites/{userInviteId}`](./userinvites.md#delete-user-invite)
- Resend user invite (by email): [`POST /api/v2/user-invites/{userInviteId}/resend`](#resend-user-invite)

**[Device invites](./deviceinvites.md#device-invites)**

- Get device invite: [`GET /api/v2/device-invites/{deviceInviteId}`](./deviceinvites.md#get-device-invite)
- Delete device invite: [`DELETE /api/v2/device-invites/{deviceInviteId}`](./deviceinvites.md#delete-device-invite)
- Resend device invite (by email): [`POST /api/v2/device-invites/{deviceInviteId}/resend`](./deviceinvites.md#resend-device-invite)
- Accept device invite [`POST /api/v2/device-invites/-/accept`](#accept-device-invite)
