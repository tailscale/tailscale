> [!IMPORTANT]
> The Tailscale API documentation has moved to https://tailscale.com/api

# Tailscale API

The Tailscale API documentation is located in **[tailscale/publicapi](./publicapi/readme.md#tailscale-api)**.

# APIs

**[Overview](./publicapi/readme.md)**

**[Device](./publicapi/device.md#device)**

<a href="device-delete"></a>
<a href="expire-device-key"></a>
<a href="device-routes-get">
<a href="device-routes-post"></a>
<a href="#device-authorized-post"></a>
<a href="device-tags-post"></a>
<a href="device-key-post"></a>
<a href="tailnet-acl-get"></a>

- Get a device: [`GET /api/v2/device/{deviceid}`](./publicapi/device.md#get-device)
- Delete a device: [`DELETE /api/v2/device/{deviceID}`](./publicapi/device.md#delete-device)
- Expire device key: [`POST /api/v2/device/{deviceID}/expire`](./publicapi/device.md#expire-device-key)
- [**Routes**](./publicapi/device.md#routes)
  - Get device routes: [`GET /api/v2/device/{deviceID}/routes`](./publicapi/device.md#get-device-routes)
  - Set device routes: [`POST /api/v2/device/{deviceID}/routes`](./publicapi/device.md#set-device-routes)
- [**Authorize**](./publicapi/device.md#authorize)
  - Authorize a device: [`POST /api/v2/device/{deviceID}/authorized`](./publicapi/device.md#authorize-device)
- [**Tags**](./publicapi/device.md#tags)
  - Update tags: [`POST /api/v2/device/{deviceID}/tags`](./publicapi/device.md#update-device-tags)
- [**Keys**](./publicapi/device.md#keys)
  - Update device key: [`POST /api/v2/device/{deviceID}/key`](./publicapi/device.md#update-device-key)
- [**IP Addresses**](./publicapi/device.md#ip-addresses)
  - Set device IPv4 address: [`POST /api/v2/device/{deviceID}/ip`](./publicapi/device.md#set-device-ipv4-address)
- [**Device posture attributes**](./publicapi/device.md#device-posture-attributes)
  - Get device posture attributes: [`GET /api/v2/device/{deviceID}/attributes`](./publicapi/device.md#get-device-posture-attributes)
  - Set custom device posture attributes: [`POST /api/v2/device/{deviceID}/attributes/{attributeKey}`](./publicapi/device.md#set-device-posture-attributes)
  - Delete custom device posture attributes: [`DELETE /api/v2/device/{deviceID}/attributes/{attributeKey}`](./publicapi/device.md#delete-custom-device-posture-attributes)
- [**Device invites**](./publicapi/device.md#invites-to-a-device)
  - List device invites: [`GET /api/v2/device/{deviceID}/device-invites`](./publicapi/device.md#list-device-invites)
  - Create device invites: [`POST /api/v2/device/{deviceID}/device-invites`](./publicapi/device.md#create-device-invites)

**[Tailnet](./publicapi/tailnet.md#tailnet)**

<a href="tailnet-acl-post"></a>
<a href="tailnet-acl-preview-post"></a>
<a href="tailnet-acl-validate-post"></a>
<a href="tailnet-devices"></a>
<a href="tailnet-keys-get"></a>
<a href="tailnet-keys-post"></a>
<a href="tailnet-keys-key-get"></a>
<a href="tailnet-keys-key-delete"></a>
<a href="tailnet-dns"></a>
<a href="tailnet-dns-nameservers-get"></a>
<a href="tailnet-dns-nameservers-post"></a>
<a href="tailnet-dns-preferences-get"></a>
<a href="tailnet-dns-preferences-post"></a>
<a href="tailnet-dns-searchpaths-get"></a>
<a href="tailnet-dns-searchpaths-post"></a>

- [**Policy File**](./publicapi/tailnet.md#policy-file)
  - Get policy file: [`GET /api/v2/tailnet/{tailnet}/acl`](./publicapi/tailnet.md#get-policy-file)
  - Update policy file: [`POST /api/v2/tailnet/{tailnet}/acl`](./publicapi/tailnet.md#update-policy-file)
  - Preview rule matches: [`POST /api/v2/tailnet/{tailnet}/acl/preview`](./publicapi/tailnet.md#preview-policy-file-rule-matches)
  - Validate and test policy file: [`POST /api/v2/tailnet/{tailnet}/acl/validate`](./publicapi/tailnet.md#validate-and-test-policy-file)
- [**Devices**](./publicapi/tailnet.md#devices)
  - List tailnet devices: [`GET /api/v2/tailnet/{tailnet}/devices`](./publicapi/tailnet.md#list-tailnet-devices)
- [**Keys**](./publicapi/tailnet.md#tailnet-keys)
  - List tailnet keys: [`GET /api/v2/tailnet/{tailnet}/keys`](./publicapi/tailnet.md#list-tailnet-keys)
  - Create an auth key: [`POST /api/v2/tailnet/{tailnet}/keys`](./publicapi/tailnet.md#create-auth-key)
  - Get a key: [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](./publicapi/tailnet.md#get-key)
  - Delete a key: [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](./publicapi/tailnet.md#delete-key)
- [**DNS**](./publicapi/tailnet.md#dns)
  - [**Nameservers**](./publicapi/tailnet.md#nameservers)
    - Get nameservers: [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](./publicapi/tailnet.md#get-nameservers)
    - Set nameservers: [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](./publicapi/tailnet.md#set-nameservers)
  - [**Preferences**](./publicapi/tailnet.md#preferences)
    - Get DNS preferences: [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](./publicapi/tailnet.md#get-dns-preferences)
    - Set DNS preferences: [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](./publicapi/tailnet.md#set-dns-preferences)
  - [**Search Paths**](./publicapi/tailnet.md#search-paths)
    - Get search paths: [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths`](./publicapi/tailnet.md#get-search-paths)
    - Set search paths: [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](./publicapi/tailnet.md#set-search-paths)
  - [**Split DNS**](./publicapi/tailnet.md#split-dns)
    - Get split DNS: [`GET /api/v2/tailnet/{tailnet}/dns/split-dns`](./publicapi/tailnet.md#get-split-dns)
    - Update split DNS: [`PATCH /api/v2/tailnet/{tailnet}/dns/split-dns`](./publicapi/tailnet.md#update-split-dns)
    - Set split DNS: [`PUT /api/v2/tailnet/{tailnet}/dns/split-dns`](./publicapi/tailnet.md#set-split-dns)
- [**User invites**](./publicapi/tailnet.md#tailnet-user-invites)
  - List user invites: [`GET /api/v2/tailnet/{tailnet}/user-invites`](./publicapi/tailnet.md#list-user-invites)
  - Create user invites: [`POST /api/v2/tailnet/{tailnet}/user-invites`](./publicapi/tailnet.md#create-user-invites)

**[User invites](./publicapi/userinvites.md#user-invites)**

- Get user invite: [`GET /api/v2/user-invites/{userInviteId}`](./publicapi/userinvites.md#get-user-invite)
- Delete user invite: [`DELETE /api/v2/user-invites/{userInviteId}`](./publicapi/userinvites.md#delete-user-invite)
- Resend user invite (by email): [`POST /api/v2/user-invites/{userInviteId}/resend`](#resend-user-invite)

**[Device invites](./publicapi/deviceinvites.md#device-invites)**

- Get device invite: [`GET /api/v2/device-invites/{deviceInviteId}`](./publicapi/deviceinvites.md#get-device-invite)
- Delete device invite: [`DELETE /api/v2/device-invites/{deviceInviteId}`](./publicapi/deviceinvites.md#delete-device-invite)
- Resend device invite (by email): [`POST /api/v2/device-invites/{deviceInviteId}/resend`](./publicapi/deviceinvites.md#resend-device-invite)
- Accept device invite [`POST /api/v2/device-invites/-/accept`](#accept-device-invite)
