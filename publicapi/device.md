# Device

A Tailscale device (sometimes referred to as _node_ or _machine_), is any computer or mobile device that joins a tailnet.

Each device has a unique ID (`nodeId` in the JSON below) that is used to identify the device in API calls.
This ID can be found by going to the [**Machines**](https://login.tailscale.com/admin/machines) page in the admin console,
selecting the relevant device, then finding the ID in the Machine Details section.
You can also [list all devices in the tailnet](#list-tailnet-devices) to get their `nodeId` values.

(A device's numeric `id` value can also be used in API calls, but `nodeId` is preferred.)

### Attributes

```jsonc
{
  // addresses (array of strings) is a list of Tailscale IP
  // addresses for the device, including both IPv4 (formatted as 100.x.y.z)
  // and IPv6 (formatted as fd7a:115c:a1e0:a:b:c:d:e) addresses.
  "addresses": ["100.87.74.78", "fd7a:115c:a1e0:ac82:4843:ca90:697d:c36e"],

  // id (string) is the legacy identifier for a device; you
  // can supply this value wherever {deviceId} is indicated in the
  // endpoint. Note that although "id" is still accepted, "nodeId" is
  // preferred.
  "id": "393735751060",

  // nodeID (string) is the preferred identifier for a device;
  // supply this value wherever {deviceId} is indicated in the endpoint.
  "nodeId": "n5SUKe8CNTRL",

  // user (string) is the user who registered the node. For untagged nodes,
  // this user is the device owner.
  "user": "amelie@example.com",

  // name (string) is the MagicDNS name of the device.
  // Learn more about MagicDNS at https://tailscale.com/kb/1081/.
  "name": "pangolin.tailfe8c.ts.net",

  // hostname (string) is the machine name in the admin console
  // Learn more about machine names at https://tailscale.com/kb/1098/.
  "hostname": "pangolin",

  // clientVersion (string) is the version of the Tailscale client
  // software; this is empty for external devices.
  "clientVersion": "",

  // updateAvailable (boolean) is 'true' if a Tailscale client version
  // upgrade is available. This value is empty for external devices.
  "updateAvailable": false,

  // os (string) is the operating system that the device is running.
  "os": "linux",

  // created (string) is the date on which the device was added
  // to the tailnet; this is empty for external devices.
  "created": "2022-12-01T05:23:30Z",

  // lastSeen (string) is when device was last active on the tailnet.
  "lastSeen": "2022-12-01T05:23:30Z",

  // keyExpiryDisabled (boolean) is 'true' if the keys for the device
  // will not expire. Learn more at https://tailscale.com/kb/1028/.
  "keyExpiryDisabled": true,

  // expires (string) is the expiration date of the device's auth key.
  // Learn more about key expiry at https://tailscale.com/kb/1028/.
  "expires": "2023-05-30T04:44:05Z",

  // authorized (boolean) is 'true' if the device has been
  // authorized to join the tailnet; otherwise, 'false'. Learn
  // more about device authorization at https://tailscale.com/kb/1099/.
  "authorized": true,

  // isExternal (boolean) if 'true', indicates that a device is not
  // a member of the tailnet, but is shared in to the tailnet;
  // if 'false', the device is a member of the tailnet.
  // Learn more about node sharing at https://tailscale.com/kb/1084/.
  "isExternal": true,

  // machineKey (string) is for internal use and is not required for
  // any API operations. This value is empty for external devices.
  "machineKey": "",

  // nodeKey (string) is mostly for internal use, required for select
  // operations, such as adding a node to a locked tailnet.
  // Learn about tailnet locks at https://tailscale.com/kb/1226/.
  "nodeKey": "nodekey:01234567890abcdef",

  // blocksIncomingConnections (boolean) is 'true' if the device is not
  // allowed to accept any connections over Tailscale, including pings.
  // Learn more in the "Allow incoming connections"
  // section of https://tailscale.com/kb/1072/.
  "blocksIncomingConnections": false,

  // enabledRoutes (array of strings) are the subnet routes for this
  // device that have been approved by the tailnet admin.
  // Learn more about subnet routes at https://tailscale.com/kb/1019/.
  "enabledRoutes": ["10.0.0.0/16", "192.168.1.0/24"],

  // advertisedRoutes (array of strings) are the subnets this device
  // intends to expose.
  // Learn more about subnet routes at https://tailscale.com/kb/1019/.
  "advertisedRoutes": ["10.0.0.0/16", "192.168.1.0/24"],

  // clientConnectivity provides a report on the device's current physical
  // network conditions.
  "clientConnectivity": {
    // endpoints (array of strings) Client's magicsock UDP IP:port
    // endpoints (IPv4 or IPv6)
    "endpoints": ["199.9.14.201:59128", "192.68.0.21:59128"],

    // mappingVariesByDestIP (boolean) is 'true' if the host's NAT mappings
    // vary based on the destination IP.
    "mappingVariesByDestIP": false,

    // latency (JSON object) lists DERP server locations and their current
    // latency; "preferred" is 'true' for the node's preferred DERP
    // server for incoming traffic.
    "latency": {
      "Dallas": {
        "latencyMs": 60.463043
      },
      "New York City": {
        "preferred": true,
        "latencyMs": 31.323811
      }
    },

    // clientSupports (JSON object) identifies features supported by the client.
    "clientSupports": {
      // hairpinning (boolean) is 'true' if your router can route connections
      // from endpoints on your LAN back to your LAN using those endpoints’
      // globally-mapped IPv4 addresses/ports
      "hairPinning": false,

      // ipv6 (boolean) is 'true' if the device OS supports IPv6,
      // regardless of whether IPv6 internet connectivity is available.
      "ipv6": false,

      // pcp (boolean) is 'true' if PCP port-mapping service exists on
      // your router.
      "pcp": false,

      // pmp (boolean) is 'true' if NAT-PMP port-mapping service exists
      // on your router.
      "pmp": false,

      // udp (boolean) is 'true' if UDP traffic is enabled on the
      // current network; if 'false', Tailscale may be unable to make
      // direct connections, and will rely on our DERP servers.
      "udp": true,

      // upnp (boolean) is 'true' if UPnP port-mapping service exists
      // on your router.
      "upnp": false
    }
  },

  // tags (array of strings) let you assign an identity to a device that
  // is separate from human users, and use it as part of an ACL to restrict
  // access. Once a device is tagged, the tag is the owner of that device.
  // A single node can have multiple tags assigned. This value is empty for
  // external devices.
  // Learn more about tags at https://tailscale.com/kb/1068/.
  "tags": ["tag:golink"],

  // tailnetLockError (string) indicates an issue with the tailnet lock
  // node-key signature on this device.
  // This field is only populated when tailnet lock is enabled.
  "tailnetLockError": "",

  // tailnetLockKey (string) is the node's tailnet lock key. Every node
  // generates a tailnet lock key (so the value will be present) even if
  // tailnet lock is not enabled.
  // Learn more about tailnet lock at https://tailscale.com/kb/1226/.
  "tailnetLockKey": "",

  // postureIdentity contains extra identifiers from the device when the tailnet
  // it is connected to has device posture identification collection enabled.
  // If the device has not opted-in to posture identification collection, this
  // will contain {"disabled": true}.
  // Learn more about posture identity at https://tailscale.com/kb/1326/device-identity
  "postureIdentity": {
    "serialNumbers": ["CP74LFQJXM"]
  }
}
```

# APIs

**[Device](#device)**

- Get a device: [`GET /api/v2/device/{deviceid}`](#get-device)
- Delete a device: [`DELETE /api/v2/device/{deviceID}`](#delete-device)
- Expire device key: [`POST /api/v2/device/{deviceID}/expire`](#expire-device-key)
- [**Routes**](#routes)
  - Get device routes: [`GET /api/v2/device/{deviceID}/routes`](#get-device-routes)
  - Set device routes: [`POST /api/v2/device/{deviceID}/routes`](#set-device-routes)
- [**Authorize**](#authorize)
  - Authorize a device: [`POST /api/v2/device/{deviceID}/authorized`](#authorize-device)
- [**Tags**](#tags)
  - Update tags: [`POST /api/v2/device/{deviceID}/tags`](#update-device-tags)
- [**Keys**](#keys)
  - Update device key: [`POST /api/v2/device/{deviceID}/key`](#update-device-key)
- [**IP Addresses**](#ip-addresses)
  - Set device IPv4 address: [`POST /api/v2/device/{deviceID}/ip`](#set-device-ipv4-address)
- [**Device posture attributes**](#device-posture-attributes)
  - Get device posture attributes: [`GET /api/v2/device/{deviceID}/attributes`](#get-device-posture-attributes)
  - Set custom device posture attributes: [`POST /api/v2/device/{deviceID}/attributes/{attributeKey}`](#set-device-posture-attributes)
  - Delete custom device posture attributes: [`DELETE /api/v2/device/{deviceID}/attributes/{attributeKey}`](#delete-custom-device-posture-attributes)
- [**Device invites**](#invites-to-a-device)
  - List device invites: [`GET /api/v2/device/{deviceID}/device-invites`](#list-device-invites)
  - Create device invites: [`POST /api/v2/device/{deviceID}/device-invites`](#create-device-invites)

### Subnet routes

Devices within a tailnet can be set up as subnet routers.
A subnet router acts as a gateway, relaying traffic from your Tailscale network onto your physical subnet.
Setting up subnet routers exposes routes to other devices in the tailnet.
Learn more about [subnet routers](https://tailscale.com/kb/1019).

A device can act as a subnet router if its subnet routes are both advertised and enabled.
This is a two-step process, but the steps can occur in any order:

- The device that intends to act as a subnet router exposes its routes by **advertising** them.
  This is done in the Tailscale command-line interface.
- The tailnet admin must approve the routes by **enabling** them.
  This is done in the [**Machines**](https://login.tailscale.com/admin/machines) page of the Tailscale admin console
  or [via the API](#set-device-routes).

If a device has advertised routes, they are not exposed to traffic until they are enabled by the tailnet admin.
Conversely, if a tailnet admin pre-approves certain routes by enabling them, they are not available for routing until the device in question has advertised them.

The API exposes two methods for dealing with subnet routes:

- Get routes: [`GET /api/v2/device/{deviceID}/routes`](#get-device-routes) to fetch lists of advertised and enabled routes for a device
- Set routes: [`POST /api/v2/device/{deviceID}/routes`](#set-device-routes) to set enabled routes for a device

## Get device

```http
GET /api/v2/device/{deviceid}
```

Retrieve the details for the specified device.
This returns a JSON `device` object listing device attributes.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

#### `fields` (optional in query string)

Controls whether the response returns **all** object fields or only a predefined subset of fields.
Currently, there are two supported options:

- **`all`:** return all object fields in the response
- **`default`:** return all object fields **except**:
  - `enabledRoutes`
  - `advertisedRoutes`
  - `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)
  - `postureIdentity`

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device/12345?fields=all" \
  -u "tskey-api-xxxxx:"
```

### Response

```jsonc
{
  "addresses":[
    "100.71.74.78",
    "fd7a:115c:a1e0:ac82:4843:ca90:697d:c36e"
  ],
  "id":"12345",

  // Additional fields as documented in device "Attributes" section above
}
{
  "addresses":[
    "100.74.66.78",
    "fd7a:115c:a1e0:ac82:4843:ca90:697d:c36f"
  ],
  "id":"67890",

  // Additional fields as documented in device "Attributes" section above
}
```

## Delete device

```http
DELETE /api/v2/device/{deviceID}
```

Deletes the supplied device from its tailnet.
The device must belong to the user's tailnet.
Deleting shared/external devices is not supported.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

### Request example

```sh
curl -X DELETE 'https://api.tailscale.com/api/v2/device/12345' \
  -u "tskey-api-xxxxx:"
```

### Response

If successful, the response should be empty:

```http
HTTP/1.1 200 OK
```

If the device is not owned by your tailnet:

```http
HTTP/1.1 501 Not Implemented
...
{"message":"cannot delete devices outside of your tailnet"}
```

## Expire a device's key

```http
POST /api/v2/device/{deviceID}/expire
```

Mark a device's node key as expired.
This will require the device to re-authenticate in order to connect to the tailnet.
The device must belong to the requesting user's tailnet.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

### Request example

```sh
curl -X POST 'https://api.tailscale.com/api/v2/device/12345/expire' \
  -u "tskey-api-xxxxx:" \
  -H "Content-Type: application/json"
```

### Response

If successful, the response should be empty:

```http
HTTP/1.1 200 OK
```

## Routes

## Get device routes

```http
GET /api/v2/device/{deviceID}/routes
```

Retrieve the list of [subnet routes](#subnet-routes) that a device is advertising, as well as those that are enabled for it:

- **Enabled routes:** The subnet routes for this device that have been approved by the tailnet admin.
- **Advertised routes:** The subnets this device intends to expose.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device/11055/routes" \
-u "tskey-api-xxxxx:"
```

### Response

Returns the enabled and advertised subnet routes for a device.

```jsonc
{
  "advertisedRoutes": ["10.0.0.0/16", "192.168.1.0/24"],
  "enabledRoutes": []
}
```

## Set device routes

```http
POST /api/v2/device/{deviceID}/routes
```

Sets a device's enabled [subnet routes](#subnet-routes) by replacing the existing list of subnet routes with the supplied parameters.
Advertised routes cannot be set through the API, since they must be set directly on the device.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

#### `routes` (required in `POST` body)

The new list of enabled subnet routes.

```jsonc
{
  "routes": ["10.0.0.0/16", "192.168.1.0/24"]
}
```

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device/11055/routes" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '{"routes": ["10.0.0.0/16", "192.168.1.0/24"]}'
```

### Response

Returns the enabled and advertised subnet routes for a device.

```jsonc
{
  "advertisedRoutes": ["10.0.0.0/16", "192.168.1.0/24"],
  "enabledRoutes": ["10.0.0.0/16", "192.168.1.0/24"]
}
```

## Authorize

## Authorize device

```http
POST /api/v2/device/{deviceID}/authorized
```

Authorize a device.
This call marks a device as authorized or revokes its authorization for tailnets where device authorization is required, according to the `authorized` field in the payload.

This returns a successful 2xx response with an empty JSON object in the response body.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

#### `authorized` (required in `POST` body)

Specify whether the device is authorized. False to deauthorize an authorized device, and true to authorize a new device or to re-authorize a previously deauthorized device.

```jsonc
{
  "authorized": true
}
```

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device/11055/authorized" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '{"authorized": true}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

## Tags

## Update device tags

```http
POST /api/v2/device/{deviceID}/tags
```

Update the tags set on a device.
Tags let you assign an identity to a device that is separate from human users, and use that identity as part of an ACL to restrict access.
Tags are similar to role accounts, but more flexible.

Tags are created in the tailnet policy file by defining the tag and an owner of the tag.
Once a device is tagged, the tag is the owner of that device.
A single node can have multiple tags assigned.

Consult the policy file for your tailnet in the [admin console](https://login.tailscale.com/admin/acls) for the list of tags that have been created for your tailnet.
Learn more about [tags](https://tailscale.com/kb/1068/).

This returns a 2xx code if successful, with an empty JSON object in the response body.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

#### `tags` (required in `POST` body)

The new list of tags for the device.

```jsonc
{
  "tags": ["tag:foo", "tag:bar"]
}
```

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device/11055/tags" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '{"tags": ["tag:foo", "tag:bar"]}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

If the tags supplied in the `POST` call do not exist in the tailnet policy file, the response is '400 Bad Request':

```jsonc
{
  "message": "requested tags [tag:madeup tag:wrongexample] are invalid or not permitted"
}
```

## Keys

## Update device key

```http
POST /api/v2/device/{deviceID}/key
```

Update properties of the device key.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

#### `keyExpiryDisabled` (optional in `POST` body)

Disable or enable the expiry of the device's node key.

When a device is added to a tailnet, its key expiry is set according to the tailnet's [key expiry](https://tailscale.com/kb/1028/) setting.
If the key is not refreshed and expires, the device can no longer communicate with other devices in the tailnet.

Set `"keyExpiryDisabled": true` to disable key expiry for the device and allow it to rejoin the tailnet (for example to access an accidentally expired device).
You can then call this method again with `"keyExpiryDisabled": false` to re-enable expiry.

```jsonc
{
  "keyExpiryDisabled": true
}
```

- If `true`, disable the device's key expiry.
  The original key expiry time is still maintained.
  Upon re-enabling, the key will expire at that original time.
- If `false`, enable the device's key expiry.
  Sets the key to expire at the original expiry time prior to disabling.
  The key may already have expired. In that case, the device must be re-authenticated.
- Empty value will not change the key expiry.

This returns a 2xx code on success, with an empty JSON object in the response body.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device/11055/key" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '{"keyExpiryDisabled": true}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

## IP Addresses

## Set device IPv4 address

```http
POST /api/v2/device/{deviceID}/ip
```

Set the Tailscale IPv4 address of the device.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

#### `ipv4` (optional in `POST` body)

Provide a new IPv4 address for the device.

When a device is added to a tailnet, its Tailscale IPv4 address is set at random either from the CGNAT range, or a subset of the CGNAT range specified by an [ip pool](https://tailscale.com/kb/1304/ip-pool).
This endpoint can be used to replace the existing IPv4 address with a specific value.

```jsonc
{
  "ipv4": "100.80.0.1"
}
```

This action will break any existing connections to this machine.
You will need to reconnect to this machine using the new IP address.
You may also need to flush your DNS cache.

This returns a 2xx code on success, with an empty JSON object in the response body.

### Request example

```sh
curl "https://api.tailscale.com/api/v2/device/11055/ip" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '{"ipv4": "100.80.0.1"}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

## Device posture attributes

## Get device posture attributes

The posture attributes API endpoints can be called with OAuth access tokens with
an `acl` or `devices` [scope](https://tailscale.com/kb/1215/oauth-clients#scopes), or personal access belonging to
[user roles](https://tailscale.com/kb/1138/user-roles) Owners, Admins, Network Admins, or IT Admins.

```
GET /api/v2/device/{deviceID}/attributes
```

Retrieve all posture attributes for the specified device. This returns a JSON object of all the key-value pairs of posture attributes for the device.

### Parameters

#### `deviceID` (required in URL path)

The ID of the device to fetch posture attributes for.

### Request example

```
curl "https://api.tailscale.com/api/v2/device/11055/attributes" \
-u "tskey-api-xxxxx:"
```

### Response

The response is 200 on success. The response body is a JSON object containing all the posture attributes assigned to the node. Attribute values can be strings, numbers or booleans.

```json
{
  "attributes": {
    "custom:myScore": 87,
    "custom:diskEncryption": true,
    "custom:myAttribute": "my_value",
    "node:os": "linux",
    "node:osVersion": "5.19.0-42-generic",
    "node:tsReleaseTrack": "stable",
    "node:tsVersion": "1.40.0",
    "node:tsAutoUpdate": false
  }
}
```

## Set custom device posture attributes

```
POST /api/v2/device/{deviceID}/attributes/{attributeKey}
```

Create or update a custom posture attribute on the specified device. User-managed attributes must be in the `custom` namespace, which is indicated by prefixing the attribute key with `custom:`.

Custom device posture attributes are available for the Personal and Enterprise plans.

### Parameters

#### `deviceID` (required in URL path)

The ID of the device on which to set the custom posture attribute.

#### `attributeKey` (required in URL path)

The name of the posture attribute to set. This must be prefixed with `custom:`.

Keys have a maximum length of 50 characters including the namespace, and can only contain letters, numbers, underscores, and colon.

Keys are case-sensitive. Keys must be unique, but are checked for uniqueness in a case-insensitive manner. For example, `custom:MyAttribute` and `custom:myattribute` cannot both be set within a single tailnet.

All values for a given key need to be of the same type, which is determined when the first value is written for a given key. For example, `custom:myattribute` cannot have a numeric value (`87`) for one node and a string value (`"78"`) for another node within the same tailnet.

### Posture attribute `value` (required in POST body)

```json
{
  "value": "foo"
}
```

A value can be either a string, number or boolean.

A string value can have a maximum length of 50 characters, and can only contain letters, numbers, underscores, and periods.

A number value is an integer and must be a JSON safe number (up to 2^53 - 1).

### Request example

```
curl "https://api.tailscale.com/api/v2/device/11055/attributes/custom:my_attribute" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '{"value": "my_value"}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

## Delete custom device posture attributes

```
DELETE /api/v2/device/{deviceID}/attributes/{attributeKey}
```

Delete a posture attribute from the specified device. This is only applicable to user-managed posture attributes in the `custom` namespace, which is indicated by prefixing the attribute key with `custom:`.

<PricingPlanNote feature="Custom device posture attributes" verb="are" plan="the Personal and Enterprise plans" />

### Parameters

#### `deviceID` (required in URL path)

The ID of the device from which to delete the posture attribute.

#### `attributeKey` (required in URL path)

The name of the posture attribute to delete. This must be prefixed with `custom:`.

Keys have a maximum length of 50 characters including the namespace, and can only contain letters, numbers, underscores, and a delimiting colon.

### Request example

```
curl -X DELETE "https://api.tailscale.com/api/v2/device/11055/attributes/custom:my_attribute" \
-u "tskey-api-xxxxx:"
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

## Invites to a device

The device sharing invite methods let you create and list [invites to share a device](https://tailscale.com/kb/1084/sharing).

## List device invites

```http
GET /api/v2/device/{deviceID}/device-invites
```

List all share invites for a device.

### Parameters

#### `deviceID` (required in URL path)

The ID of the device.

### Request example

```sh
curl -X GET "https://api.tailscale.com/api/v2/device/11055/device-invites" \
-u "tskey-api-xxxxx:"
```

### Response

```jsonc
[
  {
    "id": "12345",
    "created": "2024-05-08T20:19:51.777861756Z",
    "tailnetId": 59954,
    "deviceId": 11055,
    "sharerId": 22011,
    "allowExitNode": true,
    "email": "user@example.com",
    "lastEmailSentAt": "2024-05-08T20:19:51.777861756Z",
    "inviteUrl": "https://login.tailscale.com/admin/invite/<code>",
    "accepted": false
  },
  {
    "id": "12346",
    "created": "2024-04-03T21:38:49.333829261Z",
    "tailnetId": 59954,
    "deviceId": 11055,
    "sharerId": 22012,
    "inviteUrl": "https://login.tailscale.com/admin/invite/<code>",
    "accepted": true,
    "acceptedBy": {
      "id": 33223,
      "loginName": "someone@example.com",
      "profilePicUrl": ""
    }
  }
]
```

## Create device invites

```http
POST /api/v2/device/{deviceID}/device-invites
```

Create new share invites for a device.

### Parameters

#### `deviceID` (required in URL path)

The ID of the device.

#### List of invite requests (required in `POST` body)

Each invite request is an object with the following optional fields:

- **`multiUse`:** (Optional) Specify whether the invite can be accepted more than once. When set to `true`, it results in an invite that can be accepted up to 1,000 times.
- **`allowExitNode`:** (Optional) Specify whether the invited user can use the device as an exit node when it advertises as one.
- **`email`:** (Optional) Specify the email to send the created invite. If not set, the endpoint generates and returns an invite URL (but doesn't send it out).

### Request example

```sh
curl -X POST "https://api.tailscale.com/api/v2/device/11055/device-invites" \
-u "tskey-api-xxxxx:" \
-H "Content-Type: application/json" \
--data-binary '[{"multiUse": true, "allowExitNode": true, "email":"user@example.com"}]'
```

### Response

```jsonc
[
  {
    "id": "12347",
    "created": "2024-05-08T20:29:45.842358533Z",
    "tailnetId": 59954,
    "deviceId": 11055,
    "sharerId": 22012,
    "multiUse": true,
    "allowExitNode": true,
    "email": "user@example.com",
    "lastEmailSentAt": "2024-05-08T20:29:45.842358533Z",
    "inviteUrl": "https://login.tailscale.com/admin/invite/<code>",
    "accepted": false
  }
]
```
