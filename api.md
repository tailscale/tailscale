# Tailscale API

The Tailscale API is a (mostly) RESTful API. Typically, both `POST` bodies and responses are JSON-encoded.

## Base URL

The base URL for the Tailscale API is `https://api.tailscale.com/api/v2/`.

Examples in this document may abbreviate this to `/api/v2/`.

## Authentication

Requests to the Tailscale API are authenticated with an API access token (sometimes called an API key).
Access tokens can be supplied as the username portion of HTTP Basic authentication (leave the password blank) or as an OAuth Bearer token:

``` sh
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

``` jsonc
{
  "message": "additional error information"
}
```

## Pagination

The Tailscale API does not currently support pagination. All results are returned at once.

# APIs

**[Device](#device)**
- Get a device: [`GET /api/v2/device/{deviceid}`](#get-device)
- Delete a device: [`DELETE /api/v2/device/{deviceID}`](#delete-device)
- **Routes**
  - Get device routes: [`GET /api/v2/device/{deviceID}/routes`](#get-device-routes)
  - Set device routes: [`POST /api/v2/device/{deviceID}/routes`](#set-device-routes)
- **Authorize**
  - Authorize a device: [`POST /api/v2/device/{deviceID}/authorized`](#authorize-device)
- **Tags**
  - Update tags: [`POST /api/v2/device/{deviceID}/tags`](#update-device-tags)
- **Key**
  - Update device key: [`POST /api/v2/device/{deviceID}/key`](#update-device-key)
- **IP Address**
  - Set device IPv4 address: [`POST /api/v2/device/{deviceID}/ip`](#set-device-ipv4-address)

**[Tailnet](#tailnet)**
- [**Policy File**](#policy-file)
  - Get policy file: [`GET /api/v2/tailnet/{tailnet}/acl`](#get-policy-file)
  - Update policy file: [`POST /api/v2/tailnet/{tailnet}/acl`](#update-policy-file)
  - Preview rule matches: [`POST /api/v2/tailnet/{tailnet}/acl/preview`](#preview-policy-file-rule-matches)
  - Validate and test policy file: [`POST /api/v2/tailnet/{tailnet}/acl/validate`](#validate-and-test-policy-file)
- Devices
  - List tailnet devices: [`GET /api/v2/tailnet/{tailnet}/devices`](#list-tailnet-devices)
- [**Keys**](#tailnet-keys)
  - List tailnet keys: [`GET /api/v2/tailnet/{tailnet}/keys`](#list-tailnet-keys)
  - Create an auth key: [`POST /api/v2/tailnet/{tailnet}/keys`](#create-auth-key)
  - Get a key: [`GET /api/v2/tailnet/{tailnet}/keys/{keyid}`](#get-key)
  - Delete a key: [`DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}`](#delete-key)
- [**DNS**](#dns)
  - **Nameservers**
    - Get nameservers: [`GET /api/v2/tailnet/{tailnet}/dns/nameservers`](#get-nameservers)
    - Set nameservers: [`POST /api/v2/tailnet/{tailnet}/dns/nameservers`](#set-nameservers)
  - **Preferences**
    - Get DNS preferences: [`GET /api/v2/tailnet/{tailnet}/dns/preferences`](#get-dns-preferences)
    - Set DNS preferences: [`POST /api/v2/tailnet/{tailnet}/dns/preferences`](#set-dns-preferences)
  - **Search paths**
    - Get search paths: [`GET /api/v2/tailnet/{tailnet}/dns/searchpaths](#get-search-paths)
    - Set search paths: [`POST /api/v2/tailnet/{tailnet}/dns/searchpaths`](#set-search-paths)

# Device

A Tailscale device (sometimes referred to as _node_ or _machine_), is any computer or mobile device that joins a tailnet.

Each device has a unique ID (`nodeId` in the JSON below) that is used to identify the device in API calls.
This ID can be found by going to the [**Machines**](https://login.tailscale.com/admin/machines) page in the admin console,
selecting the relevant device, then finding the ID in the Machine Details section.
You can also [list all devices in the tailnet](#list-tailnet-devices) to get their `nodeId` values.

(A device's numeric `id` value can also be used in API calls, but `nodeId` is preferred.)

### Attributes

``` jsonc
{
  // addresses (array of strings) is a list of Tailscale IP
  // addresses for the device, including both IPv4 (formatted as 100.x.y.z)
  // and IPv6 (formatted as fd7a:115c:a1e0:a:b:c:d:e) addresses.
  "addresses": [
    "100.87.74.78",
    "fd7a:115c:a1e0:ac82:4843:ca90:697d:c36e"
  ],

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
  "enabledRoutes" : [
    "10.0.0.0/16",
    "192.168.1.0/24",
  ],

  // advertisedRoutes (array of strings) are the subnets this device
  // intends to expose.
  // Learn more about subnet routes at https://tailscale.com/kb/1019/.
  "advertisedRoutes" : [
    "10.0.0.0/16",
    "192.168.1.0/24",
  ],

  // clientConnectivity provides a report on the device's current physical
  // network conditions.
  "clientConnectivity": {

    // endpoints (array of strings) Client's magicsock UDP IP:port
    // endpoints (IPv4 or IPv6)
    "endpoints":[
      "199.9.14.201:59128",
      "192.68.0.21:59128"
    ],

    // mappingVariesByDestIP (boolean) is 'true' if the host's NAT mappings
    // vary based on the destination IP.
    "mappingVariesByDestIP":false,

    // latency (JSON object) lists DERP server locations and their current
    // latency; "preferred" is 'true' for the node's preferred DERP
    // server for incoming traffic.
    "latency":{
      "Dallas":{
        "latencyMs":60.463043
      },
      "New York City":{
        "preferred":true,
        "latencyMs":31.323811
      },
    },

    // clientSupports (JSON object) identifies features supported by the client.
    "clientSupports":{

      // hairpinning (boolean) is 'true' if your router can route connections
      // from endpoints on your LAN back to your LAN using those endpoints’
      // globally-mapped IPv4 addresses/ports
      "hairPinning":false,

      // ipv6 (boolean) is 'true' if the device OS supports IPv6,
      // regardless of whether IPv6 internet connectivity is available.
      "ipv6":false,

      // pcp (boolean) is 'true' if PCP port-mapping service exists on
      // your router.
      "pcp":false,

      // pmp (boolean) is 'true' if NAT-PMP port-mapping service exists
      // on your router.
      "pmp":false,

      // udp (boolean) is 'true' if UDP traffic is enabled on the
      // current network; if 'false', Tailscale may be unable to make
      // direct connections, and will rely on our DERP servers.
      "udp":true,

      // upnp (boolean) is 'true' if UPnP port-mapping service exists
      // on your router.
      "upnp":false
    },
  },

  // tags (array of strings) let you assign an identity to a device that
  // is separate from human users, and use it as part of an ACL to restrict
  // access. Once a device is tagged, the tag is the owner of that device.
  // A single node can have multiple tags assigned. This value is empty for
  // external devices.
  // Learn more about tags at https://tailscale.com/kb/1068/.
  "tags": [
    "tag:golink"
  ],

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

<a name="device-get"></a>

## Get device

``` http
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

``` sh
curl "https://api.tailscale.com/api/v2/device/12345?fields=all" \
  -u "tskey-api-xxxxx:"
```

### Response

``` jsonc
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

<a href="device-delete"></a>

## Delete device

``` http
DELETE /api/v2/device/{deviceID}
```

Deletes the supplied device from its tailnet.
The device must belong to the user's tailnet.
Deleting shared/external devices is not supported.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

### Request example

``` sh
curl -X DELETE 'https://api.tailscale.com/api/v2/device/12345' \
  -u "tskey-api-xxxxx:"
```

### Response

If successful, the response should be empty:

``` http
HTTP/1.1 200 OK
```

If the device is not owned by your tailnet:

``` http
HTTP/1.1 501 Not Implemented
...
{"message":"cannot delete devices outside of your tailnet"}
```

<a href="device-routes-get">

## Get device routes

``` http
GET /api/v2/device/{deviceID}/routes
```

Retrieve the list of [subnet routes](#subnet-routes) that a device is advertising, as well as those that are enabled for it:
- **Enabled routes:** The subnet routes for this device that have been approved by the tailnet admin.
- **Advertised routes:** The subnets this device intends to expose.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/device/11055/routes" \
-u "tskey-api-xxxxx:"
```

### Response

Returns the enabled and advertised subnet routes for a device.

``` jsonc
{
   "advertisedRoutes" : [
      "10.0.0.0/16",
      "192.168.1.0/24"
   ],
   "enabledRoutes" : []
}
```

<a href="device-routes-post"></a>

## Set device routes

``` http
POST /api/v2/device/{deviceID}/routes
```

Sets a device's enabled [subnet routes](#subnet-routes) by replacing the existing list of subnet routes with the supplied parameters.
Advertised routes cannot be set through the API, since they must be set directly on the device.

### Parameters

#### `deviceid` (required in URL path)

The ID of the device.

#### `routes` (required in `POST` body)

The new list of enabled subnet routes.

``` jsonc
{
  "routes": ["10.0.0.0/16", "192.168.1.0/24"]
}
```

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/device/11055/routes" \
-u "tskey-api-xxxxx:" \
--data-binary '{"routes": ["10.0.0.0/16", "192.168.1.0/24"]}'
```

### Response

Returns the enabled and advertised subnet routes for a device.

``` jsonc
{
   "advertisedRoutes" : [
      "10.0.0.0/16",
      "192.168.1.0/24"
   ],
   "enabledRoutes" : [
      "10.0.0.0/16",
      "192.168.1.0/24"
   ]
}
```

<a href="#device-authorized-post"></a>

## Authorize device

``` http
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


``` jsonc
{
  "authorized": true
}
```

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/device/11055/authorized" \
-u "tskey-api-xxxxx:" \
--data-binary '{"authorized": true}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

<a href="device-tags-post"></a>

## Update device tags

``` http
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

``` jsonc
{
  "tags": ["tag:foo", "tag:bar"]
}
```

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/device/11055/tags" \
-u "tskey-api-xxxxx:" \
--data-binary '{"tags": ["tag:foo", "tag:bar"]}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

If the tags supplied in the `POST` call do not exist in the tailnet policy file, the response is '400 Bad Request':

``` jsonc
{
  "message": "requested tags [tag:madeup tag:wrongexample] are invalid or not permitted"
}
```

<a href="device-key-post"></a>

## Update device key

``` http
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

``` jsonc
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

``` sh
curl "https://api.tailscale.com/api/v2/device/11055/key" \
-u "tskey-api-xxxxx:" \
--data-binary '{"keyExpiryDisabled": true}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

## Set device IPv4 address

``` http
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

``` jsonc
{
  "ipv4": "100.80.0.1"
}
```

This action will break any existing connections to this machine.
You will need to reconnect to this machine using the new IP address.
You may also need to flush your DNS cache.

This returns a 2xx code on success, with an empty JSON object in the response body.

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/device/11055/ip" \
-u "tskey-api-xxxxx:" \
--data-binary '{"ipv4": "100.80.0.1"}'
```

### Response

The response is 2xx on success. The response body is currently an empty JSON object.

# Tailnet

A tailnet is your private network, composed of all the devices on it and their configuration.
Learn more about [tailnets](https://tailscale.com/kb/1136/).

When specifying a tailnet in the API, you can:

- Provide a dash (`-`) to reference the default tailnet of the access token being used to make the API call.
  This is the best option for most users.
  Your API calls would start:

  ``` sh
  curl "https://api.tailscale.com/api/v2/tailnet/-/..."
  ```

- Provide the **organization** name found on the **[General Settings](https://login.tailscale.com/admin/settings/general)**
  page of the Tailscale admin console (not to be confused with the "tailnet name" found in the DNS tab).

  For example, if your organization name is `alice@gmail.com`, your API calls would start:

  ``` sh
  curl "https://api.tailscale.com/api/v2/tailnet/alice@gmail.com/..."
  ```

## Policy File

The tailnet policy file contains access control lists and related configuration.
The policy file is expressed using "[HuJSON](https://github.com/tailscale/hujson#readme)"
(human JSON, a superset of JSON that allows comments and trailing commas).
Most policy file API methods can also return regular JSON for compatibility with other tools.
Learn more about [network access controls](https://tailscale.com/kb/1018/).

<a href="tailnet-acl-get"></a>

## Get Policy File

``` http
GET /api/v2/tailnet/{tailnet}/acl
```

Retrieves the current policy file for the given tailnet; this includes the ACL along with the rules and tests that have been defined.

This method can return the policy file as JSON or HuJSON, depending on the `Accept` header.
The response also includes an `ETag` header, which can be optionally included when [updating the policy file](#update-policy-file) to avoid missed updates.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `Accept` (optional in request header)

Response is encoded as JSON if `application/json` is requested, otherwise HuJSON will be returned.

#### `details` (optional in query string)

Request a detailed description of the tailnet policy file by providing `details=1` in the URL query string.
If using this, do not supply an `Accept` parameter in the header.

The response will contain a JSON object with the fields:
- **tailnet policy file:** a base64-encoded string representation of the huJSON format
- **warnings:** array of strings for syntactically valid but nonsensical entries
- **errors:** an array of strings for parsing failures

### Request example (response in HuJSON format)

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl" \
  -u "tskey-api-xxxxx:" \
```

### Response in HuJSON format

On success, returns a 200 status code and the tailnet policy file in HuJSON format.
No errors or warnings are returned.

``` jsonc
...
Content-Type: application/hujson
Etag: "e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c"
...

// Example/default ACLs for unrestricted connections.
{
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": ["user1@example.com", "user2@example.com"],
  },

  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100",
  },

  // Access control lists.
  "acls": [
    // Match absolutely everything.
    // Comment this section out if you want to define specific restrictions.
    {"action": "accept", "src": ["*"], "dst": ["*:*"]},
  ],
}

```

### Request example (response in JSON format)

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl" \
  -u "tskey-api-xxxxx:" \
  -H "Accept: application/json" \
```

### Response in JSON format

On success, returns a 200 status code and the tailnet policy file in JSON format.
No errors or warnings are returned.

``` jsonc
...
Content-Type: application/json
Etag: "e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c"
...
{
   "acls" : [
      {
         "action" : "accept",
         "ports" : [
            "*:*"
         ],
         "users" : [
            "*"
         ]
      }
   ],
   "groups" : {
      "group:example" : [
         "user1@example.com",
         "user2@example.com"
      ]
   },
   "hosts" : {
      "example-host-1" : "100.100.100.100"
   }
}
```

### Request example (with details)

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl?details=1" \
  -u "tskey-api-xxxxx:" \
```

### Response (with details)

On success, returns a 200 status code and the tailnet policy file in a base64-encoded string representation of the huJSON format.
In addition, errors and warnings are returned.

``` sh
{
  "acl": "Ly8gUG9raW5nIGFyb3VuZCBpbiB0aGUgQVBJIGRvY3MsIGhvcGluZyB5b3UnZCBmaW5kIHNvbWV0aGluZyBnb29kLCBlaD8KLy8gV2UgbGlrZSB5b3VyIHN0eWxlISAgR28gZ3JhYiB5b3Vyc2VsZiBhIFRhaWxzY2FsZSB0LXNoaXJ0IGlmIHRoZXJlIGFyZQovLyBzdGlsbCBzb21lIGF2YWlsYWJsZS4gQnV0IHNoaGguLi4gZG9uJ3QgdGVsbCBhbnlvbmUhCi8vCi8vICAgICAgICAgICAgIGh0dHBzOi8vc3dhZy5jb20vZ2lmdC82a29mNGs1Z3B1ZW95ZDB2NXd6MHJkYmMKewoJLy8gRGVjbGFyZSBzdGF0aWMgZ3JvdXBzIG9mIHVzZXJzIGJleW9uZCB0aG9zZSBpbiB0aGUgaWRlbnRpdHkgc2VydmljZS4KCSJncm91cHMiOiB7CgkJImdyb3VwOmV4YW1wbGUiOiBbInVzZXIxQGV4YW1wbGUuY29tIiwgInVzZXIyQGV4YW1wbGUuY29tIl0sCgl9LAoKCS8vIERlY2xhcmUgY29udmVuaWVudCBob3N0bmFtZSBhbGlhc2VzIHRvIHVzZSBpbiBwbGFjZSBvZiBJUCBhZGRyZXNzZXMuCgkiaG9zdHMiOiB7CgkJImV4YW1wbGUtaG9zdC0xIjogIjEwMC4xMDAuMTAwLjEwMCIsCgl9LAoKCS8vIEFjY2VzcyBjb250cm9sIGxpc3RzLgoJImFjbHMiOiBbCgkJLy8gTWF0Y2ggYWJzb2x1dGVseSBldmVyeXRoaW5nLgoJCS8vIENvbW1lbnQgdGhpcyBzZWN0aW9uIG91dCBpZiB5b3Ugd2FudCB0byBkZWZpbmUgc3BlY2lmaWMgcmVzdHJpY3Rpb25zLgoJCXsiYWN0aW9uIjogImFjY2VwdCIsICJ1c2VycyI6IFsiKiJdLCAicG9ydHMiOiBbIio6KiJdfSwKCV0sCn0K",
  "warnings": [
    "\"group:example\": user not found: \"user1@example.com\"",
    "\"group:example\": user not found: \"user2@example.com\""
  ],
  "errors": null
}
```

<a href="tailnet-acl-post"></a>

## Update policy file

``` http
POST /api/v2/tailnet/{tailnet}/acl`
```

Sets the ACL for the given tailnet.
HuJSON and JSON are both accepted inputs.
An `If-Match` header can be set to avoid missed updates.

On success, returns the updated ACL in JSON or HuJSON according to the `Accept` header.
Otherwise, errors are returned for incorrectly defined ACLs, ACLs with failing tests on attempted updates, and mismatched `If-Match` header and ETag.

### Parameters

#### tailnet (required in URL path)

The tailnet organization name.

#### `If-Match` (optional in request header)

This is a safety mechanism to avoid overwriting other users' updates to the tailnet policy file.

- Set the `If-Match` value to that of the ETag header returned in a `GET` request to `/api/v2/tailnet/{tailnet}/acl`.
  Tailscale compares the ETag value in your request to that of the current tailnet file and only replaces the file if there's a match.
  (A mismatch indicates that another update has been made to the file.)
  For example: `-H "If-Match: \"e0b2816b418\""`
- Alternately, set the `If-Match` value to `ts-default` to ensure that the policy file is replaced
  _only if the current policy file is still the untouched default_ created automatically for each tailnet.
  For example: `-H "If-Match: \"ts-default\""`

#### `Accept` (optional in request header)

Sets the return type of the updated tailnet policy file.
Response is encoded as JSON if `application/json` is requested, otherwise HuJSON will be returned.

#### Tailnet policy file entries (required in `POST` body)

Define the policy file in the `POST` body.
Include the entire policy file.
Note that the supplied object fully replaces your existing tailnet policy file.

The `POST` body should be formatted as JSON or HuJSON.
Learn about the [ACL policy properties you can include in the request](https://tailscale.com/kb/1018/#tailscale-policy-syntax).

### Request example

``` sh
POST /api/v2/tailnet/example.com/acl
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl" \
  -u "tskey-api-xxxxx:" \
  -H "If-Match: \"e0b2816b418b3f266309d94426ac7668ab3c1fa87798785bf82f1085cc2f6d9c\""
  --data-binary '// Example/default ACLs for unrestricted connections.
{
  // Declare tests to check functionality of ACL rules. User must be a valid user with registered machines.
  "tests": [
    // {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "acls": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "action": "accept", "users": ["*"], "ports": ["*:*"] },
  ]
}'
```

### Response

A successful response returns an HTTP status of '200' and the modified tailnet policy file in JSON or HuJSON format, depending on the request header.

``` jsonc
// Example/default ACLs for unrestricted connections.
{
  // Declare tests to check functionality of ACL rules. User must be a valid user with registered machines.
  "tests": [
    // {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "acls": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "action": "accept", "users": ["*"], "ports": ["*:*"] },
  ]
}
```

### Response: failed test error

```
{
    "message": "test(s) failed",
    "data": [
        {
            "user": "user1@example.com",
            "errors": [
                "address \"user2@example.com:400\": want: Accept, got: Drop"
            ]
        }
    ]
}
```

<a href="tailnet-acl-preview-post"></a>

## Preview policy file rule matches

``` http
POST /api/v2/tailnet/{tailnet}/acl/preview
```
When given a user or IP port to match against, returns the tailnet policy rules that
apply to that resource without saving the policy file to the server.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `type` (required in query string)

Specify for which type of resource (user or IP port) matching rules are to be fetched.
Read about [previewing changes in the admin console](https://tailscale.com/kb/1018/#previewing-changes).

- `user`: Specify `user` if the `previewFor` value is a user's email.
  Note that `user` remains in the API for compatibility purposes, but has been replaced by `src` in policy files.
- `ipport`: Specify `ipport` if the `previewFor` value is an IP address and port.
  Note that `ipport` remains in the API for compatibility purposes, but has been replaced by `dst` in policy files.

#### `previewFor` (required in query string)

- If `type=user`, provide the email of a valid user with registered machines.
- If `type=ipport`, provide an IP address + port: `10.0.0.1:80`.

The supplied policy file is queried with this parameter to determine which rules match.

#### Tailnet policy file (required in `POST` body)

Provide the tailnet policy file in the `POST` body in JSON or HuJSON format.
Learn about [tailnet policy file entries](https://tailscale.com/kb/1018).

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl/preview?previewFor=user1@example.com&type=user" \
  -u "tskey-api-xxxxx:" \
  --data-binary '// Example/default ACLs for unrestricted connections.
{
  // Declare tests to check functionality of ACL rules. User must be a valid user with registered machines.
  "tests": [
    // {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]},
  ],
  // Declare static groups of users beyond those in the identity service.
  "groups": {
    "group:example": [ "user1@example.com", "user2@example.com" ],
  },
  // Declare convenient hostname aliases to use in place of IP addresses.
  "hosts": {
    "example-host-1": "100.100.100.100",
  },
  // Access control lists.
  "acls": [
    // Match absolutely everything. Comment out this section if you want
    // to define specific ACL restrictions.
    { "action": "accept", "users": ["*"], "ports": ["*:*"] },
  ]
}'
```

### Response

A successful response returns an HTTP status of '200' and a list of rules that apply to the resource supplied as a list of matches as JSON objects.
Each match object includes:
- `users`: array of strings indicating source entities affected by the rule
- `ports`: array of strings representing destinations that can be accessed
- `lineNumber`: integer indicating the rule's location in the policy file

The response also echoes the `type` and `previewFor` values supplied in the request.

``` jsonc
{
  "matches": [
    {
      "users": ["*"],
      "ports": ["*:*"],
      "lineNumber": 19
    }
  ],
  "type": "user",
  "previewFor: "user1@example.com"
}
```

<a href="tailnet-acl-validate-post"></a>

## Validate and test policy file

``` http
POST /api/v2/tailnet/{tailnet}/acl/validate
```

This method works in one of two modes, neither of which modifies your current tailnet policy file:

- **Run ACL tests:** When the **request body contains ACL tests as a JSON array**,
  Tailscale runs ACL tests against the tailnet's current policy file.
  Learn more about [ACL tests](https://tailscale.com/kb/1018/#tests).
- **Validate a new policy file:** When the **request body is a JSON object**,
  Tailscale interprets the body as a hypothetical new tailnet policy file with new ACLs, including any new rules and tests.
  It validates that the policy file is parsable and runs tests to validate the existing rules.

In either case, this method does not modify the tailnet policy file in any way.

### Parameters for "Run ACL tests" mode

#### `tailnet` (required in URL path)

The tailnet organization name.

#### ACL tests (required in `POST` body)

The `POST` body should be a JSON formatted array of ACL Tests.
Learn more about [tailnet policy file tests](https://tailscale.com/kb/1018/#tests).

### Request example to run ACL tests

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate" \
  -u "tskey-api-xxxxx:" \
  --data-binary '
  [
    {"src": "user1@example.com", "accept": ["example-host-1:22"], "deny": ["example-host-2:100"]}
  ]'
```

### Parameters for "Validate a new policy file" mode

#### `tailnet` (required in URL path)

The tailnet organization name.

#### Entire tailnet policy file (required in `POST` body)

The `POST` body should be a JSON object with a JSON or HuJSON representation of a tailnet policy file.

### Request example to validate a policy file

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/acl/validate" \
  -u "tskey-api-xxxxx:" \
  --data-binary '
  {
    "acls": [
     { "action": "accept", "src": ["100.105.106.107"], "dst": ["1.2.3.4:*"] },
    ],
    "tests", [
      {"src": "100.105.106.107", "allow": ["1.2.3.4:80"]}
    ],
  }'
```

### Response

The HTTP status code will be '200' if the request was well formed and there were no server errors, even in the case of failing tests or an invalid ACL.
Look at the response body to determine whether there was a problem within your ACL or tests:
- If the tests are valid, an empty body or a JSON object with no `message` is returned.
- If there's a problem, the response body will be a JSON object with a non-empty `message` property and optionally additional details in `data`:

  ``` jsonc
  {
    "message":"test(s) failed",
    "data":[
             {
               "user":"user1@example.com",
               "errors":["address \"2.2.2.2:22\": want: Drop, got: Accept"]
             }
           ]
  }
  ```

If your tailnet has [user and group provisioning](https://tailscale.com/kb/1180/sso-okta-scim/) turned on, we will also warn you about
any groups that are used in the policy file that are not being synced from SCIM. Explicitly defined groups will not trigger this warning.

```jsonc
{
  "message":"warning(s) found",
  "data":[
          {
            "user": "group:unknown@example.com",
            "warnings":["group is not syncing from SCIM and will be ignored by rules in the policy file"]
          }
        ]
}
```

<a href="tailnet-devices"></a>

## List tailnet devices

``` http
GET /api/v2/tailnet/{tailnet}/devices
```

Lists the devices in a tailnet.
Optionally use the `fields` query parameter to explicitly indicate which fields are returned.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `fields` (optional in query string)

Controls whether the response returns **all** fields or only a predefined subset of fields.
Currently, there are two supported options:
- **`all`:** return all fields in the response
- **`default`:** return all fields **except**:
  * `enabledRoutes`
  * `advertisedRoutes`
  * `clientConnectivity` (which contains the following fields: `mappingVariesByDestIP`, `derp`, `endpoints`, `latency`, and `clientSupports`)

If the `fields` parameter is not supplied, then the default (limited fields) option is used.

### Request example for default set of fields

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/devices" \
  -u "tskey-api-xxxxx:"
```

### Request example for all fields

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/devices?fields=all" \
  -u "tskey-api-xxxxx:"
```

### Response

On success, returns a 200 status code and a JSON array of the tailnet devices and their details.

## Tailnet keys

These methods operate primarily on auth keys, and in some cases on [API access tokens](#authentication).

- Auth keys: Pre-authentication keys (or "auth keys") let you register new devices on a tailnet without needing to sign in via a web browser.
  Auth keys are identifiable by the prefix `tskey-auth-`. Learn more about [auth keys](https://tailscale.com/kb/1085/).

- API access tokens: used to [authenticate API requests](#authentication).

If you authenticate with a user-owned API access token, all the methods on tailnet keys operate on _keys owned by that user_.
If you authenticate with an access token derived from an OAuth client, then these methods operate on _keys owned by the tailnet_.
Learn more about [OAuth clients](https://tailscale.com/kb/1215).

The `POST /api/v2/tailnet/{tailnet}/keys` method is used to create auth keys only.
The remaining three methods operate on auth keys and API access tokens.

### Attributes

``` jsonc
{
  // capabilities (JSON object) is a mapping of resources to permissible
  // actions.
  "capabilities": {

    // devices (JSON object) specifies the key's permissions over devices.
    "devices": {

      // create (JSON object) specifies the key's permissions when
      // creating devices.
      "create": {

        // reusable (boolean) for auth keys only; reusable auth keys
        // can be used multiple times to register different devices.
        // Learn more about reusable auth keys at
        // https://tailscale.com/kb/1085/#types-of-auth-keys
        "reusable": false,

        // ephemeral (boolean) for auth keys only; ephemeral keys are
        // used to connect and then clean up short-lived devices.
        // Learn about ephemeral nodes at https://tailscale.com/kb/1111/.
        "ephemeral": false,

        // preauthorized (boolean) for auth keys only; these are also
        // referred to as "pre-approved" keys. 'true' means that devices
        // registered with this key won't require additional approval from a
        // tailnet admin.
        // Learn about device approval at https://tailscale.com/kb/1099/.
        "preauthorized": false,

        // tags (string) are the tags that will be set on devices registered
        // with this key.
        // Learn about tags at https://tailscale.com/kb/1068/.
        "tags": [
          "tag:example"
            ]
          }
        }
  }

  // expirySeconds (int) is the duration in seconds a new key is valid.
  "expirySeconds": 86400

  // description (string) is an optional short phrase that describes what
  // this key is used for. It can be a maximum of 50 alphanumeric characters.
  // Hyphens and underscores are also allowed.
  "description": "short description of key purpose"
}
```

<a href="tailnet-keys-get"></a>

## List tailnet keys

``` http
GET /api/v2/tailnet/{tailnet}/keys
```

Returns a list of active auth keys and API access tokens. The set of keys returned depends on the access token used to make the request:
- If the API call is made with a user-owned API access token, this returns only the keys owned by that user.
- If the API call is made with an access token derived from an OAuth client, this returns all keys owned directly by the tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/keys" \
  -u "tskey-api-xxxxx:"
```

### Response

Returns a JSON object with the IDs of all active keys.

``` jsonc
{"keys": [
  {"id": "XXXX14CNTRL"},
  {"id": "XXXXZ3CNTRL"},
  {"id": "XXXX43CNTRL"},
  {"id": "XXXXgj1CNTRL"}
]}
```

<a href="tailnet-keys-post"></a>

## Create auth key

``` http
POST /api/v2/tailnet/{tailnet}/keys
```

Creates a new auth key in the specified tailnet.
The key will be associated with the user who owns the API access token used to make this call,
or, if the call is made with an access token derived from an OAuth client, the key will be owned by the tailnet.

Returns a JSON object with the supplied capabilities in addition to the generated key.
The key should be recorded and kept safe and secure because it wields the capabilities specified in the request.
The identity of the key is embedded in the key itself and can be used to perform operations on the key (e.g., revoking it or retrieving information about it).
The full key can no longer be retrieved after the initial response.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### Tailnet key object (required in `POST` body)

Supply the tailnet key attributes as a JSON object in the `POST` body following the request example below.

At minimum, the request `POST` body must have a `capabilities` object (see below).
With nothing else supplied, such a request generates a single-use key with no tags.

Note the following about required vs. optional values:

- **`capabilities`:** A `capabilities` object is required and must contain `devices`.

- **`devices`:** A `devices` object is required within `capabilities`, but can be an empty JSON object.

- **`tags`:** Whether tags are required or optional depends on the owner of the auth key:
  - When creating an auth key _owned by the tailnet_ (using OAuth), it must have tags.
    The auth tags specified for that new auth key must exactly match the tags that are on the OAuth client used to create that auth key (or they must be tags that are owned by the tags that are on the OAuth client used to create the auth key).
  - When creating an auth key _owned by a user_ (using a user's access token), tags are optional.

- **`expirySeconds`:** Optional in `POST` body.
  Specifies the duration in seconds until the key should expire.
  Defaults to 90 days if not supplied.

- **`description`:** Optional in `POST` body.
  A short string specifying the purpose of the key. Can be a maximum of 50 alphanumeric characters. Hyphens and spaces are also allowed.

### Request example

``` jsonc
curl "https://api.tailscale.com/api/v2/tailnet/example.com/keys" \
  -u "tskey-api-xxxxx:" \
  --data-binary '
{
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": false,
        "preauthorized": false,
        "tags": [ "tag:example" ]
      }
    }
  },
  "expirySeconds": 86400,
  "description": "dev access"
}'
```

### Response

The response is a JSON object that includes the `key` value, which will only be returned once.
Record and safely store the `key` returned.
It holds the capabilities specified in the request and can no longer be retrieved by the server.

``` jsonc
{
  "id":           "k123456CNTRL",
  "key":          "tskey-auth-k123456CNTRL-abcdefghijklmnopqrstuvwxyz",
  "created":      "2021-12-09T23:22:39Z",
  "expires":      "2022-03-09T23:22:39Z",
  "revoked":      "2022-03-12T23:22:39Z",
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": false,
        "preauthorized": false,
        "tags": [ "tag:example" ]
      }
    }
  },
  "description": "dev access"
}
```

<a href="tailnet-keys-key-get"></a>

## Get key

``` http
GET /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Returns a JSON object with information about a specific key, such as its creation and expiration dates and its capabilities.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `keyId` (required in URL path)

The ID of the key.

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL" \
  -u "tskey-api-xxxxx:"
```

### Response

The response is a JSON object with information about the key supplied.

``` jsonc
{
  "id": "abc123456CNTRL",
  "created": "2022-05-05T18:55:44Z",
  "expires": "2022-08-03T18:55:44Z",
  "capabilities": {
    "devices": {
      "create": {
        "reusable": false,
        "ephemeral": true,
        "preauthorized": false,
        "tags": [
          "tag:bar",
          "tag:foo"
        ]
      }
    }
  },
  "description": "dev access"
}
```

Response for a revoked (deleted) or expired key will have an `invalid` field set to `true`:

``` jsonc
{
  "id": "abc123456CNTRL",
  "created": "2022-05-05T18:55:44Z",
  "expires": "2022-08-03T18:55:44Z",
  "revoked": "2023-04-01T20:50:00Z",
  "invalid": true
}
```

<a href="tailnet-keys-key-delete"></a>

## Delete key

``` http
DELETE /api/v2/tailnet/{tailnet}/keys/{keyid}
```

Deletes a specific key.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `keyId` (required in URL path)

The ID of the key. The key ID can be found in the [admin console](https://login.tailscale.com/admin/settings/keys).

### Request example

``` sh
curl -X DELETE 'https://api.tailscale.com/api/v2/tailnet/example.com/keys/k123456CNTRL' \
  -u "tskey-api-xxxxx:"
```

### Response

This returns status 200 upon success.

<a href="tailnet-dns"></a>

## DNS

The tailnet DNS methods are provided for fetching and modifying various DNS settings for a tailnet.
These include nameservers, DNS preferences, and search paths.
Learn more about [DNS in Tailscale](https://tailscale.com/kb/1054/).

<a href="tailnet-dns-nameservers-get"></a>

## Get nameservers

``` http
GET /api/v2/tailnet/{tailnet}/dns/nameservers
```

Lists the global DNS nameservers for a tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers" \
  -u "tskey-api-xxxxx:"
```

### Response

``` jsonc
{
  "dns": ["8.8.8.8"],
}
```

<a href="tailnet-dns-nameservers-post"></a>

## Set nameservers

``` http
POST /api/v2/tailnet/{tailnet}/dns/nameservers
```

Replaces the list of global DNS nameservers for the given tailnet with the list supplied in the request.
Note that changing the list of DNS nameservers may also affect the status of MagicDNS (if MagicDNS is on; learn about [MagicDNS](https://tailscale.com/kb/1081).
If all nameservers have been removed, MagicDNS will be automatically disabled (until explicitly turned back on by the user).

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `dns` (required in `POST` body)

The new list of DNS nameservers in JSON.

``` jsonc
{
  "dns":["8.8.8.8"]
}
```

### Request example: adding DNS nameservers with MagicDNS on

Adding DNS nameservers with the MagicDNS on:

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers" \
  -u "tskey-api-xxxxx:" \
  --data-binary '{"dns": ["8.8.8.8"]}'
```

### Response example: adding DNS nameservers, MagicDNS on

The response is a JSON object containing the new list of nameservers and the status of MagicDNS.

``` jsonc
{
  "dns":["8.8.8.8"],
  "magicDNS":true,
}
```

### Request example: removing all DNS nameservers, MagicDNS on

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/nameservers" \
  -u "tskey-api-xxxxx:" \
  --data-binary '{"dns": []}'
```

### Response example: removing all DNS nameservers with MagicDNS on

The response is a JSON object containing the new list of nameservers and the status of MagicDNS.

``` jsonc
{
  "dns":[],
  "magicDNS": false,
}
```

<a href="tailnet-dns-preferences-get"></a>

## Get DNS preferences

``` http
GET /api/v2/tailnet/{tailnet}/dns/preferences`
```

Retrieves the DNS preferences that are currently set for the given tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences" \
  -u "tskey-api-xxxxx:"
```

### Response

``` jsonc
{
  "magicDNS":false,
}
```

<a href="tailnet-dns-preferences-post"></a>

## Set DNS preferences

``` http
POST /api/v2/tailnet/{tailnet}/dns/preferences
```

Set the DNS preferences for a tailnet; specifically, the MagicDNS setting.
Note that MagicDNS is dependent on DNS servers.
Learn about [MagicDNS](https://tailscale.com/kb/1081).

If there is at least one DNS server, then MagicDNS can be enabled.
Otherwise, it returns an error.

Note that removing all nameservers will turn off MagicDNS.
To reenable it, nameservers must be added back, and MagicDNS must be explicitly turned on.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### DNS preference (required in `POST` body)

The DNS preferences in JSON. Currently, MagicDNS is the only setting available:

- **`magicDNS`:** Automatically registers DNS names for devices in your tailnet.

``` jsonc
{
  "magicDNS": true
}
```

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/preferences" \
  -u "tskey-api-xxxxx:" \
  --data-binary '{"magicDNS": true}'
```

### Response

If there are no DNS servers, this returns an error message:

``` jsonc
{
  "message":"need at least one nameserver to enable MagicDNS"
}
```

If there are DNS servers, this returns the MagicDNS status:

``` jsonc
{
  "magicDNS":true,
}
```

<a href="tailnet-dns-searchpaths-get"></a>

## Get search paths

``` http
GET /api/v2/tailnet/{tailnet}/dns/searchpaths
```

Retrieves the list of search paths, also referred to as _search domains_, that is currently set for the given tailnet.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths" \
  -u "tskey-api-xxxxx:"
```

### Response

``` jsonc
{
  "searchPaths": ["user1.example.com"],
}
```

<a href="tailnet-dns-searchpaths-post"></a>

## Set search paths

``` http
POST /api/v2/tailnet/{tailnet}/dns/searchpaths
```

Replaces the list of search paths with the list supplied by the user and returns an error otherwise.

### Parameters

#### `tailnet` (required in URL path)

The tailnet organization name.

#### `searchPaths` (required in `POST` body)

Specify a list of search paths in a JSON object:

``` jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"]
}
```

### Request example

``` sh
curl "https://api.tailscale.com/api/v2/tailnet/example.com/dns/searchpaths" \
  -u "tskey-api-xxxxx:" \
  --data-binary '{"searchPaths": ["user1.example.com", "user2.example.com"]}'
```

### Response

The response is a JSON object containing the new list of search paths.

``` jsonc
{
  "searchPaths": ["user1.example.com", "user2.example.com"],
}
```
